use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use aes::Aes256;
use base64::prelude::*;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr32BE;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;

pub mod signal {
    include!(concat!(env!("OUT_DIR"), "/signal.rs"));
}

use signal::BackupFrame;

#[derive(Debug)]
struct HeaderData {
    initialisation_vector: Vec<u8>,
    salt: Vec<u8>,
    version: Option<u32>,
}

#[derive(Debug)]
struct Keys {
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

fn to_io_error(e: rusqlite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

fn read_backup_header<R: Read>(backup_file: &mut R) -> io::Result<HeaderData> {
    let mut length_bytes = [0u8; 4];
    backup_file.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes);

    let mut backup_frame_bytes = vec![0u8; length as usize];
    backup_file.read_exact(&mut backup_frame_bytes)?;

    let backup_frame: BackupFrame = BackupFrame::decode(&backup_frame_bytes[..])?;

    let header = backup_frame
        .header
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing header"))?;

    Ok(HeaderData {
        initialisation_vector: header.iv.unwrap(),
        salt: header.salt.unwrap(),
        version: header.version,
    })
}

fn derive_keys(passphrase: &str, salt: &[u8]) -> io::Result<Keys> {
    let passphrase_bytes = passphrase.replace(" ", "").as_bytes().to_vec();

    let mut hash = passphrase_bytes.clone();
    let mut sha512 = Sha512::new();

    Digest::update(&mut sha512, salt);

    for _ in 0..250000 {
        Digest::update(&mut sha512, &hash);
        Digest::update(&mut sha512, &passphrase_bytes);
        hash = sha512.finalize_reset().to_vec();
    }

    let hkdf = Hkdf::<Sha256>::new(Some(b""), &hash[..32]);
    let mut keys = vec![0u8; 64];
    hkdf.expand(b"Backup Export", &mut keys)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HKDF expand failed"))?;

    Ok(Keys {
        cipher_key: keys[..32].to_vec(),
        hmac_key: keys[32..].to_vec(),
    })
}

fn increment_initialisation_vector(initialisation_vector: &[u8]) -> Vec<u8> {
    let mut counter = u32::from_be_bytes(initialisation_vector[..4].try_into().unwrap());
    counter = (counter + 1) & 0xFFFFFFFF;
    let mut new_iv = counter.to_be_bytes().to_vec();
    new_iv.extend_from_slice(&initialisation_vector[4..]);
    new_iv
}

fn parameter_to_native_type(
    parameter: &signal::sql_statement::SqlParameter,
) -> rusqlite::Result<Option<Box<dyn rusqlite::ToSql>>> {
    if let Some(s) = &parameter.string_paramter {
        Ok(Some(Box::new(s.clone())))
    } else if let Some(i) = parameter.integer_parameter {
        let signed_i = if i & (1 << 63) != 0 {
            i | (-1_i64 << 63) as u64
        } else {
            i
        };
        Ok(Some(Box::new(signed_i as i64)))
    } else if let Some(d) = parameter.double_parameter {
        Ok(Some(Box::new(d)))
    } else if let Some(b) = &parameter.blob_parameter {
        Ok(Some(Box::new(b.clone())))
    } else if parameter.nullparameter.is_some() {
        Ok(None)
    } else {
        Ok(None)
    }
}

fn decrypt_frame<R: Read>(
    backup_file: &mut R,
    hmac_key: &[u8],
    cipher_key: &[u8],
    initialisation_vector: &[u8],
    header_version: Option<u32>,
    ciphertext_buf: &mut Vec<u8>,
    plaintext_buf: &mut Vec<u8>,
) -> io::Result<BackupFrame> {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid HMAC key"))?;

    let mut ctr =
        <Ctr32BE<Aes256> as KeyIvInit>::new_from_slices(cipher_key, initialisation_vector)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid CTR parameters"))?;

    let length = match header_version {
        None => {
            let mut length_bytes = [0u8; 4];
            backup_file.read_exact(&mut length_bytes)?;
            u32::from_be_bytes(length_bytes)
        }
        Some(1) => {
            let mut encrypted_length = [0u8; 4];
            backup_file.read_exact(&mut encrypted_length)?;

            println!("encrypted length bytes: {:02x?}", encrypted_length);

            Mac::update(&mut hmac, &encrypted_length);

            let mut decrypted_length = encrypted_length;
            ctr.apply_keystream(&mut decrypted_length);

            println!("decrypted length bytes: {:02x?}", decrypted_length);

            let len = u32::from_be_bytes(decrypted_length);
            println!("length: {}", len);
            len
        }
        Some(v) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported version: {}", v),
            ))
        }
    };

    if length < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Frame too short",
        ));
    }

    ciphertext_buf.clear();
    ciphertext_buf.resize((length - 10) as usize, 0);
    backup_file.read_exact(ciphertext_buf)?;

    let mut their_mac = [0u8; 10];
    backup_file.read_exact(&mut their_mac)?;

    Mac::update(&mut hmac, ciphertext_buf);
    let our_mac = hmac.finalize().into_bytes();

    println!(
        "Their MAC: {:02x?}, Our MAC: {:02x?}",
        their_mac,
        &our_mac[..10]
    );

    if their_mac != our_mac[..10] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "MAC verification failed. Their MAC: {:02x?}, Our MAC: {:02x?}",
                their_mac,
                &our_mac[..10]
            ),
        ));
    }

    plaintext_buf.clear();
    plaintext_buf.extend_from_slice(ciphertext_buf);
    ctr.apply_keystream(plaintext_buf);

    BackupFrame::decode(&plaintext_buf[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn decrypt_frame_payload<R: Read>(
    backup_file: &mut R,
    length: usize,
    hmac_key: &[u8],
    cipher_key: &[u8],
    initialisation_vector: &[u8],
    chunk_size: usize,
) -> io::Result<Vec<u8>> {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid HMAC key"))?;
    Mac::update(&mut hmac, initialisation_vector);

    let mut ctr =
        <Ctr32BE<Aes256> as KeyIvInit>::new_from_slices(cipher_key, initialisation_vector)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid CTR parameters"))?;

    let mut decrypted_data = Vec::new();
    let mut remaining_length = length;

    while remaining_length > 0 {
        let this_chunk_length = remaining_length.min(chunk_size);
        remaining_length -= this_chunk_length;

        let mut ciphertext = vec![0u8; this_chunk_length];
        backup_file.read_exact(&mut ciphertext)?;
        Mac::update(&mut hmac, &ciphertext);

        let mut decrypted_chunk = ciphertext;
        ctr.apply_keystream(&mut decrypted_chunk);
        decrypted_data.extend(decrypted_chunk);
    }

    let mut their_mac = [0u8; 10];
    backup_file.read_exact(&mut their_mac)?;

    let our_mac = hmac.finalize().into_bytes();

    if &their_mac != &our_mac[..10] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload: MAC verification failed. Their MAC: {:02x?}, Our MAC: {:02x?}",
                their_mac,
                &our_mac[..10]
            ),
        ));
    }

    Ok(decrypted_data)
}

fn decrypt_backup<R>(
    backup_file: &mut R,
    passphrase: &str,
    output_directory: &Path,
) -> io::Result<()>
where
    R: Read + Seek,
{
    let mut backup_file = BufReader::with_capacity(32 * 1024, backup_file);
    let total_size = backup_file.seek(SeekFrom::End(0))?;
    // reset the reader
    backup_file.seek(SeekFrom::Start(0))?;
    let mut last_percentage = 0;

    let database_filename = output_directory.join("database.sqlite");
    let preferences_filename = output_directory.join("preferences.json");
    let key_value_filename = output_directory.join("key_value.json");
    let attachments_directory = output_directory.join("attachments");
    let stickers_directory = output_directory.join("stickers");
    let avatars_directory = output_directory.join("avatars");

    for directory in [
        output_directory,
        &attachments_directory,
        &stickers_directory,
        &avatars_directory,
    ] {
        fs::create_dir_all(directory)?;
    }

    if database_filename.exists() {
        fs::remove_file(&database_filename)?;
    }

    let mut db_connection = Connection::open(&database_filename).map_err(to_io_error)?;

    db_connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 30000000000;
             PRAGMA page_size = 4096;",
        )
        .map_err(to_io_error)?;

    let tx = db_connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_io_error)?;

    let mut preferences: HashMap<String, HashMap<String, HashMap<String, serde_json::Value>>> =
        HashMap::new();
    let mut key_values: HashMap<String, HashMap<String, serde_json::Value>> = HashMap::new();

    let header_data = read_backup_header(&mut backup_file)?;
    let keys = derive_keys(passphrase, &header_data.salt)?;
    let mut initialisation_vector = header_data.initialisation_vector.clone();

    let mut ciphertext: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut plaintext: Vec<u8> = Vec::with_capacity(1024 * 1024);

    loop {
        let current_position = backup_file.stream_position()?;
        let percentage = ((current_position as f64 / total_size as f64) * 100.0) as u32;
        if percentage != last_percentage {
            eprintln!("Progress: {}%", percentage);
            last_percentage = percentage;
        }

        let backup_frame = decrypt_frame(
            &mut backup_file,
            &keys.hmac_key,
            &keys.cipher_key,
            &initialisation_vector,
            header_data.version,
            &mut ciphertext,
            &mut plaintext,
        )?;

        initialisation_vector = increment_initialisation_vector(&initialisation_vector);

        if backup_frame.end.unwrap_or(false) {
            break;
        } else if let Some(version) = backup_frame.version {
            if let Some(ver_num) = version.version {
                let pragma_sql = format!("PRAGMA user_version = {}", ver_num);
                tx.execute_batch(&pragma_sql).map_err(to_io_error)?;
            }
        } else if let Some(statement) = backup_frame.statement {
            if let Some(sql) = statement.statement {
                if !sql.to_lowercase().starts_with("create table sqlite_")
                    && !sql.contains("sms_fts_")
                    && !sql.contains("mms_fts_")
                {
                    let params: Vec<Option<Box<dyn rusqlite::ToSql>>> = statement
                        .parameters
                        .iter()
                        .map(parameter_to_native_type)
                        .collect::<Result<_, _>>()
                        .map_err(to_io_error)?;

                    tx.execute(
                        &sql,
                        rusqlite::params_from_iter(params.iter().map(|p| p.as_deref())),
                    )
                    .map_err(to_io_error)?;
                }
            }
        } else if let Some(preference) = backup_frame.preference {
            let value_dict = preferences
                .entry(preference.file.unwrap_or_default())
                .or_default()
                .entry(preference.key.unwrap_or_default())
                .or_default();

            if let Some(value) = preference.value {
                value_dict.insert("value".to_string(), serde_json::Value::String(value));
            }
            if let Some(boolean_value) = preference.boolean_value {
                value_dict.insert(
                    "booleanValue".to_string(),
                    serde_json::Value::Bool(boolean_value),
                );
            }
            if preference.is_string_set_value.unwrap_or(false) {
                value_dict.insert(
                    "stringSetValue".to_string(),
                    serde_json::Value::Array(
                        preference
                            .string_set_value
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                );
            }
        } else if let Some(key_value) = backup_frame.key_value {
            let value_dict = key_values
                .entry(key_value.key.unwrap_or_default())
                .or_default();

            if let Some(boolean_value) = key_value.boolean_value {
                value_dict.insert(
                    "booleanValue".to_string(),
                    serde_json::Value::Bool(boolean_value),
                );
            }
            if let Some(float_value) = key_value.float_value {
                value_dict.insert(
                    "floatValue".to_string(),
                    serde_json::Value::Number(
                        serde_json::Number::from_f64(float_value.into()).unwrap(),
                    ),
                );
            }
            if let Some(integer_value) = key_value.integer_value {
                value_dict.insert(
                    "integerValue".to_string(),
                    serde_json::Value::Number(integer_value.into()),
                );
            }
            if let Some(long_value) = key_value.long_value {
                value_dict.insert(
                    "longValue".to_string(),
                    serde_json::Value::Number(long_value.into()),
                );
            }
            if let Some(string_value) = key_value.string_value {
                value_dict.insert(
                    "stringValue".to_string(),
                    serde_json::Value::String(string_value),
                );
            }
            if let Some(blob_value) = key_value.blob_value {
                value_dict.insert(
                    "blobValueBase64".to_string(),
                    serde_json::Value::String(BASE64_STANDARD.encode(&blob_value)),
                );
            }
        } else {
            let (filename, length) = if let Some(attachment) = backup_frame.attachment {
                (
                    attachments_directory.join(format!("{}.bin", attachment.row_id.unwrap_or(0))),
                    attachment.length.unwrap_or(0),
                )
            } else if let Some(sticker) = backup_frame.sticker {
                (
                    stickers_directory.join(format!("{}.bin", sticker.row_id.unwrap_or(0))),
                    sticker.length.unwrap_or(0),
                )
            } else if let Some(avatar) = backup_frame.avatar {
                (
                    avatars_directory
                        .join(format!("{}.bin", avatar.recipient_id.unwrap_or_default())),
                    avatar.length.unwrap_or(0),
                )
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid field type found",
                ));
            };

            let mut file = File::create(&filename)?;
            let payload = decrypt_frame_payload(
                &mut backup_file,
                length as usize,
                &keys.hmac_key,
                &keys.cipher_key,
                &initialisation_vector,
                8 * 1024,
            )?;
            file.write_all(&payload)?;
            initialisation_vector = increment_initialisation_vector(&initialisation_vector);
        }
    }

    tx.commit().map_err(to_io_error)?;

    let mut preferences_file = File::create(preferences_filename)?;
    serde_json::to_writer_pretty(&mut preferences_file, &preferences)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut key_values_file = File::create(key_value_filename)?;
    serde_json::to_writer_pretty(&mut key_values_file, &key_values)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <backup_file> [output_directory] [-p PASSPHRASE]",
            args[0]
        );
        std::process::exit(1);
    }

    let backup_file_path = &args[1];
    let output_directory = if args.len() > 2 {
        Path::new(&args[2]).to_path_buf()
    } else {
        Path::new("./out").to_path_buf()
    };

    let passphrase = if let Some(pos) = args.iter().position(|arg| arg == "-p") {
        args.get(pos + 1).expect("Passphrase not provided").clone()
    } else {
        rpassword::prompt_password("Backup passphrase: ").expect("Failed to read passphrase")
    };

    let mut backup_file = File::open(backup_file_path)?;
    decrypt_backup(&mut backup_file, &passphrase, &output_directory)?;

    Ok(())
}
