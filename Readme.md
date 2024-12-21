# signal-decrypt-backup-rust
A port of [https://github.com/mossblaser/signal_for_android_decryption](signal_for_android_decryption) in Rust.

This port was done for speed improvements and easier integration with wasm.

The wasm version is available at [https://git.duskflower.dev/duskflower/signal-decrypt-backup-wasm](duskflower/signal-decrypt-backup-wasm)

## Build
`cargo build`

`cargo run --release`

## Usage
`./target/release/signal-decrypt-backup-rust <backup_file> [output_directory] [-p PASSPHRASE]`

If no passphrase is provided, you will be asked for it.
