// use protobuf_codegen::Codegen;

// fn main() {
//     // Specify the path to your .proto file
//     let proto_file = "./src/Backups.proto"; // Adjust the path accordingly

//     // Generate Rust code from the .proto file
//     Codegen::new()
//         .out_dir("./src/proto") // Output directory for generated code
//         .inputs(&[proto_file])
//         .include("./src") // Include path for imports
//         .run()
//         .expect("protoc failed.");
// }

use std::io::Result;

fn main() -> Result<()> {
    // Specify the path to your .proto files
    let proto_files = &["src/Backups.proto"]; // Adjust the path as necessary

    // Specify the output directory
    let _out_dir = [std::env::var("OUT_DIR").unwrap()];

    // Compile the proto files
    prost_build::compile_protos(proto_files, &["src"]).unwrap();

    Ok(())
}
