use protobuf_codegen::Codegen;


fn main() -> () {
    Codegen::new()
        .protoc()
        .cargo_out_dir("generated_with_native")
        .input("src/protos/protocol.proto")
        .include("src/protos")
        .run_from_script();
}