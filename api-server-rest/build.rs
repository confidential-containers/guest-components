use ttrpc_codegen::{Codegen, Customize, ProtobufCustomize};

fn main() -> std::io::Result<()> {
    let protos = vec![
        "./protos/confidential_data_hub.proto",
        "./protos/attestation_agent.proto",
    ];
    let protobuf_customized = ProtobufCustomize::default().gen_mod_rs(false);

    Codegen::new()
        .out_dir("src/ttrpc_proto")
        .inputs(&protos)
        .include("./protos")
        .rust_protobuf()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .rust_protobuf_customize(protobuf_customized)
        .run()
        .expect("Generate ttrpc protocol code failed.");

    Ok(())
}
