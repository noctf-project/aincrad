fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix(".")
        .file("proto.capnp")
        .run()
        .expect("schema compiler command");
}
