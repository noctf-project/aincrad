use std::env;

fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix(".")
        .file("proto.capnp")
        .run()
        .expect("schema compiler command");

    // Only link libmnl when targeting musl
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "musl" {
        println!("cargo:rustc-link-lib=static=mnl");
    }
}