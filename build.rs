fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf message definitions
    prost_build::compile_protos(&["proto/agent_message.proto"], &["proto/"])?;
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
