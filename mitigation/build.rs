// mitigation/build.rs
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("src/proto")?;
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["../proto/radm.proto"], &["../proto/"])?;
    println!("cargo:rerun-if-changed=../proto/radm.proto");
    Ok(())
}
