// mitigation/build.rs
fn main() {
    println!("cargo:rerun-if-changed=../proto/radm.proto");
    println!("cargo:rerun-if-changed=src/proto/radm.v1.rs");
}
