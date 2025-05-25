use std::{
    path::Path,
    process::{Command, Stdio},
};

fn main() {
    let workspace_root =
        std::fs::canonicalize(Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join(".."))
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
    for (cwd, src, obj) in [
        (workspace_root.as_str(), "nanos.elf", "nanos.o"),
        (
            format!("{}/target/x86_64-sel4/release", workspace_root).as_str(),
            "logserver.elf",
            "logserver.o",
        ),
        (
            format!("{}/target/x86_64-sel4/release", workspace_root).as_str(),
            "timeserver.elf",
            "timeserver.o",
        ),
        (
            format!("{}/target/x86_64-sel4/release", workspace_root).as_str(),
            "virtioserver.elf",
            "virtioserver.o",
        ),
        (
            format!("{}/target/x86_64-sel4/release", workspace_root).as_str(),
            "dbgserver.elf",
            "dbgserver.o",
        ),
        (
            format!("{}/target/x86_64-sel4/release", workspace_root).as_str(),
            "vmmserver.elf",
            "vmmserver.o",
        ),
    ] {
        let status = Command::new("objcopy")
            .arg("--input")
            .arg("binary")
            .arg("--output")
            .arg("elf64-x86-64")
            .arg("--binary-architecture")
            .arg("i386:x86-64")
            .arg("--rename-section")
            .arg(format!(".data=.blob.{}", src))
            .arg("--set-section-alignment")
            .arg(".data=4096")
            .arg(src)
            .arg(format!("{}/{}", workspace_root, obj))
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .unwrap();
        if !status.success() {
            panic!("objcopy failed");
        }
        println!("cargo:rerun-if-changed={}/{}", workspace_root, src);
        println!("cargo:rustc-link-arg={}/{}", workspace_root, obj);
    }
}
