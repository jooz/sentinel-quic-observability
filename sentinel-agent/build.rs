use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap();

    let ebpf_binary_name = "sentinel_ebpf";
    let target_path = workspace_root
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join(ebpf_binary_name);

    if !target_path.exists() {
        let status = Command::new("cargo")
            .args([
                "+nightly-2026-04-01",
                "build",
                "--release",
                "--package",
                "sentinel-ebpf",
                "-Z",
                "build-std=core",
                "--target",
                "bpfel-unknown-none",
            ])
            .current_dir(workspace_root)
            .status()?;

        if !status.success() {
            anyhow::bail!("eBPF build failed");
        }
    }

    println!("cargo:rerun-if-changed=../sentinel-ebpf/src/");
    println!("cargo:rerun-if-changed=../sentinel-ebpf-common/src/");

    Ok(())
}
