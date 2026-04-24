use std::{env, fs, path::PathBuf};

fn sync_windows_cli_resource_alias() {
    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("windows") {
        return;
    }

    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(_) => return,
    };

    let release_dir = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("target")
        .join("release");
    let source = release_dir.join("qypha.exe");
    let alias = release_dir.join("qypha");

    println!("cargo:rerun-if-changed={}", source.display());

    if !source.exists() {
        return;
    }

    let should_copy = match (fs::metadata(&source), fs::metadata(&alias)) {
        (Ok(source_meta), Ok(alias_meta)) => {
            let source_modified = source_meta.modified().ok();
            let alias_modified = alias_meta.modified().ok();
            source_meta.len() != alias_meta.len() || source_modified != alias_modified
        }
        (Ok(_), Err(_)) => true,
        _ => false,
    };

    if !should_copy {
        return;
    }

    let _ = fs::remove_file(&alias);
    let _ = fs::copy(&source, &alias);
}

fn main() {
    sync_windows_cli_resource_alias();
    tauri_build::build()
}
