//! NIST SP 800-88 compliant secure file/directory wipe.
//!
//! Strategy for each file:
//!   Pass 1: Overwrite with cryptographically random bytes + fsync (HDD: sufficient)
//!   Pass 2: Truncate to 0 + fsync (SSD: triggers TRIM, controller erases flash cells)
//!   Pass 3: unlink (removes directory entry)
//!
//! On SSDs, the combination of overwrite + truncate provides defense-in-depth:
//!   - Overwrite: best-effort (wear leveling may redirect, but old cells enter GC queue)
//!   - Truncate: triggers TRIM, telling the SSD controller to physically erase blocks
//!   - With FileVault/LUKS: even unTRIMmed cells contain only encrypted data

use std::io::Write;
use std::path::Path;

/// Securely wipe an entire directory tree (depth-first).
///
/// All files are overwritten with random bytes, truncated (TRIM trigger),
/// then unlinked. Directories are removed after their contents are wiped.
pub fn secure_wipe_dir(dir: &Path) {
    if !dir.exists() {
        return;
    }

    // Depth-first: wipe files first, then remove empty dirs
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() || path.is_symlink() {
                secure_wipe_file(&path);
            } else if path.is_dir() {
                secure_wipe_dir(&path);
            }
        }
    }

    // Remove the now-empty directory
    let _ = std::fs::remove_dir_all(dir);
}

/// Securely wipe a single file: random overwrite + truncate/TRIM + unlink.
///
/// When `_QYPHA_FDE_OFF=1` is set (FileVault/LUKS not active), uses 3-pass
/// random overwrite to maximize the chance of overwriting the same physical SSD cells
/// despite wear leveling. With FDE active, 1 pass suffices since the underlying
/// data is already encrypted.
pub fn secure_wipe_file(path: &Path) {
    use std::io::Seek;

    let fde_off = std::env::var("_QYPHA_FDE_OFF").unwrap_or_default() == "1";
    let passes = if fde_off { 3 } else { 1 };

    // Security: never follow symlinks during wipe. Unlink the symlink itself.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(path);
            return;
        }

        let size = meta.len() as usize;
        if size > 0 {
            // Multi-pass random overwrite
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let chunk_size = 1024 * 1024; // 1 MB
                for _pass in 0..passes {
                    // Seek to beginning for each pass
                    let _ = f.seek(std::io::SeekFrom::Start(0));
                    let mut remaining = size;
                    while remaining > 0 {
                        let this_chunk = remaining.min(chunk_size);
                        let random_bytes: Vec<u8> =
                            (0..this_chunk).map(|_| rand::random::<u8>()).collect();
                        if f.write_all(&random_bytes).is_err() {
                            break;
                        }
                        remaining -= this_chunk;
                    }
                    let _ = f.sync_all(); // Force flush to physical media after each pass
                }
            }

            // Truncate to 0 (triggers TRIM on SSD)
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
                let _ = f.set_len(0);
                let _ = f.sync_all();
            }
        }
    }

    // Unlink
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_secure_wipe_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("secret.key");

        // Write sensitive data
        std::fs::write(&file_path, b"TOP SECRET KEY MATERIAL 1234567890").unwrap();
        assert!(file_path.exists());

        // Wipe it
        secure_wipe_file(&file_path);

        // File should be gone
        assert!(!file_path.exists());
    }

    #[test]
    fn test_secure_wipe_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("keys");
        std::fs::create_dir_all(&sub).unwrap();

        std::fs::write(sub.join("agent.key"), b"secret key").unwrap();
        std::fs::write(sub.join("public.key"), b"public key").unwrap();
        std::fs::write(dir.path().join("config.toml"), b"[agent]\nname=\"ghost\"").unwrap();

        // All files should exist
        assert!(sub.join("agent.key").exists());

        // Wipe the root
        secure_wipe_dir(dir.path());

        // Nothing should remain
        assert!(!sub.exists());
        assert!(!dir.path().join("config.toml").exists());
    }

    #[test]
    fn test_secure_wipe_nonexistent() {
        // Should not panic on nonexistent paths
        secure_wipe_file(Path::new("/tmp/nonexistent_file_12345"));
        secure_wipe_dir(Path::new("/tmp/nonexistent_dir_12345"));
    }
}
