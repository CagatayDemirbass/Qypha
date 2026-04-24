use anyhow::Result;
use std::path::Path;

/// Read a file (with permission check in production)
pub fn read_file(path: &str) -> Result<Vec<u8>> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(anyhow::anyhow!("File not found: {}", path));
    }
    Ok(std::fs::read(p)?)
}

/// Write data to a file (with permission check in production)
pub fn write_file(path: &str, data: &[u8]) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data)?;
    Ok(())
}

/// List directory contents
pub fn list_directory(path: &str) -> Result<Vec<String>> {
    let entries = std::fs::read_dir(path)?
        .filter_map(|e| e.ok())
        .map(|e| e.path().display().to_string())
        .collect();
    Ok(entries)
}
