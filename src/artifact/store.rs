/// Artifact Store — local encrypted file storage
/// In production: backed by MinIO (S3-compatible) with AES-256-GCM encryption-at-rest
///
/// Each artifact is stored as:
///   ~/.qypha/artifacts/<artifact_id>/
///     ├── manifest.json     (signed manifest)
///     ├── data.enc          (encrypted archive)
///     └── key.enc           (wrapped symmetric key)

pub struct ArtifactStore {
    pub base_dir: std::path::PathBuf,
}

impl ArtifactStore {
    pub fn new(base_dir: std::path::PathBuf) -> Self {
        Self { base_dir }
    }
}
