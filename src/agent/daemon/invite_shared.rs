use super::*;

pub(crate) async fn direct_invite_already_used(
    used_invites: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    code: &str,
) -> bool {
    let used = used_invites.lock().await;
    used.contains(&invite_code_fingerprint(code))
}

pub(crate) async fn persist_direct_invite_use(
    used_invites: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    used_invites_path: Option<&std::path::PathBuf>,
    used_invites_persist_key: Option<&[u8; 32]>,
    code: &str,
) {
    let invite_fp = invite_code_fingerprint(code);
    let mut used = used_invites.lock().await;
    if used.insert(invite_fp) {
        if let Some(path) = used_invites_path {
            persist_used_invites(path, &used, used_invites_persist_key);
        }
    }
}

pub(crate) async fn try_reserve_direct_invite_use(
    used_invites: &Arc<tokio::sync::Mutex<HashSet<String>>>,
    used_invites_path: Option<&std::path::PathBuf>,
    used_invites_persist_key: Option<&[u8; 32]>,
    code: &str,
) -> bool {
    let invite_fp = invite_code_fingerprint(code);
    let mut used = used_invites.lock().await;
    if used.contains(&invite_fp) {
        return false;
    }
    used.insert(invite_fp);
    if let Some(path) = used_invites_path {
        persist_used_invites(path, &used, used_invites_persist_key);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_reserve_direct_invite_use_is_single_use() {
        let used_invites = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let code = "invite-code";

        assert!(
            try_reserve_direct_invite_use(&used_invites, None, None, code).await,
            "first reservation should succeed"
        );
        assert!(
            direct_invite_already_used(&used_invites, code).await,
            "successful reservation should mark the invite as used"
        );
        assert!(
            !try_reserve_direct_invite_use(&used_invites, None, None, code).await,
            "second reservation should be rejected"
        );
    }
}
