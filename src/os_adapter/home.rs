use std::path::PathBuf;

#[cfg(unix)]
fn sudo_invoker_home_dir() -> Option<PathBuf> {
    use std::ffi::{CStr, CString};

    let sudo_user = std::env::var("SUDO_USER").ok()?;
    let sudo_user = sudo_user.trim();
    if sudo_user.is_empty() || sudo_user.eq_ignore_ascii_case("root") {
        return None;
    }

    let user_cstr = CString::new(sudo_user).ok()?;
    unsafe {
        let pwd = libc::getpwnam(user_cstr.as_ptr());
        if pwd.is_null() || (*pwd).pw_dir.is_null() {
            return None;
        }
        CStr::from_ptr((*pwd).pw_dir)
            .to_str()
            .ok()
            .map(PathBuf::from)
    }
}

#[cfg(not(unix))]
fn sudo_invoker_home_dir() -> Option<PathBuf> {
    None
}

pub(crate) fn preferred_user_home_dir() -> Option<PathBuf> {
    sudo_invoker_home_dir()
        .or_else(dirs::home_dir)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
}

pub(crate) fn preferred_desktop_dir() -> Option<PathBuf> {
    if let Some(home) = sudo_invoker_home_dir() {
        return Some(home.join("Desktop"));
    }
    dirs::desktop_dir().or_else(|| preferred_user_home_dir().map(|home| home.join("Desktop")))
}
