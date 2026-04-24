#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EMBEDDED_RUNTIME_DIR="${ROOT_DIR}/embedded_runtime"
DESKTOP_DIR="${ROOT_DIR}/apps/qypha-desktop"

NODE_VERSION="22.16.0"
PROTOC_VERSION="28.3"
LOCAL_TOOLS_DIR="${HOME}/.qypha-tools"
LOCAL_BIN_DIR="${HOME}/.local/bin"
DOWNLOADS_DIR="${LOCAL_TOOLS_DIR}/downloads"

INSTALL_DESKTOP=1
BUILD_DESKTOP_BUNDLE=1
INSTALL_DESKTOP_APP=1
SKIP_BUILD=0
CLEAN_BUILD=0
UNINSTALL=0
INSTALLED_DESKTOP_PATH=""
DESKTOP_SHORTCUT_PATH=""
TERMINAL_DESKTOP_LAUNCHER=""
TERMINAL_CLI_LAUNCHER=""

log_step() {
  printf '\n[%s] %s\n' "$1" "$2"
}

log_info() {
  printf '  - %s\n' "$1"
}

fail() {
  printf '\n[setup] %s\n' "$1" >&2
  exit 1
}

version_gte() {
  local current="$1"
  local minimum="$2"
  local current_parts minimum_parts i current_part minimum_part
  IFS='.' read -r -a current_parts <<< "${current}"
  IFS='.' read -r -a minimum_parts <<< "${minimum}"
  for i in 0 1 2 3; do
    current_part="${current_parts[$i]:-0}"
    minimum_part="${minimum_parts[$i]:-0}"
    if ((10#${current_part} > 10#${minimum_part})); then
      return 0
    fi
    if ((10#${current_part} < 10#${minimum_part})); then
      return 1
    fi
  done
  return 0
}

ensure_line_in_file() {
  local file_path="$1"
  local line="$2"
  mkdir -p "$(dirname "${file_path}")"
  touch "${file_path}"
  if ! grep -Fq "${line}" "${file_path}"; then
    printf '\n%s\n' "${line}" >> "${file_path}"
  fi
}

ensure_local_bin_on_path() {
  mkdir -p "${LOCAL_BIN_DIR}"
  export PATH="${LOCAL_BIN_DIR}:$PATH"
  case "${SHELL##*/}" in
    zsh)
      ensure_line_in_file "${HOME}/.zprofile" 'export PATH="$HOME/.local/bin:$PATH"'
      ;;
    bash)
      ensure_line_in_file "${HOME}/.bash_profile" 'export PATH="$HOME/.local/bin:$PATH"'
      ;;
    *)
      ensure_line_in_file "${HOME}/.profile" 'export PATH="$HOME/.local/bin:$PATH"'
      ;;
  esac
}

require_command() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || fail "Required command not found: ${cmd}"
}

file_exists_from_glob() {
  local glob="$1"
  compgen -G "${glob}" >/dev/null 2>&1
}

os_name() {
  case "$(uname -s)" in
    Darwin) printf 'macos' ;;
    Linux) printf 'linux' ;;
    *) fail "Unsupported operating system: $(uname -s)" ;;
  esac
}

arch_name() {
  case "$(uname -m)" in
    arm64|aarch64) printf 'arm64' ;;
    x86_64|amd64) printf 'x64' ;;
    *) fail "Unsupported architecture: $(uname -m)" ;;
  esac
}

with_sudo() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "This step needs root privileges but sudo is not available."
  fi
}

apt_has_package() {
  apt-cache show "$1" >/dev/null 2>&1
}

dnf_has_package() {
  dnf list --quiet --available "$1" >/dev/null 2>&1 || dnf list --quiet --installed "$1" >/dev/null 2>&1
}

pacman_has_package() {
  pacman -Si "$1" >/dev/null 2>&1 || pacman -Qi "$1" >/dev/null 2>&1
}

zypper_has_package() {
  zypper --quiet info "$1" >/dev/null 2>&1
}

resolve_first_available_linux_package() {
  local manager="$1"
  shift
  local candidate
  for candidate in "$@"; do
    case "${manager}" in
      apt)
        if apt_has_package "${candidate}"; then
          printf '%s' "${candidate}"
          return 0
        fi
        ;;
      dnf)
        if dnf_has_package "${candidate}"; then
          printf '%s' "${candidate}"
          return 0
        fi
        ;;
      pacman)
        if pacman_has_package "${candidate}"; then
          printf '%s' "${candidate}"
          return 0
        fi
        ;;
      zypper)
        if zypper_has_package "${candidate}"; then
          printf '%s' "${candidate}"
          return 0
        fi
        ;;
    esac
  done
  return 1
}

install_linux_packages() {
  local manager="$1"
  shift
  case "${manager}" in
    apt)
      with_sudo apt-get update
      with_sudo apt-get install -y "$@"
      ;;
    dnf)
      with_sudo dnf install -y "$@"
      ;;
    pacman)
      with_sudo pacman -Sy --noconfirm --needed "$@"
      ;;
    zypper)
      with_sudo zypper --non-interactive install "$@"
      ;;
    *)
      fail "Unsupported Linux package manager: ${manager}"
      ;;
  esac
}

detect_linux_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    printf 'apt'
  elif command -v dnf >/dev/null 2>&1; then
    printf 'dnf'
  elif command -v pacman >/dev/null 2>&1; then
    printf 'pacman'
  elif command -v zypper >/dev/null 2>&1; then
    printf 'zypper'
  else
    fail "Unsupported Linux distribution. Install the Rust toolchain, WebKitGTK, appindicator, OpenSSL headers, curl, unzip, and xz manually."
  fi
}

ensure_macos_prerequisites() {
  log_step "1/9" "Checking macOS prerequisites"
  if ! xcode-select -p >/dev/null 2>&1; then
    log_info "Xcode Command Line Tools are missing. Triggering installer..."
    xcode-select --install >/dev/null 2>&1 || true
    fail "Install Xcode Command Line Tools, then rerun ./setup.sh"
  fi
  log_info "Xcode Command Line Tools ready"
}

ensure_linux_prerequisites() {
  local manager
  local packages=()
  manager="$(detect_linux_package_manager)"
  log_step "1/9" "Installing Linux build prerequisites via ${manager}"

  case "${manager}" in
    apt)
      packages=(build-essential curl file pkg-config libssl-dev unzip xz-utils)
      ;;
    dnf)
      packages=(gcc-c++ make curl file openssl-devel pkgconf-pkg-config unzip xz)
      ;;
    pacman)
      packages=(base-devel curl file openssl pkgconf unzip xz)
      ;;
    zypper)
      packages=(gcc-c++ make curl file libopenssl-devel pkg-config unzip xz)
      ;;
  esac

  if [[ "${INSTALL_DESKTOP}" -eq 1 ]]; then
    case "${manager}" in
      apt)
        packages+=(
          libgtk-3-dev
          librsvg2-dev
          libxdo-dev
          patchelf
          "$(resolve_first_available_linux_package apt libayatana-appindicator3-dev libappindicator3-dev)"
          "$(resolve_first_available_linux_package apt libwebkit2gtk-4.1-dev libwebkit2gtk-4.0-dev)"
          "$(resolve_first_available_linux_package apt libjavascriptcoregtk-4.1-dev libjavascriptcoregtk-4.0-dev)"
        )
        ;;
      dnf)
        packages+=(
          gtk3-devel
          librsvg2-devel
          libxdo-devel
          patchelf
          "$(resolve_first_available_linux_package dnf libayatana-appindicator-gtk3-devel libappindicator-gtk3-devel)"
          "$(resolve_first_available_linux_package dnf webkit2gtk4.1-devel webkit2gtk4.0-devel webkit2gtk3-devel)"
        )
        ;;
      pacman)
        packages+=(
          gtk3
          librsvg
          xdotool
          patchelf
          "$(resolve_first_available_linux_package pacman libayatana-appindicator libappindicator-gtk3)"
          "$(resolve_first_available_linux_package pacman webkit2gtk-4.1 webkit2gtk)"
        )
        ;;
      zypper)
        packages+=(
          gtk3-devel
          librsvg-devel
          libxdo-devel
          patchelf
          "$(resolve_first_available_linux_package zypper libayatana-appindicator3-devel libappindicator3-devel)"
          "$(resolve_first_available_linux_package zypper webkit2gtk3-devel libwebkit2gtk3-devel)"
        )
        ;;
    esac
  fi

  install_linux_packages "${manager}" "${packages[@]}"
  log_info "Linux prerequisites ready"
}

ensure_rust() {
  log_step "2/9" "Checking Rust toolchain"
  if ! command -v rustup >/dev/null 2>&1; then
    log_info "Installing rustup + Rust stable"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  fi
  # shellcheck disable=SC1090
  source "${HOME}/.cargo/env"
  rustup toolchain install stable >/dev/null
  rustup default stable >/dev/null
  rustup update stable >/dev/null
  log_info "$(rustc --version)"
}

node_asset_name() {
  local os="$1"
  local arch="$2"
  if [[ "${os}" == "macos" ]]; then
    printf 'node-v%s-darwin-%s.tar.gz' "${NODE_VERSION}" "${arch}"
  else
    printf 'node-v%s-linux-%s.tar.xz' "${NODE_VERSION}" "${arch}"
  fi
}

install_or_update_local_node() {
  local os="$1"
  local arch="$2"
  local node_dir="${LOCAL_TOOLS_DIR}/node-v${NODE_VERSION}-${os}-${arch}"
  local asset archive_url archive_path staging_dir extracted_root
  asset="$(node_asset_name "${os}" "${arch}")"
  archive_url="https://nodejs.org/dist/v${NODE_VERSION}/${asset}"
  archive_path="${DOWNLOADS_DIR}/${asset}"

  mkdir -p "${DOWNLOADS_DIR}" "${LOCAL_TOOLS_DIR}" "${LOCAL_BIN_DIR}"

  if [[ ! -x "${node_dir}/bin/node" ]]; then
    log_info "Installing Node.js v${NODE_VERSION}"
    rm -rf "${node_dir}" "${node_dir}.staging"
    mkdir -p "${node_dir}.staging"
    curl -fsSL "${archive_url}" -o "${archive_path}"
    tar -xf "${archive_path}" -C "${node_dir}.staging"
    extracted_root="${node_dir}.staging/$(basename "${asset}" .tar.gz)"
    extracted_root="${extracted_root%.tar.xz}"
    if [[ ! -d "${extracted_root}" ]]; then
      fail "Unexpected Node archive layout for ${asset}"
    fi
    mv "${extracted_root}" "${node_dir}"
    rm -rf "${node_dir}.staging"
  fi

  ln -sf "${node_dir}/bin/node" "${LOCAL_BIN_DIR}/node"
  ln -sf "${node_dir}/bin/npm" "${LOCAL_BIN_DIR}/npm"
  ln -sf "${node_dir}/bin/npx" "${LOCAL_BIN_DIR}/npx"
  if [[ -x "${node_dir}/bin/corepack" ]]; then
    ln -sf "${node_dir}/bin/corepack" "${LOCAL_BIN_DIR}/corepack"
  fi
  export PATH="${LOCAL_BIN_DIR}:$PATH"
  if ! version_gte "$(node --version | sed 's/^v//')" "${NODE_VERSION}"; then
    fail "Node.js ${NODE_VERSION}+ is required but the active version is $(node --version)"
  fi
  log_info "Using Node.js $(node --version)"
}

protoc_asset_name() {
  local os="$1"
  local arch="$2"
  case "${os}-${arch}" in
    macos-arm64) printf 'protoc-%s-osx-aarch_64.zip' "${PROTOC_VERSION}" ;;
    macos-x64) printf 'protoc-%s-osx-x86_64.zip' "${PROTOC_VERSION}" ;;
    linux-arm64) printf 'protoc-%s-linux-aarch_64.zip' "${PROTOC_VERSION}" ;;
    linux-x64) printf 'protoc-%s-linux-x86_64.zip' "${PROTOC_VERSION}" ;;
    *) fail "Unsupported protoc target: ${os}/${arch}" ;;
  esac
}

install_or_update_local_protoc() {
  local os="$1"
  local arch="$2"
  local asset archive_url archive_path protoc_dir
  asset="$(protoc_asset_name "${os}" "${arch}")"
  archive_url="https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${asset}"
  archive_path="${DOWNLOADS_DIR}/${asset}"
  protoc_dir="${LOCAL_TOOLS_DIR}/protoc-${PROTOC_VERSION}-${os}-${arch}"

  mkdir -p "${DOWNLOADS_DIR}" "${LOCAL_TOOLS_DIR}" "${LOCAL_BIN_DIR}"

  if [[ ! -x "${protoc_dir}/bin/protoc" ]]; then
    log_info "Installing protoc v${PROTOC_VERSION}"
    rm -rf "${protoc_dir}" "${protoc_dir}.staging"
    mkdir -p "${protoc_dir}.staging"
    curl -fsSL "${archive_url}" -o "${archive_path}"
    unzip -q -o "${archive_path}" -d "${protoc_dir}.staging"
    mv "${protoc_dir}.staging" "${protoc_dir}"
  fi

  ln -sf "${protoc_dir}/bin/protoc" "${LOCAL_BIN_DIR}/protoc"
  export PATH="${LOCAL_BIN_DIR}:$PATH"
  log_info "Using $(protoc --version)"
}

run_npm_ci() {
  local dir="$1"
  log_info "npm ci in ${dir#${ROOT_DIR}/}"
  (cd "${dir}" && npm ci)
}

build_desktop_bundle() {
  case "${OS}" in
    macos)
      (cd "${DESKTOP_DIR}" && npm run tauri:build -- --bundles app,dmg)
      ;;
    linux)
      (cd "${DESKTOP_DIR}" && npm run tauri:build -- --bundles appimage)
      ;;
    *)
      fail "Desktop bundle build is not supported on ${OS}"
      ;;
  esac
}

create_unix_desktop_launcher() {
  local binary_path="$1"
  TERMINAL_DESKTOP_LAUNCHER="${LOCAL_BIN_DIR}/Qypha-desktop"
  cat > "${TERMINAL_DESKTOP_LAUNCHER}" <<EOF
#!/usr/bin/env bash
exec "${binary_path}" "\$@"
EOF
  chmod +x "${TERMINAL_DESKTOP_LAUNCHER}"
}

create_unix_cli_launcher() {
  local binary_path="$1"
  TERMINAL_CLI_LAUNCHER="${LOCAL_BIN_DIR}/Qypha"
  cat > "${TERMINAL_CLI_LAUNCHER}" <<EOF
#!/usr/bin/env bash
if [[ -t 1 || -t 2 ]]; then
  if [[ "\$#" -gt 0 ]]; then
    printf '\033]0;%s\007' "Qypha \$*"
  else
    printf '\033]0;%s\007' "Qypha"
  fi
fi
exec "${binary_path}" "\$@"
EOF
  chmod +x "${TERMINAL_CLI_LAUNCHER}"
}

remove_path_if_exists() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    log_info "Removing ${path}"
    if rm -rf "${path}" 2>/dev/null; then
      return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
      sudo rm -rf "${path}"
      return 0
    fi
    fail "Could not remove ${path}. Try rerunning with a user that can delete it."
  fi
}

clean_project_artifacts() {
  log_step "0/9" "Removing repo build artifacts and generated runtime payloads for a clean rebuild"

  local paths=(
    "${ROOT_DIR}/target"
    "${EMBEDDED_RUNTIME_DIR}/dist"
    "${EMBEDDED_RUNTIME_DIR}/node_modules"
    "${DESKTOP_DIR}/dist"
    "${DESKTOP_DIR}/node_modules"
    "${DESKTOP_DIR}/src-tauri/target"
  )
  local path
  for path in "${paths[@]}"; do
    if [[ -e "${path}" ]]; then
      log_info "Removing ${path#${ROOT_DIR}/}"
      rm -rf "${path}"
    fi
  done

  local runtime_payload_patterns=(
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/python/.downloads"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/python/*/python"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/git/.downloads"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/git/*/micromamba"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/git/*/pkgs"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/git/*/prefix"
    "${EMBEDDED_RUNTIME_DIR}/internal/runtime/git/*/mamba-root"
    "${EMBEDDED_RUNTIME_DIR}/internal/bundled-mcp-plugins/.runtime-state"
    "${EMBEDDED_RUNTIME_DIR}/internal/bundled-mcp-plugins/fetch-server/vendor/site-packages"
    "${EMBEDDED_RUNTIME_DIR}/internal/bundled-mcp-plugins/git-server/vendor/site-packages"
    "${EMBEDDED_RUNTIME_DIR}/internal/bundled-mcp-plugins/playwright-mcp/vendor/node_modules"
    "${EMBEDDED_RUNTIME_DIR}/internal/bundled-mcp-plugins/playwright-mcp/vendor/ms-playwright"
  )
  local pattern match
  for pattern in "${runtime_payload_patterns[@]}"; do
    while IFS= read -r match; do
      [[ -n "${match}" ]] || continue
      if [[ -e "${match}" ]]; then
        log_info "Removing ${match#${ROOT_DIR}/}"
        rm -rf "${match}"
      fi
    done < <(compgen -G "${pattern}" || true)
  done
}

mark_build_outputs_non_indexable() {
  local dirs=(
    "${ROOT_DIR}/target"
    "${DESKTOP_DIR}/src-tauri/target"
  )
  local dir
  for dir in "${dirs[@]}"; do
    mkdir -p "${dir}"
    touch "${dir}/.metadata_never_index"
  done
}

uninstall_macos_desktop_app() {
  remove_path_if_exists "/Applications/Qypha.app"
  remove_path_if_exists "${HOME}/Applications/Qypha.app"
  remove_path_if_exists "${HOME}/Desktop/Qypha.app"
}

uninstall_linux_desktop_app() {
  remove_path_if_exists "${HOME}/.local/share/qypha"
  remove_path_if_exists "${HOME}/.local/share/applications/qypha.desktop"
  remove_path_if_exists "${HOME}/Desktop/Qypha.desktop"
}

uninstall_common_launchers() {
  remove_path_if_exists "${LOCAL_BIN_DIR}/Qypha-desktop"
  remove_path_if_exists "${LOCAL_BIN_DIR}/Qypha"
}

uninstall_qypha() {
  local os="$1"
  log_step "1/1" "Uninstalling Qypha app and build outputs"

  case "${os}" in
    macos)
      uninstall_macos_desktop_app
      ;;
    linux)
      uninstall_linux_desktop_app
      ;;
  esac

  uninstall_common_launchers
  clean_project_artifacts

  printf '\nQypha uninstall complete.\n\n'
  printf 'Removed:\n'
  printf '  - installed desktop app / shortcuts\n'
  printf '  - terminal launchers under %s\n' "${LOCAL_BIN_DIR}"
  printf '  - repo build artifacts (target, dist, node_modules)\n'
  printf '  - generated embedded runtime payloads under embedded_runtime/internal\n\n'
  printf 'Preserved:\n'
  printf '  - this repository folder\n'
  printf '  - local toolchains under %s\n' "${LOCAL_TOOLS_DIR}"
  printf '  - user data / agent state under ~/.qypha and related config dirs\n'
}

install_macos_desktop_app() {
  local bundle_dir="${DESKTOP_DIR}/src-tauri/target/release/bundle/macos"
  local source_app="${bundle_dir}/Qypha.app"
  local install_dir install_target
  [[ -d "${source_app}" ]] || fail "macOS bundle not found at ${source_app}"

  if [[ -w "/Applications" ]]; then
    install_dir="/Applications"
  elif command -v sudo >/dev/null 2>&1; then
    install_dir="/Applications"
  else
    install_dir="${HOME}/Applications"
    mkdir -p "${install_dir}"
  fi

  install_target="${install_dir}/Qypha.app"
  if [[ "${install_dir}" == "/Applications" && ! -w "/Applications" ]]; then
    with_sudo rm -rf "${install_target}"
    with_sudo ditto "${source_app}" "${install_target}"
  else
    rm -rf "${install_target}"
    ditto "${source_app}" "${install_target}"
  fi

  mkdir -p "${HOME}/Desktop"
  DESKTOP_SHORTCUT_PATH="${HOME}/Desktop/Qypha.app"
  rm -rf "${DESKTOP_SHORTCUT_PATH}"
  ln -s "${install_target}" "${DESKTOP_SHORTCUT_PATH}"

  INSTALLED_DESKTOP_PATH="${install_target}"
  create_unix_desktop_launcher "${install_target}/Contents/MacOS/qypha-desktop"
}

install_linux_desktop_app() {
  local bundle_root="${DESKTOP_DIR}/src-tauri/target/release/bundle"
  local appimage_path app_dir desktop_entry_path desktop_shortcut icon_target
  if file_exists_from_glob "${bundle_root}/appimage/"'*.AppImage'; then
    appimage_path="$(compgen -G "${bundle_root}/appimage/*.AppImage" | head -n 1)"
  else
    fail "Linux AppImage bundle not found under ${bundle_root}/appimage. Check the Tauri build output."
  fi

  app_dir="${HOME}/.local/share/qypha"
  mkdir -p "${app_dir}" "${HOME}/.local/share/applications" "${HOME}/Desktop"
  INSTALLED_DESKTOP_PATH="${app_dir}/Qypha.AppImage"
  icon_target="${app_dir}/qypha-logo.png"
  cp "${appimage_path}" "${INSTALLED_DESKTOP_PATH}"
  chmod +x "${INSTALLED_DESKTOP_PATH}"
  cp "${ROOT_DIR}/logo.png" "${icon_target}"

  desktop_entry_path="${HOME}/.local/share/applications/qypha.desktop"
  desktop_shortcut="${HOME}/Desktop/Qypha.desktop"
  cat > "${desktop_entry_path}" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Qypha
Comment=Qypha secure multi-agent desktop
Exec=${INSTALLED_DESKTOP_PATH}
Icon=${icon_target}
Terminal=false
Categories=Network;Utility;
EOF
  chmod +x "${desktop_entry_path}"
  cp "${desktop_entry_path}" "${desktop_shortcut}"
  chmod +x "${desktop_shortcut}"

  DESKTOP_SHORTCUT_PATH="${desktop_shortcut}"
  create_unix_desktop_launcher "${INSTALLED_DESKTOP_PATH}"
}

install_desktop_app() {
  [[ "${INSTALL_DESKTOP}" -eq 1 ]] || return 0
  [[ "${BUILD_DESKTOP_BUNDLE}" -eq 1 ]] || return 0
  [[ "${INSTALL_DESKTOP_APP}" -eq 1 ]] || return 0
  [[ "${SKIP_BUILD}" -eq 0 ]] || return 0

  log_step "8/9" "Installing desktop application"
  case "${OS}" in
    macos)
      install_macos_desktop_app
      ;;
    linux)
      install_linux_desktop_app
      ;;
    *)
      fail "Desktop installation is not implemented for ${OS}"
      ;;
  esac
}

build_embedded_worker() {
  log_step "5/9" "Installing JavaScript dependencies"
  run_npm_ci "${EMBEDDED_RUNTIME_DIR}"
  if [[ "${INSTALL_DESKTOP}" -eq 1 ]]; then
    run_npm_ci "${DESKTOP_DIR}"
  fi

  log_step "6/9" "Building embedded AI worker"
  (cd "${EMBEDDED_RUNTIME_DIR}" && npm run build:embedded-worker)
}

build_project() {
  if [[ "${SKIP_BUILD}" -eq 1 ]]; then
    log_step "7/9" "Skipping build steps"
    return
  fi

  log_step "7/9" "Building Rust core"
  (cd "${ROOT_DIR}" && cargo build --release)
  create_unix_cli_launcher "${ROOT_DIR}/target/release/qypha"

  if [[ "${INSTALL_DESKTOP}" -eq 1 ]]; then
    log_info "Building desktop web assets"
    (cd "${DESKTOP_DIR}" && npm run build:web)
  fi

  if [[ "${BUILD_DESKTOP_BUNDLE}" -eq 1 ]]; then
    log_info "Building desktop bundle"
    build_desktop_bundle
  fi
}

print_next_steps() {
  log_step "9/9" "Setup complete"
  printf '\nQypha is ready.\n\n'
  printf 'CLI:\n'
  if [[ -n "${TERMINAL_CLI_LAUNCHER}" ]]; then
    printf '  Terminal launch: %s\n' "${TERMINAL_CLI_LAUNCHER}"
    printf '  Or simply: Qypha launch\n\n'
  else
    printf '  cd %s\n' "${ROOT_DIR}"
    printf '  cargo run --release -- launch\n\n'
  fi
  if [[ "${INSTALL_DESKTOP}" -eq 1 ]]; then
    printf 'Desktop App:\n'
    if [[ -n "${INSTALLED_DESKTOP_PATH}" ]]; then
      printf '  Installed app: %s\n' "${INSTALLED_DESKTOP_PATH}"
    fi
    if [[ -n "${DESKTOP_SHORTCUT_PATH}" ]]; then
      printf '  Desktop shortcut: %s\n' "${DESKTOP_SHORTCUT_PATH}"
    fi
    if [[ -n "${TERMINAL_DESKTOP_LAUNCHER}" ]]; then
      printf '  Terminal launch: %s\n' "${TERMINAL_DESKTOP_LAUNCHER}"
      printf '  Or simply: Qypha-desktop\n'
    fi
    printf '\n'
    printf 'Desktop dev mode:\n'
    printf '  cd %s\n' "${DESKTOP_DIR}"
    printf '  npm run tauri:dev\n\n'
  fi
  printf 'Local toolchain installed under:\n'
  printf '  %s\n' "${LOCAL_TOOLS_DIR}"
  printf '  %s\n\n' "${LOCAL_BIN_DIR}"
  printf 'If you open a new shell and node/protoc are not found immediately, run:\n'
  printf '  export PATH="$HOME/.local/bin:$PATH"\n'
}

usage() {
  cat <<'EOF'
Usage: ./setup.sh [options]

Options:
  --uninstall         Remove installed app, launchers, and repo build artifacts
  --clean             Remove repo build artifacts first, then rebuild from scratch
  --skip-desktop      Skip desktop app prerequisites and npm install in apps/qypha-desktop
  --desktop-bundle    Build the packaged desktop bundle explicitly (default on)
  --skip-desktop-install  Prepare desktop build outputs but do not install the desktop app
  --skip-build        Install dependencies but skip cargo/npm build steps
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall)
      UNINSTALL=1
      ;;
    --clean)
      CLEAN_BUILD=1
      ;;
    --skip-desktop)
      INSTALL_DESKTOP=0
      ;;
    --desktop-bundle)
      BUILD_DESKTOP_BUNDLE=1
      ;;
    --skip-desktop-install)
      INSTALL_DESKTOP_APP=0
      ;;
    --skip-build)
      SKIP_BUILD=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
  shift
done

if [[ "${UNINSTALL}" -eq 1 ]]; then
  uninstall_qypha "$(os_name)"
  exit 0
fi

require_command curl
require_command tar
ensure_local_bin_on_path
mark_build_outputs_non_indexable

if [[ "${CLEAN_BUILD}" -eq 1 ]]; then
  clean_project_artifacts
  mark_build_outputs_non_indexable
fi

OS="$(os_name)"
ARCH="$(arch_name)"

if [[ "${OS}" == "macos" ]]; then
  ensure_macos_prerequisites
else
  ensure_linux_prerequisites
fi

ensure_rust
require_command unzip

log_step "3/9" "Installing local Node.js"
install_or_update_local_node "${OS}" "${ARCH}"

log_step "4/9" "Installing local protoc"
install_or_update_local_protoc "${OS}" "${ARCH}"

build_embedded_worker
build_project
install_desktop_app
print_next_steps
