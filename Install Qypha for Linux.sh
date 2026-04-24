#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SETUP_SCRIPT="${ROOT_DIR}/setup.sh"

if [[ ! -f "${SETUP_SCRIPT}" ]]; then
  echo "Qypha setup.sh not found next to this installer."
  read -r -p "Press Enter to close..."
  exit 1
fi

chmod +x "${SETUP_SCRIPT}"

clear || true
printf '
'
printf '  Qypha Linux Setup
'
printf '  =================

'
printf '  1. Full install (CLI + desktop)
'
printf '  2. CLI only
'
printf '  3. Clean rebuild
'
printf '  4. Uninstall
'
printf '  5. Quit

'

read -r -p "Choose an option [1-5]: " choice

case "${choice}" in
  1)
    exec "${SETUP_SCRIPT}"
    ;;
  2)
    exec "${SETUP_SCRIPT}" --skip-desktop
    ;;
  3)
    exec "${SETUP_SCRIPT}" --clean
    ;;
  4)
    exec "${SETUP_SCRIPT}" --uninstall
    ;;
  5)
    exit 0
    ;;
  *)
    echo "Invalid selection."
    read -r -p "Press Enter to close..."
    exit 1
    ;;
esac
