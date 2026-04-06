#!/usr/bin/env bash
# =============================================================================
# install.command — Mac entry point (double-click in Finder)
# =============================================================================
# If macOS blocks this: right-click → Open → confirm in dialog

# Change to the directory containing this script
# (Finder sets CWD to ~/ by default, not the USB folder)
cd "$(dirname "$0")"

# Keep Terminal window open long enough to read results
trap 'echo ""; echo "  Press any key to close..."; read -rn1' EXIT

source "./_core.sh"
run_installer
