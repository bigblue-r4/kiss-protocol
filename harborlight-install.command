#!/usr/bin/env bash
# =============================================================================
# install.command — Mac entry point (double-click in Finder)
# =============================================================================
# If macOS blocks this: right-click → Open → confirm in dialog

# Change to the directory containing this script
# (Finder sets CWD to ~/ by default, not the USB folder)
#
# The cd is checked and _core.sh is sourced by absolute path: with Finder's
# CWD being the user's home directory, an unchecked cd here would have meant
# sourcing ~/_core.sh instead of the installer's own.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || {
  echo "cannot determine the installer directory" >&2
  exit 1
}
cd "$SCRIPT_DIR" || exit 1

[ -r "$SCRIPT_DIR/_core.sh" ] || {
  echo "missing $SCRIPT_DIR/_core.sh — run this from an unpacked release" >&2
  exit 1
}

# Keep Terminal window open long enough to read results
trap 'echo ""; echo "  Press any key to close..."; read -rn1' EXIT

# shellcheck source=_core.sh
source "$SCRIPT_DIR/_core.sh"
run_installer
