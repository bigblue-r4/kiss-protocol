#!/usr/bin/env bash
# =============================================================================
# install.sh — Linux entry point
# Usage: bash install.sh
# =============================================================================

# The cd is checked, and _core.sh is sourced by absolute path built from the
# same place: an unchecked cd would leave this running in whatever directory
# the user happened to be in, and `source ./_core.sh` would then load that
# directory's file rather than the installer's own.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || {
  echo "cannot determine the installer directory" >&2
  exit 1
}
cd "$SCRIPT_DIR" || exit 1

[ -r "$SCRIPT_DIR/_core.sh" ] || {
  echo "missing $SCRIPT_DIR/_core.sh — run this from an unpacked release" >&2
  exit 1
}

# shellcheck source=_core.sh
source "$SCRIPT_DIR/_core.sh"
run_installer
