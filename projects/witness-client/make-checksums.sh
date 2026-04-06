#!/usr/bin/env bash
# =============================================================================
# make-checksums.sh — Run this on your BUILD MACHINE before copying to USB
# Never run this on the target machine
# =============================================================================
# Usage: bash make-checksums.sh
# Output: writes VERIFY.txt next to this script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payload"
OUT_FILE="$SCRIPT_DIR/VERIFY.txt"

if [[ ! -d "$PAYLOAD_DIR" ]]; then
  echo "ERROR: payload/ directory not found at $SCRIPT_DIR"
  exit 1
fi

echo "# Harborlight USB Installer — Payload Checksums"   > "$OUT_FILE"
echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$OUT_FILE"
echo "# DO NOT EDIT — regenerate with make-checksums.sh" >> "$OUT_FILE"
echo ""                                                   >> "$OUT_FILE"

COUNT=0
find "$PAYLOAD_DIR" -type f | sort | while read -r file; do
  rel="${file#$SCRIPT_DIR/}"

  if command -v sha256sum &>/dev/null; then
    hash=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum &>/dev/null; then
    hash=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    echo "ERROR: No SHA256 tool available."
    exit 1
  fi

  echo "$hash  $rel" >> "$OUT_FILE"
  echo "  hashed: $rel"
  (( COUNT++ )) || true
done

echo ""
echo "Done. $COUNT files hashed → VERIFY.txt"
echo "Now copy the entire USB folder to your stick."
