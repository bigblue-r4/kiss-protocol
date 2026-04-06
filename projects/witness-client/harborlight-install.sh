#!/usr/bin/env bash
# =============================================================================
# install.sh — Linux entry point
# Usage: bash install.sh
# =============================================================================

cd "$(dirname "$0")"

source "./_core.sh"
run_installer
