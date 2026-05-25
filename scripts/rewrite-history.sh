#!/usr/bin/env bash
# scripts/rewrite-history.sh — sanitize git history before public release.
#
# Uses git-filter-repo to strip accidentally committed secrets, large binaries,
# or any other content that should not appear in the public history.
#
# SAFETY GATES:
#   - Requires explicit --confirm flag.
#   - Tags pre-rewrite HEAD as pre-v2-history for anyone who needs the original.
#   - Never force-pushes; prints the push command for review.
#   - Must be run from the repo root on a clean working tree.
#
# Prerequisites:
#   pip install git-filter-repo
#
# Usage:
#   ./scripts/rewrite-history.sh [--dry-run] [--confirm]

set -euo pipefail

DRY_RUN=false
CONFIRM=false

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --confirm) CONFIRM=true ;;
        *) echo "Unknown flag: $arg" >&2; exit 1 ;;
    esac
done

# ── Preflight ────────────────────────────────────────────────────────────────

command -v git-filter-repo >/dev/null 2>&1 \
    || { echo "FATAL: git-filter-repo not found. Install: pip install git-filter-repo" >&2; exit 1; }

if [[ "$(git status --porcelain)" != "" ]]; then
    echo "FATAL: working tree is not clean. Commit or stash changes first." >&2
    exit 1
fi

BRANCH=$(git symbolic-ref --short HEAD)
if [[ "$BRANCH" != "main" && "$BRANCH" != "master" ]]; then
    echo "WARN: current branch is '$BRANCH', not main/master."
    echo "      Run on the branch you intend to rewrite."
fi

if [[ "$CONFIRM" = false ]]; then
    echo ""
    echo "  This script rewrites git history. All existing commit SHAs will change."
    echo "  Anyone with a clone of this repo will need to re-clone or rebase."
    echo ""
    echo "  Review the filter rules in this script before proceeding."
    echo "  Then re-run with: $0 --confirm"
    echo ""
    exit 0
fi

# ── Tag pre-rewrite state ────────────────────────────────────────────────────

PRE_TAG="pre-v2-history"
if git rev-parse --verify "$PRE_TAG" >/dev/null 2>&1; then
    echo "INFO: $PRE_TAG already exists — not re-tagging."
else
    echo "INFO: Tagging pre-rewrite HEAD as $PRE_TAG"
    if [[ "$DRY_RUN" = false ]]; then
        git tag "$PRE_TAG"
    else
        echo "[dry-run] git tag $PRE_TAG"
    fi
fi

# ── Filter rules ─────────────────────────────────────────────────────────────

# Paths to remove entirely from history.
# Add any accidentally committed secrets, binaries, or large files here.
PATHS_TO_REMOVE=(
    # Examples — uncomment and adjust as needed:
    # ".env"
    # "secrets.json"
    # "*.pem"
)

# Strings to replace in blobs (e.g. leaked tokens).
# Format: "literal-string==>REDACTED"
STRINGS_TO_REPLACE=(
    # Examples:
    # "sk-ant-api03-REAL_KEY==>REDACTED_API_KEY"
)

# ── Build filter-repo args ────────────────────────────────────────────────────

ARGS=()

for p in "${PATHS_TO_REMOVE[@]}"; do
    ARGS+=("--path" "$p" "--invert-paths")
done

for pair in "${STRINGS_TO_REPLACE[@]}"; do
    ARGS+=("--replace-text" <(echo "$pair"))
done

if [[ ${#ARGS[@]} -eq 0 ]]; then
    echo "INFO: No filter rules configured. Edit PATHS_TO_REMOVE / STRINGS_TO_REPLACE in this script."
    echo "      Exiting without changes."
    exit 0
fi

# ── Execute ───────────────────────────────────────────────────────────────────

echo "INFO: Running git-filter-repo${DRY_RUN:+ (dry run)} ..."
if [[ "$DRY_RUN" = true ]]; then
    echo "[dry-run] git filter-repo ${ARGS[*]}"
else
    git filter-repo "${ARGS[@]}"
fi

# ── Post-run guidance ─────────────────────────────────────────────────────────

echo ""
echo "History rewrite complete."
echo ""
echo "Next steps:"
echo "  1. Review the rewritten history:   git log --oneline | head -20"
echo "  2. Verify no sensitive content:    git log --all -p | grep -i 'secret\\|token\\|key'"
echo "  3. Force-push ONLY after sign-off:"
echo "     git push --force-with-lease origin $BRANCH"
echo "  4. Notify collaborators — all clones must re-clone or hard-reset."
echo "     The pre-rewrite state is preserved at tag: $PRE_TAG"
echo ""
echo "NEVER use 'git push --force' (without --force-with-lease) on a shared repo."
