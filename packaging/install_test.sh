#!/usr/bin/env bash
# Installer input fixtures: no network, actual root, service, or host writes.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export CALLS="$W/calls"
unset PIPELOCK_VERSION
export TEST_PIPELOCK_MISSING=0 TEST_INSTALLED_VERSION=v3.8.0 TEST_GO_VERSION=1.26.11
# Simulate lookup absence even if the host has an installed Pipelock elsewhere.
export BASH_ENV="$W/stub-env"
cat > "$BASH_ENV" <<'ENV'
command() {
    if [[ "${1:-}" == -v && "${2:-}" == pipelock && "$TEST_PIPELOCK_MISSING" == 1 ]]; then return 1; fi
    builtin command "$@"
}
ENV
mkdir -p "$W/bin" "$W/home"
export HOME="$W/home"
export PATH="$W/bin:$PATH"
cat > "$W/bin/go" <<'STUB'
#!/usr/bin/env bash
set -eu
if [[ "$1" == version ]]; then printf 'go version go%s linux/amd64\n' "$TEST_GO_VERSION"; exit; fi
if [[ "$1" == install ]]; then printf 'pipelock %s\n' "$2" >> "$CALLS"; exit; fi
[[ "$1" == build && "$2" == -mod=readonly ]] || exit 90
printf 'build %s\n' "$(cat REVISION)" >> "$CALLS"
cat REVISION > witness
STUB
cat > "$W/bin/install" <<'STUB'
#!/usr/bin/env bash
set -eu
printf 'binary %s\n' "$(cat witness)" >> "$CALLS"
STUB
cat > "$W/bin/pipelock" <<'STUB'
#!/usr/bin/env bash
printf 'pipelock %s\n' "$TEST_INSTALLED_VERSION"
STUB
cat > "$W/bin/uname" <<'STUB'
#!/usr/bin/env bash
printf 'Linux\n'
STUB
cat > "$W/bin/id" <<'STUB'
#!/usr/bin/env bash
printf '0\n'
STUB
for cmd in curl git systemctl; do
    cat > "$W/bin/$cmd" <<'STUB'
#!/usr/bin/env bash
printf 'UNEXPECTED %s\n' "$(basename "$0")" >> "$CALLS"
exit 91
STUB
 done
chmod +x "$W/bin/"*
new_fixture() {
    F="$W/$1"
    mkdir -p "$F"
    cp "$REPO/install.sh" "$F/install.sh"
    : > "$CALLS"
}
# A standalone script with an unverified helper must fail before any install.
new_fixture standalone
mkdir -p "$F/packaging"
cat > "$F/packaging/witness-service.sh" <<'UNVERIFIED'
echo UNVERIFIED >> "$CALLS"
UNVERIFIED
if bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'standalone accepted' >&2; exit 1; fi
grep -q 'run install.sh from a clone or release bundle' "$W/refusal"
[[ ! -s "$CALLS" ]] || { echo 'standalone caused side effects' >&2; exit 1; }
# Each selected revision supplies the binary build, helper, soul and unit together.
for revision in v1.2.3 v9.8.7; do
    new_fixture "$revision"
    mkdir -p "$F/cmd/witness" "$F/payload/witness" "$F/packaging/systemd" "$F/packaging/launchd"
    printf '%s\n' "$revision" > "$F/REVISION"
    printf 'module fixture\n\ngo 1.26.0\n' > "$F/go.mod"
    touch "$F/go.sum" "$F/cmd/witness/main.go" "$F/packaging/launchd/ai.sgail.harborlight.witness.plist"
    printf '%s\n' "$revision" > "$F/payload/witness/default-soul.toml"
    printf '%s\n' "$revision" > "$F/packaging/systemd/witness.service"
    cat > "$F/packaging/witness-service.sh" <<'HELPER'
witness_service_setup() {
    local revision
    revision=$(cat "$SCRIPT_DIR/REVISION")
    [[ "$(cat "$2")" == "$revision" && "$(cat "$3")" == "$revision" ]] || return 92
    printf 'helper %s\n' "$revision" >> "$CALLS"
}
HELPER
    bash "$F/install.sh" > "$W/output" 2>&1
    printf 'build %s\nbinary %s\nhelper %s\n' "$revision" "$revision" "$revision" > "$W/expected"
    cmp "$CALLS" "$W/expected"
    grep -q 'pinned v3.8.0; skipping install' "$W/output" || { echo 'installed/pinned version context missing' >&2; exit 1; }
    if grep -q 'does not match' "$W/output"; then echo 'matched version warned' >&2; exit 1; fi
    # Existing mismatched versions warn, but still never install Pipelock.
    : > "$CALLS"
    TEST_INSTALLED_VERSION=v9.9.9 bash "$F/install.sh" > "$W/output" 2>&1
    cmp "$CALLS" "$W/expected"
    grep -q 'v9.9.9 does not match pinned v3.8.0' "$W/output"
    # Missing Pipelock uses only exact defaults/overrides; Go is fully stubbed.
    for selected in default v4.5.6; do
        : > "$CALLS"
        args=()
        pin=v3.8.0
        if [[ "$selected" != default ]]; then args=(--pipelock-version "$selected"); pin=$selected; fi
        TEST_PIPELOCK_MISSING=1 bash "$F/install.sh" "${args[@]}" > "$W/output" 2>&1
        printf 'pipelock github.com/luckyPipewrench/pipelock/cmd/pipelock@%s\n' "$pin" > "$W/install-expected"
        cat "$W/expected" >> "$W/install-expected"
        cmp "$CALLS" "$W/install-expected"
        if grep -q '@latest' "$CALLS"; then echo 'moving Pipelock ref installed' >&2; exit 1; fi
    done
    : > "$CALLS"
    TEST_PIPELOCK_MISSING=1 PIPELOCK_VERSION=v4.5.7 bash "$F/install.sh" > "$W/output" 2>&1
    grep -qx 'pipelock github.com/luckyPipewrench/pipelock/cmd/pipelock@v4.5.7' "$CALLS"
    # Invalid flags and env overrides fail before any install/build/helper effect.
    for bad in latest main 3.8 v3.8.0-rc1 v03.8.0; do
        : > "$CALLS"
        if TEST_PIPELOCK_MISSING=1 bash "$F/install.sh" --pipelock-version "$bad" > "$W/refusal" 2>&1; then echo 'bad version accepted' >&2; exit 1; fi
        [[ ! -s "$CALLS" ]] || { echo 'bad override caused installation' >&2; exit 1; }
        if TEST_PIPELOCK_MISSING=1 PIPELOCK_VERSION="$bad" bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'bad env version accepted' >&2; exit 1; fi
        [[ ! -s "$CALLS" ]] || exit 1
    done
    : > "$CALLS"
    if TEST_GO_VERSION=1.25.9 bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'Go below go.mod accepted' >&2; exit 1; fi
    grep -q 'Go 1.26.0+ required' "$W/refusal"
    [[ ! -s "$CALLS" ]] || exit 1
    # Missing local helper must not fall back to a mismatched network helper.
    rm "$F/packaging/witness-service.sh"
    : > "$CALLS"
    if bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'incomplete bundle accepted' >&2; exit 1; fi
    [[ ! -s "$CALLS" ]] || { echo 'incomplete bundle caused side effects' >&2; exit 1; }
done
printf 'PASS: bundle isolation, exact Pipelock versions, installed-version skip/warning, invalid override refusal and Go minimum\n'
