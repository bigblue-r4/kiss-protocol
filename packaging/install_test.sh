#!/usr/bin/env bash
# Installer input fixtures: no network, actual root, service, or host writes.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export CALLS="$W/calls"
mkdir -p "$W/bin" "$W/home"
export HOME="$W/home"
export PATH="$W/bin:$PATH"
cat > "$W/bin/go" <<'STUB'
#!/usr/bin/env bash
set -eu
if [[ "$1" == version ]]; then echo 'go version go1.26.11 linux/amd64'; exit; fi
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
printf 'fixture pipelock\n'
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
printf 'echo UNVERIFIED >> "$CALLS"\n' > "$F/packaging/witness-service.sh"
if bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'standalone accepted' >&2; exit 1; fi
grep -q 'run install.sh from a clone or release bundle' "$W/refusal"
[[ ! -s "$CALLS" ]] || { echo 'standalone caused side effects' >&2; exit 1; }
# Each selected revision supplies the binary build, helper, soul and unit together.
for revision in v1.2.3 v9.8.7; do
    new_fixture "$revision"
    mkdir -p "$F/cmd/witness" "$F/payload/witness" "$F/packaging/systemd" "$F/packaging/launchd"
    printf '%s\n' "$revision" > "$F/REVISION"
    touch "$F/go.mod" "$F/go.sum" "$F/cmd/witness/main.go" "$F/packaging/launchd/ai.sgail.harborlight.witness.plist"
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
    # Missing local helper must not fall back to a mismatched network helper.
    rm "$F/packaging/witness-service.sh"
    : > "$CALLS"
    if bash "$F/install.sh" > "$W/refusal" 2>&1; then echo 'incomplete bundle accepted' >&2; exit 1; fi
    [[ ! -s "$CALLS" ]] || { echo 'incomplete bundle caused side effects' >&2; exit 1; }
done
printf 'PASS: complete bundle revisions stay together; standalone/incomplete inputs fail without fetch or install\n'
