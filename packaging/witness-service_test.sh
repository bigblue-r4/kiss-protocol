#!/usr/bin/env bash
# Tests for packaging/witness-service.sh that need no root: the root-only
# commands (useradd, chown, systemctl, writing /etc) are stubbed, and every
# path points into a temporary directory. `witness init` asks for confirmation
# when it finds AI tools already installed (a CI runner may have some), so the
# tests answer "y" to it. Run: bash packaging/witness-service_test.sh <witness-binary>
set -euo pipefail

BIN=${1:?usage: $0 <witness binary>}
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
REPO=$(cd "$(dirname "$0")/.." && pwd)
fails=0
pass() { echo "ok    $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

info() { :; }
warn() { :; }
fatal() { echo "fatal: $*" >&2; exit 99; }   # as in the installers; run_setup runs in a subshell

new_world() {
    W=$(mktemp -d)
    # shellcheck source=packaging/witness-service.sh
    source "$REPO/packaging/witness-service.sh"
    WITNESS_HOME="$W/var/lib/witness"
    WITNESS_DIR="$WITNESS_HOME/.witness"
    UNIT_DIR="$W/systemd"; ETC_DIR="$W/etc-witness"; mkdir -p "$UNIT_DIR"
    # Stubs for what needs root.
    id() { [[ "$1" == witness && -f "$W/user-created" ]]; }
    useradd() { touch "$W/user-created"; }
    chown() { echo "chown $*" >> "$W/calls"; }
    systemctl() { echo "systemctl $*" >> "$W/calls"; }
}

run_setup() {   # $1 = unit path
    (set -e; witness_service_setup "$BIN" "$REPO/payload/witness/default-soul.toml" "$1" start) <<<"y" >/dev/null 2>&1
}

# 1. Fresh install: user, soul, config (software signer), genesis, signed soul, hardened unit.
new_world
if run_setup "$REPO/packaging/systemd/witness.service"; then
    [[ -f "$W/user-created" ]] && pass "fresh: user created" || fail "fresh: no user"
    [[ -f "$WITNESS_DIR/primary/genesis.enc" ]] && pass "fresh: genesis taken" || fail "fresh: no genesis"
    grep -q '"signer": "software"' "$WITNESS_DIR/config.json" && pass "fresh: signer software" || fail "fresh: signer not set"
    [[ -f "$WITNESS_DIR/soul.toml.sig" && -f "$WITNESS_DIR/trust/signers.txt" ]] && pass "fresh: soul signed" || fail "fresh: soul not signed"
    grep -q "chown -R witness:witness $WITNESS_HOME" "$W/calls" && pass "fresh: handed to witness" || fail "fresh: no chown"
    grep -q "^User=witness" "$UNIT_DIR/witness.service" && pass "fresh: hardened unit installed" || fail "fresh: wrong unit"
    grep -q "systemctl start witness.service" "$W/calls" && pass "fresh: started" || fail "fresh: not started"
else
    fail "fresh: setup failed"
fi

# 2. Re-run: the genesis baseline must not be replaced.
before=$(sha256sum "$WITNESS_DIR/primary/genesis.enc" | cut -d' ' -f1)
sig_before=$(sha256sum "$WITNESS_DIR/soul.toml.sig" | cut -d' ' -f1)
run_setup "$REPO/packaging/systemd/witness.service" || fail "rerun: setup failed"
[[ "$(sha256sum "$WITNESS_DIR/primary/genesis.enc" | cut -d' ' -f1)" == "$before" ]] && pass "rerun: genesis kept" || fail "rerun: GENESIS REPLACED"
[[ "$(sha256sum "$WITNESS_DIR/soul.toml.sig" | cut -d' ' -f1)" == "$sig_before" ]] && pass "rerun: soul signature kept" || fail "rerun: soul re-signed"
rm -rf "$W"

# 3. Migration: an old install in the invoking user's home is copied across,
#    its config re-pointed, the original left in place, and init not re-run.
new_world
OLDHOME="$W/home/alice"
mkdir -p "$OLDHOME/.witness"
cp "$REPO/payload/witness/default-soul.toml" "$OLDHOME/.witness/soul.toml"
printf '{\n  "primary_dir": "%s/.witness/primary",\n  "drift_interval_sec": 30\n}\n' "$OLDHOME" > "$OLDHOME/.witness/config.json"
HOME="$OLDHOME" "$BIN" init <<<"y" >/dev/null 2>&1
old_genesis=$(sha256sum "$OLDHOME/.witness/primary/genesis.enc" | cut -d' ' -f1)
getent() { [[ "$1" == passwd && "$2" == alice ]] && echo "alice:x:1000:1000::$OLDHOME:/bin/bash"; }
SUDO_USER=alice
if run_setup "$REPO/packaging/systemd/witness.service"; then
    [[ "$(sha256sum "$WITNESS_DIR/primary/genesis.enc" | cut -d' ' -f1)" == "$old_genesis" ]] && pass "migrate: genesis carried over, not retaken" || fail "migrate: genesis differs"
    grep -q "\"primary_dir\": \"$WITNESS_DIR/primary\"" "$WITNESS_DIR/config.json" && pass "migrate: config re-pointed" || fail "migrate: config still points at the old home"
    grep -q '"signer": "software"' "$WITNESS_DIR/config.json" && pass "migrate: signer added to old config" || fail "migrate: signer missing"
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$WITNESS_DIR/config.json" && pass "migrate: config is valid JSON" || fail "migrate: config broken"
    [[ -f "$OLDHOME/.witness/primary/genesis.enc" ]] && pass "migrate: original left in place" || fail "migrate: original removed"
else
    fail "migrate: setup failed"
fi
unset SUDO_USER
rm -rf "$W"

# 4. No hardened unit: refuse, never fall back to an unhardened one.
new_world
if run_setup "$W/does-not-exist.service"; then
    fail "missing unit: setup succeeded"
else
    [[ ! -f "$UNIT_DIR/witness.service" ]] && pass "missing unit: refused, nothing installed" || fail "missing unit: something installed"
fi
rm -rf "$W"

echo
[[ $fails -eq 0 ]] && echo "all passed" || { echo "$fails failed"; exit 1; }
