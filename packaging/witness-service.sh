# witness-service.sh — shared by install.sh and usb-setup.sh. Source it; don't run it.
#
# Sets the witness up to run as a hardened systemd service under its own
# unprivileged user, the way packaging/systemd/witness.service expects:
#
#   - user `witness`, home and state in /var/lib/witness (mode 0700)
#   - genesis taken as root (so root-only files are fingerprinted), then
#     everything handed to the witness user
#   - an existing witness found in /root or the invoking user's home is copied
#     across (the original is left in place) and never re-initialised:
#     `witness init` replaces the genesis baseline, so it runs only when none exists
#   - soul signed, so the daemon starts in production mode (not --dev)
#   - the hardened unit from packaging/systemd, or nothing: no weaker fallback
#
# Requires the caller to define info, warn and fatal, and to run as root on Linux.

WITNESS_HOME="/var/lib/witness"
WITNESS_DIR="$WITNESS_HOME/.witness"
UNIT_DIR="/etc/systemd/system"
ETC_DIR="/etc/witness"

witness_create_user() {
    if id witness &>/dev/null; then
        info "System user 'witness' already exists."
    else
        useradd --system --no-create-home --home-dir "$WITNESS_HOME" \
                --shell /usr/sbin/nologin --comment "SGAIL Harborlight Witness daemon" witness \
            || fatal "Could not create system user 'witness'. Refusing to run the witness as root."
        info "System user 'witness' created (home: $WITNESS_HOME)"
    fi
    mkdir -p "$WITNESS_DIR"
    chmod 0700 "$WITNESS_HOME" "$WITNESS_DIR"
}

# Copy an existing witness (genesis, log, keys, config) into WITNESS_DIR.
witness_migrate_existing() {
    [[ -f "$WITNESS_DIR/primary/genesis.enc" ]] && return 0
    local candidates=("/root/.witness")
    if [[ -n "${SUDO_USER:-}" ]]; then
        local h
        h=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        [[ -n "$h" ]] && candidates+=("$h/.witness")
    fi
    local old
    for old in "${candidates[@]}"; do
        if [[ -f "$old/primary/genesis.enc" ]]; then
            info "Existing witness found at $old: copying it to $WITNESS_DIR (the original stays where it is)."
            cp -a "$old/." "$WITNESS_DIR/"
            if [[ -f "$WITNESS_DIR/config.json" ]]; then
                sed -i "s#\"$old/primary\"#\"$WITNESS_DIR/primary\"#g" "$WITNESS_DIR/config.json"
            fi
            return 0
        fi
    done
}

# Soul file: keep one that is already there, else install the bundled default.
witness_install_soul() {
    local src="$1"
    local dst="$WITNESS_DIR/soul.toml"
    if [[ -f "$dst" ]]; then
        info "Soul file already present — kept."
        return 0
    fi
    [[ -f "$src" ]] || fatal "Soul file not found at $src."
    cp "$src" "$dst"
    chmod 0400 "$dst"
    info "Soul file installed → $dst"
}

# Config: the witness's own primary dir and a signer it can actually use.
witness_write_config() {
    local cfg="$WITNESS_DIR/config.json"
    if command -v lsusb &>/dev/null && lsusb 2>/dev/null | grep -qi yubico; then
        info "YubiKey detected. Hardware signing needs the PIV build of the witness, which is not in this"
        info "release yet; using an on-disk software key for now. Switch when the PIV build ships."
    fi
    if [[ ! -f "$cfg" ]]; then
        cat > "$cfg" <<CFG
{
  "primary_dir": "$WITNESS_DIR/primary",
  "drift_interval_sec": 30,
  "signer": "software"
}
CFG
        chmod 0600 "$cfg"
        info "Config written → $cfg (signer: software)"
    elif ! grep -q '"signer"' "$cfg"; then
        sed -i '0,/{/s//{\n  "signer": "software",/' "$cfg"
        info "Config updated: signer set to software."
    fi
    if ! grep -q '"mirror_url"' "$cfg"; then
        warn "No transparency mirror configured. The witness will record CRITICAL mirror_not_configured at every"
        warn "start until you set \"mirror_url\" in $cfg (see docs/mirror-setup.md)."
    fi
}

# Genesis only when there is none: `witness init` replaces the baseline.
witness_genesis() {
    local bin="$1"
    if [[ -f "$WITNESS_DIR/primary/genesis.enc" ]]; then
        info "Genesis already taken on this machine — kept (re-running init would replace the baseline)."
        return 0
    fi
    HOME="$WITNESS_HOME" "$bin" init
}

# Sign the soul so the daemon passes its production checks.
witness_sign_soul() {
    local bin="$1"
    if [[ -f "$WITNESS_DIR/soul.toml.sig" && -f "$WITNESS_DIR/trust/signers.txt" ]]; then
        info "Soul already signed — kept."
        return 0
    fi
    HOME="$WITNESS_HOME" "$bin" soul sign
}

witness_hand_over() {
    chown -R witness:witness "$WITNESS_HOME"
    chmod 0700 "$WITNESS_HOME"
}

# Install the hardened unit. $1 = path to packaging/systemd/witness.service,
# $2 = "start" to start it now (otherwise enabled for next boot).
witness_install_unit() {
    local unit_src="$1" start="${2:-}"
    [[ -f "$unit_src" ]] || fatal "Hardened unit not found at $unit_src. Refusing to install an unhardened service."
    cp "$unit_src" "$UNIT_DIR/witness.service"
    chmod 0644 "$UNIT_DIR/witness.service"
    mkdir -p "$ETC_DIR"
    systemctl daemon-reload
    systemctl enable witness.service
    if [[ "$start" == "start" ]]; then
        systemctl start witness.service
        info "Witness service started (runs as user 'witness')."
    else
        info "Witness service enabled; it starts on next boot, or now with: sudo systemctl start witness"
    fi
}

# Everything above, in order. $1 = witness binary, $2 = bundled soul file,
# $3 = hardened unit, $4 = "start" to start now.
witness_service_setup() {
    witness_create_user
    witness_migrate_existing
    witness_install_soul "$2"
    witness_write_config
    witness_genesis "$1"
    witness_sign_soul "$1"
    witness_hand_over
    witness_install_unit "$3" "${4:-}"
}
