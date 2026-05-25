# Migrating from SGAIL Remote Sync

SGAIL remote sync (`witness enable-sync`) is deprecated as of Witness v2 and
will be removed in the next major release. The replacement is the gossip peer
mesh, which gives you peer-to-peer heartbeat monitoring and death detection
without routing log data through a central server.

---

## Why is SGAIL sync being removed?

SGAIL sync pushed encrypted log data to a remote server on a fixed interval.
This had two problems:

1. **Central point of failure.** If the SGAIL server was unreachable, the sync
   window widened to zero redundancy.
2. **Polling, not witnessing.** A compromised daemon could continue to push
   valid-looking heartbeats to the server; nothing verified that the daemon was
   behaving correctly between syncs.

The gossip mesh fixes both: peers exchange signed heartbeats directly. If a
node stops sending heartbeats — whether due to a crash, a kill, or a network
partition — every peer detects the silence independently within `N` heartbeat
intervals.

---

## Migration steps

### Step 1 — Find your peers

You need at least one other machine running Witness that you control. The peer
must also be running v2. A single peer is enough; more peers raise the bar for
an attacker to silence all witnesses simultaneously.

### Step 2 — Exchange public keys

On each machine, get the signer's public key:

```
# Production (PIV key):
witness soul verify --print-key

# Dev mode:
cat ~/.witness/dev-signing.key | openssl pkey -inform raw -pubout ...
# or check soul.toml.sig which includes the signer_key field
```

Exchange these pubkeys out-of-band (SSH, Signal, in-person). Do **not** accept
a pubkey over an unverified channel — an attacker who controls the pubkey you
add controls a trusted peer slot.

### Step 3 — Add peers on each machine

On machine A (say, IP `10.0.0.1`), add machine B as a peer:

```
witness peer add machine-b 10.0.0.2:9273 <hex-pubkey-of-machine-b>
```

On machine B, add machine A:

```
witness peer add machine-a 10.0.0.1:9273 <hex-pubkey-of-machine-a>
```

Verify the peer list on each machine:

```
witness peer list
```

### Step 4 — Open the gossip port

Ensure UDP port 9273 is open between peers. To use a different port, set
`gossip_listen_addr` in `~/.witness/config.json` (default: `":9273"`) and
use the same port in `witness peer add`.

### Step 5 — Restart the daemon

```
# systemd:
sudo systemctl restart witness

# launchd:
sudo launchctl unload /Library/LaunchDaemons/ai.sgail.harborlight.witness.plist
sudo launchctl load   /Library/LaunchDaemons/ai.sgail.harborlight.witness.plist
```

The daemon logs a line like:

```
[witness] Gossip listening on [::]:9273 (2 peer(s))
```

### Step 6 — Disable SGAIL sync

Once the gossip mesh is healthy (you can verify by checking the log for
`peer_silent` entries that should not be firing), disable remote sync:

```json
// ~/.witness/config.json
{
  "sgail_enabled": false,
  "sgail_endpoint": ""
}
```

Restart the daemon.

---

## Trust model

Gossip peering uses the **same ed25519 signer** that signs Merkle tree heads.
Heartbeat packets are signed; packets from pubkeys not in your peer list are
silently dropped. There is no automatic discovery and no TOFU — all trust is
operator-configured.

The peer store is at `~/.witness/peers.json` (mode 0600).

---

## Timeline

| Version | Status |
|---------|--------|
| v2.0    | SGAIL sync deprecated; gossip ships; both work |
| v2.1    | `internal/sgail` removed; `enable-sync` command removed |
