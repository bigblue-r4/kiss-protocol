# Gate operator guide

The gate decides; the protected service enforces. Deploy the gate beside the
protected service and its witness: one witness log describes one host. See
[gate-arch.md](gate-arch.md) for the security contract. The daemon currently
uses a software signing key; the separate PIV-slot path is deferred.

## Install and permissions

Build with the installed Go toolchain and dependencies, then install as root
(from the repository root):

```sh
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/gate ./cmd/gate
sudo install -m 0755 /tmp/gate /usr/local/bin/gate
sudo groupadd --system gate
sudo useradd --system --gid gate --home-dir /var/lib/gate --no-create-home --shell /usr/sbin/nologin gate
sudo usermod -a -G witness gate
sudo install -d -o root -g gate -m 0750 /etc/gate /etc/gate/trust
sudo install -d -o gate -g gate -m 0750 /var/lib/gate
sudo install -m 0640 -o root -g gate examples/gate-config.json /etc/gate/config.json
sudo install -m 0640 -o root -g gate examples/gate-policy.toml /etc/gate/gate-policy.toml
sudo install -m 0644 packaging/systemd/gate.service /etc/systemd/system/gate.service
sudo systemctl daemon-reload
```

Skip account creation if the account already exists. The `witness` group must
already exist. Edit `/etc/gate/config.json`: set `witness_dir` to the deployed
primary log directory (the example uses `/var/lib/witness/.witness/primary`).
Keep `state_dir`, `key_dir` and `socket` under `/var/lib/gate` and `/run/gate`
as in the example. The service's writable persistent/runtime paths are limited
to those directories; it also has a private temporary directory.

Give group `witness` read permission on the witness log files and traversal on
all their parent directories, including the primary directory (0750). Do not
grant group write access. Test access as `gate`; the unit has no capability to
bypass permissions. `ProtectSystem=strict` keeps evidence read-only inside the
gate service. It runs as `gate`, with supplementary group `witness`, no new
privileges, hidden home directories and the hardening used by the witness unit.

## Keys and signed policy

Create the daemon's separate key and save the printed hex public key for
pinning in protected services:

```sh
sudo -u gate gate keygen --key-dir /var/lib/gate/key
```

Each operator creates their own key on their own trusted machine, for example:

```sh
gate operator keygen --key-dir "$HOME/.gate/alice" --label alice
```

Verify the printed `alice <hex-public-key>` line out of band, then install it
in `/etc/gate/trust/operators.txt`. Repeat for distinct operators (for example,
Alice and Bob). Use one `<label> <hex>` line per operator; keep this file
root-owned, readable by `gate`, and not writable by the daemon. Keep operator
private keys off the gate host. The gate key is not an operator approval key.

Review a local copy of `gate-policy.toml`. Replace the placeholder
`global.witness_keys` with the actual pinned witness public key (`witness
pubkey`), and set the actual `witness_drift_interval_sec`; it must be at most
half `head_max_age`. Review targets, destinations, assets, budgets, tightening
rules and breaker thresholds. Configure enough distinct operator keys for
`reset_quorum` and every class's `approvals_required`. Unset approval counts
default to two; a one-approver class must explicitly specify one.

On an operator's trusted machine, sign the exact policy bytes:

```sh
gate policy sign gate-policy.toml --key-dir "$HOME/.gate/alice"
```

Install both the reviewed policy and its generated `gate-policy.toml.sig` in
`/etc/gate/`, root-owned and readable by `gate`. Any edit requires a new
signature. Verify on the gate host:

```sh
sudo -u gate gate policy verify /etc/gate/gate-policy.toml --operators /etc/gate/trust/operators.txt
```

Unsigned or invalid policy means deny-all. For subsequent valid signed policy
updates, use `sudo systemctl reload gate` (SIGHUP). A bad reload keeps the old
policy and reports the error. Changing pinned witness keys requires a restart.

## Register the gate feed before starting witness

For an existing deployment, stop gate and witness during this setup. Create
an empty feed **before the witness starts**, and start gate only after witness
has started with the feed registered. Never truncate an existing feed: it is
also used to restore breaker state.

```sh
sudo touch /var/lib/gate/gate.jsonl
sudo chown gate:witness /var/lib/gate/gate.jsonl
sudo chmod 0640 /var/lib/gate/gate.jsonl
sudo setfacl -m g:witness:--x /var/lib/gate
```

The directory ACL gives witness traversal without access to gate keys or state;
retain it when maintaining directory permissions. If ACL tooling is unavailable,
provide equivalent group traversal with a reviewed directory permission setup.
The feed must remain `0640 gate:witness`, including after any manual recreation.
A legacy root-run witness can already read it.

Merge this entry into the deployed witness configuration's `event_feeds` array,
retaining other feeds:

```json
{"path": "/var/lib/gate/gate.jsonl", "source": "gate"}
```

A never-seen feed is tailed from its end. Creating it late can drop initial
records, including through the failed-open/stat race described in the
architecture. Preserve the feed and witness feed positions across restarts.
The `After=witness.service` ordering in gate.service does not itself start or
configure witness.

```sh
sudo systemctl start witness
sudo -u gate gate verify-evidence --config /etc/gate/config.json
sudo systemctl enable --now gate
```

## Connect the protected service

Add each service's numeric UID to `allowed_uids` in `/etc/gate/config.json`
and restart gate after configuration changes. Linux checks socket callers with
`SO_PEERCRED`; the gate's own UID is always allowed. `allowed_uids` alone does
not grant filesystem access: the socket is `0660 gate:gate`, under the 0750
`/run/gate` directory. Give callers directory traversal and socket read/write
access, for example by supplementary group `gate` in each protected service's
unit, then restart those services. Do not grant them access to gate state or
private keys. Non-Linux socket callers are refused.

Inside the service that actually holds the dangerous capability:

- Pin the gate public key in `pkg/gateenforce.Config.GateKeys` and keep one
  `Verifier` for replay tracking.
- Fetch signed epochs from `GET /v1/epoch` over the Unix socket, and pass the
  canonical response to `UpdateEpoch`. Refresh within `EpochMaxAge` (default
  10 seconds); high-tier actions require a fresh signed epoch.
- Send the exact action request and approvals to `POST /v1/decide`; pass the
  returned canonical token to `Check` immediately before executing that exact
  request. Set `Options.HighTier` and `Options.CommitWait` to the class's actual
  requirements. On any refusal, do not perform the action.
- For commit-wait classes, supply `Config.Witness` using
  `pkg/gateenforce/witnessproof.New` with pinned witness keys. A token alone
  without its verified inclusion evidence is insufficient.
- Optionally write `Config.Refusals` to a separate service-owned NDJSON feed
  registered with witness under the service's own source name. Pre-create that
  feed before witness starts too.

Every execution path must call `Check`; gate decisions cannot protect a bypass.
The optional `trip_hook` is an absolute path to an operator-owned script. It
runs inside the gate unit's permissions and sandbox; no infrastructure-killing
adapter is built in.

## Approve an action

Review the complete request file, especially amount, asset, destination,
principal, origin host and target. Each required distinct operator signs the
same request on their trusted machine:

```sh
gate approve request.json --label alice --key-dir "$HOME/.gate/alice" --ttl 10m > alice-approval.json
gate approve request.json --label bob --key-dir "$HOME/.gate/bob" --ttl 10m > bob-approval.json
```

The CLI prints the action summary and hash to stderr; stdout is the approval
JSON. Transfer approvals to the authorized caller. For a drill, that caller can
use:

```sh
gate decide request.json alice-approval.json bob-approval.json
```

Approval binds the action hash and expires. A successful decision reserves that
action against replay; this command can issue a real token. `Allow` still needs
the service's enforcement check. `Escalate` requests the configured approvals;
`Deny` must be investigated rather than bypassed. Automated envelopes may also
require approvals when tightening rules or the breaker escalate level apply.

## Read status and reset a scope

Run socket commands as the gate UID (or an allowed UID with socket access):

```sh
sudo -u gate gate status
sudo -u gate gate epoch
sudo journalctl -u gate
```

Status includes `synced`, `breaker_restored`, `head_size`, `head_age_seconds`,
`epoch`, `open_scopes`, `pending`, policy hash, and error fields such as
`policy_error`, `feed_error`, `chain_failure`, `poll_error` and `deny_all`.
A running systemd unit is not proof of readiness: invalid policy or a failed
feed can leave it alive in deny-all. Until verified evidence and breaker restore
are ready, decisions return `GATE_NOT_SYNCED`. Head age measures time since a
larger verified head, not the unsigned witness timestamp. A feed write failure
is sticky; repair access/storage and restart. Never erase state to clear a trip.

Investigate the cause and make the scope safe before resetting. Trips do not
expire or reset automatically. Read the current epoch from status, choose the
next integer, and create one shared reset file. For example, if status shows
epoch 7 and `class:withdrawal_manual` is open:

```sh
gate reset new --scope class:withdrawal_manual --epoch 8 --reason 'Incident investigated; withdrawal path secured' > reset.json
```

Scope syntax is `global` or `class:VALUE`, `principal:VALUE`,
`origin_host:VALUE`, `destination:VALUE`, `asset:VALUE`. Each quorum member
reviews and signs that same file on their trusted machine:

```sh
gate reset sign reset.json --label alice --key-dir "$HOME/.gate/alice" > alice-reset.json
gate reset sign reset.json --label bob --key-dir "$HOME/.gate/bob" > bob-reset.json
```

Transfer the reset and partial signatures to an authorized socket caller:

```sh
gate reset submit reset.json alice-reset.json bob-reset.json
```

The daemon requires `reset_quorum` distinct trusted operators, an unused nonce
and `new_epoch == current epoch + 1`. If another trip advances the epoch, make
a new reset and collect new signatures. An accepted reset applies at once, but
it survives a restart only once its record is in the verified witness log,
where the quorum is checked again. If the reset record cannot be written, the
gate trips again instead of clearing. Check status and signed epoch afterwards.
Restart reconstructs restrictive state from verified log records and local
records; it is not a reset mechanism.

## Breaker trips are an availability lever

An attacker who can cause denies, noisy advisory events or limit violations can
push a scope toward a trip and deny legitimate work. Treat trips as a potential
DoS lever as well as a containment mechanism. Prefer narrow class, principal,
origin-host, destination or asset scopes; review trigger weights, thresholds,
budgets and in-flight limits against expected traffic. Feed evidence can only
tighten decisions, never supply approval authority or learn trusted edges.

Global trips are reserved for chain verification/append-only failures and gate
self-check failures. Other triggers have fixed narrower scopes; policy cannot
redirect a noisy trigger to Global. Host-wide evidence problems can still trip
every class. Do not broaden a local incident into a Global freeze or automate
resets to mask noise. Keep quorum recovery available on independent operator
machines and investigate before reopening the affected scope.
