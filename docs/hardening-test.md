# Hardening test (needs root, on a throwaway machine or VM)

Some protections can only be checked with root: they depend on systemd granting
a capability and on a real `witness` system user. Run this after installing with
`install.sh` (or the USB installer) on a disposable Linux machine.

## 1. The witness runs unprivileged, with exactly one capability

```sh
systemctl status witness                      # active (running)
PID=$(systemctl show -p MainPID --value witness)
ps -o user= -p "$PID"                         # witness  (not root)
grep -E '^Cap(Eff|Prm|Amb)' /proc/$PID/status
```

Expected: `CapEff` and `CapPrm` = `0000000000000004` (CAP_DAC_READ_SEARCH only),
`CapAmb` = `0000000000000000` (cleared at start, so nothing it launches inherits it).

## 2. Programs it starts inherit nothing

```sh
for c in $(pgrep -P "$PID"); do ps -o pid=,comm= -p $c; grep -E '^Cap(Eff|Amb)' /proc/$c/status; done
```

Expected for every child (Pipelock, the watchdog): `CapEff` and `CapAmb` all zeros.

## 3. Root-only files are still covered, without false drift

```sh
sudo -u witness HOME=/var/lib/witness witness status   # drift events: 0 after a few minutes
journalctl -u witness --since -10min | grep -c file_removed   # 0
```

Then change a watched root-only file and confirm drift is recorded. Drift compares
content hashes and file modes (not timestamps), so use a reversible mode change:

```sh
stat -c %a /etc/shadow                 # note it (640 on Ubuntu)
sudo chmod 0600 /etc/shadow            # wait one drift interval (30 s)
journalctl -u witness --since -2min | grep -i drift   # file_mode_changed /etc/shadow
sudo chmod 0640 /etc/shadow            # restore the noted mode
```

## 4. Downtime and mirror events

```sh
sudo systemctl kill -s KILL witness; sleep 10; sudo systemctl start witness
# the log now holds CRITICAL witness_downtime (clean_stop: false)
sudo systemctl stop witness; sudo systemctl start witness
# INFO witness_downtime (clean_stop: true)
```

With no `mirror_url` set, every start records CRITICAL `mirror_not_configured`.
