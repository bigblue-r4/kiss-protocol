#!/usr/bin/env bash
# Harborlight pilot benchmark: measures each stage separately on this
# machine and prints CPU seconds, peak memory and bytes, per run and per
# million events. Synthetic data; nothing leaves the machine.
#
#   pilot/bench.sh WORKDIR [EVENTS]     (EVENTS default 200000)
#
# Needs the binaries pilot/demo.sh builds in WORKDIR/bin (run it first, or
# point WORKDIR at a demo directory) and GNU time (/usr/bin/time).
set -euo pipefail
WORK="$(cd "$1" && pwd)"; EVENTS="${2:-200000}"
BIN="$WORK/bin" K="$WORK/keys" B="$WORK/bench-$(date +%s)"
mkdir -p "$B"
APORT=18543 WPORT=18101
T=/usr/bin/time
[[ -x $T ]] || { echo "needs GNU time at /usr/bin/time" >&2; exit 1; }

PIDS=(); trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
"$BIN/omniwitness" --listen="127.0.0.1:$WPORT" --metrics_listen= --db_file="$B/w.db" \
  --private_key_path="$K/witness.sec" --additional_logs="$K/witness-logs.yaml" >"$B/witness.log" 2>&1 & PIDS+=($!)

measure() { # name, command...
  local name=$1; shift
  $T -f "%e %U %S %M" -o "$B/$name.time" "$@" >"$B/$name.out" 2>&1
  read -r wall user sys rss < "$B/$name.time"
  python3 - "$name" "$wall" "$user" "$sys" "$rss" "$EVENTS" <<'PY'
import sys
n,wall,u,s,rss,ev=sys.argv[1],float(sys.argv[2]),float(sys.argv[3]),float(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6])
cpu=u+s; m=1e6/ev
print(f"{n:<22} wall {wall:7.2f}s  cpu {cpu:7.2f}s  peak RSS {rss/1024:7.1f} MiB  | per 1M events: cpu {cpu*m:8.1f}s, {ev/wall if wall else 0:9.0f} events/s wall")
PY
}

# 1. Adapter: receive gzip NDJSON uploads and fsync each batch to the feed.
"$BIN/harborlight-cf-adapter" serve --listen "127.0.0.1:$APORT" --feed "$B/feed.jsonl" --token-file "$K/adapter.token" >"$B/adapter.log" 2>&1 & APID=$!; PIDS+=($APID)
sleep 0.5
S0=$(awk '{print $14+$15}' /proc/$APID/stat)
measure "generator+upload" "$BIN/harborlight-cf-adapter" synth --url "http://127.0.0.1:$APORT/" --token-file "$K/adapter.token" --events "$EVENTS" --batch 1000
S1=$(awk '{print $14+$15}' /proc/$APID/stat); HZ=$(getconf CLK_TCK)
python3 -c "import sys;c=($S1-$S0)/$HZ;e=$EVENTS;print(f'{\"adapter (server side)\":<22} cpu {c:7.2f}s | per 1M events: cpu {c*1e6/e:8.1f}s')"

# 2. Log: ingest the whole feed, checkpoint, witness cosign (one round).
skey_origin=$(cut -d+ -f1 "$K/log.key.pub")
measure "log ingest+checkpoint" "$BIN/harborlight-log" run --once --key "$K/log.key" --data "$B/data" --public "$B/public" \
  --feed "$B/feed.jsonl" --witness "@$K/witness.pub,http://127.0.0.1:$WPORT,operator"

# 3. Verifier: full independent verification from the files.
measure "verify (full)" "$BIN/harborlight-verify" --source "$B/public" --log-key "@$K/log.key.pub" --operator-witness-key "@$K/witness.pub" --max-age 1h

grep -q '^VERIFIED' "$B/verify (full).out" || { echo "verification did not pass:"; head -3 "$B/verify (full).out"; exit 1; }
FEED=$(stat -c %s "$B/feed.jsonl"); REC=$(stat -c %s "$B/public/records.jsonl"); N=$(wc -l < "$B/public/records.jsonl")
GZ=$(gzip -c "$B/public/records.jsonl" | wc -c)
python3 - <<PY
ev=$EVENTS; m=1e6/ev
for name,b in (("feed (adapter output)",$FEED),("records.jsonl (public)",$REC),("records.jsonl gzip",$GZ)):
    print(f"{name:<22} {b/2**20:9.1f} MiB | per 1M events: {b*m/2**30:6.2f} GiB, {b/$N:6.0f} bytes/record")
PY
echo
echo "machine: $(uname -m), $(nproc) CPUs, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), $(awk '/MemTotal/{printf "%.0f GiB RAM", $2/1048576}' /proc/meminfo)"
echo "disk: $(df -h --output=source,fstype "$B" | tail -1)"
echo "events: $EVENTS (records incl. validation upload: $N); results in $B"
