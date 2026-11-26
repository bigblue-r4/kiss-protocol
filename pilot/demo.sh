#!/usr/bin/env bash
# Harborlight Stage 2 pilot demo, without Docker.
#
# Runs, on this machine: an unmodified transparency-dev/witness omniwitness,
# the evidence log, the Cloudflare Logpush adapter, and the synthetic
# generator; then verifies the result with the standalone verifier and runs
# the adversarial suite. Synthetic data only. Nothing leaves this machine.
#
#   pilot/demo.sh [WORKDIR]        (default: ./pilot-demo)
#
# Needs Go 1.26 and network access to the Go module proxy the first time.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mkdir -p "${1:-pilot-demo}" && cd "${1:-pilot-demo}" && pwd)"
# Pinned witness implementation (see pilot/README.md, "Pinned components").
WITNESS_VERSION="${WITNESS_VERSION:-v0.0.0-20261125093440-4aa9dadc1f0b}"
EVENTS="${EVENTS:-2000}"
WPORT="${WPORT:-18100}" LPORT="${LPORT:-18080}" APORT="${APORT:-18443}"
LOG_ORIGIN="pilot.example/demo-log"
WITNESS_NAME="pilot.example/demo-witness"

say() { printf '\n== %s\n' "$*"; }
BIN="$WORK/bin"; mkdir -p "$BIN" "$WORK/keys" "$WORK/feed"

say "Building harborlight binaries"
(cd "$REPO" && go build -trimpath -o "$BIN/" ./cmd/harborlight-log ./cmd/harborlight-verify ./cmd/harborlight-cf-adapter ./cmd/harborlight-adversarial)
if [[ ! -x "$BIN/omniwitness" ]]; then
  say "Installing omniwitness $WITNESS_VERSION (checked against the Go checksum database)"
  GOBIN="$BIN" GOFLAGS=-mod=mod go install \
    "github.com/transparency-dev/witness/cmd/omniwitness@$WITNESS_VERSION" \
    "github.com/transparency-dev/witness/cmd/generate_keys@$WITNESS_VERSION"
fi

K="$WORK/keys"
if [[ ! -f "$K/log.key" ]]; then
  say "Generating keys (software keys, demo only)"
  "$BIN/harborlight-log" keygen --origin "$LOG_ORIGIN" --out "$K/log.key" >/dev/null
  "$BIN/generate_keys" --origin="$WITNESS_NAME" --print > "$K/witness.both"
  head -1 "$K/witness.both" > "$K/witness.sec"; tail -1 "$K/witness.both" > "$K/witness.pub"; rm "$K/witness.both"
  chmod 600 "$K/witness.sec"
  head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$K/adapter.token"; chmod 600 "$K/adapter.token"
  printf 'Logs:\n  - Origin: %s\n    PublicKey: %s\n    URL: http://unused.invalid/\n' "$LOG_ORIGIN" "$(cat "$K/log.key.pub")" > "$K/witness-logs.yaml"
fi

PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

say "Starting the witness, the evidence log and the adapter"
"$BIN/omniwitness" --listen="127.0.0.1:$WPORT" --metrics_listen= --db_file="$WORK/witness.db" \
  --private_key_path="$K/witness.sec" --additional_logs="$K/witness-logs.yaml" >"$WORK/witness.log" 2>&1 & PIDS+=($!)
sleep 1
"$BIN/harborlight-log" run --key "$K/log.key" --data "$WORK/log-data" --public "$WORK/public" \
  --feed "$WORK/feed/feed.jsonl" --witness "@$K/witness.pub,http://127.0.0.1:$WPORT,operator" \
  --interval 2s --listen "127.0.0.1:$LPORT" >"$WORK/log.log" 2>&1 & PIDS+=($!)
"$BIN/harborlight-cf-adapter" serve --listen "127.0.0.1:$APORT" --feed "$WORK/feed/feed.jsonl" \
  --token-file "$K/adapter.token" >"$WORK/adapter.log" 2>&1 & PIDS+=($!)
sleep 1
for i in 0 1 2; do
  if ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
    echo "a component did not start (port in use?); see $WORK/*.log" >&2; tail -3 "$WORK"/*.log >&2; exit 1
  fi
done

say "Sending $EVENTS synthetic ai_gateway_events records as Logpush uploads (batch 2 delivered twice on purpose)"
"$BIN/harborlight-cf-adapter" synth --url "http://127.0.0.1:$APORT/?dataset=ai_gateway_events" \
  --token-file "$K/adapter.token" --events "$EVENTS" --batch 250 --redeliver-batch 2 | tail -2

say "Waiting for a cosigned checkpoint that covers every record"
for _ in $(seq 1 30); do
  n=$(wc -l < "$WORK/public/records.jsonl" 2>/dev/null || echo 0)
  s=$(sed -n 2p "$WORK/public/checkpoint" 2>/dev/null || echo -1)
  [[ "$n" -gt 0 && "$n" == "$s" ]] && grep -q "$WITNESS_NAME" "$WORK/public/checkpoint" && break
  sleep 1
done
echo "records: $n, checkpoint size: $s"

V=("$BIN/harborlight-verify" --source "http://127.0.0.1:$LPORT" --log-key "@$K/log.key.pub"
   --operator-witness-key "@$K/witness.pub" --max-age 5m)

say "1. Independent verification over HTTP, with public keys only"
"${V[@]}" --state "$WORK/evaluator-state.json" --report "$WORK/report.html" --json "$WORK/report.json" || true

say "2. Tampered copy: one record changed after the fact"
rm -rf "${WORK:?}/tampered" && cp -r "$WORK/public" "$WORK/tampered"
sed -i '3s/"StatusCode":200/"StatusCode":201/; 3s/"StatusCode":429/"StatusCode":200/; 3s/"StatusCode":500/"StatusCode":200/' "$WORK/tampered/records.jsonl"
"$BIN/harborlight-verify" --source "$WORK/tampered" --log-key "@$K/log.key.pub" --operator-witness-key "@$K/witness.pub" | head -1 || true

say "3. Witness stopped: the log keeps running, the verifier will not say VERIFIED once the cosignature is stale"
kill "${PIDS[0]}" 2>/dev/null || true; sleep 4
"$BIN/harborlight-verify" --source "http://127.0.0.1:$LPORT" --log-key "@$K/log.key.pub" --operator-witness-key "@$K/witness.pub" --max-age 3s | head -1 || true

say "4. Adversarial regression suite"
"$BIN/harborlight-adversarial" --json "$WORK/adversarial.json" | tail -1

say "Done. Open $WORK/report.html"
