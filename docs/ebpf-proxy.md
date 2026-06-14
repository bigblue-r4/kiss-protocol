# OS-Level Proxy Enforcement — Beyond HTTPS_PROXY

## Problem

Pipelock uses the HTTPS_PROXY / HTTP_PROXY environment variables to intercept
agent HTTP traffic. An evasive agent can bypass this by:

- Ignoring the env vars and opening raw TCP sockets directly.
- Using a different networking library that doesn't honour proxy env vars.
- Unsetting the env vars before spawning subprocesses.
- Tunnelling over non-HTTP protocols (DNS, WebSocket over port 443, etc.).

OS-level enforcement closes these bypass paths by redirecting all TCP egress at
the kernel level, regardless of what the agent does in userspace.

---

## Option 1: iptables / nftables (Linux)

Redirect all TCP egress from the agent's UID through the Pipelock proxy port
using netfilter. This affects the agent process regardless of env vars.

### iptables (kernel < 5.15)

```bash
#!/bin/bash
# enforce-proxy.sh — run as root before starting the agent
# Variables: adjust to match your deployment.
AGENT_UID=1001           # UID of the agent process
PROXY_PORT=8889          # Pipelock listen port (pipelock.yaml: proxy.listen)
PROXY_UID=1000           # UID of the pipelock process (exempt from redirect)

# Do not redirect pipelock's own traffic (avoids redirect loop).
iptables -t nat -A OUTPUT \
  -m owner --uid-owner "$PROXY_UID" \
  -j RETURN

# Redirect all TCP from the agent UID to the pipelock proxy.
iptables -t nat -A OUTPUT \
  -m owner --uid-owner "$AGENT_UID" \
  -p tcp \
  ! -d 127.0.0.1 \
  -j REDIRECT --to-ports "$PROXY_PORT"

# Drop non-TCP egress from agent (UDP, ICMP) — optional, adjust to policy.
iptables -A OUTPUT \
  -m owner --uid-owner "$AGENT_UID" \
  ! -p tcp \
  -j DROP
```

To remove on shutdown:

```bash
iptables -t nat -F OUTPUT
iptables -F OUTPUT
```

### nftables (kernel ≥ 5.15, preferred)

```nft
# /etc/nftables.d/harborlight-proxy.conf
table ip harborlight {
    chain output {
        type nat hook output priority -100;

        # Never redirect pipelock's own traffic.
        meta skuid 1000 return

        # Redirect agent TCP egress to pipelock.
        meta skuid 1001 tcp dport != 8889 redirect to :8889

        # Drop agent non-TCP egress (optional).
        meta skuid 1001 ip protocol != tcp drop
    }
}
```

```bash
nft -f /etc/nftables.d/harborlight-proxy.conf
```

---

## Option 2: eBPF TC (Linux ≥ 5.8, preferred for containers)

Traffic Control (TC) eBPF programs run at the network interface level and can
redirect packets before they leave the container namespace. This works even if
iptables is unavailable (e.g., in rootless containers).

### Concept

Attach an eBPF program to the TC egress hook of the veth or loopback interface
that intercepts TCP SYN packets from the agent process and rewrites the
destination to 127.0.0.1:PROXY_PORT.

```c
// harborlight_redirect.c  — minimal TC eBPF egress redirector
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AGENT_UID   1001
#define PROXY_PORT  8889

SEC("tc/egress")
int harborlight_redirect(struct __sk_buff *skb) {
    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return TC_ACT_OK;

    // Only intercept TCP from the agent UID.
    if (sk->uid != AGENT_UID)
        return TC_ACT_OK;
    if (sk->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Rewrite destination to loopback:PROXY_PORT.
    // Full implementation: parse IP+TCP headers, rewrite daddr + dport,
    // recompute checksums with bpf_csum_diff.
    // See: samples/bpf/tcbpf2_kern.c in the Linux source tree.
    return TC_ACT_OK; // stub — implement checksum rewrite here
}

char _license[] SEC("license") = "GPL";
```

Attach with:

```bash
# Compile
clang -O2 -target bpf -c harborlight_redirect.c -o harborlight_redirect.o

# Attach to egress of agent's network namespace veth
tc qdisc add dev veth0 clsact
tc filter add dev veth0 egress bpf da obj harborlight_redirect.o sec tc/egress
```

Reference implementation: `bpf-next/samples/bpf/tcbpf2_kern.c`.

---

## Option 3: macOS — pf + pfctl

On macOS, use the packet filter (`pf`) to redirect TCP egress from the agent
user. macOS does not support eBPF TC or iptables.

```
# /etc/pf.anchors/harborlight
# Redirect agent TCP egress through Pipelock.
# Replace 1001 with the agent user's UID.
rdr pass on lo0 proto tcp from any to any port 1:65535 user 1001 -> 127.0.0.1 port 8889
```

```bash
# Load the anchor
echo "rdr-anchor \"harborlight\"" >> /etc/pf.conf
echo "load anchor \"harborlight\" from \"/etc/pf.anchors/harborlight\"" >> /etc/pf.conf
pfctl -f /etc/pf.conf
pfctl -e
```

Note: macOS SIP (System Integrity Protection) may restrict pf rules targeting
Apple-signed binaries. Test in a controlled environment first.

---

## Pipelock Transparent Mode

When the OS redirects traffic rather than relying on env vars, Pipelock must
run in **transparent proxy** mode (accepting CONNECT on a non-HTTP connection):

```yaml
# pipelock.yaml — transparent mode addition
proxy:
  listen: "127.0.0.1:8889"
  mode: transparent   # accept raw TCP, not just HTTP CONNECT
```

Check Pipelock's documentation for the `mode: transparent` flag. In transparent
mode, Pipelock terminates TLS with its CA certificate and re-encrypts outbound.
Agents must trust the Pipelock CA (installed by the Harborlight installer).

---

## Deployment Notes

1. Apply the redirect rule **before** starting the agent process.
2. Exempt the `witness` and `enforcer` UIDs from redirection to avoid
   interfering with gossip and mirror push traffic.
3. Log all redirect events (iptables: `-j LOG --log-prefix "HBL-REDIRECT: "`).
   These logs feed back into the core Merkle log via the anomaly detector.
4. For systemd services, set `User=` and use a dedicated slice so that
   the agent UID is deterministic and the redirect rule is scoped correctly.
