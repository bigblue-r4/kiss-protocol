// gate — the kiss-protocol provenance gate and circuit breaker.
//
// The gate decides whether a high-consequence action (a withdrawal, a key
// use, a production deploy) may run, and signs a short-lived token for it if
// so. It reads the witness log through a verified, read-only view and never
// writes to it; its own records go to the gate feed, which the witness
// records as source "gate". See docs/gate-arch.md and docs/gate-ops.md.
//
// Commands:
//
//	gate start [--config FILE]                 run the daemon
//	gate keygen --key-dir DIR                  create (or show) the gate's software key
//	gate operator keygen --key-dir DIR --label L   an operator key; prints its operators.txt line
//	gate policy sign FILE --key-dir DIR         sign a policy (writes FILE.sig)
//	gate policy verify FILE --operators PATH    check a policy's signature and contents
//	gate approve REQUEST --label L --key-dir DIR [--ttl 10m]   operator approval for one request
//	gate reset new --scope KIND[:VALUE] --epoch N --reason TEXT   the reset all operators sign
//	gate reset sign RESET --label L --key-dir DIR               one operator's partial signature
//	gate reset submit RESET PARTIAL...                          send a quorum to the gate
//	gate decide REQUEST [APPROVAL...]           ask the gate (testing and drills)
//	gate status | gate epoch                    daemon state / current signed epoch
//	gate verify-evidence [--config FILE]        one full verify of the witness log
//	gate version
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/encrypt"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/breaker"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/daemon"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/evidence"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/policy"
	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/machid"
	"github.com/bigblue-r4/kiss-protocol/internal/signer"
)

const version = "0.1.0-dev"

// Config is /etc/gate/config.json.
type Config struct {
	WitnessDir   string `json:"witness_dir"`   // e.g. /var/lib/witness/.witness/primary
	PolicyPath   string `json:"policy"`        // /etc/gate/gate-policy.toml
	Operators    string `json:"operators"`     // /etc/gate/trust/operators.txt
	StateDir     string `json:"state_dir"`     // /var/lib/gate
	KeyDir       string `json:"key_dir"`       // where the software gate key lives
	Socket       string `json:"socket"`        // /run/gate/gate.sock
	AllowedUIDs  []int  `json:"allowed_uids"`  // callers besides the gate's own uid
	PollInterval string `json:"poll_interval"` // default 1s
	TripHook     string `json:"trip_hook"`     // optional absolute path, run on every trip
}

const defaultConfig = "/etc/gate/config.json"

func defaults() Config {
	return Config{PolicyPath: "/etc/gate/gate-policy.toml", Operators: "/etc/gate/trust/operators.txt",
		StateDir: "/var/lib/gate", KeyDir: "/var/lib/gate/key", Socket: "/run/gate/gate.sock"}
}

func loadConfig(path string) (Config, error) {
	c := defaults()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.WitnessDir == "" {
		return c, fmt.Errorf("%s: witness_dir is required", path)
	}
	return c, nil
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gate: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "start":
		cmdStart(args)
	case "keygen":
		cmdKeygen(args)
	case "operator":
		if len(args) == 0 || args[0] != "keygen" {
			die("usage: gate operator keygen --key-dir DIR --label LABEL")
		}
		cmdOperatorKeygen(args[1:])
	case "policy":
		cmdPolicy(args)
	case "approve":
		cmdApprove(args)
	case "reset":
		cmdReset(args)
	case "decide":
		cmdDecide(args)
	case "status":
		cmdGet(args, "/v1/status")
	case "epoch":
		cmdGet(args, "/v1/epoch")
	case "verify-evidence":
		cmdVerifyEvidence(args)
	case "version", "--version", "-v":
		fmt.Printf("SGAIL Labs Harborlight gate v%s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: gate <command>

  start [--config FILE]                               run the daemon
  keygen --key-dir DIR                                create or show the gate key
  operator keygen --key-dir DIR --label L             operator key + operators.txt line
  policy sign FILE --key-dir DIR                      sign a policy (writes FILE.sig)
  policy verify FILE --operators PATH                 verify a signed policy
  approve REQUEST --label L --key-dir DIR [--ttl D]   approve one action request
  reset new --scope KIND[:VALUE] --epoch N --reason T create the reset to sign
  reset sign RESET --label L --key-dir DIR            one operator's partial signature
  reset submit RESET PARTIAL...                       submit a quorum to the gate
  decide REQUEST [APPROVAL...]                        ask the gate (drills, testing)
  status | epoch                                      daemon state / signed epoch
  verify-evidence [--config FILE]                     full verify of the witness log
  version
`)
}

// parse runs fs over args, allowing flags after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func softwareSigner(dir string) *signer.DevSigner {
	if dir == "" {
		die("--key-dir is required")
	}
	s, err := signer.NewSoftware(dir)
	if err != nil {
		die("%v", err)
	}
	return s
}

func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "config file")
	parse(fs, args)
	c, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		die("derive log key: %v", err)
	}
	poll := daemon.DefaultPollInterval
	if c.PollInterval != "" {
		if poll, err = time.ParseDuration(c.PollInterval); err != nil || poll <= 0 {
			die("poll_interval %q", c.PollInterval)
		}
	}
	var adapter breaker.TripAdapter = &breaker.LogOnly{W: os.Stderr}
	if c.TripHook != "" {
		adapter = multiAdapter{&breaker.LogOnly{W: os.Stderr}, breaker.ExecHook{Path: c.TripHook}}
	}
	d, err := daemon.New(daemon.Config{WitnessDir: c.WitnessDir, LogKey: key, PolicyPath: c.PolicyPath,
		OperatorsPath: c.Operators, StateDir: c.StateDir, Signer: softwareSigner(c.KeyDir),
		PollInterval: poll, Adapter: adapter})
	if err != nil {
		die("%v", err)
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			d.ReloadPolicy()
		}
	}()
	go d.Run(ctx)
	fmt.Fprintf(os.Stderr, "[gate] v%s listening on %s\n", version, c.Socket)
	if err := d.Serve(ctx, c.Socket, c.AllowedUIDs); err != nil {
		die("serve: %v", err)
	}
}

type multiAdapter []breaker.TripAdapter

func (m multiAdapter) OnTrip(ctx context.Context, e breaker.Event) error {
	var errs []error
	for _, a := range m {
		errs = append(errs, a.OnTrip(ctx, e))
	}
	return errors.Join(errs...)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("key-dir", "", "key directory (created 0700)")
	parse(fs, args)
	fmt.Println(hex.EncodeToString(softwareSigner(*dir).PublicKey()))
}

func cmdOperatorKeygen(args []string) {
	fs := flag.NewFlagSet("operator keygen", flag.ExitOnError)
	dir := fs.String("key-dir", "", "the operator's own key directory")
	label := fs.String("label", "", "operator label for operators.txt")
	parse(fs, args)
	if *label == "" || strings.ContainsAny(*label, " \t\n") {
		die("--label is required and may not contain spaces")
	}
	fmt.Printf("%s %s\n", *label, hex.EncodeToString(softwareSigner(*dir).PublicKey()))
	fmt.Fprintln(os.Stderr, "Append that line to /etc/gate/trust/operators.txt on the gate host (verify it out of band).")
}

func cmdPolicy(args []string) {
	if len(args) == 0 {
		die("usage: gate policy sign|verify FILE ...")
	}
	switch args[0] {
	case "sign":
		fs := flag.NewFlagSet("policy sign", flag.ExitOnError)
		dir := fs.String("key-dir", "", "operator key directory")
		pos := parse(fs, args[1:])
		if len(pos) != 1 {
			die("usage: gate policy sign FILE --key-dir DIR")
		}
		data, err := os.ReadFile(pos[0])
		if err != nil {
			die("%v", err)
		}
		if _, err := policy.Parse(data); err != nil {
			die("refusing to sign an invalid policy: %v", err)
		}
		sig, err := policy.Sign(data, softwareSigner(*dir))
		if err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(policy.SigPath(pos[0]), sig, 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("signed %s (policy_hash %s)\n", pos[0], policy.Hash(data))
	case "verify":
		fs := flag.NewFlagSet("policy verify", flag.ExitOnError)
		ops := fs.String("operators", defaults().Operators, "operators.txt")
		pos := parse(fs, args[1:])
		if len(pos) != 1 {
			die("usage: gate policy verify FILE --operators PATH")
		}
		o, err := policy.LoadOperators(*ops)
		if err != nil {
			die("%v", err)
		}
		l, err := policy.Load(pos[0], o)
		if err != nil {
			die("%v", err)
		}
		fmt.Printf("OK: signed by %s, policy_hash %s, classes %s\n", l.SignedBy, l.Hash, strings.Join(l.Policy.ClassNames(), ", "))
	default:
		die("unknown policy command %q", args[0])
	}
}

// readCanonical reads a JSON file and re-encodes it canonically, so hand-
// written files work; the gate itself accepts only canonical input.
func readCanonical[T any](path string, decode func([]byte) (T, error)) (T, []byte) {
	b, err := os.ReadFile(path)
	if err != nil {
		die("%v", err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		die("%s: %v", path, err)
	}
	raw, err := proto.Canonical(v)
	if err != nil {
		die("%s: %v", path, err)
	}
	if v, err = decode(raw); err != nil {
		die("%s: %v", path, err)
	}
	return v, raw
}

func cmdApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	dir := fs.String("key-dir", "", "operator key directory")
	label := fs.String("label", "", "your label in operators.txt")
	ttl := fs.Duration("ttl", 10*time.Minute, "approval lifetime")
	pos := parse(fs, args)
	if len(pos) != 1 || *label == "" {
		die("usage: gate approve REQUEST --label L --key-dir DIR [--ttl 10m]")
	}
	req, _ := readCanonical(pos[0], proto.DecodeActionRequest)
	if err := req.Validate(); err != nil {
		die("%v", err)
	}
	h, _ := proto.ActionHashHex(req)
	// Show the operator exactly what they are approving.
	fmt.Fprintf(os.Stderr, "Approving: %s %s %s to %s via %s (principal %s, from %s)\naction_hash %s\n",
		req.Class, req.Amount, req.Asset, req.Destination, req.Target, req.Principal, req.OriginHost, h)
	a, err := proto.SignApproval(proto.Approval{V: proto.Version, ActionHash: h, ApproverLabel: *label,
		ExpiresAt: proto.FormatTime(time.Now().Add(*ttl))}, softwareSigner(*dir))
	if err != nil {
		die("%v", err)
	}
	out, _ := proto.Canonical(a)
	fmt.Println(string(out))
}

func cmdReset(args []string) {
	if len(args) == 0 {
		die("usage: gate reset new|sign|submit ...")
	}
	switch args[0] {
	case "new":
		fs := flag.NewFlagSet("reset new", flag.ExitOnError)
		scope := fs.String("scope", "", "global, or KIND:VALUE (class, principal, origin_host, destination, asset)")
		epoch := fs.Uint64("epoch", 0, "the gate's current epoch + 1 (see gate status)")
		reason := fs.String("reason", "", "why the scope is safe to reopen")
		parse(fs, args[1:])
		kind, value, _ := strings.Cut(*scope, ":")
		n := make([]byte, 16)
		rand.Read(n)
		r := proto.Reset{V: proto.Version, Scope: proto.Scope{Kind: kind, Value: value}, NewEpoch: *epoch,
			Reason: *reason, Nonce: hex.EncodeToString(n), TS: proto.FormatTime(time.Now())}
		if err := r.Validate(); err != nil {
			die("%v", err)
		}
		out, _ := proto.Canonical(r)
		fmt.Println(string(out))
	case "sign":
		fs := flag.NewFlagSet("reset sign", flag.ExitOnError)
		dir := fs.String("key-dir", "", "operator key directory")
		label := fs.String("label", "", "your label in operators.txt")
		pos := parse(fs, args[1:])
		if len(pos) != 1 || *label == "" {
			die("usage: gate reset sign RESET --label L --key-dir DIR")
		}
		r, _ := readCanonical(pos[0], func(b []byte) (proto.Reset, error) {
			var r proto.Reset
			if err := json.Unmarshal(b, &r); err != nil {
				return r, err
			}
			return r, r.Validate()
		})
		fmt.Fprintf(os.Stderr, "Signing reset of %s to epoch %d: %s\n", r.Scope, r.NewEpoch, r.Reason)
		p, err := proto.SignReset(r, *label, softwareSigner(*dir))
		if err != nil {
			die("%v", err)
		}
		out, _ := proto.Canonical(p)
		fmt.Println(string(out))
	case "submit":
		fs := flag.NewFlagSet("reset submit", flag.ExitOnError)
		sock := fs.String("socket", defaults().Socket, "gate socket")
		pos := parse(fs, args[1:])
		if len(pos) < 2 {
			die("usage: gate reset submit RESET PARTIAL...")
		}
		var b proto.ResetBundle
		rb, err := os.ReadFile(pos[0])
		if err != nil || json.Unmarshal(rb, &b.Reset) != nil {
			die("cannot read reset %s", pos[0])
		}
		for _, p := range pos[1:] {
			var ps proto.PartialSig
			pb, err := os.ReadFile(p)
			if err != nil || json.Unmarshal(pb, &ps) != nil {
				die("cannot read partial %s", p)
			}
			b.Partials = append(b.Partials, ps)
		}
		raw, err := proto.Canonical(b)
		if err != nil {
			die("%v", err)
		}
		post(*sock, "/v1/reset", raw)
	default:
		die("unknown reset command %q", args[0])
	}
}

func client(sock string) *http.Client {
	return &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
}

func show(resp *http.Response, err error) {
	if err != nil {
		die("%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var pretty bytes.Buffer
	if json.Indent(&pretty, b, "", "  ") == nil {
		b = pretty.Bytes()
	}
	fmt.Println(strings.TrimSpace(string(b)))
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
}

func post(sock, path string, body []byte) {
	show(client(sock).Post("http://gate"+path, "application/json", bytes.NewReader(body)))
}

func cmdGet(args []string, path string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	sock := fs.String("socket", defaults().Socket, "gate socket")
	parse(fs, args)
	show(client(*sock).Get("http://gate" + path))
}

func cmdDecide(args []string) {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	sock := fs.String("socket", defaults().Socket, "gate socket")
	pos := parse(fs, args)
	if len(pos) < 1 {
		die("usage: gate decide REQUEST [APPROVAL...]")
	}
	var body daemon.DecideRequest
	_, body.Request = readCanonical(pos[0], proto.DecodeActionRequest)
	for _, p := range pos[1:] {
		_, raw := readCanonical(p, proto.DecodeApproval)
		body.Approvals = append(body.Approvals, raw)
	}
	b, _ := json.Marshal(body)
	post(*sock, "/v1/decide", b)
}

func cmdVerifyEvidence(args []string) {
	fs := flag.NewFlagSet("verify-evidence", flag.ExitOnError)
	cfgPath := fs.String("config", defaultConfig, "config file")
	parse(fs, args)
	c, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	ops, err := policy.LoadOperators(c.Operators)
	if err != nil {
		die("%v", err)
	}
	l, err := policy.Load(c.PolicyPath, ops)
	if err != nil {
		die("%v (the policy carries the pinned witness keys)", err)
	}
	key, err := encrypt.DeriveKey(machid.Get())
	if err != nil {
		die("%v", err)
	}
	v, err := evidence.New(evidence.Config{Dir: c.WitnessDir, Key: key, Pins: l.Policy.WitnessKeys()})
	if err != nil {
		die("%v", err)
	}
	start := time.Now()
	if err := v.Poll(); err != nil {
		die("FAIL: %v", err)
	}
	if err := v.FullVerify(); err != nil {
		die("FAIL: %v", err)
	}
	st := v.Status()
	fmt.Printf("OK: %d records verified against a pinned witness key (%s), root %s, in %s\n",
		st.Size, st.SignerKey[:16]+"…", st.Root[:16]+"…", time.Since(start).Round(time.Millisecond))
}
