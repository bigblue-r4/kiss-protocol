// Package policy loads and verifies the gate's signed policy
// (gate-policy.toml plus a detached gate-policy.toml.sig).
//
// The signature uses the soul's SoulSig JSON envelope and the soul's
// "<label> <hex>" allowlist format, but signs "kiss-gate/policy/1\n" || bytes
// instead of the raw bytes (gate-arch.md C12), so a soul signature can never
// pass as a policy signature or the reverse. Soul code is not changed.
//
// Decoding is strict: an unknown key is an error, not a silently ignored
// typo. Anything that fails to load, verify or validate leaves the caller in
// deny-all (POLICY_INVALID); this package never returns a half-valid policy.
package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
)

// ErrInvalid wraps every load, signature and validation failure.
var ErrInvalid = errors.New("POLICY_INVALID")

// MaxFileSize bounds the policy file and its signature.
const MaxFileSize = 1 << 20

// Root kinds and tiers.
const (
	RootApproval  = "approval"
	RootAutomated = "automated_envelope"
	TierHigh      = "high"
	TierLow       = "low"
	FailClosed    = "closed"
	FailOpen      = "open"
	ActionOff     = "off"
	ActionEscal   = "escalate"
	ActionDeny    = "deny"
	EdgeEnforce   = "enforce"
	EdgeLearn     = "learn"
	AnyDest       = "*"
)

// Defaults.
const (
	DefaultHeadMaxAge        = 60 * time.Second
	DefaultCriticalWindow    = 24 * time.Hour
	DefaultRequestMaxSkew    = 5 * time.Minute
	DefaultCommitWaitTimeout = 10 * time.Second
	DefaultLookback          = time.Hour
	DefaultApprovals         = 2 // Chris, 2026-11-03: two operators for withdrawals; lower explicitly
	DefaultBreakerWindow     = time.Hour
	DefaultWarnAt            = 3
	DefaultEscalateAt        = 6
	DefaultHaltAt            = 10
)

// Duration decodes a TOML string such as "60s" or "1h".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", b)
	}
	d.Duration = v
	return nil
}

// Policy is the decoded gate-policy.toml.
type Policy struct {
	Version int              `toml:"version"`
	Global  Global           `toml:"global"`
	Assets  map[string]Asset `toml:"assets"`
	Classes map[string]Class `toml:"classes"`
	Breaker Breaker          `toml:"breaker"`

	witnessKeys []ed25519.PublicKey
}

// Global holds settings that apply to every class.
type Global struct {
	WitnessKeys []string `toml:"witness_keys"` // pinned witness tree-head keys (hex)
	HeadMaxAge  Duration `toml:"head_max_age"` // default 60s
	// WitnessDriftIntervalSec is the witness's drift_interval_sec as the
	// operator deployed it. Heads only arrive that often on a quiet host, so
	// it must be at most head_max_age/2 (C9).
	WitnessDriftIntervalSec int      `toml:"witness_drift_interval_sec"`
	Production              bool     `toml:"production"`       // mirror_not_configured counts against health
	CriticalWindow          Duration `toml:"critical_window"`  // how far back an unacknowledged CRITICAL counts (default 24h)
	RequestMaxSkew          Duration `toml:"request_max_skew"` // request ts must be within this of the gate clock (default 5m)
	ResetQuorum             int      `toml:"reset_quorum"`     // M of the operators in operators.txt
	Budget                  Limit    `toml:"budget"`           // global value-per-window, in reference units, across every asset
}

// Asset declares one asset's units and its weight in the global budget.
type Asset struct {
	Decimals int `toml:"decimals"`
	// RefValue is the value of one whole unit in the policy's reference unit
	// (e.g. USD). It is an operator-set constant, not a live price: the
	// global budget must not move with a feed an attacker could influence.
	RefValue string `toml:"ref_value"`
	Budget   Limit  `toml:"budget"` // per-asset, in units of this asset

	ref *big.Rat
}

// Class is one kind of high-consequence action.
type Class struct {
	Tier              string   `toml:"tier"` // high | low
	Root              string   `toml:"root"` // approval | automated_envelope
	ApprovalsRequired int      `toml:"approvals_required"`
	Targets           []string `toml:"targets"`      // allowed ActionRequest.target values; required
	Assets            []string `toml:"assets"`       // allowed assets; empty = moves no value
	Destinations      []string `toml:"destinations"` // allowed destinations; "*" = any
	MaxValue          string   `toml:"max_value"`    // per action, reference units; "" = no cap
	TokenLifetime     Duration `toml:"token_lifetime"`
	CommitWait        bool     `toml:"commit_wait"`
	CommitWaitTimeout Duration `toml:"commit_wait_timeout"`
	FailMode          string   `toml:"fail_mode"` // closed | open (low tier only)
	Inflight          Inflight `toml:"inflight"`
	Budget            Limit    `toml:"budget"`             // whole class, reference units
	PrincipalBudget   Limit    `toml:"principal_budget"`   // per principal within the class
	DestinationBudget Limit    `toml:"destination_budget"` // per destination within the class
	Tighten           Tighten  `toml:"tighten"`

	maxValue *big.Rat
	anyDest  bool
}

// Inflight caps concurrent pending requests (addendum 3). Zero means the
// tier default; there is no way to switch the cap off.
type Inflight struct {
	Class      int `toml:"class"`
	Principal  int `toml:"principal"`
	OriginHost int `toml:"origin_host"`
}

// Tighten says what each advisory signal does to this class. Signals can
// only tighten: the strongest action is deny, and none can allow.
type Tighten struct {
	Lookback      Duration `toml:"lookback"`
	Drift         string   `toml:"drift"`
	SBH           string   `toml:"sbh"`
	Pipelock      string   `toml:"pipelock"`
	FirstSeenEdge string   `toml:"first_seen_edge"`
	EdgeMode      string   `toml:"edge_mode"` // enforce | learn (learn records new edges and is logged)
}

// Limit is a sliding-window budget: at most MaxCount actions and MaxValue
// value inside any Window. A zero field is no limit on that dimension.
type Limit struct {
	Window   Duration `toml:"window"`
	MaxCount int      `toml:"max_count"`
	MaxValue string   `toml:"max_value"`

	max *big.Rat
}

// Breaker holds the soul-style tick model (gate-arch.md section 7).
type Breaker struct {
	Window     Duration       `toml:"window"`
	WarnAt     int            `toml:"warn_at"`
	EscalateAt int            `toml:"escalate_at"`
	HaltAt     int            `toml:"halt_at"`
	Triggers   map[string]int `toml:"triggers"` // trigger -> weight; 0 disables
}

// Triggers and their default weights. The scope each trigger ticks is fixed
// in code (internal/gate/core), not configurable: Global is reserved for
// chain failures and self-check (addendum 6).
var DefaultTriggers = map[string]int{
	"velocity_exceeded":   10,
	"deny":                1,
	"chain_unverified":    10,
	"witness_death":       10,
	"witness_downtime":    10,
	"mirror_unreachable":  10,
	"tree_head_unsigned":  10,
	"drift_detected":      10,
	"sbh_escalation":      10,
	"commit_wait_timeout": 4,
	"inflight_limit":      2,
	"self_check":          10,
}

// Parse decodes and validates policy bytes. It does not check a signature.
func Parse(data []byte) (*Policy, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%w: policy larger than %d bytes", ErrInvalid, MaxFileSize)
	}
	var p Policy
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&p)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("%w: unknown keys %s", ErrInvalid, strings.Join(keys, ", "))
	}
	if err := p.normalize(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return &p, nil
}

func ratOf(s, what string) (*big.Rat, error) {
	if s == "" {
		return nil, nil
	}
	if _, err := proto.ParseAmount(s, 36); err != nil {
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("%s: %q is not a decimal", what, s)
	}
	return r, nil
}

func (l *Limit) normalize(what string) error {
	r, err := ratOf(l.MaxValue, what+".max_value")
	if err != nil {
		return err
	}
	l.max = r
	if l.MaxCount < 0 {
		return fmt.Errorf("%s.max_count is negative", what)
	}
	if (l.MaxCount > 0 || l.max != nil) && l.Window.Duration <= 0 {
		return fmt.Errorf("%s: a limit needs a window", what)
	}
	return nil
}

// Active reports whether the limit constrains anything.
func (l Limit) Active() bool { return l.MaxCount > 0 || l.max != nil }

// Max returns the value cap (nil = none). The caller must not modify it.
func (l Limit) Max() *big.Rat { return l.max }

func validName(s string) bool {
	return proto.Scope{Kind: proto.ScopeClass, Value: s}.Validate() == nil
}

func action(s *string, def, what string) error {
	switch *s {
	case "":
		*s = def
	case ActionOff, ActionEscal, ActionDeny:
	default:
		return fmt.Errorf("%s must be off, escalate or deny, not %q", what, *s)
	}
	return nil
}

func (p *Policy) normalize() error {
	if p.Version != 1 {
		return fmt.Errorf("version must be 1, not %d", p.Version)
	}
	g := &p.Global
	if len(g.WitnessKeys) == 0 {
		return errors.New("global.witness_keys: at least one pinned witness key is required")
	}
	p.witnessKeys = nil
	for i, k := range g.WitnessKeys {
		raw, err := hex.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("global.witness_keys[%d] is not a hex ed25519 key", i)
		}
		p.witnessKeys = append(p.witnessKeys, ed25519.PublicKey(raw))
	}
	if g.HeadMaxAge.Duration == 0 {
		g.HeadMaxAge.Duration = DefaultHeadMaxAge
	}
	if g.WitnessDriftIntervalSec <= 0 {
		return errors.New("global.witness_drift_interval_sec is required (the witness's drift_interval_sec)")
	}
	if time.Duration(g.WitnessDriftIntervalSec)*time.Second*2 > g.HeadMaxAge.Duration {
		return fmt.Errorf("global.head_max_age %s is less than twice witness_drift_interval_sec %ds: a quiet but healthy witness would read as stale",
			g.HeadMaxAge.Duration, g.WitnessDriftIntervalSec)
	}
	if g.CriticalWindow.Duration == 0 {
		g.CriticalWindow.Duration = DefaultCriticalWindow
	}
	if g.RequestMaxSkew.Duration == 0 {
		g.RequestMaxSkew.Duration = DefaultRequestMaxSkew
	}
	if g.ResetQuorum < 1 {
		return errors.New("global.reset_quorum must be at least 1")
	}
	if err := g.Budget.normalize("global.budget"); err != nil {
		return err
	}

	for name, a := range p.Assets {
		if !validName(name) {
			return fmt.Errorf("asset name %q is not valid", name)
		}
		if a.Decimals < 0 || a.Decimals > 36 {
			return fmt.Errorf("assets.%s.decimals must be 0-36", name)
		}
		r, err := ratOf(a.RefValue, "assets."+name+".ref_value")
		if err != nil {
			return err
		}
		if r == nil {
			return fmt.Errorf("assets.%s.ref_value is required (weight in the global budget)", name)
		}
		a.ref = r
		if err := a.Budget.normalize("assets." + name + ".budget"); err != nil {
			return err
		}
		p.Assets[name] = a
	}

	if len(p.Classes) == 0 {
		return errors.New("at least one class is required")
	}
	for name, c := range p.Classes {
		if err := p.normalizeClass(name, &c); err != nil {
			return err
		}
		p.Classes[name] = c
	}

	b := &p.Breaker
	if b.Window.Duration == 0 {
		b.Window.Duration = DefaultBreakerWindow
	}
	if b.WarnAt == 0 && b.EscalateAt == 0 && b.HaltAt == 0 {
		b.WarnAt, b.EscalateAt, b.HaltAt = DefaultWarnAt, DefaultEscalateAt, DefaultHaltAt
	}
	if !(0 < b.WarnAt && b.WarnAt <= b.EscalateAt && b.EscalateAt <= b.HaltAt) {
		return errors.New("breaker thresholds must satisfy 0 < warn_at <= escalate_at <= halt_at")
	}
	w := map[string]int{}
	for k, v := range DefaultTriggers {
		w[k] = v
	}
	for k, v := range b.Triggers {
		if _, ok := DefaultTriggers[k]; !ok {
			return fmt.Errorf("breaker.triggers: unknown trigger %q", k)
		}
		if v < 0 {
			return fmt.Errorf("breaker.triggers.%s is negative", k)
		}
		w[k] = v
	}
	if w["chain_unverified"] < b.HaltAt {
		// A chain failure is never something to count up to.
		return errors.New("breaker.triggers.chain_unverified must be at least halt_at")
	}
	b.Triggers = w
	return nil
}

func (p *Policy) normalizeClass(name string, c *Class) error {
	at := "classes." + name
	if !validName(name) {
		return fmt.Errorf("class name %q is not valid", name)
	}
	switch c.Tier {
	case TierHigh, TierLow:
	default:
		return fmt.Errorf("%s.tier must be high or low", at)
	}
	switch c.Root {
	case RootApproval, RootAutomated:
	default:
		return fmt.Errorf("%s.root must be approval or automated_envelope", at)
	}
	if c.ApprovalsRequired == 0 {
		c.ApprovalsRequired = DefaultApprovals
	}
	if c.ApprovalsRequired < 1 {
		return fmt.Errorf("%s.approvals_required must be at least 1", at)
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("%s.targets is required", at)
	}
	for _, a := range c.Assets {
		if _, ok := p.Assets[a]; !ok {
			return fmt.Errorf("%s.assets: %q is not declared under [assets]", at, a)
		}
	}
	c.anyDest = false
	for _, d := range c.Destinations {
		if d == AnyDest {
			c.anyDest = true
		}
	}
	r, err := ratOf(c.MaxValue, at+".max_value")
	if err != nil {
		return err
	}
	c.maxValue = r
	if c.TokenLifetime.Duration == 0 {
		c.TokenLifetime.Duration = proto.DefaultTokenLifetime
	}
	if c.TokenLifetime.Duration > proto.MaxTokenLifetime {
		return fmt.Errorf("%s.token_lifetime is over %s", at, proto.MaxTokenLifetime)
	}
	if c.CommitWaitTimeout.Duration == 0 {
		c.CommitWaitTimeout.Duration = DefaultCommitWaitTimeout
	}
	switch c.FailMode {
	case "":
		c.FailMode = FailClosed
	case FailClosed:
	case FailOpen:
		if c.Tier == TierHigh {
			return fmt.Errorf("%s: a high-tier class always fails closed", at)
		}
	default:
		return fmt.Errorf("%s.fail_mode must be closed or open", at)
	}
	def := Inflight{Class: 64, Principal: 16, OriginHost: 32}
	if c.Tier == TierHigh {
		def = Inflight{Class: 8, Principal: 2, OriginHost: 4}
	}
	for _, f := range []struct {
		v *int
		d int
		n string
	}{{&c.Inflight.Class, def.Class, "class"}, {&c.Inflight.Principal, def.Principal, "principal"}, {&c.Inflight.OriginHost, def.OriginHost, "origin_host"}} {
		if *f.v == 0 {
			*f.v = f.d
		}
		if *f.v < 0 {
			return fmt.Errorf("%s.inflight.%s is negative", at, f.n)
		}
	}
	for _, l := range []struct {
		l *Limit
		n string
	}{{&c.Budget, "budget"}, {&c.PrincipalBudget, "principal_budget"}, {&c.DestinationBudget, "destination_budget"}} {
		if err := l.l.normalize(at + "." + l.n); err != nil {
			return err
		}
	}
	if c.Root == RootAutomated {
		// The signed envelope is the root, so it has to actually bound
		// something (trust model (b)).
		if len(c.Destinations) == 0 || c.anyDest {
			return fmt.Errorf("%s: an automated envelope needs an explicit destinations list", at)
		}
		if len(c.Assets) > 0 {
			if c.maxValue == nil || !c.Budget.Active() || p.Global.Budget.Max() == nil {
				return fmt.Errorf("%s: an automated value-moving class needs max_value, a class budget and a global budget", at)
			}
		}
	}
	t := &c.Tighten
	if t.Lookback.Duration == 0 {
		t.Lookback.Duration = DefaultLookback
	}
	for _, a := range []struct {
		s *string
		n string
	}{{&t.Drift, "drift"}, {&t.SBH, "sbh"}, {&t.Pipelock, "pipelock"}, {&t.FirstSeenEdge, "first_seen_edge"}} {
		def := ActionEscal
		if a.n == "drift" {
			def = ActionDeny
		}
		if err := action(a.s, def, at+".tighten."+a.n); err != nil {
			return err
		}
	}
	switch t.EdgeMode {
	case "":
		t.EdgeMode = EdgeEnforce
	case EdgeEnforce, EdgeLearn:
	default:
		return fmt.Errorf("%s.tighten.edge_mode must be enforce or learn", at)
	}
	return nil
}

// WitnessKeys returns the pinned witness keys.
func (p *Policy) WitnessKeys() []ed25519.PublicKey {
	return append([]ed25519.PublicKey(nil), p.witnessKeys...)
}

// ClassNames returns the class names, sorted.
func (p *Policy) ClassNames() []string {
	out := make([]string, 0, len(p.Classes))
	for k := range p.Classes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MaxValueRat returns the class's per-action cap (nil = none).
func (c Class) MaxValueRat() *big.Rat { return c.maxValue }

// AllowsDestination reports whether d is inside the class's destination rule.
// An empty list allows any destination (approval classes only; automated
// classes must list them).
func (c Class) AllowsDestination(d string) bool {
	if len(c.Destinations) == 0 || c.anyDest {
		return true
	}
	for _, x := range c.Destinations {
		if x == d {
			return true
		}
	}
	return false
}

// Value returns a request's amount in asset units and in reference units.
// An asset the policy does not declare is an error.
func (p *Policy) Value(asset, amount string) (units, ref *big.Rat, err error) {
	if asset == "" {
		if strings.Trim(amount, "0.") != "" {
			return nil, nil, errors.New("value without an asset")
		}
		return new(big.Rat), new(big.Rat), nil
	}
	a, ok := p.Assets[asset]
	if !ok {
		return nil, nil, fmt.Errorf("asset %q is not declared", asset)
	}
	n, err := proto.ParseAmount(amount, a.Decimals)
	if err != nil {
		return nil, nil, err
	}
	units = new(big.Rat).SetFrac(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(a.Decimals)), nil))
	return units, new(big.Rat).Mul(units, a.ref), nil
}

// Hash is the hex SHA-256 of the policy file bytes; every token carries it.
func Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SigPath is the detached signature path for a policy file.
func SigPath(path string) string { return path + ".sig" }

func sigMessage(data []byte) []byte {
	return append([]byte(proto.DomainPolicy), data...)
}

// Sign signs policy bytes and returns the .sig file contents.
func Sign(data []byte, s proto.Signer) ([]byte, error) {
	sig, err := s.Sign(sigMessage(data))
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}
	return json.MarshalIndent(soul.SoulSig{
		Algorithm: "ed25519",
		SignerKey: hex.EncodeToString(s.PublicKey()),
		Signature: hex.EncodeToString(sig),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
}

// Verify checks sigData over data against ops and returns the signer's label.
func Verify(data, sigData []byte, ops []proto.Operator) (string, error) {
	if len(sigData) > MaxFileSize {
		return "", fmt.Errorf("%w: signature file too large", ErrInvalid)
	}
	var ss soul.SoulSig
	dec := json.NewDecoder(bytes.NewReader(sigData))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ss); err != nil {
		return "", fmt.Errorf("%w: parse signature: %v", ErrInvalid, err)
	}
	if ss.Algorithm != "ed25519" {
		return "", fmt.Errorf("%w: unsupported signature algorithm %q", ErrInvalid, ss.Algorithm)
	}
	key, err := hex.DecodeString(ss.SignerKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: malformed signer_key", ErrInvalid)
	}
	sig, err := hex.DecodeString(ss.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w: malformed signature", ErrInvalid)
	}
	for _, op := range ops {
		if bytes.Equal(op.Key, key) {
			if !ed25519.Verify(op.Key, sigMessage(data), sig) {
				return "", fmt.Errorf("%w: signature does not verify (policy changed after signing?)", ErrInvalid)
			}
			return op.Label, nil
		}
	}
	return "", fmt.Errorf("%w: signing key is not in operators.txt", ErrInvalid)
}

// Loaded is a verified policy and what the gate records about it.
type Loaded struct {
	Policy   *Policy
	Hash     string // policy_hash in every token
	SignedBy string // operator label
}

// Load reads path and path.sig, verifies the signature against ops, then
// parses and validates. Approvals and the reset quorum must be satisfiable by
// ops, or every request in that class would escalate forever.
func Load(path string, ops []proto.Operator) (*Loaded, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	sig, err := readCapped(SigPath(path))
	if err != nil {
		return nil, fmt.Errorf("%w: policy is unsigned: %v", ErrInvalid, err)
	}
	return LoadBytes(data, sig, ops)
}

// LoadBytes is Load on bytes already read.
func LoadBytes(data, sig []byte, ops []proto.Operator) (*Loaded, error) {
	label, err := Verify(data, sig, ops)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	n := distinctKeys(ops)
	if p.Global.ResetQuorum > n {
		return nil, fmt.Errorf("%w: reset_quorum %d exceeds the %d operator keys", ErrInvalid, p.Global.ResetQuorum, n)
	}
	for _, name := range p.ClassNames() {
		if r := p.Classes[name].ApprovalsRequired; r > n {
			return nil, fmt.Errorf("%w: classes.%s.approvals_required %d exceeds the %d operator keys", ErrInvalid, name, r, n)
		}
	}
	return &Loaded{Policy: p, Hash: Hash(data), SignedBy: label}, nil
}

func distinctKeys(ops []proto.Operator) int {
	seen := map[string]bool{}
	for _, o := range ops {
		seen[string(o.Key)] = true
	}
	return len(seen)
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(io.LimitReader(f, MaxFileSize+1)); err != nil {
		return nil, err
	}
	if buf.Len() > MaxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, MaxFileSize)
	}
	return buf.Bytes(), nil
}

// LoadOperators reads operators.txt ("<label> <hex>", the soul allowlist
// format) into gate operators.
func LoadOperators(path string) ([]proto.Operator, error) {
	entries, err := soul.LoadAllowlist(path)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s lists no operators", path)
	}
	ops := make([]proto.Operator, len(entries))
	for i, e := range entries {
		ops[i] = proto.Operator{Label: e.Label, Key: e.PubKey}
	}
	return ops, nil
}
