// Package gateenforce is the enforcement point for kiss-gate: the check a
// protected service (signer, wallet, deploy service) runs immediately before
// it performs a high-consequence action. The gate decides; this package is
// the control. A service path that does not call Check is not protected.
//
// Check refuses unless every condition holds:
//
//   - the token is canonical and signed by a pinned gate key;
//   - it has not expired (allowing ClockSkew);
//   - its action_hash equals the hash of the exact request about to run, so a
//     token for one amount or destination cannot be used for another;
//   - its token_id has not been used before (kept until the token expires);
//   - it is not from an epoch older than the newest signed Epoch seen, and no
//     open scope in a fresh Epoch covers the request; for high-tier actions an
//     Epoch fresher than EpochMaxAge is required;
//   - for commit-wait classes, the token's witness evidence verifies (see
//     package witnessproof, plugged in through Config.Witness).
//
// Every refusal is returned as a *Refusal and, if Config.Refusals is set,
// written there as one NDJSON line, ready to be a witness event feed.
//
// The package is stdlib-only. Types are aliases of the gate's wire formats.
package gateenforce

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/gate/proto"
)

// Wire formats (aliases, so callers outside this module can name them).
type (
	ActionRequest = proto.ActionRequest
	Token         = proto.Token
	Epoch         = proto.Epoch
	Scope         = proto.Scope
	Witnessed     = proto.Witnessed
	WitnessHead   = proto.WitnessHead
)

// Refusal codes: a stable enum, recorded in the service's feed.
const (
	TokenInvalid      = "TOKEN_INVALID"
	TokenExpired      = "TOKEN_EXPIRED"
	ActionMismatch    = "ACTION_MISMATCH"
	TokenReplayed     = "TOKEN_REPLAYED"
	EpochStale        = "EPOCH_STALE"
	EpochSuperseded   = "EPOCH_SUPERSEDED"
	ScopeFrozen       = "SCOPE_FROZEN"
	CommitWaitMissing = "COMMIT_WAIT_MISSING"
	CommitWaitInvalid = "COMMIT_WAIT_INVALID"
	RequestInvalid    = "REQUEST_INVALID"
)

// Refusal is why Check refused.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string { return "gate token refused: " + r.Code + ": " + r.Detail }

// WitnessVerifier checks a token's commit-wait evidence for the action with
// hash actionHash (hex). witnessproof.New returns one.
type WitnessVerifier func(w proto.Witnessed, actionHash string) error

// Config configures a Verifier.
type Config struct {
	GateKeys    []ed25519.PublicKey // pinned gate keys; at least one
	EpochMaxAge time.Duration       // default 10s
	ClockSkew   time.Duration       // default 2s
	Now         func() time.Time    // default time.Now
	Refusals    io.Writer           // NDJSON refusal lines; nil = none
	Witness     WitnessVerifier     // required for commit-wait classes
}

// Options says what the action being checked requires.
type Options struct {
	HighTier   bool // a fresh Epoch is required
	CommitWait bool // the token must carry verified witness evidence
}

// Verifier checks tokens. Safe for concurrent use.
type Verifier struct {
	cfg Config

	mu          sync.Mutex
	used        map[string]time.Time // token_id → when it may be forgotten
	epoch       *proto.Epoch
	epochIssued time.Time
	out         sync.Mutex // serialises refusal lines
}

// New returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	if len(cfg.GateKeys) == 0 {
		return nil, errors.New("gateenforce: at least one pinned gate key is required")
	}
	if cfg.EpochMaxAge <= 0 {
		cfg.EpochMaxAge = 10 * time.Second
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, used: map[string]time.Time{}}, nil
}

// UpdateEpoch accepts a signed Epoch fetched from the gate. An epoch older
// than one already held is rejected: the gate's epoch only rises, so an older
// one is a replay. The same epoch with a later issue time refreshes it.
func (v *Verifier) UpdateEpoch(raw []byte) error {
	e, err := proto.DecodeEpoch(raw)
	if err != nil {
		return err
	}
	issued, err := proto.VerifyEpoch(e, v.cfg.GateKeys)
	if err != nil {
		return err
	}
	if issued.After(v.cfg.Now().Add(v.cfg.ClockSkew)) {
		return errors.New("gateenforce: epoch issued in the future")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.epoch != nil {
		if e.Epoch < v.epoch.Epoch {
			return fmt.Errorf("gateenforce: epoch %d is older than held epoch %d", e.Epoch, v.epoch.Epoch)
		}
		if e.Epoch == v.epoch.Epoch && !issued.After(v.epochIssued) {
			return nil // nothing newer
		}
	}
	v.epoch, v.epochIssued = &e, issued
	return nil
}

// Check verifies rawToken for req and, on success, marks the token used. It
// returns the decoded token, or a *Refusal.
func (v *Verifier) Check(req ActionRequest, rawToken []byte, opt Options) (Token, error) {
	tok, err := v.check(req, rawToken, opt)
	if err != nil {
		var r *Refusal
		if !errors.As(err, &r) {
			r = &Refusal{Code: TokenInvalid, Detail: err.Error()}
		}
		v.record(r, tok, req)
		return Token{}, r
	}
	return tok, nil
}

func (v *Verifier) check(req ActionRequest, rawToken []byte, opt Options) (Token, error) {
	now := v.cfg.Now()
	tok, err := proto.DecodeToken(rawToken)
	if err != nil {
		return Token{}, &Refusal{TokenInvalid, err.Error()}
	}
	if err := proto.VerifyTokenSig(tok, v.cfg.GateKeys); err != nil {
		return tok, &Refusal{TokenInvalid, err.Error()}
	}
	issued, expires, _ := tok.Times() // form already checked by VerifyTokenSig
	if now.After(expires.Add(v.cfg.ClockSkew)) {
		return tok, &Refusal{TokenExpired, "expired at " + tok.ExpiresAt}
	}
	if issued.After(now.Add(v.cfg.ClockSkew)) {
		return tok, &Refusal{TokenInvalid, "issued in the future: " + tok.IssuedAt}
	}
	want, err := proto.ActionHashHex(req)
	if err != nil {
		return tok, &Refusal{RequestInvalid, err.Error()}
	}
	if tok.ActionHash != want {
		return tok, &Refusal{ActionMismatch, "token is for a different action than the one about to run"}
	}
	if err := v.checkEpoch(tok, req, now, opt.HighTier); err != nil {
		return tok, err
	}
	if opt.CommitWait {
		if tok.Witnessed == nil {
			return tok, &Refusal{CommitWaitMissing, "class requires witness commit-wait evidence"}
		}
		if v.cfg.Witness == nil {
			return tok, &Refusal{CommitWaitInvalid, "no witness verifier configured"}
		}
		if err := v.cfg.Witness(*tok.Witnessed, tok.ActionHash); err != nil {
			return tok, &Refusal{CommitWaitInvalid, err.Error()}
		}
	}
	// Last, so a refused token is never burned and a used one never re-checks.
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, until := range v.used {
		if now.After(until) {
			delete(v.used, id)
		}
	}
	if _, dup := v.used[tok.TokenID]; dup {
		return tok, &Refusal{TokenReplayed, "token_id " + tok.TokenID + " already used"}
	}
	v.used[tok.TokenID] = expires.Add(v.cfg.ClockSkew)
	return tok, nil
}

func (v *Verifier) checkEpoch(tok Token, req ActionRequest, now time.Time, high bool) error {
	v.mu.Lock()
	e, issued := v.epoch, v.epochIssued
	v.mu.Unlock()
	if e == nil {
		if high {
			return &Refusal{EpochStale, "no signed epoch from the gate yet"}
		}
		return nil
	}
	if tok.BreakerEpoch < e.Epoch {
		return &Refusal{EpochSuperseded, fmt.Sprintf("token from epoch %d, gate is at epoch %d", tok.BreakerEpoch, e.Epoch)}
	}
	if now.Sub(issued) > v.cfg.EpochMaxAge+v.cfg.ClockSkew {
		if high {
			return &Refusal{EpochStale, "newest epoch was issued at " + e.IssuedAt}
		}
		return nil
	}
	if s, frozen := e.Frozen(req); frozen && tok.BreakerEpoch == e.Epoch {
		return &Refusal{ScopeFrozen, "breaker open for " + s.String()}
	}
	return nil
}

// refusalLine is the NDJSON record written for each refusal. Every value is a
// string: the witness stores feed lines re-encoded, and numbers would become
// floats (docs/gate-arch.md C8).
type refusalLine struct {
	Kind       string `json:"kind"`
	Level      string `json:"level"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
	TokenID    string `json:"token_id,omitempty"`
	ActionHash string `json:"action_hash,omitempty"`
	Class      string `json:"class,omitempty"`
	Principal  string `json:"principal,omitempty"`
	TS         string `json:"ts"`
}

func (v *Verifier) record(r *Refusal, tok Token, req ActionRequest) {
	if v.cfg.Refusals == nil {
		return
	}
	line, err := json.Marshal(refusalLine{
		Kind: "gate_refusal", Level: "WARN", Code: r.Code, Detail: r.Detail,
		TokenID: tok.TokenID, ActionHash: tok.ActionHash, Class: req.Class, Principal: req.Principal,
		TS: proto.FormatTime(v.cfg.Now()),
	})
	if err != nil {
		return
	}
	v.out.Lock()
	defer v.out.Unlock()
	_, _ = v.cfg.Refusals.Write(append(line, '\n'))
}
