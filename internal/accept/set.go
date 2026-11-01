package accept

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/bigblue-r4/kiss-protocol/internal/drift"
	"github.com/bigblue-r4/kiss-protocol/internal/soul"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Policy decides whose requests count.
type Policy struct {
	MachineID string
	// Operators are the keys allowed to approve (trust/operators.txt).
	Operators []soul.AllowlistEntry
	// Own is the witness's own signing key. It may not approve: anyone who can
	// act as the witness user can sign with it, and approving drift is exactly
	// what an intruder on the box would want. AllowOwn lifts that for --dev.
	Own      ed25519.PublicKey
	AllowOwn bool
	// AnySigner accepts any valid signature. Only for `witness accept list`,
	// which shows what the daemon recorded (it checked trust when it did);
	// never for the daemon.
	AnySigner bool
}

// signerLabel checks a request's signer against the policy and returns the
// label it is trusted under.
func (p Policy) signerLabel(r *Request) (string, error) {
	pub, err := r.SignerKey()
	if err != nil {
		return "", err
	}
	if p.Own != nil && bytes.Equal(pub, p.Own) {
		if !p.AllowOwn {
			return "", errors.New("signed with the witness's own key; approvals need a separate operator key (see 'witness accept keygen'), or --dev")
		}
		return "witness-key(dev)", nil
	}
	for _, op := range p.Operators {
		if bytes.Equal(pub, op.PubKey) {
			return op.Label, nil
		}
	}
	if p.AnySigner {
		return "(not in operators.txt)", nil
	}
	return "", errors.New("signer is not in the operator allowlist (trust/operators.txt)")
}

// Approval is one active operator approval.
type Approval struct {
	ID      string         `json:"id"`
	By      string         `json:"by"`    // signer public key, hex
	Label   string         `json:"label"` // its operators.txt label
	Reason  string         `json:"reason"`
	Created string         `json:"created"`
	Changes []drift.Change `json:"changes"`
}

// Set is the active approvals, rebuilt from the log at start and extended as
// requests arrive. Not safe for concurrent use; the daemon uses it from its
// main loop only.
type Set struct {
	approvals map[string]*Approval
	items     map[string]bool // itemKey -> approved by some active approval
	seen      map[string]bool // request IDs already applied
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{approvals: map[string]*Approval{}, items: map[string]bool{}, seen: map[string]bool{}}
}

// itemKey is what an approval pins for one change. A file approval includes
// the observed value, so a later, different change to the same path is not
// covered.
func itemKey(c drift.Change) (string, error) {
	switch c.Type {
	case "file_changed", "file_mode_changed":
		if c.Path == "" || c.New == "" {
			return "", fmt.Errorf("%s needs path and new", c.Type)
		}
		return c.Type + "\x00" + c.Path + "\x00" + c.New, nil
	case "file_removed":
		if c.Path == "" {
			return "", errors.New("file_removed needs path")
		}
		return c.Type + "\x00" + c.Path, nil
	case "new_process":
		if c.Process == "" {
			return "", errors.New("new_process needs process")
		}
		return c.Type + "\x00" + c.Process, nil
	}
	return "", fmt.Errorf("unknown change type %q", c.Type)
}

// Apply validates r against p and, if it passes, applies it. It returns the
// label the signer is trusted under.
func (s *Set) Apply(r *Request, p Policy) (string, error) {
	if err := r.check(); err != nil {
		return "", err
	}
	if r.MachineID != p.MachineID {
		return "", errors.New("request is for a different machine")
	}
	if err := r.verifySig(); err != nil {
		return "", err
	}
	label, err := p.signerLabel(r)
	if err != nil {
		return "", err
	}
	if s.seen[r.ID] {
		return "", fmt.Errorf("request %s was already applied", r.ID)
	}
	switch r.Kind {
	case KindAccept:
		s.approvals[r.ID] = &Approval{ID: r.ID, By: r.Signer, Label: label,
			Reason: r.Reason, Created: r.Created, Changes: r.Changes}
	case KindRevoke:
		if s.approvals[r.Revokes] == nil {
			return "", fmt.Errorf("no active approval %s", r.Revokes)
		}
		delete(s.approvals, r.Revokes)
	}
	s.seen[r.ID] = true
	s.rebuild()
	return label, nil
}

func (s *Set) rebuild() {
	s.items = map[string]bool{}
	for _, a := range s.approvals {
		for _, c := range a.Changes {
			if k, err := itemKey(c); err == nil {
				s.items[k] = true
			}
		}
	}
}

// Filter splits changes into those no approval covers and a count of those
// one does.
func (s *Set) Filter(changes []drift.Change) (unapproved []drift.Change, approved int) {
	for _, c := range changes {
		if k, err := itemKey(c); err == nil && s.items[k] {
			approved++
			continue
		}
		unapproved = append(unapproved, c)
	}
	return unapproved, approved
}

// Approvals lists the active approvals, oldest first.
func (s *Set) Approvals() []Approval {
	out := make([]Approval, 0, len(s.approvals))
	for _, a := range s.approvals {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created != out[j].Created {
			return out[i].Created < out[j].Created
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// entryData is the data of a drift_accepted / drift_accept_revoked entry. The
// full signed request is kept so the approval can be re-checked from the log.
type entryData struct {
	ID      string   `json:"id"`
	Label   string   `json:"label"`
	Reason  string   `json:"reason"`
	Revokes string   `json:"revokes,omitempty"`
	Items   int      `json:"items,omitempty"`
	Request *Request `json:"request"`
}

// EntryFor returns the log event and data recording an applied request.
func EntryFor(r *Request, label string) (event string, data interface{}) {
	d := entryData{ID: r.ID, Label: label, Reason: r.Reason, Request: r}
	if r.Kind == KindRevoke {
		d.Revokes = r.Revokes
		return EventRevoked, d
	}
	d.Items = len(r.Changes)
	return EventAccepted, d
}

// RejectedData is the data of a drift_accept_rejected entry.
func RejectedData(file string, r *Request, err error) map[string]interface{} {
	d := map[string]interface{}{"file": file, "error": err.Error()}
	if r != nil {
		d["id"] = r.ID
		d["kind"] = r.Kind
		d["signer"] = r.Signer
	}
	return d
}

// Replay rebuilds a Set from log entries. Every recorded request is checked
// again, signature and signer included, against the current policy: an entry
// that does not pass (forged, or signed by a key since removed from
// operators.txt) is skipped and counted.
func Replay(entries []store.Entry, p Policy) (*Set, int) {
	s := NewSet()
	skipped := 0
	for _, e := range entries {
		if e.Source != Source || (e.Event != EventAccepted && e.Event != EventRevoked) {
			continue
		}
		var d entryData
		if err := json.Unmarshal(e.Data, &d); err != nil || d.Request == nil {
			skipped++
			continue
		}
		if _, err := s.Apply(d.Request, p); err != nil {
			skipped++
		}
	}
	return s, skipped
}
