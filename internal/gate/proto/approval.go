package proto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Approval is one operator's signature over an action_hash: the root of trust
// for manual-class actions. A request may carry several; the signed policy
// says how many distinct operators a class needs (approvals_required).
type Approval struct {
	V             int    `json:"v"`
	ActionHash    string `json:"action_hash"`    // lowercase hex SHA-256
	ApproverLabel string `json:"approver_label"` // label in operators.txt
	ExpiresAt     string `json:"expires_at"`     // FormatTime
	Sig           string `json:"sig,omitempty"`  // over DomainApproval || canonical(without sig)
}

// Approval errors, distinguishable with errors.Is so the gate can map them to
// APPROVAL_INVALID, APPROVAL_EXPIRED and NO_ROOT.
var (
	ErrApprovalInvalid  = errors.New("approval invalid")
	ErrApprovalExpired  = errors.New("approval expired")
	ErrTooFewApprovals  = errors.New("not enough distinct operator approvals")
	errApprovalWrongFor = errors.New("approval is for a different action")
)

// SignApproval signs a with s. a.Sig is ignored and replaced.
func SignApproval(a Approval, s Signer) (Approval, error) {
	a.Sig = ""
	in, err := sigInput(DomainApproval, a)
	if err != nil {
		return Approval{}, err
	}
	sig, err := s.Sign(in)
	if err != nil {
		return Approval{}, fmt.Errorf("sign approval: %w", err)
	}
	a.Sig = hex.EncodeToString(sig)
	return a, nil
}

// DecodeApproval decodes a canonical Approval (no signature check).
func DecodeApproval(data []byte) (Approval, error) {
	var a Approval
	return a, decodeCanonical(data, &a)
}

// verifyApproval checks one approval and returns the key that signed it.
func verifyApproval(a Approval, actionHash string, ops []Operator, now time.Time) (string, error) {
	if a.V != Version {
		return "", fmt.Errorf("%w: version %d", ErrApprovalInvalid, a.V)
	}
	if a.ActionHash != actionHash {
		return "", fmt.Errorf("%w: %v", ErrApprovalInvalid, errApprovalWrongFor)
	}
	exp, err := ParseTime(a.ExpiresAt, "expires_at")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrApprovalInvalid, err)
	}
	unsigned := a
	unsigned.Sig = ""
	in, err := sigInput(DomainApproval, unsigned)
	if err != nil {
		return "", err
	}
	var lastErr error = fmt.Errorf("%w: approver %q is not in operators.txt", ErrApprovalInvalid, a.ApproverLabel)
	for _, op := range ops {
		if op.Label != a.ApproverLabel {
			continue
		}
		if err := verifySig(op.Key, in, a.Sig, "approval"); err != nil {
			lastErr = fmt.Errorf("%w: %v", ErrApprovalInvalid, err)
			continue
		}
		// Expiry is checked after the signature, so an unsigned or forged
		// approval is reported as invalid, never as merely expired.
		if !now.Before(exp) {
			return "", fmt.Errorf("%w: %s expired at %s", ErrApprovalExpired, a.ApproverLabel, a.ExpiresAt)
		}
		return hex.EncodeToString(op.Key), nil
	}
	return "", lastErr
}

// VerifyApprovals checks approvals for the action with hash actionHash (hex)
// and requires at least required valid approvals from distinct operator keys
// (two labels for one key count once). It returns the labels counted.
//
// With fewer than required valid approvals it returns the first approval
// error if there was one (so a forged or expired approval is reported as
// such), otherwise ErrTooFewApprovals.
func VerifyApprovals(approvals []Approval, actionHash string, ops []Operator, required int, now time.Time) ([]string, error) {
	if required < 1 {
		required = 1
	}
	if _, err := decodeHex(actionHash, 32, "action_hash"); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var labels []string
	var firstErr error
	for _, a := range approvals {
		key, err := verifyApproval(a, actionHash, ops, now)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !seen[key] {
			seen[key] = true
			labels = append(labels, a.ApproverLabel)
		}
	}
	if len(labels) >= required {
		return labels, nil
	}
	if firstErr != nil {
		return labels, firstErr
	}
	return labels, fmt.Errorf("%w: have %d, class requires %d", ErrTooFewApprovals, len(labels), required)
}
