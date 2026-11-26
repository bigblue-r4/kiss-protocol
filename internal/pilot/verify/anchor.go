package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/pilot/rekor"
	"github.com/bigblue-r4/kiss-protocol/pkg/checkpoint"
	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// AnchorResult is what a verified Rekor anchor establishes.
type AnchorResult struct {
	Size           uint64 `json:"anchored_size"`
	IntegratedTime string `json:"rekor_integrated_time"`
	Rekor          string `json:"rekor"`
	UUID           string `json:"rekor_uuid"`
	LogIndex       int64  `json:"rekor_log_index"`
}

// anchor checks the latest Rekor anchor, if the evaluator pinned the Rekor
// and anchoring keys. Pinning them means anchoring is expected: a missing
// anchor is UNVERIFIABLE, and an anchor that does not match the records or
// does not verify is FAILED. Without the pins an anchor is only disclosed.
func (r *Result) anchor(ctx context.Context, o Options, c checkpoint.Checkpoint, leaves []tlog.Hash) {
	const title = "Rekor anchor matches the records"
	if o.RekorKey == nil || o.AnchorKey == nil {
		if _, err := fetch(ctx, o, "anchor.json", 1<<20); err == nil {
			r.Disclosures = append(r.Disclosures, "THIS RUN: the log publishes a Rekor anchor, but it was not checked (no Rekor and anchoring keys pinned).")
		}
		return
	}
	raw, err := fetch(ctx, o, "anchor.json", 1<<20)
	if err != nil {
		r.add("anchor.rekor", title, Unverifiable, "anchoring keys are pinned but no anchor could be fetched: "+err.Error())
		return
	}
	r.Manifest.InputSHA256["anchor.json"] = sha(raw)
	var a rekor.Anchor
	if err := json.Unmarshal(raw, &a); err != nil {
		r.add("anchor.rekor", title, Failed, "anchor.json is malformed: "+err.Error())
		return
	}
	if a.Size == 0 || a.Size > uint64(len(leaves)) {
		r.add("anchor.rekor", title, Failed, fmt.Sprintf("the anchor commits to %d records, but only %d are published: anchored evidence is missing", a.Size, len(leaves)))
		return
	}
	body := checkpoint.Checkpoint{Origin: c.Origin, Size: a.Size, Root: tlog.Root(leaves[:a.Size])}.Text()
	res, err := rekor.VerifyAnchor(a, rekor.Digest(body), o.RekorKey, o.AnchorKey)
	if err != nil {
		r.add("anchor.rekor", title, Failed, fmt.Sprintf("anchor at size %d: %v (records rewritten after they were anchored, or a forged anchor)", a.Size, err))
		return
	}
	at := time.Unix(res.IntegratedTime, 0).UTC()
	r.Anchor = &AnchorResult{Size: a.Size, IntegratedTime: at.Format(time.RFC3339), Rekor: a.Rekor, UUID: a.UUID, LogIndex: res.LogIndex}
	ck := r.add("anchor.rekor", title, Verified, fmt.Sprintf("the first %d records existed in exactly this form by %s (Rekor entry %d at %s)", a.Size, at.Format(time.RFC3339), res.LogIndex, a.Rekor))
	if a.Size < c.Size {
		ck.Warning = fmt.Sprintf("records %d to %d are newer than the latest anchor; only the witnesses vouch for them", a.Size+1, c.Size)
	}
	if o.RekorURL != "" {
		r.anchorHistory(ctx, o, c, leaves)
	} else {
		r.Disclosures = append(r.Disclosures, "THIS RUN: only the latest Rekor anchor was checked (offline). An operator holding the anchoring key could rewrite history and anchor the rewrite again; pass --rekor-url to check every anchor Rekor holds for the anchoring key.")
	}
	r.Disclosures = append(r.Disclosures, "Rekor anchor: Rekor's signed entry timestamp shows the anchored root existed by that time, and the verifier recomputes that root from the records, so a rewrite of anchored records fails even if the log key and every witness colluded. Rekor does not check one anchor against another, does not see the records, and is a public, permanent log run by a third party.")
}

// anchorHistory asks Rekor (online) for every entry made with the pinned
// anchoring key and checks that each one anchors a prefix of these records.
// An operator holding the log key, the anchoring key and the witnesses
// could rewrite history and anchor the rewrite again; the earlier, honest
// anchors stay in Rekor, and this finds them. Rekor's search index is not
// signed, so a missing entry proves nothing; every entry found is verified.
func (r *Result) anchorHistory(ctx context.Context, o Options, c checkpoint.Checkpoint, leaves []tlog.Hash) {
	const title = "Every Rekor anchor by this log's anchoring key matches the records"
	uuids, err := rekor.Search(ctx, o.HTTP, o.RekorURL, o.AnchorKey)
	if err != nil {
		r.add("anchor.history", title, Unverifiable, err.Error())
		return
	}
	want := map[[32]byte][]string{} // digest -> entries anchoring it
	earliest := int64(0)
	for _, u := range uuids {
		uuid, raw, err := rekor.Fetch(ctx, o.HTTP, o.RekorURL, u)
		if err != nil {
			r.add("anchor.history", title, Unverifiable, err.Error())
			return
		}
		_, body, res, err := rekor.VerifyEntry(uuid, raw, o.RekorKey)
		if err != nil {
			r.add("anchor.history", title, Failed, fmt.Sprintf("Rekor entry %s: %v", uuid, err))
			return
		}
		d, err := rekor.AnchoredDigest(body, o.AnchorKey)
		if err != nil {
			r.add("anchor.history", title, Failed, fmt.Sprintf("Rekor entry %s, made with the anchoring key: %v", uuid, err))
			return
		}
		want[d] = append(want[d], fmt.Sprintf("%d (%s)", res.LogIndex, time.Unix(res.IntegratedTime, 0).UTC().Format(time.RFC3339)))
		if earliest == 0 || res.IntegratedTime < earliest {
			earliest = res.IntegratedTime
		}
	}
	if len(want) == 0 {
		r.add("anchor.history", title, Unverifiable, "Rekor's index returned no entry for the anchoring key")
		return
	}
	// One pass over every prefix: the RFC 6962 root of the first k leaves
	// is the right-to-left fold of the compact range's perfect subtrees.
	type peak struct {
		h    tlog.Hash
		size uint64
	}
	var peaks []peak
	matched := 0
	for k, l := range leaves {
		p := peak{l, 1}
		for len(peaks) > 0 && peaks[len(peaks)-1].size == p.size {
			p = peak{tlog.HashNode(peaks[len(peaks)-1].h, p.h), p.size * 2}
			peaks = peaks[:len(peaks)-1]
		}
		peaks = append(peaks, p)
		root := peaks[len(peaks)-1].h
		for i := len(peaks) - 2; i >= 0; i-- {
			root = tlog.HashNode(peaks[i].h, root)
		}
		d := rekor.Digest(checkpoint.Checkpoint{Origin: c.Origin, Size: uint64(k + 1), Root: root}.Text())
		if _, ok := want[d]; ok {
			delete(want, d)
			matched++
		}
	}
	if len(want) > 0 {
		var bad []string
		for _, es := range want {
			bad = append(bad, es...)
		}
		sort.Strings(bad)
		r.add("anchor.history", title, Failed, fmt.Sprintf("%d Rekor anchor(s) by this log's anchoring key match no prefix of these records: the history was rewritten or forked after it was anchored, or records were lost. Rekor entries: %s", len(bad), strings.Join(bad, ", ")))
		return
	}
	r.add("anchor.history", title, Verified, fmt.Sprintf("%d anchor(s) found in Rekor, all prefixes of these records; the earliest was integrated %s", matched, time.Unix(earliest, 0).UTC().Format(time.RFC3339)))
}
