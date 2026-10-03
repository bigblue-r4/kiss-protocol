// Poultry-house demo for the Harborlight witness.
//
// Runs the real witness store, tailer and farm feed against a simulated poultry
// operation, entirely on this machine: no network, no daemons, nothing installed,
// everything in a temporary directory. Four scenes:
//
//  1. A normal stretch: readings, an alarm, a remote ventilation change, door
//     access and a vaccination record, all recorded.
//  2. The witness goes down while the houses keep logging; on restart it catches
//     up and the record says so.
//  3. A house controller goes quiet; the record flags it, then notes it is back.
//  4. Someone tries to rewrite the record; verification catches each attempt.
//
// Run:  go run ./examples/poultry-demo            (about 30 seconds)
//
//	go run ./examples/poultry-demo -keep      (keep the files to inspect)
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/farm"
	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

var (
	keep      = flag.Bool("keep", false, "keep the demo directory afterwards")
	silence   = flag.Duration("silence", 6*time.Second, "silent-house threshold (the real default is 10m)")
	demoKey   = make([]byte, 32) // the real witness derives its key from the machine ID
	shown     = 0                // entries already printed
	workDir   string
	feedPath  string
	storeDir  string
	statePath string
)

type witness struct {
	s *store.Store
	b *farm.Bridge
}

func main() {
	flag.Parse()
	var err error
	workDir, err = os.MkdirTemp("", "poultry-demo-")
	check(err)
	if *keep {
		defer fmt.Printf("\nDemo files kept in %s\n", workDir)
	} else {
		defer os.RemoveAll(workDir)
	}
	feedPath = filepath.Join(workDir, "farm-events.jsonl")
	storeDir = filepath.Join(workDir, "witness")
	statePath = filepath.Join(storeDir, "tail-state", "farm_events.json")
	check(os.WriteFile(feedPath, nil, 0600))

	title("Harborlight witness — poultry house demo")
	say("Simulated farm: House 3 and House 4 controllers, a door reader, the records office.")
	say("Everything runs locally in %s", workDir)

	// ── Scene 1 ──────────────────────────────────────────────────────────
	scene(1, "A normal stretch of the day")
	w := start()
	emit("house-3/controller", "reading", `"metric":"ammonia_ppm","value":18.5,"unit":"ppm"`)
	emit("house-4/controller", "reading", `"metric":"temperature_f","value":78.2,"unit":"F"`)
	emit("house-3/controller", "alarm", `"alarm":"high_temperature","severity":"critical","value":92.1,"unit":"F"`)
	emit("house-3/controller", "setting_change", `"setting":"min_ventilation_pct","from":30,"to":10,"by":"remote:jdoe"`)
	emit("house-3/entry-door", "access", `"door":"house-3/entry","person":"badge:1042","direction":"in"`)
	emit("office/records", "health", `"record":"vaccination","flock":"F-2026-41","product":"example-vaccine","by":"crew:ana"`)
	waitFor(w, 7) // tail_fresh + 6 events
	printNew()

	// ── Scene 2 ──────────────────────────────────────────────────────────
	scene(2, "The witness goes down — the houses keep logging")
	w.stop()
	say("Witness stopped (power cut, update, crash: same thing).")
	emit("house-4/controller", "setting_change", `"setting":"feed_line_minutes","from":12,"to":20,"by":"local:panel"`)
	emit("house-3/controller", "reading", `"metric":"ammonia_ppm","value":27.0,"unit":"ppm"`)
	emit("house-3/controller", "alarm", `"alarm":"high_ammonia","severity":"warning","value":27.0,"unit":"ppm"`)
	say("While it was down, the farm logged 3 events.")
	time.Sleep(500 * time.Millisecond)
	w = start()
	say("Witness restarted.")
	waitFor(w, 11) // + tail_resumed + 3 caught-up events
	printNew()

	// ── Scene 3 ──────────────────────────────────────────────────────────
	scene(3, "House 3's controller goes quiet")
	say("House 4 keeps reporting every 2s. House 3 stops. Alarm threshold: %s (real default: 10 min).", *silence)
	deadline := time.Now().Add(*silence + 5*time.Second)
	for time.Now().Before(deadline) && !has(w, "farm_source_silent") {
		emit("house-4/controller", "heartbeat", "")
		time.Sleep(2 * time.Second)
	}
	printNew()
	say("House 3 comes back.")
	emit("house-3/controller", "heartbeat", "")
	for i := 0; i < 50 && !has(w, "farm_source_resumed"); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	printNew()
	say("The door reader and the records office were quiet the whole time and were never flagged:")
	say("they only report when something happens, so their silence is normal.")
	w.stop()

	// ── Scene 4 ──────────────────────────────────────────────────────────
	scene(4, "Someone tries to rewrite the record")
	entries, err := store.ReadAll(storeDir, demoKey)
	check(err)
	say("The untouched record:  %s", verify(storeDir))
	ventilation := indexOf(entries, "farm_setting_change:min_ventilation_pct")
	tamper("Erase the remote ventilation cut (one entry deleted)", func(recs [][]byte) [][]byte {
		return append(append([][]byte{}, recs[:ventilation]...), recs[ventilation+1:]...)
	})
	tamper("Change one byte of the ammonia alarm", func(recs [][]byte) [][]byte {
		i := indexOf(entries, "farm_alarm:high_ammonia")
		out := clone(recs)
		out[i][len(out[i])/2] ^= 0x01
		return out
	})
	cutEnd := func(recs [][]byte) [][]byte { return recs[:indexOf(entries, "farm_source_silent")] }
	tamper("Cut off the end of the log (hide the silence warning)", cutEnd)
	tamperNoHead("…and also delete the signed head file", cutEnd)

	title("What this shows, and what it doesn't")
	say("✓ Every event is recorded, including ones logged while the witness was down.")
	say("✓ A controller that stops reporting is flagged, and so is its return.")
	say("✓ Deleting, altering or cutting off entries is detected.")
	say("✗ It detects and records. It controls nothing and cannot keep a house running.")
	say("✗ The record is signed on the farm computer. Someone with full control of that computer")
	say("  could rewrite the log and re-sign it, because the key lives there too. A copy of the")
	say("  signed head kept elsewhere (the transparency mirror, `witness audit`) catches that.")
}

// ── witness lifecycle ─────────────────────────────────────────────────────

func start() *witness {
	s, err := store.Open(storeDir, demoKey, nil)
	check(err)
	b := farm.New(feedPath, s, *silence)
	b.SetCheckEvery(500 * time.Millisecond)
	b.ResumeFrom(statePath)
	before := s.Head().Size
	b.Start()
	// The witness records a tail_* entry when it opens the feed. Waiting for it
	// means the farm's next event lands after the point the witness reads from.
	w := &witness{s: s, b: b}
	waitFor(w, before+1)
	return w
}

func (w *witness) stop() {
	w.b.Stop()
	check(w.s.Close())
}

func waitFor(w *witness, n uint64) {
	deadline := time.Now().Add(10 * time.Second)
	for w.s.Head().Size < n && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if w.s.Head().Size < n {
		fmt.Fprintf(os.Stderr, "demo: record reached %d entries, expected %d\n", w.s.Head().Size, n)
		os.Exit(1)
	}
}

func has(w *witness, event string) bool {
	es, err := store.ReadAll(storeDir, demoKey)
	check(err)
	_ = w
	return indexOf(es, event) >= 0
}

// ── the simulated farm ────────────────────────────────────────────────────

func emit(source, kind, fields string) {
	line := fmt.Sprintf(`{"ts":%q,"source":%q,"kind":%q`, time.Now().UTC().Format(time.RFC3339Nano), source, kind)
	if fields != "" {
		line += "," + fields
	}
	f, err := os.OpenFile(feedPath, os.O_APPEND|os.O_WRONLY, 0600)
	check(err)
	_, err = f.WriteString(line + "}\n")
	check(err)
	check(f.Close())
}

// ── verification and tampering ────────────────────────────────────────────

// verify does what `witness verify` does: open the store (which checks the signed
// head) and re-verify the whole tree.
func verify(dir string) string {
	s, err := store.Open(dir, demoKey, nil)
	if err != nil {
		return "INTEGRITY FAILURE — " + short(err)
	}
	defer s.Close()
	n, err := s.VerifyIntegrity()
	if err != nil {
		return "INTEGRITY FAILURE — " + short(err)
	}
	return fmt.Sprintf("OK (%d entries verified)", n)
}

func tamper(label string, edit func([][]byte) [][]byte) { tamperCopy(label, edit, true) }

// tamperNoHead is the same attack plus removing tree-head.json, the file that
// records how long the log should be.
func tamperNoHead(label string, edit func([][]byte) [][]byte) { tamperCopy(label, edit, false) }

func tamperCopy(label string, edit func([][]byte) [][]byte, keepHead bool) {
	dir, err := os.MkdirTemp(workDir, "tampered-")
	check(err)
	if keepHead {
		head, err := os.ReadFile(filepath.Join(storeDir, "tree-head.json"))
		check(err)
		check(os.WriteFile(filepath.Join(dir, "tree-head.json"), head, 0600))
	}
	recs := readRecords(filepath.Join(storeDir, "witness.log"))
	writeRecords(filepath.Join(dir, "witness.log"), edit(recs))
	say("Attempt: %-55s → %s", label, verify(dir))
}

// The log is a sequence of [4-byte big-endian length][encrypted entry] records.
func readRecords(path string) [][]byte {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	var out [][]byte
	for {
		var l [4]byte
		if _, err := io.ReadFull(f, l[:]); err != nil {
			return out
		}
		rec := make([]byte, binary.BigEndian.Uint32(l[:]))
		_, err := io.ReadFull(f, rec)
		check(err)
		out = append(out, rec)
	}
}

func writeRecords(path string, recs [][]byte) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	check(err)
	for _, r := range recs {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(r)))
		_, err = f.Write(append(l[:], r...))
		check(err)
	}
	check(f.Close())
}

// ── output ────────────────────────────────────────────────────────────────

func printNew() {
	es, err := store.ReadAll(storeDir, demoKey)
	check(err)
	for _, e := range es[shown:] {
		var p map[string]interface{}
		_ = json.Unmarshal(e.Data, &p)
		mark := "  "
		if e.Level == "WARN" {
			mark = "⚠ "
		}
		fmt.Printf("    %s#%-3d %-5s %-42s %s\n", mark, e.Seq, e.Level, e.Event, detail(e.Event, p))
	}
	shown = len(es)
}

func detail(event string, p map[string]interface{}) string {
	get := func(k string) string {
		if v, ok := p[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	switch {
	case strings.HasPrefix(event, "tail_"):
		return fmt.Sprintf("feed opened (%s), %s bytes to catch up", get("mode"), get("catch_up_bytes"))
	case event == "farm_source_silent":
		return fmt.Sprintf("%s quiet for %ss", get("source"), get("silent_for_seconds"))
	case event == "farm_source_resumed":
		return fmt.Sprintf("%s back after %ss", get("source"), get("silent_for_seconds"))
	case strings.HasPrefix(event, "farm_setting_change"):
		return fmt.Sprintf("%s → %s by %s", get("from"), get("to"), get("by"))
	case strings.HasPrefix(event, "farm_alarm"), strings.HasPrefix(event, "farm_reading"):
		return fmt.Sprintf("%s %s %s", get("source"), get("value"), get("unit"))
	case strings.HasPrefix(event, "farm_access"):
		return fmt.Sprintf("%s %s", get("person"), get("direction"))
	case strings.HasPrefix(event, "farm_health"):
		return fmt.Sprintf("flock %s, by %s", get("flock"), get("by"))
	}
	return get("source")
}

func indexOf(es []store.Entry, event string) int {
	for i, e := range es {
		if e.Event == event {
			return i
		}
	}
	return -1
}

func clone(recs [][]byte) [][]byte {
	out := make([][]byte, len(recs))
	for i, r := range recs {
		out[i] = append([]byte{}, r...)
	}
	return out
}

func short(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "size mismatch"):
		return "the log is shorter than its signed head says"
	case strings.Contains(s, "root mismatch"):
		return "the entries no longer match the signed head"
	case strings.Contains(s, "tree head missing"):
		return "the signed head is gone but the log has entries"
	}
	return s
}

func title(s string) { fmt.Printf("\n══ %s ══\n", s) }
func scene(n int, s string) {
	fmt.Printf("\n── Scene %d: %s ──\n", n, s)
}
func say(format string, a ...interface{}) { fmt.Printf("  "+format+"\n", a...) }

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}
