package lifecycle

import (
	"errors"
	"testing"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func entry(level, event string, at time.Time) store.Entry {
	return store.Entry{Seq: 42, Timestamp: at, Level: level, Event: event, Source: "witness"}
}

func genesis(at time.Time) store.Entry {
	return store.Entry{Seq: 1, Timestamp: at, Level: "SYSTEM", Event: GenesisEvent, Source: "witness-init"}
}

// A "genesis" record anywhere but first is not a fresh install.
func TestLateGenesisRecordIsNotAFreshInstall(t *testing.T) {
	e := genesis(t0)
	e.Seq = 900
	if ev, _ := Downtime(e, true, t0.Add(time.Second), time.Minute); ev.Level != "CRITICAL" {
		t.Fatalf("level = %s", ev.Level)
	}
}

func TestFirstStartHasNoGap(t *testing.T) {
	if _, ok := Downtime(store.Entry{}, false, t0, 10*time.Minute); ok {
		t.Fatal("an empty log reported downtime")
	}
}

func TestDowntimeLevels(t *testing.T) {
	cases := []struct {
		name  string
		last  store.Entry
		now   time.Time
		level string
		clean bool
	}{
		{"clean, short", entry("DEATH", CleanStopEvent, t0), t0.Add(2 * time.Minute), "INFO", true},
		{"clean, long", entry("DEATH", CleanStopEvent, t0), t0.Add(3 * time.Hour), "WARN", true},
		{"unrecorded, short (crash + restart)", entry("INFO", "drift_clean", t0), t0.Add(6 * time.Second), "CRITICAL", false},
		{"unrecorded, long", entry("INFO", "drift_clean", t0), t0.Add(48 * time.Hour), "CRITICAL", false},
		{"other DEATH (storage anomaly) is not a clean stop", entry("DEATH", "storage_anomaly", t0), t0.Add(time.Minute), "CRITICAL", false},
		{"first start after init", genesis(t0), t0.Add(5 * time.Second), "INFO", true},
		{"init, then a long wait before the first start", genesis(t0), t0.Add(72 * time.Hour), "WARN", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := Downtime(c.last, true, c.now, 10*time.Minute)
			if !ok || ev.Name != "witness_downtime" {
				t.Fatalf("no downtime event: %+v", ev)
			}
			if ev.Level != c.level || ev.Data["clean_stop"] != c.clean {
				t.Fatalf("level=%s clean=%v, want %s %v", ev.Level, ev.Data["clean_stop"], c.level, c.clean)
			}
			if got, want := ev.Data["gap_seconds"], int64(c.now.Sub(t0)/time.Second); got != want {
				t.Fatalf("gap_seconds=%v, want %v", got, want)
			}
		})
	}
}

func TestClockGoingBackwardsIsZeroGap(t *testing.T) {
	ev, _ := Downtime(entry("INFO", "x", t0), true, t0.Add(-time.Hour), time.Minute)
	if ev.Data["gap_seconds"] != int64(0) {
		t.Fatalf("gap = %v", ev.Data["gap_seconds"])
	}
}

func TestMirrorHealthRecordsFirstFailureEscalationAndRecovery(t *testing.T) {
	m := NewMirrorHealth(3)
	down := errors.New("connection refused")
	var got []string
	for _, err := range []error{nil, down, down, down, down, down, nil, nil, down} {
		if ev, ok := m.Result(err); ok {
			got = append(got, ev.Level+":"+ev.Name)
		}
	}
	want := []string{
		"WARN:mirror_push_failed",     // first failure
		"CRITICAL:mirror_unreachable", // third in a row
		"INFO:mirror_push_recovered",  // back after five
		"WARN:mirror_push_failed",     // a new outage starts over
	}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

func TestMirrorHealthEscalateAfterOne(t *testing.T) {
	m := NewMirrorHealth(0) // clamps to 1: the first failure is already WARN, never silently skipped
	ev, ok := m.Result(errors.New("x"))
	if !ok || ev.Name != "mirror_push_failed" {
		t.Fatalf("got %+v", ev)
	}
}

func TestMirrorConfig(t *testing.T) {
	if ev, ok := MirrorConfig("", nil, false); !ok || ev.Level != "CRITICAL" || ev.Name != "mirror_not_configured" {
		t.Fatalf("production without a mirror: %+v", ev)
	}
	if ev, ok := MirrorConfig("", nil, true); !ok || ev.Level != "WARN" {
		t.Fatalf("dev without a mirror: %+v", ev)
	}
	if ev, ok := MirrorConfig("bogus://x", errors.New("unknown scheme"), false); !ok || ev.Name != "mirror_misconfigured" {
		t.Fatalf("broken mirror: %+v", ev)
	}
	if _, ok := MirrorConfig("file:///m", nil, false); ok {
		t.Fatal("a working mirror produced an event")
	}
}
