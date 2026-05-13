// Package anomaly detects storage and network anomalies that should trigger
// the death broadcast even when no termination signal is received.
//
// Two detectors run as goroutines:
//   - Storage: writes a probe file every tick; failure = storage anomaly.
//   - Network: checks that at least one non-loopback interface is up every tick.
//
// Both send an Event to the shared channel when an anomaly is detected.
package anomaly

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Kind identifies the type of anomaly.
type Kind string

const (
	KindStorage Kind = "storage_anomaly"
	KindNetwork Kind = "network_cut"
)

// Event describes a detected anomaly.
type Event struct {
	Kind   Kind   `json:"kind"`
	Detail string `json:"detail"`
}

// Detector watches for storage and network anomalies.
type Detector struct {
	probeDir string
	interval time.Duration
	events   chan Event
	stop     chan struct{}
}

// New creates an anomaly Detector.
//   - probeDir: directory used for storage probe writes (should be the primary log dir).
//   - interval: how often to run checks.
//   - events: channel that receives anomaly events (buffered recommended).
func New(probeDir string, interval time.Duration, events chan Event) *Detector {
	return &Detector{
		probeDir: probeDir,
		interval: interval,
		events:   events,
		stop:     make(chan struct{}),
	}
}

// Run starts both detectors in goroutines. Call Stop to shut them down.
func (d *Detector) Run() {
	go d.runStorage()
	go d.runNetwork()
}

// Stop halts the detector goroutines.
func (d *Detector) Stop() {
	close(d.stop)
}

// runStorage probes writes to the primary log directory.
// Three consecutive failures in a row = anomaly event.
func (d *Detector) runStorage() {
	probe := filepath.Join(d.probeDir, ".witness_probe")
	failures := 0
	tick := time.NewTicker(d.interval)
	defer tick.Stop()

	for {
		select {
		case <-d.stop:
			return
		case <-tick.C:
			if err := writeProbe(probe); err != nil {
				failures++
				if failures >= 3 {
					select {
					case d.events <- Event{
						Kind:   KindStorage,
						Detail: fmt.Sprintf("probe write failed %d times: %v", failures, err),
					}:
					default:
					}
					failures = 0 // reset after firing
				}
			} else {
				failures = 0
			}
		}
	}
}

// runNetwork checks that at least one non-loopback, non-virtual interface is up.
// Three consecutive failures = anomaly event.
func (d *Detector) runNetwork() {
	failures := 0
	tick := time.NewTicker(d.interval)
	defer tick.Stop()

	for {
		select {
		case <-d.stop:
			return
		case <-tick.C:
			if !networkUp() {
				failures++
				if failures >= 3 {
					select {
					case d.events <- Event{
						Kind:   KindNetwork,
						Detail: fmt.Sprintf("no active non-loopback interface detected for %d checks", failures),
					}:
					default:
					}
					failures = 0
				}
			} else {
				failures = 0
			}
		}
	}
}

func writeProbe(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write([]byte{1})
	closeErr := f.Close()
	_ = os.Remove(path)
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func networkUp() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		// Skip loopback and down interfaces.
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return true
	}
	return false
}
