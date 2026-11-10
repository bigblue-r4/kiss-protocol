package breaker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// TripAdapter is told about every trip after it is recorded. It is a
// notification: an adapter error never un-trips a scope, and adapters have
// no way to reset one. There are deliberately no built-in infrastructure
// killers; an operator who wants one points ExecHook at their own script.
type TripAdapter interface {
	OnTrip(ctx context.Context, e Event) error
}

// LogOnly writes one JSON line per trip to W.
type LogOnly struct {
	mu sync.Mutex
	W  io.Writer
}

// OnTrip implements TripAdapter.
func (l *LogOnly) OnTrip(_ context.Context, e Event) error {
	line, err := json.Marshal(map[string]string{
		"event": e.Type, "scope": e.Scope.String(), "epoch": strconv.FormatUint(e.Epoch, 10),
		"trigger": e.Trigger, "reason": e.Reason, "ts": e.TS.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.W.Write(append(line, '\n'))
	return err
}

// ExecHook runs an operator-owned program on each trip, with no shell and
// no arguments. The trip is passed in the environment (GATE_SCOPE_KIND,
// GATE_SCOPE_VALUE, GATE_EPOCH, GATE_TRIGGER, GATE_REASON, GATE_TS) and
// nothing else is inherited except PATH=/usr/bin:/bin.
type ExecHook struct {
	Path    string        // absolute path to the program
	Timeout time.Duration // default 10s
}

// ErrHookPath rejects a relative hook path, which would resolve against the
// gate's working directory.
var ErrHookPath = errors.New("exec hook path must be absolute")

// OnTrip implements TripAdapter.
func (h ExecHook) OnTrip(ctx context.Context, e Event) error {
	if !filepath.IsAbs(h.Path) {
		return ErrHookPath
	}
	to := h.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"GATE_SCOPE_KIND=" + e.Scope.Kind,
		"GATE_SCOPE_VALUE=" + e.Scope.Value,
		"GATE_EPOCH=" + strconv.FormatUint(e.Epoch, 10),
		"GATE_TRIGGER=" + e.Trigger,
		"GATE_REASON=" + e.Reason,
		"GATE_TS=" + e.TS.UTC().Format(time.RFC3339Nano),
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		if len(out) > 512 {
			out = out[:512]
		}
		return fmt.Errorf("trip hook %s: %w: %s", h.Path, err, out)
	}
	return nil
}
