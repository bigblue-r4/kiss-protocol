// Package death records local death evidence without copying the log or genesis.
// Cross-node death notification remains the enforcer's responsibility.
package death

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const broadcastDeadline = 8 * time.Second

// Hash describes a whole captured file prefix, never a digest of a partial read.
type Hash struct {
	Status string `json:"status"` // complete, incomplete (deadline), or error
	SHA256 string `json:"sha256,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Record preserves the signed head as stored; it does not create a new signature.
type Record struct {
	Format        string          `json:"format"`
	Timestamp     string          `json:"timestamp"`
	Trigger       string          `json:"trigger"`
	MachineID     string          `json:"machine_id"`
	TreeHead      json.RawMessage `json:"tree_head"`
	TreeHeadError string          `json:"tree_head_error,omitempty"`
	LogBytes      int64           `json:"log_bytes"` // -1 if stat failed
	LogHash       Hash            `json:"log_hash"`
	GenesisHash   Hash            `json:"genesis_hash"`
}

// Broadcaster writes small, atomic death records in the primary directory.
type Broadcaster struct {
	primaryDir string
	machineID  string
}

func New(primaryDir, machineID string) *Broadcaster {
	return &Broadcaster{primaryDir: primaryDir, machineID: machineID}
}

// Fire reserves part of the deadline for publishing the record. Cancellation
// stops hashing between reads; a stalled filesystem syscall cannot be interrupted
// portably. Hash workers never write files, even if a read outlives this call.
// Atomic publication and fsync finish synchronously rather than abandoning a write.
func (b *Broadcaster) Fire(trigger string) error {
	ctx, cancel := context.WithTimeout(context.Background(), broadcastDeadline-500*time.Millisecond)
	defer cancel()
	return b.fire(ctx, trigger)
}

func (b *Broadcaster) fire(ctx context.Context, trigger string) error {
	r := Record{Format: "witness-death/1", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Trigger: trigger, MachineID: b.machineID, LogBytes: -1}
	head, err := os.ReadFile(filepath.Join(b.primaryDir, "tree-head.json"))
	if err != nil {
		r.TreeHeadError = err.Error()
	} else if !json.Valid(head) {
		r.TreeHeadError = "tree-head.json is not valid JSON"
	} else {
		r.TreeHead = json.RawMessage(head)
	}
	logPath := filepath.Join(b.primaryDir, "witness.log")
	st, statErr := os.Stat(logPath)
	if statErr == nil {
		r.LogBytes = st.Size()
	}
	// Genesis is small and immutable; hash it first so a large log cannot starve it.
	r.GenesisHash = hashFile(ctx, filepath.Join(b.primaryDir, "genesis.enc"), -1)
	if statErr != nil {
		r.LogHash = Hash{Status: "error", Error: statErr.Error()}
	} else {
		r.LogHash = hashFile(ctx, logPath, r.LogBytes)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicRecord(b.primaryDir, append(data, '\n'))
}

// hashFile uses bounded memory and hashes exactly size bytes (or EOF for size -1).
// The buffered result lets a cancelled worker finish without blocking or writing.
func hashFile(ctx context.Context, path string, size int64) Hash {
	if ctx.Err() != nil {
		return Hash{Status: "incomplete"}
	}
	result := make(chan Hash, 1)
	go func() {
		f, err := os.Open(path)
		if err != nil {
			result <- Hash{Status: "error", Error: err.Error()}
			return
		}
		defer f.Close()
		var reader io.Reader = f
		if size >= 0 {
			reader = io.LimitReader(f, size)
		}
		sum, err := streamHash(ctx, reader, size)
		if err != nil {
			if ctx.Err() != nil {
				result <- Hash{Status: "incomplete"}
			} else {
				result <- Hash{Status: "error", Error: err.Error()}
			}
			return
		}
		result <- Hash{Status: "complete", SHA256: sum}
	}()
	select {
	case h := <-result:
		return h
	case <-ctx.Done():
		return Hash{Status: "incomplete"}
	}
}

func streamHash(ctx context.Context, r io.Reader, size int64) (string, error) {
	h := sha256.New()
	buf := make([]byte, 64*1024)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := r.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if size >= 0 && total != size {
		return "", io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func atomicRecord(dir string, data []byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// The random suffix prevents collisions between concurrent daemon/watchdog deaths.
	f, err := os.CreateTemp(dir, ".death_"+time.Now().UTC().Format("20060102T150405.000000000Z")+"_*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dest := filepath.Join(dir, filepath.Base(tmp)[1:]+".json")
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync death record directory: %w", err)
	}
	return nil
}
