package checkpoint

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/bigblue-r4/kiss-protocol/pkg/tlog"
)

// MaxProofLines is the tlog-witness limit on consistency proof lines.
const MaxProofLines = 63

// ConflictError is a 409 from a witness: its latest cosigned size for the
// origin is Size, not the old size the client sent.
type ConflictError struct{ Size uint64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("witness: conflict, witness holds size %d", e.Size)
}

// WitnessError is any other non-200 answer.
type WitnessError struct {
	Status int
	Body   string
}

func (e *WitnessError) Error() string {
	meaning := map[int]string{
		400: "bad request (old size larger than the checkpoint)",
		403: "the witness does not accept the log signature",
		404: "the witness does not know this origin",
		422: "consistency proof rejected: the checkpoint does not extend what the witness saw",
	}[e.Status]
	if meaning == "" {
		meaning = http.StatusText(e.Status)
	}
	return fmt.Sprintf("witness: HTTP %d, %s", e.Status, meaning)
}

// AddCheckpointBody builds a tlog-witness add-checkpoint request body.
func AddCheckpointBody(oldSize uint64, proof []tlog.Hash, signedCheckpoint []byte) ([]byte, error) {
	if len(proof) > MaxProofLines {
		return nil, errors.New("witness: consistency proof longer than 63 hashes")
	}
	var b bytes.Buffer
	b.WriteString("old " + strconv.FormatUint(oldSize, 10) + "\n")
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n")
	b.Write(signedCheckpoint)
	return b.Bytes(), nil
}

// AddCheckpoint submits a signed checkpoint with a consistency proof from
// oldSize to a tlog-witness at submitURL (its submission prefix) and returns
// the cosignature lines it answers with. It does not verify them: the
// caller checks them against the witness's pinned key.
func AddCheckpoint(ctx context.Context, hc *http.Client, submitURL string, oldSize uint64, proof []tlog.Hash, signedCheckpoint []byte) ([]SigLine, error) {
	body, err := AddCheckpointBody(oldSize, proof, signedCheckpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(submitURL, "/")+"/add-checkpoint", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/x.tlog.size") {
			return nil, &WitnessError{Status: resp.StatusCode, Body: string(data)}
		}
		size, err := parseDecimal(strings.TrimSuffix(string(data), "\n"))
		if err != nil {
			return nil, &WitnessError{Status: resp.StatusCode, Body: string(data)}
		}
		return nil, &ConflictError{Size: size}
	default:
		return nil, &WitnessError{Status: resp.StatusCode, Body: string(data)}
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("witness: response is not newline-terminated signature lines")
	}
	var out []SigLine
	for _, line := range strings.Split(string(data[:len(data)-1]), "\n") {
		l, err := parseSigLine(line)
		if err != nil {
			return nil, fmt.Errorf("witness: response: %w", err)
		}
		out = append(out, l)
	}
	return out, nil
}

// ParseAddCheckpointBody parses a request body (for witness implementations
// and tests).
func ParseAddCheckpointBody(body []byte) (oldSize uint64, proof []tlog.Hash, signed []byte, err error) {
	line, rest, ok := bytes.Cut(body, []byte("\n"))
	if !ok || !bytes.HasPrefix(line, []byte("old ")) {
		return 0, nil, nil, errors.New("missing old size line")
	}
	if oldSize, err = parseDecimal(string(line[4:])); err != nil {
		return 0, nil, nil, err
	}
	for {
		line, rest, ok = bytes.Cut(rest, []byte("\n"))
		if !ok {
			return 0, nil, nil, errors.New("missing blank line")
		}
		if len(line) == 0 {
			break
		}
		h, err := DecodeHash(string(line))
		if err != nil {
			return 0, nil, nil, err
		}
		proof = append(proof, h)
		if len(proof) > MaxProofLines {
			return 0, nil, nil, errors.New("proof too long")
		}
	}
	return oldSize, proof, rest, nil
}
