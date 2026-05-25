// Package sgail implements the opt-in SGAIL remote sync client.
// Nothing leaves the machine unless the user explicitly sets SGAILEnabled=true.
//
// Deprecated: SGAIL remote sync is superseded by the gossip peer mesh
// (internal/gossip). This package remains functional for one release to allow
// operators to migrate. It will be removed in the next major release.
// See docs/migrating-from-sgail-sync.md for the migration guide.
package sgail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultTimeout = 30 * time.Second
	maxRespBody    = 4 << 10 // 4 KiB
)

// Client sends encrypted log data to a remote SGAIL server.
type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

// NewClient creates a new SGAIL sync client.
func NewClient(endpoint, token string) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &Client{
		endpoint: endpoint,
		token:    token,
		http:     &http.Client{Timeout: defaultTimeout, Transport: transport},
	}
}

// Push sends encrypted log bytes to the SGAIL server.
// logData is the raw encrypted log — never plaintext.
func (c *Client) Push(machineID, genesisHash string, logData []byte) error {
	url := c.endpoint + "/api/v1/witness/sync"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(logData))
	if err != nil {
		return fmt.Errorf("sgail push: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Machine-ID", machineID)
	req.Header.Set("X-Genesis-Hash", genesisHash)
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	c.setAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("sgail push: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("sgail push: server %d: %s", resp.StatusCode, body)
	}
	return nil
}

// Death sends an emergency death broadcast to the SGAIL server.
// Called with a short deadline — must return quickly.
func (c *Client) Death(machineID string, logData []byte, deadline time.Duration) error {
	url := c.endpoint + "/api/v1/witness/death"
	client := &http.Client{Timeout: deadline, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(logData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Machine-ID", machineID)
	req.Header.Set("X-Event", "death-broadcast")
	c.setAuth(req)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Ping checks connectivity to the SGAIL server.
func (c *Client) Ping() error {
	url := c.endpoint + "/api/v1/witness/ping"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sgail ping: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}
