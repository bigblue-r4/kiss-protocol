// Package evidence manages the PD evidence catalog and tamper-evident audit log.
package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bigblue-r4/kiss-protocol/internal/store"
)

// Item is a tracked evidence item.
type Item struct {
	ID          string    `json:"id"`
	CaseNumber  string    `json:"case_number"`
	Description string    `json:"description"`
	Category    string    `json:"category"` // narcotics, firearms, digital_media, documents, other
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	LegalHold   bool      `json:"legal_hold"`
	HoldReason  string    `json:"hold_reason,omitempty"`
	Status      string    `json:"status"` // active, transferred, destroyed
	CurrentNode string    `json:"current_node"`
}

// CustodyEvent is one step in the chain of custody, stored in the tamper-evident log.
type CustodyEvent struct {
	ItemID     string    `json:"item_id"`
	CaseNumber string    `json:"case_number"`
	EventType  string    `json:"event_type"` // intake, transfer, access, hold_set, hold_release, export, destroyed
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	FromNode   string    `json:"from_node,omitempty"`
	ToNode     string    `json:"to_node,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	ExportRef  string    `json:"export_ref,omitempty"`
}

const catalogFile = "pd-items.json"

// PDStore manages the PD evidence catalog and audit log.
type PDStore struct {
	store *store.Store
	key   []byte
	dir   string
	mu    sync.RWMutex
	items map[string]*Item
}

// Open opens or creates the PD store at dir.
func Open(dir string, key []byte) (*PDStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s, err := store.Open(dir, key)
	if err != nil {
		return nil, err
	}
	pd := &PDStore{
		store: s,
		key:   key,
		dir:   dir,
		items: make(map[string]*Item),
	}
	if err := pd.loadCatalog(); err != nil {
		return nil, err
	}
	return pd, nil
}

// Close flushes and closes the store.
func (pd *PDStore) Close() error {
	return pd.store.Close()
}

// RecordIntake creates a new evidence item and logs the intake event.
func (pd *PDStore) RecordIntake(item *Item, actor string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	id, err := newItemID()
	if err != nil {
		return err
	}
	item.ID = id
	item.CreatedAt = time.Now().UTC()
	item.CreatedBy = actor
	item.Status = "active"
	pd.items[id] = item

	if err := pd.saveCatalog(); err != nil {
		return err
	}
	ev := CustodyEvent{
		ItemID:     id,
		CaseNumber: item.CaseNumber,
		EventType:  "intake",
		Timestamp:  item.CreatedAt,
		Actor:      actor,
		ToNode:     item.CurrentNode,
		Notes:      item.Description,
	}
	return pd.store.Append("INFO", "pd/intake", "pd", ev)
}

// RecordTransfer transfers an item to a new node/custodian.
func (pd *PDStore) RecordTransfer(itemID, actor, fromNode, toNode, notes string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	item, ok := pd.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	if item.LegalHold {
		return fmt.Errorf("item %s is under legal hold — release hold before transfer", itemID)
	}
	caseNum := item.CaseNumber
	item.CurrentNode = toNode
	if err := pd.saveCatalog(); err != nil {
		return err
	}
	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "transfer",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		FromNode:   fromNode,
		ToNode:     toNode,
		Notes:      notes,
	}
	return pd.store.Append("INFO", "pd/transfer", "pd", ev)
}

// RecordAccess logs that an item was accessed (viewed or examined).
func (pd *PDStore) RecordAccess(itemID, actor, notes string) error {
	pd.mu.RLock()
	caseNum := pd.caseNumberFor(itemID)
	pd.mu.RUnlock()

	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "access",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Notes:      notes,
	}
	return pd.store.Append("INFO", "pd/access", "pd", ev)
}

// SetLegalHold places a legal hold on an item.
func (pd *PDStore) SetLegalHold(itemID, actor, reason string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	item, ok := pd.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	item.LegalHold = true
	item.HoldReason = reason
	caseNum := item.CaseNumber
	if err := pd.saveCatalog(); err != nil {
		return err
	}
	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "hold_set",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Notes:      reason,
	}
	return pd.store.Append("WARN", "pd/hold_set", "pd", ev)
}

// ReleaseLegalHold removes a legal hold from an item.
func (pd *PDStore) ReleaseLegalHold(itemID, actor, notes string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	item, ok := pd.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	item.LegalHold = false
	item.HoldReason = ""
	caseNum := item.CaseNumber
	if err := pd.saveCatalog(); err != nil {
		return err
	}
	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "hold_release",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Notes:      notes,
	}
	return pd.store.Append("INFO", "pd/hold_release", "pd", ev)
}

// RecordExport logs that a court export bundle was generated for an item.
func (pd *PDStore) RecordExport(itemID, actor, exportRef string) error {
	pd.mu.RLock()
	caseNum := pd.caseNumberFor(itemID)
	pd.mu.RUnlock()

	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "export",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ExportRef:  exportRef,
	}
	return pd.store.Append("INFO", "pd/export", "pd", ev)
}

// RecordDestroyed marks an item as destroyed.
func (pd *PDStore) RecordDestroyed(itemID, actor, notes string) error {
	pd.mu.Lock()
	defer pd.mu.Unlock()

	item, ok := pd.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	if item.LegalHold {
		return fmt.Errorf("item %s is under legal hold — cannot destroy", itemID)
	}
	item.Status = "destroyed"
	caseNum := item.CaseNumber
	if err := pd.saveCatalog(); err != nil {
		return err
	}
	ev := CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "destroyed",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Notes:      notes,
	}
	return pd.store.Append("WARN", "pd/destroyed", "pd", ev)
}

// AppendSystem logs a system-level event (init, start, etc.).
func (pd *PDStore) AppendSystem(level, event, notes string) error {
	return pd.store.Append(level, event, "pd-system", map[string]string{"notes": notes})
}

// GetItem returns the current state of an item (copy, safe to modify).
func (pd *PDStore) GetItem(itemID string) (*Item, bool) {
	pd.mu.RLock()
	defer pd.mu.RUnlock()
	item, ok := pd.items[itemID]
	if !ok {
		return nil, false
	}
	cp := *item
	return &cp, true
}

// GetItems returns all items, optionally filtered by case number.
func (pd *PDStore) GetItems(caseNumber string) []*Item {
	pd.mu.RLock()
	defer pd.mu.RUnlock()
	var out []*Item
	for _, item := range pd.items {
		if caseNumber == "" || item.CaseNumber == caseNumber {
			cp := *item
			out = append(out, &cp)
		}
	}
	return out
}

// GetAllEvents decrypts and returns all audit log entries.
func (pd *PDStore) GetAllEvents() ([]store.Entry, error) {
	return store.ReadAll(pd.dir, pd.key)
}

func (pd *PDStore) caseNumberFor(itemID string) string {
	if item, ok := pd.items[itemID]; ok {
		return item.CaseNumber
	}
	return ""
}

func (pd *PDStore) loadCatalog() error {
	path := filepath.Join(pd.dir, catalogFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &pd.items)
}

func (pd *PDStore) saveCatalog() error {
	path := filepath.Join(pd.dir, catalogFile)
	data, err := json.MarshalIndent(pd.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// newItemID generates an ID in the form EV-20260512-a3b2c1d0.
func newItemID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("EV-%s-%s", time.Now().UTC().Format("20060102"), hex.EncodeToString(b[:])), nil
}
