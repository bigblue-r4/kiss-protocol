package gossip

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// FuzzDecodePacket fuzzes the wire-packet decoder with arbitrary bytes.
// Must not panic regardless of input.
func FuzzDecodePacket(f *testing.F) {
	// Valid-ish packets: magic + paylen + payload + 64-byte sig.
	validPkt := func(payload []byte) []byte {
		buf := make([]byte, 8+len(payload)+64)
		binary.BigEndian.PutUint32(buf[0:], packetMagic)
		binary.BigEndian.PutUint32(buf[4:], uint32(len(payload)))
		copy(buf[8:], payload)
		return buf
	}
	f.Add(validPkt([]byte(`{"type":"heartbeat"}`)))
	f.Add(validPkt([]byte{}))
	f.Add([]byte{})
	f.Add([]byte("\x57\x49\x54\x53"))                 // magic only
	f.Add([]byte("\x00\x00\x00\x00\xff\xff\xff\xff")) // magic + huge paylen
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _, _ = decodePacket(data)
	})
}

// FuzzHeartbeatJSON fuzzes JSON unmarshaling of heartbeat messages.
func FuzzHeartbeatJSON(f *testing.F) {
	f.Add([]byte(`{"type":"heartbeat","peer_id":"aa","seq":1,"ts":"2026-01-01T00:00:00Z","nonce":"bb"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Build a fake packet wrapping data as payload.
		pkt := make([]byte, 8+len(data)+64)
		binary.BigEndian.PutUint32(pkt[0:], packetMagic)
		binary.BigEndian.PutUint32(pkt[4:], uint32(len(data)))
		copy(pkt[8:], data)

		payload, _, err := decodePacket(pkt)
		if err != nil {
			return
		}
		// Unmarshal the heartbeat message — must not panic.
		var msg heartbeatMsg
		_ = json.Unmarshal(payload, &msg)
	})
}
