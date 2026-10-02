package pipelock

// OpenEvent maps where a tailer started reading to a witness log entry, so the
// record itself shows a restart and how much was caught up. A file replaced or
// truncated while the witness was down is a WARN: whatever was unread in the old
// file is gone, and the evidence should say so.
func OpenEvent(feed string, i OpenInfo) (level, event string, data map[string]interface{}) {
	data = map[string]interface{}{
		"feed":           feed,
		"mode":           i.Mode,
		"from":           i.From,
		"file_size":      i.FileSize,
		"catch_up_bytes": i.FileSize - i.From,
	}
	level = "INFO"
	if i.Mode == "restarted" {
		level = "WARN"
	}
	return level, "tail_" + i.Mode, data
}
