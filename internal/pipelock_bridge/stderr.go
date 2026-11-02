package pipelock_bridge

import (
	"regexp"
	"strings"
)

// stderrLevels grades pipelock's stderr lines for the witness log.
//
// Every line used to be logged as WARN, so pipelock's startup banner (about 14
// lines on each start) buried the lines that matter, such as a receipt chain
// that cannot be resumed. Lines are now graded by what they say:
//
//   - ERROR: the line says ERROR, error, fatal or panic.
//   - WARN:  the line starts with WARNING/WARN, or is not a known banner line.
//     An unrecognised line stays WARN so a new diagnostic is never quieted.
//   - INFO:  a known banner line: "Pipelock vX starting", "Pipelock stopped.",
//     or a two-space indented "Key: value" field line.
//
// A line indented by four or more spaces continues the line before it and takes
// its level, so the second line of a multi-line ERROR is still an ERROR.
//
// Not safe for concurrent use; the runner calls the stderr sink from one
// goroutine.
type stderrLevels struct {
	prev string
}

var (
	reErrorWord   = regexp.MustCompile(`\bERROR\b`)
	reErrorPrefix = regexp.MustCompile(`(?i)^\s*(error|fatal|panic)\b`)
	reWarnPrefix  = regexp.MustCompile(`(?i)^\s*warn(ing)?\b`)
	reBannerStart = regexp.MustCompile(`^Pipelock v\S+ starting$`)
	reBannerStop  = regexp.MustCompile(`^Pipelock stopped\.?$`)
	reBannerField = regexp.MustCompile(`^  [A-Z][A-Za-z0-9 ]*: `)
)

// level returns the witness log level for one stderr line.
func (c *stderrLevels) level(line string) string {
	lvl := classifyStderr(line)
	if c.prev != "" && strings.HasPrefix(line, "    ") && lvl != "ERROR" {
		lvl = c.prev
	}
	c.prev = lvl
	return lvl
}

func classifyStderr(line string) string {
	switch {
	case reErrorWord.MatchString(line), reErrorPrefix.MatchString(line):
		return "ERROR"
	case reWarnPrefix.MatchString(line):
		return "WARN"
	case reBannerStart.MatchString(line), reBannerStop.MatchString(line),
		reBannerField.MatchString(line):
		return "INFO"
	}
	return "WARN"
}
