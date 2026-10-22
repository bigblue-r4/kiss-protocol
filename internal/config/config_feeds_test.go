package config

import (
	"strings"
	"testing"
)

func TestValidateEventFeeds(t *testing.T) {
	ok := Config{EventFeeds: []EventFeed{{"/var/log/exp1/dispatch.jsonl", "exp1-dispatch"}, {"/var/log/exp1/egress.jsonl", "exp1-egress"}}}
	if err := ok.ValidateEventFeeds(); err != nil {
		t.Fatal(err)
	}
	for want, feeds := range map[string][]EventFeed{
		"path is empty":       {{"", "a"}},
		"must match":          {{"/x", "Bad Name"}},
		"reserved":            {{"/x", "witness"}},
		"used twice":          {{"/x", "a"}, {"/y", "a"}},
		"path /x/ used twice": {{"/x", "a"}, {"/x/", "b"}},
	} {
		err := (&Config{EventFeeds: feeds}).ValidateEventFeeds()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want %q", feeds, err, want)
		}
	}
}
