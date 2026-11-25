package adversarial

import "testing"

func TestAdversarialSuite(t *testing.T) {
	out, err := Run(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(Cases()) {
		t.Fatalf("%d outcomes for %d cases", len(out), len(Cases()))
	}
	for _, o := range out {
		if !o.Pass {
			t.Errorf("%s (%s): expected %s, got %s: %s", o.ID, o.Attack, o.Expect, o.Got, o.Summary)
		} else {
			t.Logf("%-32s %-12s %s", o.ID, o.Got, o.Summary)
		}
	}
}
