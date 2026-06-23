package cmd

import (
	"testing"

	"github.com/svn-arv/redacted/internal/patterns"
)

func TestCheckPatterns_PanicReportsFailure(t *testing.T) {
	orig := patternsNew
	patternsNew = func(...patterns.Option) *patterns.Scrubber { panic("boom") }
	defer func() { patternsNew = orig }()

	c := checkPatterns()
	if c.status != statusFail {
		t.Errorf("panic should report a failed check, got status %v (name %q)", c.status, c.name)
	}
	if c.name != "patterns load" {
		t.Errorf("expected check name %q, got %q", "patterns load", c.name)
	}
}
