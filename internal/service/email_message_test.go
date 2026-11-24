package service

import (
	"mime"
	"net/mail"
	"strings"
	"testing"
)

// headerLines returns the message's header lines (up to the blank line).
func headerLines(t *testing.T, msg []byte) []string {
	t.Helper()
	head, _, ok := strings.Cut(string(msg), "\r\n\r\n")
	if !ok {
		t.Fatalf("no header/body separator in %q", msg)
	}
	return strings.Split(head, "\r\n")
}

func TestBuildEmailMessage_HeadersAndBody(t *testing.T) {
	rcpt, msg, err := buildEmailMessage("Socrate", "noreply@example.com", "Ada <ada@example.com>",
		"Welcome to Café App", `<a href="https://x/?t=abc">go</a>`)
	if err != nil {
		t.Fatal(err)
	}
	if rcpt != "ada@example.com" {
		t.Fatalf("envelope recipient %q, want ada@example.com", rcpt)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatalf("not a parseable message: %v", err)
	}
	if got := m.Header.Get("To"); got != "<ada@example.com>" {
		t.Errorf("To %q", got)
	}
	if got := m.Header.Get("From"); got != `"Socrate" <noreply@example.com>` {
		t.Errorf("From %q", got)
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || subj != "Welcome to Café App" {
		t.Errorf("Subject decodes to %q (%v)", subj, err)
	}
	if got := m.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
		t.Errorf("Content-Transfer-Encoding %q", got)
	}
}

// A line break in the subject (e.g. from an application name) cannot add a
// header: it is carried inside an encoded-word.
func TestBuildEmailMessage_SubjectCannotInjectHeaders(t *testing.T) {
	_, msg, err := buildEmailMessage("", "noreply@example.com", "ada@example.com",
		"Welcome to Evil\r\nBcc: victim@example.com", "<p>hi</p>")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range headerLines(t, msg) {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") {
			t.Fatalf("injected header line %q", l)
		}
	}
	m, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Bcc") != "" {
		t.Fatal("a Bcc header was injected")
	}
}

// The From display name is encoded too.
func TestBuildEmailMessage_FromNameCannotInjectHeaders(t *testing.T) {
	_, msg, err := buildEmailMessage("Evil\r\nBcc: victim@example.com", "noreply@example.com", "ada@example.com", "s", "b")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range headerLines(t, msg) {
		if strings.HasPrefix(strings.ToLower(l), "bcc:") {
			t.Fatalf("injected header line %q", l)
		}
	}
}

// A recipient or sender that is not a single valid address is refused.
func TestBuildEmailMessage_RefusesBadAddresses(t *testing.T) {
	for _, tc := range []struct{ from, to string }{
		{"noreply@example.com", "ada@example.com\r\nBcc: victim@example.com"},
		{"noreply@example.com", "ada@example.com, eve@example.com"},
		{"noreply@example.com", "not an address"},
		{"noreply@example.com", ""},
		{"noreply@example.com\r\nBcc: victim@example.com", "ada@example.com"},
	} {
		if _, _, err := buildEmailMessage("", tc.from, tc.to, "s", "b"); err == nil {
			t.Errorf("from %q to %q: accepted", tc.from, tc.to)
		}
	}
}
