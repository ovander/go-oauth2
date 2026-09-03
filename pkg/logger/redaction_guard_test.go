package logger

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// B3 redaction-at-source guard: no log call in the tree may pass a secret-
// bearing expression as an argument. Field NAMES like "password_changed" are
// fine; the guard looks for expressions that evaluate to the secret itself.
func TestNoSecretsReachTheLogger(t *testing.T) {
	root := repoRoot(t)
	logCall := regexp.MustCompile(`(?i)\blog(ger)?\.(Logger\.)?(With\w*\([^)]*\)\.)?(Trace|Debug|Info|Warn|Warning|Error|Fatal|Panic)f?\(`)
	secretArg := regexp.MustCompile(`(?i)(\.|\b)(AccessToken|RefreshToken|IDToken|ClientSecret|HashedPassword|Password|Secret|Authorization|PrivateKey|MFASecret|CodeVerifier|code_verifier|client_secret|refresh_token|access_token)\b\s*[,)\]]`)
	fieldValue := regexp.MustCompile(`(?i)"[a-z_]+":\s*(req|r|in|user|app|claims|resp|tokenSet|ts)\.(AccessToken|RefreshToken|IDToken|ClientSecret|HashedPassword|Password|Secret|MFASecret|CodeVerifier)\b`)

	var offenders []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !logCall.MatchString(line) && !fieldValue.MatchString(line) {
				continue
			}
			if secretArg.MatchString(line) || fieldValue.MatchString(line) {
				rel, _ := filepath.Rel(root, p)
				offenders = append(offenders, rel+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("log statements that appear to carry a secret:\n  %s", strings.Join(offenders, "\n  "))
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found above the test directory")
	return ""
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
