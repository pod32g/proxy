package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecretFromFile(t *testing.T) {
	// A trailing newline is what `echo secret > file` produces, and a credential
	// carrying one fails in a way that looks like a wrong password.
	for _, tc := range []struct{ name, content, want string }{
		{"plain", "s3cret", "s3cret"},
		{"trailing newline", "s3cret\n", "s3cret"},
		{"crlf", "s3cret\r\n", "s3cret"},
		{"internal spaces kept", "a secret with spaces\n", "a secret with spaces"},
		{"leading space kept", " leading", " leading"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SecretFromFile(writeFile(t, "s", tc.content, 0o600))
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// An empty or missing file must fail loudly. Continuing with "" would, with
// -auth enabled, reproduce exactly the fail-open condition PROXY-3 fixed.
func TestSecretFromFileRejectsEmptyAndMissing(t *testing.T) {
	if _, err := SecretFromFile(writeFile(t, "empty", "", 0o600)); err == nil {
		t.Error("empty file accepted")
	}
	if _, err := SecretFromFile(writeFile(t, "newline", "\n", 0o600)); err == nil {
		t.Error("whitespace-only file accepted")
	}
	if _, err := SecretFromFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := SecretFromFile(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
	// The error must name the path; an operator debugging a failed start has
	// only this line to work from.
	_, err := SecretFromFile(writeFile(t, "empty2", "", 0o600))
	if !strings.Contains(err.Error(), "empty2") {
		t.Errorf("error does not name the file: %v", err)
	}
}

func TestFileIsWorldReadable(t *testing.T) {
	if FileIsWorldReadable(writeFile(t, "tight", "x", 0o600)) {
		t.Error("0600 reported as world-readable")
	}
	if !FileIsWorldReadable(writeFile(t, "loose", "x", 0o644)) {
		t.Error("0644 not reported as world-readable")
	}
	if FileIsWorldReadable(filepath.Join(t.TempDir(), "absent")) {
		t.Error("missing file reported as world-readable")
	}
}
