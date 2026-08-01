package config

import (
	"fmt"
	"os"
	"strings"
)

// SecretFromFile reads a secret from path.
//
// Passing a secret as a flag puts it in /proc/<pid>/cmdline and therefore in
// the output of `ps` for every local user, as well as in shell history and any
// process-monitoring agent. The environment is only marginally better:
// /proc/<pid>/environ is readable the same way and crash reporters routinely
// capture it. A file the operator controls the permissions of is the shape
// Docker and Kubernetes secrets already take.
//
// An unreadable or empty file is an error rather than an empty secret. That is
// the whole point: silently continuing with "" would, with -auth enabled, be
// the fail-open condition this codebase already had to fix once.
func SecretFromFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("reading %s: is a directory", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	// Trailing newlines are near-universal in secret files — `echo` writes one,
	// and so does every editor — and a credential with a stray \n fails in a way
	// that looks like a wrong password.
	secret := strings.TrimRight(string(data), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("reading %s: file is empty", path)
	}
	return secret, nil
}

// FileIsWorldReadable reports whether others can read the file, so the caller
// can say so. It is a warning rather than an error: the permissions may be
// deliberate, and refusing to start over them would be worse than the risk.
func FileIsWorldReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o004 != 0
}
