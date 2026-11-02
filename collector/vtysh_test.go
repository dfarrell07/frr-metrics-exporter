// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vtysh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVtyshRunner(t *testing.T) {
	path := script(t, `echo "out:$2"; echo oops >&2; exit 0`)
	out, err := (Vtysh{Path: path}).Run(context.Background(), "show x")
	if err != nil || string(out) != "out:show x\n" {
		t.Errorf("out %q, err %v", out, err)
	}
	path = script(t, `echo "% No such command" >&2; exit 1`)
	if _, err := (Vtysh{Path: path}).Run(context.Background(), "show y"); err == nil || !strings.Contains(err.Error(), "No such command") {
		t.Errorf("error should carry stderr, got %v", err)
	}
}

func TestVtyshIgnoresLongStderrOnSuccess(t *testing.T) {
	path := script(t, `head -c 100000 /dev/zero | tr '\0' w >&2; echo '{}'`)
	out, err := (Vtysh{Path: path}).Run(context.Background(), "show x")
	if err != nil || string(out) != "{}\n" {
		t.Errorf("out %q, err %v", out, err)
	}
}

func TestVtyshRejectsOversizedOutput(t *testing.T) {
	path := script(t, `head -c 5000 /dev/zero | tr '\0' x`)
	if _, err := (Vtysh{Path: path, MaxOutput: 1000}).Run(context.Background(), "show x"); err == nil {
		t.Error("oversized output accepted")
	}
}

func TestVtyshDeadlineKillsHungChild(t *testing.T) {
	// The script's child keeps the output pipe open after the script is killed.
	path := script(t, `sleep 30 & wait`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (Vtysh{Path: path}).Run(ctx, "show z")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("err %v after %v", err, time.Since(start))
	}
}
