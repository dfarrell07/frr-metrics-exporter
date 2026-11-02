// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	path := script(t, `echo "$@"; echo oops >&2; exit 0`)
	for command, daemon := range map[string]string{
		bgpCmd: "bgpd", peersCmd: "bfdd", countersCmd: "bfdd", "show evpn vni json": "zebra", esCmd: "zebra",
	} {
		out, err := (Vtysh{Path: path}).Run(context.Background(), command)
		if err != nil || string(out) != "-d "+daemon+" -c "+command+"\n" {
			t.Errorf("%s: out %q, err %v", command, out, err)
		}
	}
	path = script(t, `echo "% No such command" >&2; exit 1`)
	if _, err := (Vtysh{Path: path}).Run(context.Background(), bgpCmd); err == nil || !strings.Contains(err.Error(), "No such command") {
		t.Errorf("error should carry stderr, got %v", err)
	}
	if _, err := (Vtysh{Path: path}).Run(context.Background(), "configure terminal"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("unsupported command: %v", err)
	}
}

func TestVtyshIgnoresLongStderrOnSuccess(t *testing.T) {
	path := script(t, `head -c 100000 /dev/zero | tr '\0' w >&2; echo '{}'`)
	out, err := (Vtysh{Path: path}).Run(context.Background(), bgpCmd)
	if err != nil || string(out) != "{}\n" {
		t.Errorf("out %q, err %v", out, err)
	}
}

func TestVtyshRejectsOversizedOutput(t *testing.T) {
	path := script(t, `head -c 5000 /dev/zero | tr '\0' x`)
	if _, err := (Vtysh{Path: path, MaxOutput: 1000}).Run(context.Background(), bgpCmd); err == nil {
		t.Error("oversized output accepted")
	}
}

func TestVtyshDeadlineKillsAndReapsProcess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pid")
	t.Setenv("FRR_TEST_PID_FILE", marker)
	path := script(t, "echo $$ > \"$FRR_TEST_PID_FILE\"\nexec sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (Vtysh{Path: path}).Run(ctx, bgpCmd)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	var pid int
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Sscan(string(data), &pid); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatalf("direct child %d still exists after Run: %v", pid, err)
	}
}

func TestVtyshBoundsWaitForInheritedPipe(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pid")
	t.Setenv("FRR_TEST_PID_FILE", marker)
	path := script(t, "sleep 30 &\necho $! > \"$FRR_TEST_PID_FILE\"\nwait")
	// WaitDelay bounds inherited pipes; it does not kill descendants. Clean up the
	// test's background sleep separately, including when an assertion fails.
	defer func() {
		data, err := os.ReadFile(marker)
		if err != nil {
			t.Error(err)
			return
		}
		var pid int
		if _, err := fmt.Sscan(string(data), &pid); err != nil {
			t.Error(err)
			return
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (Vtysh{Path: path}).Run(ctx, bgpCmd)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}
