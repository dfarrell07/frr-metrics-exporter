// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultMaxOutput is the largest reply Vtysh accepts from one command.
const DefaultMaxOutput = 32 << 20

const killWaitTime = time.Second

// Vtysh runs commands with a local vtysh. Cancelling the context kills the
// process; a short wait delay bounds the wait if a child still holds the output
// pipe. Standard error is kept apart from standard output, which FRR's JSON
// must not be mixed with, and only adds context to an error.
type Vtysh struct {
	Path      string // for example /usr/bin/vtysh
	MaxOutput int    // 0 means DefaultMaxOutput
}

// Run implements Runner.
func (v Vtysh) Run(ctx context.Context, command string) ([]byte, error) {
	// Connecting to every daemon lets one unresponsive daemon stall unrelated
	// collectors during vtysh initialization. These commands each have one owner.
	var daemon string
	switch {
	case strings.HasPrefix(command, "show bgp "):
		daemon = "bgpd"
	case strings.HasPrefix(command, "show bfd "):
		daemon = "bfdd"
	case strings.HasPrefix(command, "show evpn "):
		daemon = "zebra"
	default:
		return nil, fmt.Errorf("unsupported vtysh command %q", command)
	}
	cmd := exec.CommandContext(ctx, v.Path, "-d", daemon, "-c", command) // #nosec G204 -- fixed commands from this package
	cmd.WaitDelay = killWaitTime
	limit := v.MaxOutput
	if limit == 0 {
		limit = DefaultMaxOutput
	}
	out, errOut := &limitBuffer{max: limit}, &limitBuffer{max: 4096, truncate: true}
	cmd.Stdout, cmd.Stderr = out, errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, fmt.Errorf("%q: %w: %s", command, err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}

// limitBuffer keeps at most max bytes. Beyond that it fails the write, or with
// truncate silently drops the excess (for stderr, which only adds context to
// an error and must not fail a command that succeeded). It does not embed
// bytes.Buffer: the promoted ReadFrom would let io.Copy bypass Write and the limit.
type limitBuffer struct {
	buf      bytes.Buffer
	max      int
	truncate bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		if !b.truncate {
			return 0, fmt.Errorf("output exceeds %d bytes", b.max)
		}
		b.buf.Write(p[:room])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *limitBuffer) String() string { return b.buf.String() }
