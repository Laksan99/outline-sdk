// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package quicprelude

import (
	"context"
	"fmt"
	"net"
	"sync"

	"golang.getoutline.org/sdk/transport"
)

// maxTrackedDestinations bounds the per-connection record of destinations that
// have already been preluded. A long-lived connection that exceeds it starts
// over, which resends a prelude to a destination already seen. That is wasteful
// but harmless, and it keeps memory bounded.
const maxTrackedDestinations = 1024

// PacketListener wraps another [transport.PacketListener] so that the first
// datagram sent to each destination is preceded by the configured prelude.
//
// The prelude is written to the same connection as the traffic that follows,
// so both share a four-tuple by construction. That is the property the
// technique depends on: a middlebox keying on the flow must see them as one.
type PacketListener struct {
	// Inner is the listener that provides the underlying connection. Required.
	Inner transport.PacketListener

	// Config describes the datagrams to send.
	Config Config
}

var _ transport.PacketListener = (*PacketListener)(nil)

// ListenPacket creates a [net.PacketConn] that sends the prelude ahead of the
// first datagram to each destination.
func (l *PacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if l.Inner == nil {
		return nil, fmt.Errorf("quicprelude: inner listener is required")
	}
	if err := l.Config.Validate(); err != nil {
		return nil, fmt.Errorf("quicprelude: %w", err)
	}
	conn, err := l.Inner.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	if l.Config.Count == 0 {
		return conn, nil
	}
	return &preludeConn{PacketConn: conn, config: l.Config, seen: make(map[string]bool)}, nil
}

// preludeConn sends the prelude before the first datagram to each destination.
// Everything else is delegated to the embedded [net.PacketConn].
type preludeConn struct {
	net.PacketConn

	config Config

	mu   sync.Mutex
	seen map[string]bool
}

// WriteTo sends the prelude datagrams if this is the first write to addr, then
// writes p. The prelude is sent while holding the lock so that a concurrent
// write to the same destination cannot overtake it.
func (c *preludeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.sendPreludeOnce(addr); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *preludeConn) sendPreludeOnce(addr net.Addr) error {
	key := addr.String()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[key] {
		return nil
	}
	if len(c.seen) >= maxTrackedDestinations {
		clear(c.seen)
	}

	for i := 0; i < c.config.Count; i++ {
		datagram, err := c.config.Datagram()
		if err != nil {
			return fmt.Errorf("quicprelude: build datagram %d: %w", i+1, err)
		}
		if _, err := c.PacketConn.WriteTo(datagram, addr); err != nil {
			return fmt.Errorf("quicprelude: send datagram %d: %w", i+1, err)
		}
	}
	// Recorded only after every datagram is sent, so a failed attempt is retried
	// rather than silently skipped on the next write.
	c.seen[key] = true
	return nil
}
