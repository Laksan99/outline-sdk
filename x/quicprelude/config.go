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
	"errors"
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

// Config describes the datagrams to send ahead of a flow's real traffic, and
// produces the listener that sends them. Its zero value sends nothing.
//
// A Config may be reused to create several listeners. Each listener takes a
// copy of the settings, so configuring the Config afterwards does not affect
// listeners already created.
type Config struct {
	generator Generator
}

// NewConfig returns a Config that sends one Initial-shaped datagram, sized to
// match the packet it precedes and carrying a freshly chosen version codepoint.
// It never fails; problems with the configuration surface in
// [Config.NewPacketListener].
func NewConfig() *Config {
	// The default arguments are constants known to be valid, so the error
	// cannot occur.
	generator, err := InvalidInitial(RandomVersion, MatchPacketLength)
	if err != nil {
		panic("quicprelude: default generator is invalid: " + err.Error())
	}
	return &Config{generator: generator}
}

// WithGenerator sets what the datagrams contain, replacing the default.
func (c *Config) WithGenerator(generator Generator) *Config {
	c.generator = generator
	return c
}

// NewPacketListener returns a [transport.PacketListener] whose connections send
// the configured prelude before the first datagram to each destination.
//
// The prelude is written to the same connection as the traffic that follows,
// so both share a four-tuple by construction. That is the property the
// technique depends on: a middlebox keying on the flow must see them as one.
func (c *Config) NewPacketListener(inner transport.PacketListener) (transport.PacketListener, error) {
	if inner == nil {
		return nil, errors.New("quicprelude: inner listener must not be nil")
	}
	if c.generator == nil {
		return nil, errors.New("quicprelude: generator must not be nil")
	}
	// Copied, so configuring the Config afterwards does not reach this listener.
	return &packetListener{inner: inner, generator: c.generator}, nil
}

type packetListener struct {
	inner     transport.PacketListener
	generator Generator
}

func (l *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := l.inner.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &preludeConn{
		PacketConn: conn,
		generator:  l.generator,
		seen:       make(map[string]bool),
	}, nil
}

// preludeConn sends the prelude before the first datagram to each destination.
// Everything else is delegated to the embedded [net.PacketConn].
type preludeConn struct {
	net.PacketConn

	generator Generator

	mu   sync.Mutex
	seen map[string]bool
}

// WriteTo sends the prelude datagrams if this is the first write to addr, then
// writes p. The prelude is sent while holding the lock so that a concurrent
// write to the same destination cannot overtake it.
func (c *preludeConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.sendPreludeOnce(p, addr); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *preludeConn) sendPreludeOnce(packet []byte, addr net.Addr) error {
	key := addr.String()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[key] {
		return nil
	}

	datagrams, err := c.generator(GeneratorInput{Packet: packet, Destination: addr})
	if err != nil {
		return fmt.Errorf("quicprelude: build prelude: %w", err)
	}
	if len(datagrams) == 0 {
		// The generator declined. Leave the destination unmarked so it is asked
		// again, rather than locking out a QUIC flow because an unrelated
		// datagram happened to go first.
		return nil
	}

	for i, datagram := range datagrams {
		if _, err := c.PacketConn.WriteTo(datagram, addr); err != nil {
			return fmt.Errorf("quicprelude: send datagram %d: %w", i+1, err)
		}
	}

	if len(c.seen) >= maxTrackedDestinations {
		clear(c.seen)
	}
	// Recorded only after every datagram is sent, so a failed attempt is retried
	// rather than silently skipped on the next write.
	c.seen[key] = true
	return nil
}
