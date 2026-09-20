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
	"net"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
)

type recordingConn struct {
	mu       sync.Mutex
	writes   [][]byte
	addrs    []string
	writeErr error
	closed   bool
}

func (c *recordingConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.addrs = append(c.addrs, addr.String())
	return len(p), nil
}

func (c *recordingConn) Close() error                   { c.closed = true; return nil }
func (*recordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingConn) snapshot() ([][]byte, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.addrs
}

type fixedListener struct {
	conn net.PacketConn
	err  error
}

func (l *fixedListener) ListenPacket(context.Context) (net.PacketConn, error) {
	return l.conn, l.err
}

func addr(t *testing.T, s string) net.Addr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newTestConn(t *testing.T, config Config) (net.PacketConn, *recordingConn) {
	t.Helper()
	inner := &recordingConn{}
	l := &PacketListener{Inner: &fixedListener{conn: inner}, Config: config}
	conn, err := l.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return conn, inner
}

func TestPreludePrecedesFirstWrite(t *testing.T) {
	config := Config{Count: 3, Mode: ModeInvalidInitial, Length: 1280, Version: DefaultVersion}
	conn, inner := newTestConn(t, config)

	payload := []byte("real traffic")
	if _, err := conn.WriteTo(payload, addr(t, "192.0.2.1:443")); err != nil {
		t.Fatal(err)
	}

	writes, addrs := inner.snapshot()
	if len(writes) != 4 {
		t.Fatalf("wrote %d datagrams, want 3 preludes plus the payload", len(writes))
	}
	for i := 0; i < 3; i++ {
		if len(writes[i]) != 1280 {
			t.Errorf("prelude %d length = %d, want 1280", i+1, len(writes[i]))
		}
		if writes[i][0]&0xc0 != 0xc0 {
			t.Errorf("prelude %d is not long-header shaped", i+1)
		}
		if addrs[i] != "192.0.2.1:443" {
			t.Errorf("prelude %d went to %s", i+1, addrs[i])
		}
	}
	if string(writes[3]) != string(payload) {
		t.Errorf("last write = %q, want the payload; the prelude must come first", writes[3])
	}
}

func TestPreludeSentOncePerDestination(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	dst := addr(t, "192.0.2.1:443")

	for i := 0; i < 5; i++ {
		if _, err := conn.WriteTo([]byte("x"), dst); err != nil {
			t.Fatal(err)
		}
	}

	writes, _ := inner.snapshot()
	// One prelude, then five payloads.
	if len(writes) != 6 {
		t.Fatalf("wrote %d datagrams, want 1 prelude plus 5 payloads", len(writes))
	}
	for _, w := range writes[1:] {
		if len(w) != 1 {
			t.Errorf("unexpected extra prelude after the first write: length %d", len(w))
		}
	}
}

func TestPreludeSentPerDestination(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())

	for _, host := range []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.1:443"} {
		if _, err := conn.WriteTo([]byte("x"), addr(t, host)); err != nil {
			t.Fatal(err)
		}
	}

	writes, addrs := inner.snapshot()
	// Prelude+payload for .1, prelude+payload for .2, payload only for .1 again.
	if len(writes) != 5 {
		t.Fatalf("wrote %d datagrams, want 5", len(writes))
	}
	preludesPerAddr := map[string]int{}
	for i, w := range writes {
		if len(w) == DefaultLength {
			preludesPerAddr[addrs[i]]++
		}
	}
	for _, host := range []string{"192.0.2.1:443", "192.0.2.2:443"} {
		if preludesPerAddr[host] != 1 {
			t.Errorf("destination %s got %d preludes, want 1", host, preludesPerAddr[host])
		}
	}
}

func TestPreludeRetriedAfterWriteFailure(t *testing.T) {
	inner := &recordingConn{writeErr: errors.New("network down")}
	l := &PacketListener{Inner: &fixedListener{conn: inner}, Config: NewConfig()}
	conn, err := l.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dst := addr(t, "192.0.2.1:443")

	if _, err := conn.WriteTo([]byte("x"), dst); err == nil {
		t.Fatal("expected the write to fail while the prelude cannot be sent")
	}

	// The destination must not be recorded as done, so a later write retries.
	inner.mu.Lock()
	inner.writeErr = nil
	inner.mu.Unlock()

	if _, err := conn.WriteTo([]byte("x"), dst); err != nil {
		t.Fatal(err)
	}
	writes, _ := inner.snapshot()
	if len(writes) != 2 {
		t.Fatalf("wrote %d datagrams, want the prelude to be retried then the payload", len(writes))
	}
}

func TestZeroCountReturnsInnerConnUnwrapped(t *testing.T) {
	inner := &recordingConn{}
	l := &PacketListener{Inner: &fixedListener{conn: inner}, Config: Config{Count: 0}}
	conn, err := l.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if conn != net.PacketConn(inner) {
		t.Error("a disabled prelude should hand back the inner connection unwrapped")
	}
}

func TestListenPacketRejectsBadConfig(t *testing.T) {
	l := &PacketListener{
		Inner:  &fixedListener{conn: &recordingConn{}},
		Config: Config{Count: 1, Mode: ModeInvalidInitial, Length: 10},
	}
	if _, err := l.ListenPacket(context.Background()); err == nil {
		t.Error("expected ListenPacket to reject an invalid config")
	}
}

func TestListenPacketRequiresInner(t *testing.T) {
	l := &PacketListener{Config: NewConfig()}
	if _, err := l.ListenPacket(context.Background()); err == nil {
		t.Error("expected ListenPacket to require an inner listener")
	}
}

func TestConcurrentWritesSendOnePrelude(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	dst := addr(t, "192.0.2.1:443")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := conn.WriteTo([]byte("x"), dst); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	writes, _ := inner.snapshot()
	preludes := 0
	for _, w := range writes {
		if len(w) == DefaultLength {
			preludes++
		}
	}
	if preludes != 1 {
		t.Errorf("sent %d preludes across concurrent writes, want exactly 1", preludes)
	}
}

var _ transport.PacketListener = (*PacketListener)(nil)
