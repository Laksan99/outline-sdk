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

	"github.com/stretchr/testify/require"
)

// recordingConn records what was written, so a test can assert on the order and
// shape of the datagrams that reached the wire.
type recordingConn struct {
	mu       sync.Mutex
	writes   [][]byte
	addrs    []string
	writeErr error
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

func (*recordingConn) Close() error                     { return nil }
func (*recordingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

func (c *recordingConn) snapshot() ([][]byte, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.addrs
}

func (c *recordingConn) setWriteErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeErr = err
}

// countPreludes counts datagrams of the configured prelude length.
func (c *recordingConn) countPreludes(length int) int {
	writes, _ := c.snapshot()
	n := 0
	for _, w := range writes {
		if len(w) == length {
			n++
		}
	}
	return n
}

type fixedListener struct {
	conn net.PacketConn
}

func (l *fixedListener) ListenPacket(context.Context) (net.PacketConn, error) {
	return l.conn, nil
}

func newTestConn(t *testing.T, config *Config) (net.PacketConn, *recordingConn) {
	t.Helper()
	inner := &recordingConn{}
	listener, err := config.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	return conn, inner
}

func udpAddr(t *testing.T, address string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", address)
	require.NoError(t, err)
	return addr
}

func TestPreludePrecedesFirstWrite(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig().WithCount(3))

	payload := []byte("real traffic")
	_, err := conn.WriteTo(payload, udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)

	writes, addrs := inner.snapshot()
	require.Len(t, writes, 4, "expected 3 preludes followed by the payload")
	for i := range 3 {
		require.Len(t, writes[i], 1280, "prelude %d", i+1)
		require.Equal(t, byte(0xc0), writes[i][0]&0xc0, "prelude %d is not long-header shaped", i+1)
		require.Equal(t, "192.0.2.1:443", addrs[i], "prelude %d destination", i+1)
	}
	// The ordering is the whole point: the prelude has to reach the wire first.
	require.Equal(t, payload, writes[3])
}

func TestPreludeSentOncePerDestination(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")

	for range 5 {
		_, err := conn.WriteTo([]byte("x"), destination)
		require.NoError(t, err)
	}

	writes, _ := inner.snapshot()
	require.Len(t, writes, 6, "expected 1 prelude followed by 5 payloads")
	require.Equal(t, 1, inner.countPreludes(DefaultLength))
}

func TestPreludeSentForEachDestination(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())

	// The third write repeats the first destination and must not prelude again.
	for _, address := range []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.1:443"} {
		_, err := conn.WriteTo([]byte("x"), udpAddr(t, address))
		require.NoError(t, err)
	}

	writes, addrs := inner.snapshot()
	require.Len(t, writes, 5, "expected a prelude for each of 2 destinations plus 3 payloads")

	preludesPerAddr := map[string]int{}
	for i, w := range writes {
		if len(w) == DefaultLength {
			preludesPerAddr[addrs[i]]++
		}
	}
	require.Equal(t, 1, preludesPerAddr["192.0.2.1:443"])
	require.Equal(t, 1, preludesPerAddr["192.0.2.2:443"])
}

func TestPreludeRetriedAfterWriteFailure(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")
	inner.setWriteErr(errors.New("network down"))

	_, err := conn.WriteTo([]byte("x"), destination)
	require.Error(t, err)

	// The destination must not be recorded as done while the prelude failed,
	// otherwise the real traffic would later go out with no prelude at all.
	inner.setWriteErr(nil)
	_, err = conn.WriteTo([]byte("x"), destination)
	require.NoError(t, err)

	writes, _ := inner.snapshot()
	require.Len(t, writes, 2, "expected the prelude to be retried, then the payload")
	require.Len(t, writes[0], DefaultLength)
}

func TestZeroCountReturnsInnerConnUnwrapped(t *testing.T) {
	inner := &recordingConn{}
	listener, err := NewConfig().WithCount(0).NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)

	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	require.Same(t, inner, conn, "a disabled prelude should not wrap the connection")
}

func TestNewPacketListenerRequiresInnerListener(t *testing.T) {
	_, err := NewConfig().NewPacketListener(nil)
	require.Error(t, err)
}

func TestNewPacketListenerRejectsNegativeCount(t *testing.T) {
	_, err := NewConfig().WithCount(-1).NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.Error(t, err)
}

func TestNewPacketListenerRequiresGenerator(t *testing.T) {
	_, err := NewConfig().WithGenerator(nil).NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.Error(t, err)

	// A nil generator is fine while the prelude is disabled, since it is never
	// called.
	_, err = NewConfig().WithCount(0).WithGenerator(nil).NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.NoError(t, err)
}

func TestListenersDoNotSeeLaterConfigChanges(t *testing.T) {
	config := NewConfig()
	inner := &recordingConn{}
	listener, err := config.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)

	// Reconfiguring the Config must not reach a listener already created.
	config.WithCount(5)

	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("x"), udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)
	require.Equal(t, 1, inner.countPreludes(DefaultLength))
}

func TestGeneratorReceivesDestinationAndErrorsPropagate(t *testing.T) {
	inner := &recordingConn{}
	var gotDst net.Addr
	listener, err := NewConfig().
		WithGenerator(func(dst net.Addr) ([]byte, error) {
			gotDst = dst
			return []byte("custom prelude"), nil
		}).
		NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)

	destination := udpAddr(t, "192.0.2.1:443")
	_, err = conn.WriteTo([]byte("payload"), destination)
	require.NoError(t, err)

	require.Equal(t, destination.String(), gotDst.String(), "the generator is told where the datagram goes")
	writes, _ := inner.snapshot()
	require.Len(t, writes, 2)
	require.Equal(t, []byte("custom prelude"), writes[0])

	// A generator that fails aborts the write rather than sending unpreluded.
	failing, err := NewConfig().
		WithGenerator(func(net.Addr) ([]byte, error) { return nil, errors.New("no datagram") }).
		NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.NoError(t, err)
	conn, err = failing.ListenPacket(context.Background())
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("payload"), destination)
	require.ErrorContains(t, err, "no datagram")
}

func TestConcurrentWritesSendOnePrelude(t *testing.T) {
	conn, inner := newTestConn(t, NewConfig())
	destination := udpAddr(t, "192.0.2.1:443")

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := conn.WriteTo([]byte("x"), destination)
			require.NoError(t, err)
		}()
	}
	wg.Wait()

	require.Equal(t, 1, inner.countPreludes(DefaultLength), "racing writes must not each send a prelude")
}
