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

// mustDefaultGenerator returns the generator NewConfig uses.
func mustDefaultGenerator(t *testing.T) Generator {
	t.Helper()
	generator, err := InvalidInitial(mustFixed(t, exampleReserved), MatchPacketLength)
	require.NoError(t, err)
	return generator
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
	repeated, err := Repeat(3, mustDefaultGenerator(t))
	require.NoError(t, err)
	conn, inner := newTestConn(t, NewConfig().WithGenerator(repeated))

	// A realistic Initial-sized payload, so the default generator's length
	// matching is exercised rather than its fallback.
	payload := make([]byte, DefaultLength)
	copy(payload, "real traffic")
	_, err = conn.WriteTo(payload, udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)

	writes, addrs := inner.snapshot()
	require.Len(t, writes, 4, "expected 3 preludes followed by the payload")
	for i := range 3 {
		require.Len(t, writes[i], len(payload), "prelude %d should match the packet length", i+1)
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

func TestDecliningGeneratorSendsNothingAndKeepsAsking(t *testing.T) {
	// A generator that only preludes QUIC long headers must not be locked out by
	// an unrelated datagram, such as a DNS query, going to the same destination
	// first.
	conn, inner := newTestConn(t, NewConfig().WithGenerator(
		func(input GeneratorInput) ([][]byte, error) {
			if len(input.Packet) == 0 || input.Packet[0]&0x80 == 0 {
				return nil, nil
			}
			return [][]byte{[]byte("prelude")}, nil
		}))
	destination := udpAddr(t, "192.0.2.1:443")

	_, err := conn.WriteTo([]byte{0x00, 0x01}, destination)
	require.NoError(t, err)
	writes, _ := inner.snapshot()
	require.Len(t, writes, 1, "a declined prelude sends the payload alone")

	// The long-header packet still gets its prelude.
	_, err = conn.WriteTo([]byte{0xc0, 0x02}, destination)
	require.NoError(t, err)
	writes, _ = inner.snapshot()
	require.Len(t, writes, 3)
	require.Equal(t, []byte("prelude"), writes[1])
}

func TestNewPacketListenerRequiresInnerListener(t *testing.T) {
	_, err := NewConfig().NewPacketListener(nil)
	require.Error(t, err)
}

func TestNewPacketListenerRequiresGenerator(t *testing.T) {
	_, err := NewConfig().WithGenerator(nil).NewPacketListener(&fixedListener{conn: &recordingConn{}})
	require.Error(t, err)
}

func TestListenersDoNotSeeLaterConfigChanges(t *testing.T) {
	config := NewConfig()
	inner := &recordingConn{}
	listener, err := config.NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)

	// Reconfiguring the Config must not reach a listener already created.
	repeated, err := Repeat(5, mustDefaultGenerator(t))
	require.NoError(t, err)
	config.WithGenerator(repeated)

	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)
	_, err = conn.WriteTo([]byte("x"), udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)
	require.Equal(t, 1, inner.countPreludes(DefaultLength))
}

func TestGeneratorReceivesDestinationAndErrorsPropagate(t *testing.T) {
	inner := &recordingConn{}
	var gotDst net.Addr
	var gotPacket []byte
	listener, err := NewConfig().
		WithGenerator(func(input GeneratorInput) ([][]byte, error) {
			gotDst = input.Destination
			gotPacket = append([]byte(nil), input.Packet...)
			return [][]byte{[]byte("custom prelude")}, nil
		}).
		NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(context.Background())
	require.NoError(t, err)

	destination := udpAddr(t, "192.0.2.1:443")
	_, err = conn.WriteTo([]byte("payload"), destination)
	require.NoError(t, err)

	require.Equal(t, destination.String(), gotDst.String(), "the generator is told where the datagram goes")
	require.Equal(t, []byte("payload"), gotPacket, "the generator is given the packet it precedes")
	writes, _ := inner.snapshot()
	require.Len(t, writes, 2)
	require.Equal(t, []byte("custom prelude"), writes[0])

	// A generator that fails aborts the write rather than sending unpreluded.
	failing, err := NewConfig().
		WithGenerator(func(GeneratorInput) ([][]byte, error) { return nil, errors.New("no datagram") }).
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
