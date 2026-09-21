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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireLongHeader asserts the invariants every Initial-shaped datagram must
// hold, and returns the version and long packet type it declares.
func requireLongHeader(t *testing.T, p []byte, length int) (version uint32, packetType byte) {
	t.Helper()
	require.Len(t, p, length)
	require.Equal(t, byte(0xc0), p[0]&0xc0, "long-header and fixed bits must be set")
	require.Equal(t, byte(connectionIDLength), p[5], "destination connection ID length")
	require.Equal(t, byte(connectionIDLength), p[14], "source connection ID length")
	require.Zero(t, p[23], "token length")
	require.Equal(t, byte(0x40), p[24]&0xc0, "length must be a two-byte varint")
	require.Equal(t, len(p)-headerLength, int(p[24]&0x3f)<<8|int(p[25]), "protected length")
	version = uint32(p[1])<<24 | uint32(p[2])<<16 | uint32(p[3])<<8 | uint32(p[4])
	return version, p[0] & 0x30
}

// generate calls a generator once with a placeholder packet and destination,
// and requires it to return exactly one datagram.
func generate(t *testing.T, generator Generator) []byte {
	t.Helper()
	datagrams := generateFor(t, generator, make([]byte, DefaultLength))
	require.Len(t, datagrams, 1)
	return datagrams[0]
}

// generateFor calls a generator with the packet it would precede.
func generateFor(t *testing.T, generator Generator, packet []byte) [][]byte {
	t.Helper()
	datagrams, err := generator(packet, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443})
	require.NoError(t, err)
	return datagrams
}

func TestInvalidInitialV1UsesInitialTypeBits(t *testing.T) {
	generator, err := InvalidInitial(Version1, 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, Version1, version)
	// QUIC v1 encodes Initial as 0b00.
	require.Equal(t, byte(0x00), packetType)
}

func TestInvalidInitialV2UsesInitialTypeBits(t *testing.T) {
	generator, err := InvalidInitial(Version2, 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, Version2, version)
	// QUIC v2 encodes Initial as 0b01. Writing v1's 0b00 here would announce a
	// Retry packet instead, which is not what we want to be seen sending.
	require.Equal(t, byte(0x10), packetType)
}

func TestInvalidInitialUnknownVersionUsesV1Layout(t *testing.T) {
	// RFC 8999 defines only the header form and version field for a version the
	// reader does not know, so anything else falls back to the v1 layout.
	generator, err := InvalidInitial(DefaultVersion, 1280)
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, DefaultVersion, version)
	require.Equal(t, byte(0x00), packetType)

	generator, err = InvalidInitial(0xdeadbeef, 1280)
	require.NoError(t, err)

	version, packetType = requireLongHeader(t, generate(t, generator), 1280)
	require.Equal(t, uint32(0xdeadbeef), version)
	require.Equal(t, byte(0x00), packetType)
}

func TestInvalidInitialRejectsBadArguments(t *testing.T) {
	// Version zero denotes Version Negotiation, which a client never sends.
	_, err := InvalidInitial(0, 1280)
	require.Error(t, err)

	// RFC 9000 requires a client Initial to travel in a datagram of at least
	// MinimumInitialLength bytes.
	_, err = InvalidInitial(Version1, MinimumInitialLength-1)
	require.Error(t, err)

	// The length field is written as a two-byte varint, which caps the payload.
	_, err = InvalidInitial(Version1, headerLength+maxProtectedLength)
	require.Error(t, err)
}

func TestInvalidInitialAcceptsBoundaryLengths(t *testing.T) {
	_, err := InvalidInitial(Version1, MinimumInitialLength)
	require.NoError(t, err)

	_, err = InvalidInitial(Version1, headerLength+maxProtectedLength-1)
	require.NoError(t, err)
}

func TestValidateInitialLength(t *testing.T) {
	require.NoError(t, ValidateInitialLength(MinimumInitialLength))
	require.NoError(t, ValidateInitialLength(DefaultLength))
	require.Error(t, ValidateInitialLength(MinimumInitialLength-1))
	require.Error(t, ValidateInitialLength(headerLength+maxProtectedLength))
}

func TestDatagramsDifferBetweenCalls(t *testing.T) {
	generator, err := InvalidInitial(DefaultVersion, DefaultLength)
	require.NoError(t, err)

	first := generate(t, generator)
	second := generate(t, generator)

	// Connection IDs and payload are random, so two datagrams must not match.
	// Identical datagrams would make a repeated prelude trivially fingerprintable.
	require.NotEqual(t, first, second)
	require.NotEqual(t, first[6:14], second[6:14], "destination connection IDs")
}

func TestRandomIsNotInitialShaped(t *testing.T) {
	generator, err := Random(1280)
	require.NoError(t, err)

	// The first byte is random, so check over enough samples that a datagram
	// which always looked like a long header would be caught.
	sawNonLongHeader := false
	for range 64 {
		p := generate(t, generator)
		require.Len(t, p, 1280)
		if p[0]&0xc0 != 0xc0 {
			sawNonLongHeader = true
		}
	}
	require.True(t, sawNonLongHeader, "every random datagram set the long-header bits")
}

func TestRandomRejectsNegativeLength(t *testing.T) {
	_, err := Random(-1)
	require.Error(t, err)
}

func TestInvalidInitialMatchesPacketLength(t *testing.T) {
	generator, err := InvalidInitial(DefaultVersion, MatchPacketLength)
	require.NoError(t, err)

	// A prelude sized like the packet it precedes is not separable by size.
	for _, length := range []int{MinimumInitialLength, 1280, 1350} {
		datagrams := generateFor(t, generator, make([]byte, length))
		require.Len(t, datagrams, 1)
		require.Len(t, datagrams[0], length)
		requireLongHeader(t, datagrams[0], length)
	}
}

func TestInvalidInitialFallsBackWhenPacketCannotCarryAnInitial(t *testing.T) {
	generator, err := InvalidInitial(DefaultVersion, MatchPacketLength)
	require.NoError(t, err)

	// A short packet, such as a DNS query, is not a length an Initial can have,
	// so the generator falls back rather than emitting an invalid datagram.
	datagrams := generateFor(t, generator, make([]byte, 40))
	require.Len(t, datagrams, 1)
	require.Len(t, datagrams[0], DefaultLength)
}

func TestRandomMatchesPacketLength(t *testing.T) {
	generator, err := Random(MatchPacketLength)
	require.NoError(t, err)

	datagrams := generateFor(t, generator, make([]byte, 1300))
	require.Len(t, datagrams, 1)
	require.Len(t, datagrams[0], 1300)
}

func TestRepeatConcatenatesDatagrams(t *testing.T) {
	inner, err := InvalidInitial(Version1, 1280)
	require.NoError(t, err)
	generator, err := Repeat(3, inner)
	require.NoError(t, err)

	datagrams := generateFor(t, generator, make([]byte, DefaultLength))
	require.Len(t, datagrams, 3)
	// Each call generates fresh randomness, so the repeats must differ.
	require.NotEqual(t, datagrams[0], datagrams[1])
	require.NotEqual(t, datagrams[1], datagrams[2])
}

func TestRepeatZeroDisablesThePrelude(t *testing.T) {
	inner, err := InvalidInitial(Version1, 1280)
	require.NoError(t, err)
	generator, err := Repeat(0, inner)
	require.NoError(t, err)

	require.Empty(t, generateFor(t, generator, make([]byte, DefaultLength)))
}

func TestRepeatRejectsBadArguments(t *testing.T) {
	inner, err := InvalidInitial(Version1, 1280)
	require.NoError(t, err)

	_, err = Repeat(-1, inner)
	require.Error(t, err)

	_, err = Repeat(1, nil)
	require.Error(t, err)
}

func TestGeneratorCanSplitAndDecline(t *testing.T) {
	// A generator returning several datagrams sends all of them, which is how a
	// split Initial would be expressed.
	split := Generator(func(packet []byte, _ net.Addr) ([][]byte, error) {
		half := len(packet) / 2
		return [][]byte{packet[:half], packet[half:]}, nil
	})
	require.Len(t, generateFor(t, split, make([]byte, 100)), 2)

	// Returning nothing is how a generator declines.
	decline := Generator(func([]byte, net.Addr) ([][]byte, error) { return nil, nil })
	require.Empty(t, generateFor(t, decline, make([]byte, 100)))
}

func TestNewConfigDefaults(t *testing.T) {
	inner := &recordingConn{}
	listener, err := NewConfig().NewPacketListener(&fixedListener{conn: inner})
	require.NoError(t, err)
	conn, err := listener.ListenPacket(t.Context())
	require.NoError(t, err)

	_, err = conn.WriteTo(make([]byte, DefaultLength), udpAddr(t, "192.0.2.1:443"))
	require.NoError(t, err)

	// One Initial-shaped datagram carrying DefaultVersion, sized to match the
	// packet it preceded.
	writes, _ := inner.snapshot()
	require.Len(t, writes, 2)
	version, packetType := requireLongHeader(t, writes[0], len(writes[1]))
	require.Equal(t, DefaultVersion, version)
	require.Equal(t, byte(0x00), packetType)
}
