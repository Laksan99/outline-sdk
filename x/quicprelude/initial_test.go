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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// First bytes of long-header packets, with the Header Form and Fixed Bit set.
const (
	v1Initial   byte = 0xc0
	v1ZeroRTT   byte = 0xd0
	v1Handshake byte = 0xe0
	v1Retry     byte = 0xf0
	v2Retry     byte = 0xc0
	v2Initial   byte = 0xd0
	v2ZeroRTT   byte = 0xe0
	v2Handshake byte = 0xf0
)

// longPacket builds a long-header packet with 8-byte connection IDs and
// payloadLength zero bytes. Only Initial packets carry a token field, and it is
// left empty.
func longPacket(firstByte byte, version uint32, payloadLength int) []byte {
	p := []byte{firstByte, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(p[1:5], version)
	p = append(p, 8, 1, 2, 3, 4, 5, 6, 7, 8)
	p = append(p, 8, 9, 10, 11, 12, 13, 14, 15, 16)
	initial := (version == Version2 && firstByte&0x30 == 0x10) ||
		(version != Version2 && firstByte&0x30 == 0)
	if initial {
		p = append(p, 0)
	}
	p = binary.BigEndian.AppendUint16(p, uint16(payloadLength)|0x4000)
	return append(p, make([]byte, payloadLength)...)
}

// clientInitial builds a datagram of length bytes holding one v1 Initial, as a
// client's first flight would.
func clientInitial(length int) []byte {
	return longPacket(v1Initial, Version1, length-28)
}

func coalesce(packets ...[]byte) []byte {
	var p []byte
	for _, packet := range packets {
		p = append(p, packet...)
	}
	return p
}

func TestMayCarryClientHello(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
		want   bool
	}{
		// Datagrams that may carry a ClientHello.
		{"v1 Initial", clientInitial(1200), true},
		{"v2 Initial", longPacket(v2Initial, Version2, 1172), true},
		{"draft-29 Initial", longPacket(v1Initial, 0xff00001d, 1172), true},
		{"Initial with padding after it", append(longPacket(v1Initial, Version1, 900), make([]byte, 272)...), true},
		{"Initial coalesced with 0-RTT", coalesce(longPacket(v1Initial, Version1, 1000), longPacket(v1ZeroRTT, Version1, 100)), true},
		{"v2 Initial coalesced with 0-RTT", coalesce(longPacket(v2Initial, Version2, 1000), longPacket(v2ZeroRTT, Version2, 100)), true},
		{"Initial followed by another version's Handshake", coalesce(longPacket(v1Initial, Version1, 1000), longPacket(v2Handshake, Version2, 100)), true},
		{"Initial with a Fixed Bit greased to zero", longPacket(0x80, Version1, 1172), true},
		{"Initial whose length overruns the datagram", longPacket(v1Initial, Version1, 1172)[:600], true},
		{"Initial truncated inside its header", longPacket(v1Initial, Version1, 1172)[:10], true},

		// Initials that only acknowledge the server's, coalesced with Handshake.
		{"v1 Initial coalesced with Handshake", coalesce(longPacket(v1Initial, Version1, 100), longPacket(v1Handshake, Version1, 1000)), false},
		{"v2 Initial coalesced with Handshake", coalesce(longPacket(v2Initial, Version2, 100), longPacket(v2Handshake, Version2, 1000)), false},

		// Everything else.
		{"empty", nil, false},
		{"short header", append([]byte{0x40}, make([]byte, 40)...), false},
		{"DNS query", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, false},
		{"long header shorter than a version", []byte{0xc0, 0, 0}, false},
		{"v1 Handshake", longPacket(v1Handshake, Version1, 1000), false},
		{"v1 0-RTT", longPacket(v1ZeroRTT, Version1, 1000), false},
		{"v1 Retry bits", longPacket(v1Retry, Version1, 100), false},
		{"v2 Retry bits, the v1 Initial layout", longPacket(v2Retry, Version2, 1172), false},
		{"v2 Handshake", longPacket(v2Handshake, Version2, 1000), false},
		{"Version Negotiation", longPacket(0x80, 0, 100), false},
		{"reserved version", longPacket(v1Initial, exampleReserved, 1172), false},
		{"unknown version", longPacket(v1Initial, 0xdeadbeef, 1172), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, mayCarryClientHello(tc.packet))
		})
	}
}

func TestReadVarint(t *testing.T) {
	for _, tc := range []struct {
		encoded []byte
		value   uint64
	}{
		// The examples from RFC 9000 Appendix A.1.
		{[]byte{0x25}, 37},
		{[]byte{0x40, 0x25}, 37},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
	} {
		value, n, ok := readVarint(tc.encoded, 0)
		require.True(t, ok)
		require.Equal(t, tc.value, value)
		require.Equal(t, len(tc.encoded), n)
	}

	_, _, ok := readVarint([]byte{0x9d, 0x7f}, 0)
	require.False(t, ok, "a varint cut short must not parse")
	_, _, ok = readVarint([]byte{0x25}, 1)
	require.False(t, ok, "an offset past the end must not parse")
}
