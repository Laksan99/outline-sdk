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

func TestNewConfigIsValid(t *testing.T) {
	config := NewConfig()
	require.NoError(t, config.Validate())
	require.Equal(t, 1, config.Count)
	require.Equal(t, ModeInvalidInitial, config.Mode)
	require.Equal(t, DefaultLength, config.Length)
	require.Equal(t, DefaultVersion, config.Version)
}

func TestValidateAcceptsDisabledPrelude(t *testing.T) {
	// A zero count disables the prelude, so the other fields stop mattering.
	require.NoError(t, Config{Count: 0}.Validate())
	require.NoError(t, Config{Count: 0, Mode: "nonsense"}.Validate())
}

func TestValidateRejectsNegativeCount(t *testing.T) {
	require.Error(t, Config{Count: -1}.Validate())
}

func TestValidateRandomMode(t *testing.T) {
	require.NoError(t, Config{Count: 1, Mode: ModeRandom, Length: 1}.Validate())

	// Random datagrams have no minimum size, but they must have one.
	require.Error(t, Config{Count: 1, Mode: ModeRandom}.Validate())
}

func TestValidateInvalidInitialMode(t *testing.T) {
	require.NoError(t, Config{Count: 1, Mode: ModeInvalidInitial, Length: MinimumInitialLength, Version: Version1}.Validate())

	// RFC 9000 requires a client Initial to travel in a datagram of at least
	// MinimumInitialLength bytes.
	require.Error(t, Config{Count: 1, Mode: ModeInvalidInitial, Length: MinimumInitialLength - 1, Version: Version1}.Validate())

	// The length field is written as a two-byte varint, which caps the payload.
	require.Error(t, Config{Count: 1, Mode: ModeInvalidInitial, Length: headerLength + (1 << 14), Version: Version1}.Validate())

	// Version zero denotes Version Negotiation, which a client never sends.
	require.Error(t, Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280}.Validate())
}

func TestValidateRejectsUnknownMode(t *testing.T) {
	require.Error(t, Config{Count: 1, Mode: "handshake", Length: 1280}.Validate())
}

func TestDatagramV1UsesInitialTypeBits(t *testing.T) {
	p, err := Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: Version1}.Datagram()
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, p, 1280)
	require.Equal(t, Version1, version)
	// QUIC v1 encodes Initial as 0b00.
	require.Equal(t, byte(0x00), packetType)
}

func TestDatagramV2UsesInitialTypeBits(t *testing.T) {
	p, err := Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: Version2}.Datagram()
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, p, 1280)
	require.Equal(t, Version2, version)
	// QUIC v2 encodes Initial as 0b01. Writing v1's 0b00 here would announce a
	// Retry packet instead, which is not what we want to be seen sending.
	require.Equal(t, byte(0x10), packetType)
}

func TestDatagramUnknownVersionUsesV1Layout(t *testing.T) {
	// RFC 8999 defines only the header form and version field for a version the
	// reader does not know, so anything else falls back to the v1 layout.
	p, err := Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: DefaultVersion}.Datagram()
	require.NoError(t, err)

	version, packetType := requireLongHeader(t, p, 1280)
	require.Equal(t, DefaultVersion, version)
	require.Equal(t, byte(0x00), packetType)

	p, err = Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: 0xdeadbeef}.Datagram()
	require.NoError(t, err)

	version, packetType = requireLongHeader(t, p, 1280)
	require.Equal(t, uint32(0xdeadbeef), version)
	require.Equal(t, byte(0x00), packetType)
}

func TestDatagramsDifferBetweenCalls(t *testing.T) {
	config := NewConfig()

	first, err := config.Datagram()
	require.NoError(t, err)
	second, err := config.Datagram()
	require.NoError(t, err)

	// Connection IDs and payload are random, so two datagrams must not match.
	// Identical datagrams would make a repeated prelude trivially fingerprintable.
	require.NotEqual(t, first, second)
	require.NotEqual(t, first[6:14], second[6:14], "destination connection IDs")
}

func TestDatagramRandomModeIsNotInitialShaped(t *testing.T) {
	config := Config{Count: 1, Mode: ModeRandom, Length: 1280}

	// The first byte is random, so check over enough samples that a datagram
	// which always looked like a long header would be caught.
	sawNonLongHeader := false
	for range 64 {
		p, err := config.Datagram()
		require.NoError(t, err)
		require.Len(t, p, 1280)
		if p[0]&0xc0 != 0xc0 {
			sawNonLongHeader = true
		}
	}
	require.True(t, sawNonLongHeader, "every random datagram set the long-header bits")
}

func TestDatagramRejectsInvalidConfig(t *testing.T) {
	_, err := Config{Count: 1, Mode: ModeInvalidInitial, Length: 100}.Datagram()
	require.Error(t, err)
}
