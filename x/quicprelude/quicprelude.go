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

// Package quicprelude sends datagrams on a UDP flow before the traffic that
// follows it, to influence how a middlebox classifies that flow.
//
// Some middleboxes read the TLS Server Name Indication from the first QUIC
// Initial packet they can parse on a four-tuple, decide whether the flow is
// permitted, and apply that decision to everything that follows. An
// Initial-shaped datagram they cannot decrypt yields no server name, so no
// decision is reached and later packets on the flow are not matched against it.
//
// The datagrams this package sends are deliberately not valid QUIC. They carry
// a long header with a plausible version and connection IDs, and random bytes
// where the protected payload and authentication tag would be. A QUIC server
// discards them.
package quicprelude

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// Mode selects the kind of datagram to send.
type Mode string

const (
	// ModeInvalidInitial sends a datagram shaped like a QUIC Initial packet whose
	// payload cannot be decrypted. This is the default.
	ModeInvalidInitial Mode = "invalid-initial"

	// ModeRandom sends opaque random bytes, which a middlebox that parses QUIC
	// will not recognize as QUIC at all. It is useful as a control.
	ModeRandom Mode = "random"
)

const (
	// MinimumInitialLength is the smallest datagram RFC 9000 allows a client to
	// carry an Initial packet in.
	MinimumInitialLength = 1200

	// DefaultLength matches the datagram size QUIC-Go uses for its own Initials,
	// so a prelude is not distinguishable from the traffic that follows it by
	// datagram size alone.
	DefaultLength = 1280

	// DefaultVersion is a reserved version codepoint matching the 0x?a?a?a?a
	// pattern RFC 9000 sets aside to exercise version negotiation. No
	// implementation speaks it, which is the point: a middlebox that drops the
	// versions it recognizes has no reason to hold this one in its list.
	DefaultVersion uint32 = 0x1a2a3a4a

	// Version1 and Version2 are the wire codepoints of RFC 9000 and RFC 9369.
	// They are accepted so a caller can compare against a real version.
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf

	// headerLength is the fixed part this package emits: first byte, version,
	// two 8-byte connection IDs with their lengths, a zero-length token, and a
	// two-byte length field.
	headerLength = 26

	connectionIDLength = 8
)

// Config describes the datagrams to send before a flow's real traffic.
// The zero value is not usable; use [NewConfig] or set every field.
type Config struct {
	// Count is the number of datagrams to send. Zero disables the prelude.
	Count int

	// Mode selects the kind of datagram.
	Mode Mode

	// Length is the size of each datagram in bytes.
	Length int

	// Version is the wire codepoint written into the version field, used by
	// [ModeInvalidInitial].
	Version uint32
}

// NewConfig returns a Config with the recommended defaults: one
// Initial-shaped datagram of [DefaultLength] bytes carrying [DefaultVersion].
func NewConfig() Config {
	return Config{
		Count:   1,
		Mode:    ModeInvalidInitial,
		Length:  DefaultLength,
		Version: DefaultVersion,
	}
}

// Validate reports whether the configuration can produce datagrams.
func (c Config) Validate() error {
	if c.Count < 0 {
		return fmt.Errorf("count must not be negative, got %d", c.Count)
	}
	if c.Count == 0 {
		return nil
	}
	switch c.Mode {
	case ModeRandom:
		if c.Length <= 0 {
			return fmt.Errorf("length must be positive, got %d", c.Length)
		}
	case ModeInvalidInitial:
		if c.Length < MinimumInitialLength {
			return fmt.Errorf("length must be at least %d bytes for %s, got %d",
				MinimumInitialLength, ModeInvalidInitial, c.Length)
		}
		if c.Length-headerLength >= 1<<14 {
			return fmt.Errorf("length must be under %d bytes for %s, got %d",
				headerLength+(1<<14), ModeInvalidInitial, c.Length)
		}
		if c.Version == 0 {
			return fmt.Errorf("version must not be zero, which denotes Version Negotiation")
		}
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	return nil
}

// Datagram builds one datagram according to the configuration. Each call
// produces fresh random bytes, so repeated datagrams do not share connection
// IDs and are not identical on the wire.
func (c Config) Datagram() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	switch c.Mode {
	case ModeRandom:
		return randomBytes(c.Length)
	case ModeInvalidInitial:
		return invalidInitial(c.Version, c.Length)
	default:
		return nil, fmt.Errorf("unknown mode %q", c.Mode)
	}
}

func randomBytes(length int) ([]byte, error) {
	p := make([]byte, length)
	if _, err := rand.Read(p); err != nil {
		return nil, fmt.Errorf("generate random datagram: %w", err)
	}
	return p, nil
}

// invalidInitial returns a datagram with a syntactically valid QUIC long header
// announcing an Initial packet, and random bytes beyond it. The payload cannot
// be decrypted and the authentication tag will not verify, so it is not a valid
// QUIC packet and no server will act on it.
func invalidInitial(version uint32, length int) ([]byte, error) {
	p, err := randomBytes(length)
	if err != nil {
		return nil, err
	}

	// Header Form and Fixed Bit are set. The long packet type encodes Initial,
	// which is 0b00 in QUIC v1 and 0b01 in QUIC v2. For any other version the
	// v1 layout is used, since RFC 8999 defines only the header form and the
	// version field for a version the reader does not know. The low nibble and
	// the packet number bytes stay random, mimicking header protection.
	typeBits := byte(0xc0)
	if version == Version2 {
		typeBits = 0xd0
	}
	p[0] = typeBits | (p[0] & 0x0f)
	binary.BigEndian.PutUint32(p[1:5], version)

	p[5] = connectionIDLength
	// p[6:14] is the random Destination Connection ID.
	p[14] = connectionIDLength
	// p[15:23] is the random Source Connection ID.
	p[23] = 0 // zero-length token

	// Two-byte QUIC varint for the length of the protected remainder.
	protectedLength := length - headerLength
	binary.BigEndian.PutUint16(p[24:26], uint16(protectedLength)|(1<<14))
	return p, nil
}
