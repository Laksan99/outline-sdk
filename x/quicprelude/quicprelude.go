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
// A [Config] describes what to send and produces a [transport.PacketListener]:
//
//	config := quicprelude.NewConfig()
//	listener, err := config.NewPacketListener(inner)
//
// The datagrams come from a [Generator], which is handed the packet it is about
// to precede. [InvalidInitial] and [Random] cover the cases this package was
// written for, [Repeat] sends one of them several times, and a caller who needs
// something else supplies their own:
//
//	generator, err := quicprelude.InvalidInitial(quicprelude.Version2, quicprelude.MatchPacketLength)
//	generator, err = quicprelude.Repeat(2, generator)
//	listener, err := quicprelude.NewConfig().
//		WithGenerator(generator).
//		NewPacketListener(inner)
//
// The datagrams [InvalidInitial] produces are deliberately not valid QUIC. They
// carry a long header with a plausible version and connection IDs, and random
// bytes where the protected payload and authentication tag would be. A QUIC
// server discards them.
package quicprelude

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
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

	// MatchPacketLength asks a generator to size each datagram to match the
	// packet it precedes, so the prelude is not distinguishable by size from the
	// traffic it is mixed with. A packet whose length could not carry an Initial
	// falls back to the generator's default.
	MatchPacketLength = 0

	// Version1 and Version2 are the wire codepoints of RFC 9000 and RFC 9369.
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf

	// headerLength is the fixed part InvalidInitial emits: first byte, version,
	// two 8-byte connection IDs with their lengths, a zero-length token, and a
	// two-byte length field.
	headerLength = 26

	connectionIDLength = 8

	// maxProtectedLength is the largest payload a two-byte QUIC varint can
	// describe.
	maxProtectedLength = 1 << 14
)

// GeneratorInput describes the write a prelude is about to precede.
//
// It is a struct so that fields can be added without breaking implementations
// of [Generator]. A generator should ignore fields it does not recognize.
type GeneratorInput struct {
	// Packet is the datagram about to be written. A generator may read it to
	// match its length, to find the Server Name Indication in an Initial, or to
	// decide whether to act at all. It must not be modified.
	Packet []byte

	// Destination is where Packet is addressed. It is not derivable from Packet,
	// and is what a generator needs to vary by target.
	Destination net.Addr
}

// Generator returns the datagrams to send ahead of the write described by
// input. Being given the packet lets a generator match its length, read the
// Server Name Indication out of an Initial, or decline.
//
// Returning no datagrams sends the packet unchanged, and leaves the destination
// unmarked, so a generator that is waiting for a QUIC Initial is consulted
// again on the next datagram to that destination rather than being locked out
// by an unrelated first packet.
//
// Returning an error aborts the write, and the caller sees that error.
type Generator func(input GeneratorInput) ([][]byte, error)

// Random returns a [Generator] producing opaque random bytes. A middlebox that
// parses QUIC will not recognize them as QUIC at all, which makes this useful
// as a control rather than as a technique.
func Random(length int) (Generator, error) {
	if length < 0 {
		return nil, fmt.Errorf("length must not be negative, got %d", length)
	}
	return func(input GeneratorInput) ([][]byte, error) {
		datagram, err := randomBytes(lengthFor(length, input.Packet, 1))
		if err != nil {
			return nil, err
		}
		return [][]byte{datagram}, nil
	}, nil
}

// InvalidInitial returns a [Generator] producing datagrams with a syntactically
// valid QUIC long header announcing an Initial packet, and random bytes beyond
// it. The payload cannot be decrypted and the authentication tag will not
// verify, so it is not a valid QUIC packet and no server acts on it.
//
// version is written to the wire as given. A codepoint no implementation speaks,
// such as [DefaultVersion], is not recognized by filtering that enumerates
// known versions.
func InvalidInitial(version uint32, length int) (Generator, error) {
	if version == 0 {
		return nil, fmt.Errorf("version must not be zero, which denotes Version Negotiation")
	}
	if length != MatchPacketLength {
		if err := ValidateInitialLength(length); err != nil {
			return nil, err
		}
	}
	return func(input GeneratorInput) ([][]byte, error) {
		datagram, err := invalidInitial(version, lengthFor(length, input.Packet, DefaultLength))
		if err != nil {
			return nil, err
		}
		return [][]byte{datagram}, nil
	}, nil
}

// Repeat returns a [Generator] that calls generator count times and
// concatenates the result. A count of zero yields a generator that sends
// nothing, which disables the prelude.
func Repeat(count int, generator Generator) (Generator, error) {
	if count < 0 {
		return nil, fmt.Errorf("count must not be negative, got %d", count)
	}
	if generator == nil {
		return nil, fmt.Errorf("generator must not be nil")
	}
	return func(input GeneratorInput) ([][]byte, error) {
		var datagrams [][]byte
		for range count {
			next, err := generator(input)
			if err != nil {
				return nil, err
			}
			datagrams = append(datagrams, next...)
		}
		return datagrams, nil
	}, nil
}

// lengthFor resolves a configured length against the packet being preceded.
// MatchPacketLength takes the packet's own length, so the prelude is not
// distinguishable by size, falling back when that length could not carry an
// Initial.
func lengthFor(configured int, packet []byte, fallback int) int {
	if configured != MatchPacketLength {
		return configured
	}
	if ValidateInitialLength(len(packet)) != nil {
		return fallback
	}
	return len(packet)
}

// ValidateInitialLength reports whether length can carry an Initial-shaped
// datagram. It is exported so a caller parsing a length from configuration can
// reject a bad value before building a [Generator].
func ValidateInitialLength(length int) error {
	if length < MinimumInitialLength {
		return fmt.Errorf("length must be at least %d bytes, got %d", MinimumInitialLength, length)
	}
	if length-headerLength >= maxProtectedLength {
		return fmt.Errorf("length must be under %d bytes, got %d", headerLength+maxProtectedLength, length)
	}
	return nil
}

func randomBytes(length int) ([]byte, error) {
	p := make([]byte, length)
	if _, err := rand.Read(p); err != nil {
		return nil, fmt.Errorf("generate random datagram: %w", err)
	}
	return p, nil
}

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
	binary.BigEndian.PutUint16(p[24:26], uint16(length-headerLength)|(1<<14))
	return p, nil
}
