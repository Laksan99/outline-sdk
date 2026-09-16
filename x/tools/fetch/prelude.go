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

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

type quicPreludeMode string

const (
	quicPreludeRandom        quicPreludeMode = "random"
	quicPreludeV1Invalid     quicPreludeMode = "quic-v1-invalid"
	quicPreludeV2Invalid     quicPreludeMode = "quic-v2-invalid"
	quicPreludeValidV2       quicPreludeMode = "valid-v2"
	minimumQUICPreludeLength                 = 1200
)

type quicPreludeConfig struct {
	count int
	mode  quicPreludeMode
	size  int
	sni   string
}

func (c quicPreludeConfig) validate() error {
	if c.count < 0 {
		return fmt.Errorf("prelude count must not be negative")
	}
	if c.count == 0 {
		return nil
	}
	switch c.mode {
	case quicPreludeRandom:
		if c.size <= 0 {
			return fmt.Errorf("random prelude size must be positive")
		}
	case quicPreludeV1Invalid, quicPreludeV2Invalid:
		if c.size < minimumQUICPreludeLength {
			return fmt.Errorf("QUIC-shaped prelude size must be at least %d bytes", minimumQUICPreludeLength)
		}
	case quicPreludeValidV2:
		if c.sni == "" {
			return fmt.Errorf("valid-v2 prelude requires a non-empty SNI")
		}
	default:
		return fmt.Errorf("unknown QUIC prelude mode %q", c.mode)
	}
	return nil
}

func randomDatagram(size int) ([]byte, error) {
	p := make([]byte, size)
	if _, err := rand.Read(p); err != nil {
		return nil, fmt.Errorf("generate random prelude: %w", err)
	}
	return p, nil
}

// quicShapedInvalidInitial returns a syntactically Initial-shaped datagram with
// random protected bytes and an intentionally invalid authentication tag. It is
// useful for distinguishing recognition of the invariant/long-header structure
// from successful Initial decryption. It is not a valid QUIC packet.
func quicShapedInvalidInitial(version quic.Version, size int) ([]byte, error) {
	if size < minimumQUICPreludeLength {
		return nil, fmt.Errorf("QUIC-shaped prelude size must be at least %d bytes", minimumQUICPreludeLength)
	}
	p, err := randomDatagram(size)
	if err != nil {
		return nil, err
	}

	// Header Form and Fixed Bit are set. QUIC v1 encodes Initial as type 0b00;
	// QUIC v2 encodes Initial as type 0b01. The protected low nibble and packet
	// number bytes remain random, mimicking header protection without producing a
	// valid AEAD tag.
	switch version {
	case quic.Version1:
		p[0] = 0xc0 | (p[0] & 0x0f)
	case quic.Version2:
		p[0] = 0xd0 | (p[0] & 0x0f)
	default:
		return nil, fmt.Errorf("unsupported QUIC prelude version %v", version)
	}
	binary.BigEndian.PutUint32(p[1:5], uint32(version))

	const connectionIDLength = 8
	p[5] = connectionIDLength
	// p[6:14] is the random Destination Connection ID.
	p[14] = connectionIDLength
	// p[15:23] is the random Source Connection ID.
	p[23] = 0 // zero-length token

	// Use a two-byte QUIC varint for the protected payload length.
	protectedLength := size - 26
	if protectedLength <= 0 || protectedLength >= 1<<14 {
		return nil, fmt.Errorf("unsupported QUIC-shaped prelude size %d", size)
	}
	binary.BigEndian.PutUint16(p[24:26], uint16(protectedLength)|(1<<14))
	return p, nil
}

func sendDatagramPreludes(conn net.PacketConn, addr net.Addr, config quicPreludeConfig) error {
	for i := 0; i < config.count; i++ {
		var (
			payload []byte
			err     error
		)
		switch config.mode {
		case quicPreludeRandom:
			payload, err = randomDatagram(config.size)
		case quicPreludeV1Invalid:
			payload, err = quicShapedInvalidInitial(quic.Version1, config.size)
		case quicPreludeV2Invalid:
			payload, err = quicShapedInvalidInitial(quic.Version2, config.size)
		default:
			return fmt.Errorf("prelude mode %q does not produce raw datagrams", config.mode)
		}
		if err != nil {
			return err
		}
		if _, err := conn.WriteTo(payload, addr); err != nil {
			return fmt.Errorf("send prelude datagram %d: %w", i+1, err)
		}
	}
	return nil
}
