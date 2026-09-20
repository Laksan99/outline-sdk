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
	"bytes"
	"testing"
)

func TestNewConfigIsValid(t *testing.T) {
	c := NewConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("NewConfig() is not valid: %v", err)
	}
	if c.Version != DefaultVersion {
		t.Errorf("Version = %#x, want %#x", c.Version, DefaultVersion)
	}
	if c.Length != DefaultLength {
		t.Errorf("Length = %d, want %d", c.Length, DefaultLength)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "disabled", config: Config{Count: 0}},
		{name: "disabled ignores other fields", config: Config{Count: 0, Mode: "nonsense"}},
		{name: "negative count", config: Config{Count: -1}, wantErr: true},
		{name: "random", config: Config{Count: 1, Mode: ModeRandom, Length: 1}},
		{name: "random zero length", config: Config{Count: 1, Mode: ModeRandom}, wantErr: true},
		{name: "initial", config: Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: DefaultVersion}},
		{name: "initial at minimum", config: Config{Count: 1, Mode: ModeInvalidInitial, Length: MinimumInitialLength, Version: Version1}},
		{name: "initial too short", config: Config{Count: 1, Mode: ModeInvalidInitial, Length: MinimumInitialLength - 1, Version: Version1}, wantErr: true},
		{name: "initial too long for two-byte varint", config: Config{Count: 1, Mode: ModeInvalidInitial, Length: headerLength + (1 << 14), Version: Version1}, wantErr: true},
		{name: "initial zero version", config: Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280}, wantErr: true},
		{name: "unknown mode", config: Config{Count: 1, Mode: "handshake", Length: 1280}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDatagramInvalidInitial(t *testing.T) {
	tests := []struct {
		name     string
		version  uint32
		typeBits byte
	}{
		{name: "v1 uses Initial type 0b00", version: Version1, typeBits: 0x00},
		{name: "v2 uses Initial type 0b01", version: Version2, typeBits: 0x10},
		{name: "greased uses the v1 layout", version: DefaultVersion, typeBits: 0x00},
		{name: "arbitrary uses the v1 layout", version: 0xdeadbeef, typeBits: 0x00},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{Count: 1, Mode: ModeInvalidInitial, Length: 1280, Version: tt.version}
			p, err := config.Datagram()
			if err != nil {
				t.Fatal(err)
			}
			if len(p) != 1280 {
				t.Fatalf("length = %d, want 1280", len(p))
			}
			if p[0]&0xc0 != 0xc0 {
				t.Errorf("first byte %#x does not set the long-header and fixed bits", p[0])
			}
			if got := p[0] & 0x30; got != tt.typeBits {
				t.Errorf("long packet type = %#x, want %#x", got, tt.typeBits)
			}
			if got := uint32(p[1])<<24 | uint32(p[2])<<16 | uint32(p[3])<<8 | uint32(p[4]); got != tt.version {
				t.Errorf("version = %#x, want %#x", got, tt.version)
			}
			if p[5] != connectionIDLength || p[14] != connectionIDLength || p[23] != 0 {
				t.Errorf("unexpected dcid=%d scid=%d token=%d", p[5], p[14], p[23])
			}
			if p[24]&0xc0 != 0x40 {
				t.Errorf("length field %#x is not a two-byte varint", p[24])
			}
			if got, want := int(p[24]&0x3f)<<8|int(p[25]), len(p)-headerLength; got != want {
				t.Errorf("protected length = %d, want %d", got, want)
			}
		})
	}
}

func TestDatagramsDifferBetweenCalls(t *testing.T) {
	config := NewConfig()
	first, err := config.Datagram()
	if err != nil {
		t.Fatal(err)
	}
	second, err := config.Datagram()
	if err != nil {
		t.Fatal(err)
	}
	// Connection IDs and payload are random, so two datagrams must not match.
	if bytes.Equal(first, second) {
		t.Error("two datagrams are identical; connection IDs should be random")
	}
	if bytes.Equal(first[6:14], second[6:14]) {
		t.Error("destination connection IDs are identical")
	}
}

func TestDatagramRandomModeIsNotInitialShaped(t *testing.T) {
	config := Config{Count: 1, Mode: ModeRandom, Length: 1280}
	// The first byte is random, so check over enough samples that a datagram
	// which always looked like a long header would be caught.
	sawNonLongHeader := false
	for i := 0; i < 64; i++ {
		p, err := config.Datagram()
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 1280 {
			t.Fatalf("length = %d, want 1280", len(p))
		}
		if p[0]&0xc0 != 0xc0 {
			sawNonLongHeader = true
		}
	}
	if !sawNonLongHeader {
		t.Error("every random datagram set the long-header bits; bytes are not random")
	}
}

func TestDatagramRejectsInvalidConfig(t *testing.T) {
	if _, err := (Config{Count: 1, Mode: ModeInvalidInitial, Length: 100}).Datagram(); err == nil {
		t.Error("expected an error for an undersized Initial")
	}
}
