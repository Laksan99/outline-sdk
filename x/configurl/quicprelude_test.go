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

package configurl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/x/quicprelude"
)

// parsePreludeOptions parses the options of a quicprelude config.
func parsePreludeOptions(t *testing.T, options string) (quicprelude.Config, error) {
	t.Helper()
	config, err := ParseConfig("quicprelude:" + options)
	require.NoError(t, err)
	return newQUICPreludeConfigFromURL(config.URL)
}

func TestRegisterQUICPreludePacketListener(t *testing.T) {
	providers := NewDefaultProviders()

	pl, err := providers.NewPacketListener(context.Background(), "quicprelude:count=2&version=0x1a2a3a4a")
	require.NoError(t, err)
	require.IsType(t, &quicprelude.PacketListener{}, pl)

	// The prelude must sit above another packet listener, which is how it shares
	// a four-tuple with proxied traffic.
	_, err = providers.NewPacketListener(context.Background(),
		"ss://ChaCha20-IETF-Poly1305:password@example.com:1234|quicprelude:count=1")
	require.NoError(t, err)
}

func TestQUICPreludeOptionsDefault(t *testing.T) {
	config, err := parsePreludeOptions(t, "")
	require.NoError(t, err)
	require.Equal(t, quicprelude.NewConfig(), config)
}

func TestQUICPreludeOptionCount(t *testing.T) {
	config, err := parsePreludeOptions(t, "count=3")
	require.NoError(t, err)
	require.Equal(t, 3, config.Count)

	// Zero disables the prelude, and the other options stop mattering.
	config, err = parsePreludeOptions(t, "count=0")
	require.NoError(t, err)
	require.Equal(t, 0, config.Count)

	_, err = parsePreludeOptions(t, "count=-1")
	require.Error(t, err)

	_, err = parsePreludeOptions(t, "count=many")
	require.Error(t, err)
}

func TestQUICPreludeOptionMode(t *testing.T) {
	config, err := parsePreludeOptions(t, "mode=random&length=1200")
	require.NoError(t, err)
	require.Equal(t, quicprelude.ModeRandom, config.Mode)

	config, err = parsePreludeOptions(t, "mode=invalid-initial")
	require.NoError(t, err)
	require.Equal(t, quicprelude.ModeInvalidInitial, config.Mode)

	_, err = parsePreludeOptions(t, "mode=handshake")
	require.Error(t, err)
}

func TestQUICPreludeOptionLength(t *testing.T) {
	config, err := parsePreludeOptions(t, "length=1300")
	require.NoError(t, err)
	require.Equal(t, 1300, config.Length)

	// An Initial-shaped datagram has an RFC 9000 minimum size.
	_, err = parsePreludeOptions(t, "length=100")
	require.Error(t, err)

	_, err = parsePreludeOptions(t, "length=big")
	require.Error(t, err)
}

func TestQUICPreludeOptionVersion(t *testing.T) {
	config, err := parsePreludeOptions(t, "version=0xdeadbeef")
	require.NoError(t, err)
	require.Equal(t, uint32(0xdeadbeef), config.Version)

	// The 0x prefix is optional.
	config, err = parsePreludeOptions(t, "version=1a2a3a4a")
	require.NoError(t, err)
	require.Equal(t, uint32(0x1a2a3a4a), config.Version)

	config, err = parsePreludeOptions(t, "version=v1")
	require.NoError(t, err)
	require.Equal(t, quicprelude.Version1, config.Version)

	config, err = parsePreludeOptions(t, "version=v2")
	require.NoError(t, err)
	require.Equal(t, quicprelude.Version2, config.Version)

	// Version zero denotes Version Negotiation and is not a prelude version.
	_, err = parsePreludeOptions(t, "version=0x0")
	require.Error(t, err)

	_, err = parsePreludeOptions(t, "version=zzz")
	require.Error(t, err)
}

func TestQUICPreludeRejectsUnknownAndRepeatedOptions(t *testing.T) {
	_, err := parsePreludeOptions(t, "colour=blue")
	require.Error(t, err)

	_, err = parsePreludeOptions(t, "count=1&count=2")
	require.Error(t, err)
}
