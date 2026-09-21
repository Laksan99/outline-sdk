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
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/quicprelude"
)

func registerQUICPreludePacketListener(r TypeRegistry[transport.PacketListener], typeID string, newPL BuildFunc[transport.PacketListener]) {
	r.RegisterType(typeID, func(ctx context.Context, config *Config) (transport.PacketListener, error) {
		inner, err := newPL(ctx, config.BaseConfig)
		if err != nil {
			return nil, err
		}
		preludeConfig, err := newQUICPreludeConfigFromURL(config.URL)
		if err != nil {
			return nil, err
		}
		return preludeConfig.NewPacketListener(inner)
	})
}

// quicPreludeOptions holds the options as written in the config string, before
// they are turned into a generator.
type quicPreludeOptions struct {
	count   int
	mode    string
	length  int
	version uint32
}

func newQUICPreludeConfigFromURL(configURL url.URL) (*quicprelude.Config, error) {
	options := quicPreludeOptions{
		count:   1,
		mode:    "invalid-initial",
		length:  quicprelude.MatchPacketLength,
		version: quicprelude.DefaultVersion,
	}

	values, err := url.ParseQuery(configURL.Opaque)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	for key, vs := range values {
		if len(vs) != 1 {
			return nil, fmt.Errorf("option %v must have exactly one value, found %v", key, len(vs))
		}
		value := vs[0]
		switch strings.ToLower(key) {
		case "count":
			if options.count, err = strconv.Atoi(value); err != nil {
				return nil, fmt.Errorf("invalid count %q: %w", value, err)
			}
		case "mode":
			options.mode = strings.ToLower(value)
		case "length":
			if options.length, err = strconv.Atoi(value); err != nil {
				return nil, fmt.Errorf("invalid length %q: %w", value, err)
			}
		case "version":
			if options.version, err = parseQUICVersionCodepoint(value); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported option %v", key)
		}
	}
	generator, err := newQUICPreludeGenerator(options)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	// count is applied by repeating the generator, so count=0 disables the
	// prelude without needing a separate switch.
	generator, err = quicprelude.Repeat(options.count, generator)
	if err != nil {
		return nil, fmt.Errorf("invalid quicprelude options: %w", err)
	}
	return quicprelude.NewConfig().WithGenerator(generator), nil
}

func newQUICPreludeGenerator(options quicPreludeOptions) (quicprelude.Generator, error) {
	switch options.mode {
	case "invalid-initial":
		return quicprelude.InvalidInitial(options.version, options.length)
	case "random":
		return quicprelude.Random(options.length)
	default:
		return nil, fmt.Errorf("unknown mode %q, want invalid-initial or random", options.mode)
	}
}

// parseQUICVersionCodepoint accepts a 32-bit wire codepoint, in hexadecimal
// with an optional 0x prefix, or the names "v1" and "v2".
func parseQUICVersionCodepoint(value string) (uint32, error) {
	switch strings.ToLower(value) {
	case "v1":
		return quicprelude.Version1, nil
	case "v2":
		return quicprelude.Version2, nil
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	v, err := strconv.ParseUint(trimmed, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid version %q: want a 32-bit hex codepoint such as 0x1a2a3a4a, or v1 or v2", value)
	}
	return uint32(v), nil
}
