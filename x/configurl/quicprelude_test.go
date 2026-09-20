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

	"golang.getoutline.org/sdk/x/quicprelude"
)

func TestRegisterQUICPreludePacketListener(t *testing.T) {
	providers := NewDefaultProviders()
	pl, err := providers.NewPacketListener(context.Background(), "quicprelude:count=2&version=0x1a2a3a4a")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pl.(*quicprelude.PacketListener); !ok {
		t.Fatalf("got %T, want a *quicprelude.PacketListener", pl)
	}
}

func TestQUICPreludeConfigFromURL(t *testing.T) {
	tests := []struct {
		name    string
		options string
		want    quicprelude.Config
		wantErr bool
	}{
		{
			name:    "defaults",
			options: "",
			want:    quicprelude.NewConfig(),
		},
		{
			name:    "all options",
			options: "count=3&mode=random&length=1200",
			want:    quicprelude.Config{Count: 3, Mode: quicprelude.ModeRandom, Length: 1200, Version: quicprelude.DefaultVersion},
		},
		{
			name:    "hex version",
			options: "version=0xdeadbeef",
			want:    quicprelude.Config{Count: 1, Mode: quicprelude.ModeInvalidInitial, Length: quicprelude.DefaultLength, Version: 0xdeadbeef},
		},
		{
			name:    "hex version without prefix",
			options: "version=1a2a3a4a",
			want:    quicprelude.Config{Count: 1, Mode: quicprelude.ModeInvalidInitial, Length: quicprelude.DefaultLength, Version: 0x1a2a3a4a},
		},
		{
			name:    "version by name",
			options: "version=v2",
			want:    quicprelude.Config{Count: 1, Mode: quicprelude.ModeInvalidInitial, Length: quicprelude.DefaultLength, Version: quicprelude.Version2},
		},
		{name: "unknown option", options: "colour=blue", wantErr: true},
		{name: "repeated option", options: "count=1&count=2", wantErr: true},
		{name: "non-numeric count", options: "count=many", wantErr: true},
		{name: "non-numeric length", options: "length=big", wantErr: true},
		{name: "bad version", options: "version=zzz", wantErr: true},
		{name: "zero version", options: "version=0x0", wantErr: true},
		{name: "unknown mode", options: "mode=handshake", wantErr: true},
		{name: "undersized initial", options: "length=100", wantErr: true},
		{name: "negative count", options: "count=-1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := ParseConfig("quicprelude:" + tt.options)
			if err != nil {
				t.Fatal(err)
			}
			got, err := newQUICPreludeConfigFromURL(config.URL)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Errorf("config = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestQUICPreludeWrapsBaseListener(t *testing.T) {
	providers := NewDefaultProviders()
	// The prelude must be able to sit above another packet listener, which is
	// how it shares a four-tuple with proxied traffic.
	_, err := providers.NewPacketListener(context.Background(),
		"ss://ChaCha20-IETF-Poly1305:password@example.com:1234|quicprelude:count=1")
	if err != nil {
		t.Fatalf("failed to build a prelude over a base listener: %v", err)
	}
}
