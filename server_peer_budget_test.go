// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "testing"

func TestTargetOutboundPeers(t *testing.T) {
	tests := []struct {
		name              string
		maxPeers          int
		permanentPeers    int
		automaticOutbound bool
		want              int
	}{
		{
			name:              "default",
			maxPeers:          125,
			automaticOutbound: true,
			want:              defaultTargetOutbound,
		},
		{
			name:              "permanent peers reserve capacity",
			maxPeers:          10,
			permanentPeers:    3,
			automaticOutbound: true,
			want:              7,
		},
		{
			name:           "connect only",
			maxPeers:       125,
			permanentPeers: 3,
			want:           0,
		},
		{
			name:              "permanent peers fill budget",
			maxPeers:          3,
			permanentPeers:    3,
			automaticOutbound: true,
			want:              0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := targetOutboundPeers(
				test.maxPeers, test.permanentPeers, test.automaticOutbound,
			)
			if got != test.want {
				t.Fatalf("target outbound: got %d, want %d", got, test.want)
			}
		})
	}
}

func TestReservedOutboundPeers(t *testing.T) {
	tests := []struct {
		name              string
		maxPeers          int
		targetOutbound    int
		permanentPeers    int
		automaticOutbound bool
		want              int
	}{
		{
			name:              "automatic and permanent",
			maxPeers:          125,
			targetOutbound:    8,
			permanentPeers:    2,
			automaticOutbound: true,
			want:              10,
		},
		{
			name:           "connect only",
			maxPeers:       125,
			targetOutbound: 8,
			permanentPeers: 2,
			want:           2,
		},
		{
			name:              "capped",
			maxPeers:          3,
			targetOutbound:    8,
			permanentPeers:    2,
			automaticOutbound: true,
			want:              3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := reservedOutboundPeers(test.maxPeers, test.targetOutbound,
				test.permanentPeers, test.automaticOutbound)
			if got != test.want {
				t.Fatalf("reserved outbound: got %d, want %d", got, test.want)
			}
		})
	}
}

func TestMaxInboundPeers(t *testing.T) {
	if got := maxInboundPeers(125, 10); got != 115 {
		t.Fatalf("max inbound: got %d, want 115", got)
	}
	if got := maxInboundPeers(3, 3); got != 0 {
		t.Fatalf("max inbound at capacity: got %d, want 0", got)
	}
}
