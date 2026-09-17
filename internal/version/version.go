// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is populated from the exact Git tag at build time.
var Version string

// CommitHash is populated from the Git revision at build time.
var CommitHash string

// String returns the build version and revision.
func String() string {
	version := Version
	if version == "" {
		version = "devel"
	}
	if CommitHash == "" {
		return version
	}
	return fmt.Sprintf("%s (commit %s)", version, CommitHash)
}

// Semantic returns the tag without its conventional v prefix.
func Semantic() string {
	if Version == "" {
		return "devel"
	}
	return strings.TrimPrefix(Version, "v")
}

// RPC returns the numeric version used by Handshake RPC responses.
func RPC() int32 {
	core := strings.TrimPrefix(Version, "v")
	core, _, _ = strings.Cut(core, "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return 0
	}

	values := [3]int64{}
	for i, part := range parts {
		value, err := strconv.ParseInt(part, 10, 32)
		if err != nil || value < 0 || value > 99 {
			return 0
		}
		values[i] = value
	}
	return int32(1_000_000*values[0] + 10_000*values[1] + 100*values[2])
}
