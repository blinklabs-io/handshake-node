// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package version

import "testing"

func TestBuildVersion(t *testing.T) {
	originalVersion := Version
	originalCommitHash := CommitHash
	t.Cleanup(func() {
		Version = originalVersion
		CommitHash = originalCommitHash
	})

	tests := []struct {
		name       string
		version    string
		commitHash string
		wantString string
		wantSemver string
		wantRPC    int32
	}{
		{
			name:       "development build",
			commitHash: "abc1234",
			wantString: "devel (commit abc1234)",
			wantSemver: "devel",
		},
		{
			name:       "tagged release",
			version:    "v0.5.0",
			commitHash: "abc1234",
			wantString: "v0.5.0 (commit abc1234)",
			wantSemver: "0.5.0",
			wantRPC:    50_000,
		},
		{
			name:       "release candidate",
			version:    "v1.2.3-rc1",
			wantString: "v1.2.3-rc1",
			wantSemver: "1.2.3-rc1",
			wantRPC:    1_020_300,
		},
		{
			name:       "invalid tag",
			version:    "not-semver",
			wantString: "not-semver",
			wantSemver: "not-semver",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			Version = test.version
			CommitHash = test.commitHash
			if got := String(); got != test.wantString {
				t.Fatalf("String() = %q, want %q", got, test.wantString)
			}
			if got := Semantic(); got != test.wantSemver {
				t.Fatalf("Semantic() = %q, want %q", got, test.wantSemver)
			}
			if got := RPC(); got != test.wantRPC {
				t.Fatalf("RPC() = %d, want %d", got, test.wantRPC)
			}
		})
	}
}
