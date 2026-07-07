package hnsutil

import (
	"encoding/hex"
	"testing"
)

func TestHash160AndBlake160Vectors(t *testing.T) {
	t.Parallel()

	pubKey, err := hex.DecodeString(
		"028eec61c7f625ee4bd415305cfc25396b1b083e70836386d0c0f2d50f33439b7c",
	)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}

	tests := []struct {
		name string
		hash []byte
		want string
	}{
		{
			name: "bitcoin hash160",
			hash: Hash160(pubKey),
			want: "2327cf756598d6b6c35275bd519744de5d003a39",
		},
		{
			name: "handshake blake160",
			hash: Blake160(pubKey),
			want: "ff1538413692fc752d0a5c26373f1c8141a764fe",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := hex.EncodeToString(test.hash); got != test.want {
				t.Fatalf("hash mismatch: got %s, want %s", got, test.want)
			}
		})
	}
}
