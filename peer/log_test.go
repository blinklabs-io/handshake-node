// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestMessageSummaryHnsRejectIncludesHash(t *testing.T) {
	t.Parallel()

	hash := chainhash.Hash{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c,
		0x1d, 0x1e, 0x1f, 0x20,
	}
	wantHashSummary := fmt.Sprintf(", hash %v", hash)

	tests := []struct {
		name    string
		msgType wire.HnsMsgType
	}{
		{name: "block", msgType: wire.HnsMsgTypeBlock},
		{name: "tx", msgType: wire.HnsMsgTypeTx},
		{name: "claim", msgType: wire.HnsMsgTypeClaim},
		{name: "airdrop", msgType: wire.HnsMsgTypeAirDrop},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			reject := &wire.HnsMsgReject{
				Message: test.msgType,
				Code:    wire.RejectInvalid,
				Reason:  "invalid object",
			}
			copy(reject.Hash[:], hash[:])

			summary := messageSummary(reject)
			if !strings.Contains(summary, wantHashSummary) {
				t.Fatalf("reject summary missing hash:\n got %q\nwant substring %q",
					summary, wantHashSummary)
			}
		})
	}
}

func TestMessageSummaryHnsRejectOmitsHashWhenUnused(t *testing.T) {
	t.Parallel()

	reject := &wire.HnsMsgReject{
		Message: wire.HnsMsgTypeVersion,
		Code:    wire.RejectObsolete,
		Reason:  "old version",
	}

	summary := messageSummary(reject)
	if strings.Contains(summary, ", hash ") {
		t.Fatalf("reject summary unexpectedly included hash: %q", summary)
	}
}
