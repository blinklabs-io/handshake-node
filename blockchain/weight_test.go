// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2026 The handshake-node developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestGetSigOpCostPropagatesP2SHLookupError(t *testing.T) {
	prevHash := chainhash.Hash{0x01}
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&prevHash, 0),
		wire.MaxTxInSequenceNum,
		nil,
	))

	_, err := GetSigOpCost(
		hnsutil.NewTx(tx),
		false,
		NewUtxoViewpoint(),
		true,
		false,
	)
	ruleErr, ok := err.(RuleError)
	if !ok || ruleErr.ErrorCode != ErrMissingTxOut {
		t.Fatalf(
			"GetSigOpCost error = %T %v, want ErrMissingTxOut",
			err,
			err,
		)
	}
}
