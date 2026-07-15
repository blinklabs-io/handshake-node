// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build rpctest
// +build rpctest

package integration

import (
	"encoding/json"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/integration/rpctest"
	"github.com/blinklabs-io/handshake-node/rpcclient"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
)

// TestTestMempoolAccept checks typed parameter validation, malformed wire data,
// context-free rejection, orphan handling, fee limits, and mixed results for
// the TestMempoolAccept RPC.
func TestTestMempoolAccept(t *testing.T) {
	t.Parallel()

	// Enable standardness checks so the test exercises mainnet-style mempool
	// policy on the regtest harness.
	hnsCfg := []string{"--rejectnonstd", "--debuglevel=debug"}
	r, err := rpctest.New(&chaincfg.RegressionNetParams, nil, hnsCfg, "")
	require.NoError(t, err)

	// Setup the node.
	require.NoError(t, r.SetUp(true, 100))
	t.Cleanup(func() {
		require.NoError(t, r.TearDown())
	})

	// Create a fully signed Handshake witness transaction, then copy it and
	// replace its input with an unknown outpoint to produce a well-formed
	// orphan without relying on an inherited Bitcoin serialization fixture.
	validTx := createTestTx(t, r)
	require.NotEqual(t, validTx.TxHash(), validTx.WitnessHash())
	orphanTx := validTx.Copy()
	orphanTx.TxIn[0].PreviousOutPoint = wire.OutPoint{
		Hash:  chainhash.Hash{0xff},
		Index: 0,
	}
	invalidTx := wire.NewMsgTx(wire.TxVersion)
	for range 2 {
		invalidTx.AddTxOut(wire.NewTxOut(
			validTx.TxOut[0].Value,
			validTx.TxOut[0].Address,
			wire.Covenant{},
		))
	}

	// The typed client only accepts MsgTx values and therefore cannot send
	// malformed wire bytes. Exercise the server's deserialization failure via
	// a raw request so syntactic and consensus-invalid transactions remain
	// distinct cases.
	t.Run("malformed raw tx", func(t *testing.T) {
		_, err := r.Client.RawRequest("testmempoolaccept", []json.RawMessage{
			json.RawMessage(`["00"]`),
			json.RawMessage(`0`),
		})

		var rpcErr *hnsjson.RPCError
		require.ErrorAs(t, err, &rpcErr)
		require.Equal(t, hnsjson.ErrRPCDeserialization, rpcErr.Code)
		require.Contains(t, rpcErr.Message, "TX decode failed")
	})

	testCases := []struct {
		name           string
		txns           []*wire.MsgTx
		maxFeeRate     float64
		expectedErr    error
		expectedResult []*hnsjson.TestMempoolAcceptResult
	}{
		{
			// When too many txns are provided, the method should
			// return an error.
			name:           "too many txns",
			txns:           make([]*wire.MsgTx, 26),
			maxFeeRate:     0,
			expectedErr:    rpcclient.ErrInvalidParam,
			expectedResult: nil,
		},
		{
			// When no txns are provided, the method should return
			// an error.
			name:           "empty txns",
			txns:           nil,
			maxFeeRate:     0,
			expectedErr:    rpcclient.ErrInvalidParam,
			expectedResult: nil,
		},
		{
			// A syntactically valid transaction that fails context-free
			// consensus checks receives an ordinary rejection result.
			name:       "consensus invalid tx",
			txns:       []*wire.MsgTx{invalidTx},
			maxFeeRate: 0,
			expectedResult: []*hnsjson.TestMempoolAcceptResult{{
				Txid:         invalidTx.TxHash().String(),
				Wtxid:        invalidTx.WitnessHash().String(),
				Allowed:      false,
				RejectReason: "transaction has no inputs",
			}},
		},
		{
			// When an orphan tx is provided, the method should
			// return a test mempool accept result which says this
			// tx is not allowed.
			name:       "orphan tx",
			txns:       []*wire.MsgTx{orphanTx},
			maxFeeRate: 0,
			expectedResult: []*hnsjson.TestMempoolAcceptResult{{
				Txid:         orphanTx.TxHash().String(),
				Wtxid:        orphanTx.WitnessHash().String(),
				Allowed:      false,
				RejectReason: "missing-inputs",
			}},
		},
		{
			// When a valid tx is provided but it exceeds the max
			// fee rate, the method should return a test mempool
			// accept result which says it's not allowed.
			name:       "valid tx but exceeds max fee rate",
			txns:       []*wire.MsgTx{validTx},
			maxFeeRate: 1e-5,
			expectedResult: []*hnsjson.TestMempoolAcceptResult{{
				Txid:         validTx.TxHash().String(),
				Wtxid:        validTx.WitnessHash().String(),
				Allowed:      false,
				RejectReason: "max-fee-exceeded",
			}},
		},
		{
			// When a valid tx is provided and it doesn't exceed
			// the max fee rate, the method should return a test
			// mempool accept result which says it's allowed.
			name: "valid tx and sane fee rate",
			txns: []*wire.MsgTx{validTx},
			expectedResult: []*hnsjson.TestMempoolAcceptResult{{
				Txid:    validTx.TxHash().String(),
				Wtxid:   validTx.WitnessHash().String(),
				Allowed: true,
			}},
		},
		{
			// When multiple txns are provided, the method should
			// return the correct results for each of the txns.
			name: "multiple txns",
			txns: []*wire.MsgTx{orphanTx, validTx},
			expectedResult: []*hnsjson.TestMempoolAcceptResult{{
				Txid:         orphanTx.TxHash().String(),
				Wtxid:        orphanTx.WitnessHash().String(),
				Allowed:      false,
				RejectReason: "missing-inputs",
			}, {
				Txid:    validTx.TxHash().String(),
				Wtxid:   validTx.WitnessHash().String(),
				Allowed: true,
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			results, err := r.Client.TestMempoolAccept(
				tc.txns, tc.maxFeeRate,
			)

			require.ErrorIs(err, tc.expectedErr)
			require.Len(results, len(tc.expectedResult))

			// Check each item is returned as expected.
			for i, result := range results {
				expected := tc.expectedResult[i]

				require.Equal(expected.Txid, result.Txid)
				require.Equal(expected.Wtxid, result.Wtxid)
				require.Equal(expected.Allowed, result.Allowed)
				require.Equal(expected.RejectReason,
					result.RejectReason)
				require.Empty(result.PackageError)
				if expected.Allowed {
					require.Positive(result.Vsize)
					require.NotNil(result.Fees)
					require.Positive(result.Fees.Base)
					require.Positive(result.Fees.EffectiveFeeRate)
				} else {
					require.Zero(result.Vsize)
					require.Nil(result.Fees)
				}
			}
		})
	}
}

// createTestTx creates a `wire.MsgTx` and asserts its creation.
func createTestTx(t *testing.T, h *rpctest.Harness) *wire.MsgTx {
	output := &wire.TxOut{
		Address: testWitnessPubKeyHashAddress(t, h.ActiveNet),
		Value:   1e6,
	}

	tx, err := h.CreateTransaction([]*wire.TxOut{output}, 10, true)
	require.NoError(t, err)

	return tx
}
