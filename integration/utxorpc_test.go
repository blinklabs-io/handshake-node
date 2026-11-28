// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build rpctest
// +build rpctest

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/integration/rpctest"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
	querypb "github.com/utxorpc/go-codegen/utxorpc/v1beta/query"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/query/queryconnect"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/submit/submitconnect"
	syncpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/sync"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/sync/syncconnect"
)

// utxorpcHarness is a regtest node with the UTxO RPC server enabled,
// paired with clients that reach it over the node's own TLS keypair.
type utxorpcHarness struct {
	*rpctest.Harness

	addr   string
	sync   syncconnect.SyncServiceClient
	query  queryconnect.QueryServiceClient
	submit submitconnect.SubmitServiceClient
}

// freeLoopbackPort reserves a loopback port and releases it so the node
// can bind it.
func freeLoopbackPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

func setupUtxorpcHarness(t *testing.T, matureOutputs uint32) *utxorpcHarness {
	t.Helper()

	addr := freeLoopbackPort(t)
	harness, err := rpctest.New(
		&chaincfg.RegressionNetParams,
		nil,
		[]string{
			"--utxorpclisten=" + addr,
			"--txindex",
		},
		"",
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = harness.TearDown() })
	require.NoError(t, harness.SetUp(true, matureOutputs))

	// The UTxO RPC listener shares the node's RPC keypair, so the
	// harness certificate is the right trust root for these clients.
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(harness.RPCConfig().Certificates))

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	url := "https://" + addr

	return &utxorpcHarness{
		Harness: harness,
		addr:    addr,
		sync:    syncconnect.NewSyncServiceClient(client, url),
		query:   queryconnect.NewQueryServiceClient(client, url),
		submit:  submitconnect.NewSubmitServiceClient(client, url),
	}
}

// TestUtxorpcSyncService drives the sync service against a live node.
func TestUtxorpcSyncService(t *testing.T) {
	h := setupUtxorpcHarness(t, 25)
	ctx := t.Context()

	tip, err := h.sync.ReadTip(ctx,
		connect.NewRequest(&syncpb.ReadTipRequest{}))
	require.NoError(t, err)
	t.Logf("ReadTip: height=%d slot=%d hash=%x timestamp=%d",
		tip.Msg.GetTip().GetHeight(), tip.Msg.GetTip().GetSlot(),
		tip.Msg.GetTip().GetHash(), tip.Msg.GetTip().GetTimestamp())

	best, err := h.Client.GetBestBlockHash()
	require.NoError(t, err)
	require.Equal(t, best[:], tip.Msg.GetTip().GetHash())

	// FetchBlock by height, by hash, and the implicit tip.
	fetched, err := h.sync.FetchBlock(ctx,
		connect.NewRequest(&syncpb.FetchBlockRequest{
			Ref: []*syncpb.BlockRef{
				{Height: 1},
				{Hash: tip.Msg.GetTip().GetHash()},
			},
		}))
	require.NoError(t, err)
	require.Len(t, fetched.Msg.GetBlock(), 2)
	for i, anyBlock := range fetched.Msg.GetBlock() {
		block, err := hnsutil.NewBlockFromBytes(anyBlock.GetNativeBytes())
		require.NoError(t, err)
		t.Logf("FetchBlock[%d]: hash=%s txs=%d native_bytes=%d",
			i, block.Hash(), len(block.MsgBlock().Transactions),
			len(anyBlock.GetNativeBytes()))
	}

	tipOnly, err := h.sync.FetchBlock(ctx,
		connect.NewRequest(&syncpb.FetchBlockRequest{}))
	require.NoError(t, err)
	require.Len(t, tipOnly.Msg.GetBlock(), 1)
	tipBlock, err := hnsutil.NewBlockFromBytes(
		tipOnly.Msg.GetBlock()[0].GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, tip.Msg.GetTip().GetHash(), tipBlock.Hash().CloneBytes())
	t.Logf("FetchBlock(no ref): resolved tip %s", tipBlock.Hash())

	// DumpHistory pages forward through the chain.
	var pages, blocks int
	var token *syncpb.BlockRef
	for {
		page, err := h.sync.DumpHistory(ctx,
			connect.NewRequest(&syncpb.DumpHistoryRequest{
				StartToken: token,
				MaxItems:   5,
			}))
		require.NoError(t, err)
		pages++
		blocks += len(page.Msg.GetBlock())
		if pages == 1 {
			first, err := hnsutil.NewBlockFromBytes(
				page.Msg.GetBlock()[0].GetNativeBytes())
			require.NoError(t, err)
			t.Logf("DumpHistory page 1: %d blocks, first=%s next_token=%d",
				len(page.Msg.GetBlock()), first.Hash(),
				page.Msg.GetNextToken().GetHeight())
		}
		token = page.Msg.GetNextToken()
		if token == nil {
			break
		}
	}
	require.EqualValues(t, tip.Msg.GetTip().GetHeight()+1, uint64(blocks))
	t.Logf("DumpHistory: %d blocks over %d pages of 5", blocks, pages)

	// FollowTip resets to the current tip, then streams a mined block.
	stream, err := h.sync.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{}))
	require.NoError(t, err)
	require.True(t, stream.Receive(), "follow tip reset: %v", stream.Err())
	require.Equal(t, tip.Msg.GetTip().GetHash(),
		stream.Msg().GetReset_().GetHash())
	t.Logf("FollowTip: reset to height=%d hash=%x",
		stream.Msg().GetReset_().GetHeight(),
		stream.Msg().GetReset_().GetHash())

	mined, err := h.Client.Generate(1)
	require.NoError(t, err)
	require.True(t, stream.Receive(), "follow tip apply: %v", stream.Err())
	applied, err := hnsutil.NewBlockFromBytes(
		stream.Msg().GetApply().GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, mined[0][:], applied.Hash().CloneBytes())
	// AnyChainBlock carries no height, and height is not part of the
	// wire encoding, so a client learns the position from the tip
	// reference travelling with the response.
	t.Logf("FollowTip: apply hash=%s txs=%d native_bytes=%d tip_height=%d",
		applied.Hash(), len(applied.MsgBlock().Transactions),
		len(stream.Msg().GetApply().GetNativeBytes()),
		stream.Msg().GetTip().GetHeight())
	require.NoError(t, stream.Close())
}

// TestUtxorpcQueryService drives the query service against a live node.
func TestUtxorpcQueryService(t *testing.T) {
	h := setupUtxorpcHarness(t, 25)
	ctx := t.Context()

	genesis, err := h.query.ReadGenesis(ctx,
		connect.NewRequest(&querypb.ReadGenesisRequest{}))
	require.NoError(t, err)
	require.Equal(t, chaincfg.RegressionNetParams.GenesisHash.CloneBytes(),
		genesis.Msg.GetGenesis())
	require.Equal(t, "handshake:regtest", genesis.Msg.GetCaip2())
	t.Logf("ReadGenesis: caip2=%s genesis=%x",
		genesis.Msg.GetCaip2(), genesis.Msg.GetGenesis())

	// A coinbase from an early block gives a real confirmed output.
	blockHash, err := h.Client.GetBlockHash(2)
	require.NoError(t, err)
	block, err := h.Client.GetBlock(blockHash)
	require.NoError(t, err)
	coinbase := hnsutil.NewTx(block.Transactions[0])

	readTx, err := h.query.ReadTx(ctx,
		connect.NewRequest(&querypb.ReadTxRequest{
			Hash: coinbase.Hash().CloneBytes(),
		}))
	require.NoError(t, err)
	var decoded wire.MsgTx
	require.NoError(t, decoded.Deserialize(
		bytes.NewReader(readTx.Msg.GetTx().GetNativeBytes())))
	require.Equal(t, *coinbase.Hash(), decoded.TxHash())
	t.Logf("ReadTx: hash=%s vin=%d vout=%d block_height=%d ledger_tip=%d",
		decoded.TxHash(), len(decoded.TxIn), len(decoded.TxOut),
		readTx.Msg.GetTx().GetBlockRef().GetHeight(),
		readTx.Msg.GetLedgerTip().GetHeight())

	// Read that coinbase's outputs back out of the UTxO set, alongside
	// an outpoint that does not exist.
	keys := []*querypb.TxoRef{
		{Hash: coinbase.Hash().CloneBytes(), Index: 0},
		{Hash: coinbase.Hash().CloneBytes(), Index: 99},
	}
	utxos, err := h.query.ReadUtxos(ctx,
		connect.NewRequest(&querypb.ReadUtxosRequest{Keys: keys}))
	require.NoError(t, err)
	require.Len(t, utxos.Msg.GetItems(), 1, "unknown outpoint must be skipped")

	item := utxos.Msg.GetItems()[0]
	var txOut wire.TxOut
	require.NoError(t, wire.ReadTxOut(
		bytes.NewReader(item.GetNativeBytes()),
		wire.ProtocolVersion, wire.TxVersion, &txOut))
	require.Equal(t, block.Transactions[0].TxOut[0].Value, txOut.Value)
	t.Logf("ReadUtxos: %d of %d keys resolved; "+
		"value=%d block_height=%d covenant_type=%d ledger_tip=%d",
		len(utxos.Msg.GetItems()), len(keys), txOut.Value,
		item.GetBlockRef().GetHeight(), txOut.Covenant.Type,
		utxos.Msg.GetLedgerTip().GetHeight())
}

// newSpend builds and signs a real transaction with the harness
// wallet, returning it alongside its wire encoding.
func newSpend(t *testing.T, h *utxorpcHarness, value int64) (*wire.MsgTx, []byte) {
	t.Helper()

	addr, err := h.NewAddress()
	require.NoError(t, err)
	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	wireAddr, err := txscript.AddressFromWitnessProgram(script)
	require.NoError(t, err)

	tx, err := h.CreateTransaction(
		[]*wire.TxOut{{Value: value, Address: wireAddr}}, 10, true)
	require.NoError(t, err)

	var raw bytes.Buffer
	require.NoError(t, tx.Serialize(&raw))
	return tx, raw.Bytes()
}

func submitTx(t *testing.T, h *utxorpcHarness,
	raw []byte) *connect.Response[submitpb.SubmitTxResponse] {

	t.Helper()
	resp, err := h.submit.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: raw},
			},
		}))
	require.NoError(t, err)
	return resp
}

// TestUtxorpcSubmitService submits a real signed transaction and
// follows it from the mempool through to confirmation.
func TestUtxorpcSubmitService(t *testing.T) {
	h := setupUtxorpcHarness(t, 25)
	ctx := t.Context()

	empty, err := h.submit.ReadMempool(ctx,
		connect.NewRequest(&submitpb.ReadMempoolRequest{}))
	require.NoError(t, err)
	require.Empty(t, empty.Msg.GetItems())
	t.Logf("ReadMempool (before submit): %d items", len(empty.Msg.GetItems()))

	tx, raw := newSpend(t, h, 5_000_000)
	txHash := tx.TxHash()

	submitted := submitTx(t, h, raw)
	require.Equal(t, txHash[:], submitted.Msg.GetRef())
	t.Logf("SubmitTx: accepted ref=%x (%d bytes, %d in, %d out)",
		submitted.Msg.GetRef(), len(raw), len(tx.TxIn), len(tx.TxOut))

	pending, err := h.submit.ReadMempool(ctx,
		connect.NewRequest(&submitpb.ReadMempoolRequest{}))
	require.NoError(t, err)
	require.Len(t, pending.Msg.GetItems(), 1)
	require.Equal(t, txHash[:], pending.Msg.GetItems()[0].GetRef())
	t.Logf("ReadMempool (after submit): %d item, ref=%x stage=%s "+
		"native_bytes=%d", len(pending.Msg.GetItems()),
		pending.Msg.GetItems()[0].GetRef(),
		pending.Msg.GetItems()[0].GetStage(),
		len(pending.Msg.GetItems()[0].GetNativeBytes()))

	// Opened after the submit, so the first message exercises the
	// already-reached-stage path rather than waiting on an event.
	wait, err := h.submit.WaitForTx(ctx,
		connect.NewRequest(&submitpb.WaitForTxRequest{
			Ref: [][]byte{txHash[:]},
		}))
	require.NoError(t, err)
	require.True(t, wait.Receive(), "wait for tx mempool: %v", wait.Err())
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, wait.Msg().GetStage())
	require.Equal(t, txHash[:], wait.Msg().GetRef())
	t.Logf("WaitForTx: ref=%x stage=%s", wait.Msg().GetRef(),
		wait.Msg().GetStage())

	// Mining the transaction must drive the stream to its final stage.
	mined, err := h.Client.Generate(1)
	require.NoError(t, err)
	require.True(t, wait.Receive(), "wait for tx confirmed: %v", wait.Err())
	require.Equal(t, submitpb.Stage_STAGE_CONFIRMED, wait.Msg().GetStage())
	t.Logf("WaitForTx: ref=%x stage=%s (mined into %s)",
		wait.Msg().GetRef(), wait.Msg().GetStage(), mined[0])

	// Confirmation is terminal, so the stream closes on its own.
	require.False(t, wait.Receive())
	require.NoError(t, wait.Err())
	t.Logf("WaitForTx: stream closed after confirmation")

	// The transaction is now resolvable through the index.
	confirmed, err := h.query.ReadTx(ctx,
		connect.NewRequest(&querypb.ReadTxRequest{Hash: txHash[:]}))
	require.NoError(t, err)
	require.Equal(t, raw, confirmed.Msg.GetTx().GetNativeBytes())
	require.Equal(t, mined[0][:], confirmed.Msg.GetTx().GetBlockRef().GetHash())
	t.Logf("ReadTx (after confirmation): ref=%x block_height=%d block_hash=%x",
		txHash[:], confirmed.Msg.GetTx().GetBlockRef().GetHeight(),
		confirmed.Msg.GetTx().GetBlockRef().GetHash())
}

// TestUtxorpcWatchMempool streams mempool arrivals. Opening a server
// stream blocks until the handler sends its first message, and this
// handler only speaks when a transaction arrives, so the stream is
// opened from its own goroutine and fed from the test.
func TestUtxorpcWatchMempool(t *testing.T) {
	h := setupUtxorpcHarness(t, 25)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	arrivals := make(chan *submitpb.TxInMempool, 8)
	opened := make(chan struct{})
	go func() {
		stream, err := h.submit.WatchMempool(ctx,
			connect.NewRequest(&submitpb.WatchMempoolRequest{}))
		if err != nil {
			close(arrivals)
			return
		}
		defer func() { _ = stream.Close() }()
		close(opened)
		for stream.Receive() {
			arrivals <- stream.Msg().GetTx()
		}
		close(arrivals)
	}()

	// Submit transactions until one is observed. The first may race the
	// stream's subscription, which no client can observe from outside.
	var seen *submitpb.TxInMempool
	for attempt := 1; attempt <= 5 && seen == nil; attempt++ {
		tx, raw := newSpend(t, h, int64(1_000_000*attempt))
		submitTx(t, h, raw)
		txHash := tx.TxHash()

		select {
		case arrival := <-arrivals:
			require.NotNil(t, arrival)
			seen = arrival
			t.Logf("WatchMempool: ref=%x stage=%s native_bytes=%d "+
				"(attempt %d, submitted %x)",
				arrival.GetRef(), arrival.GetStage(),
				len(arrival.GetNativeBytes()), attempt, txHash[:])
		case <-time.After(5 * time.Second):
		}
	}
	require.NotNil(t, seen, "no mempool arrival observed")
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, seen.GetStage())

	var decoded wire.MsgTx
	require.NoError(t, decoded.Deserialize(
		bytes.NewReader(seen.GetNativeBytes())))
	require.Equal(t, seen.GetRef(), func() []byte {
		hash := decoded.TxHash()
		return hash[:]
	}())
	t.Logf("WatchMempool: native_bytes decode to %s with %d in, %d out",
		decoded.TxHash(), len(decoded.TxIn), len(decoded.TxOut))
}

// TestUtxorpcSubmitRejectsBadTransactions covers the client-error paths
// of the submit service against a live node.
func TestUtxorpcSubmitRejectsBadTransactions(t *testing.T) {
	h := setupUtxorpcHarness(t, 2)
	ctx := t.Context()

	_, err := h.submit.SubmitTx(ctx,
		connect.NewRequest(&submitpb.SubmitTxRequest{}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	t.Logf("SubmitTx (no transaction): %s", err)

	_, err = h.submit.SubmitTx(ctx,
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: []byte{0xde, 0xad}},
			},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	t.Logf("SubmitTx (malformed bytes): %s", err)

	// A well-formed transaction spending nothing is rejected by policy
	// rather than failing the node.
	orphan := wire.NewMsgTx(wire.TxVersion)
	orphan.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Index: 0},
		Sequence:         wire.MaxTxInSequenceNum,
		Witness:          wire.TxWitness{{0x01}},
	})
	orphan.AddTxOut(&wire.TxOut{Value: 1000})

	var raw bytes.Buffer
	require.NoError(t, orphan.Serialize(&raw))
	_, err = h.submit.SubmitTx(ctx,
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: raw.Bytes()},
			},
		}))
	require.Error(t, err)
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	t.Logf("SubmitTx (rejected by policy): %s", err)
}

// TestUtxorpcUnsupportedProcedures records the procedures the UTxO RPC
// schema cannot express for Handshake, so a client sees a reason rather
// than an empty result.
func TestUtxorpcUnsupportedProcedures(t *testing.T) {
	h := setupUtxorpcHarness(t, 2)
	ctx := t.Context()

	calls := []struct {
		name string
		call func() error
	}{
		{"query.ReadParams", func() error {
			_, err := h.query.ReadParams(ctx,
				connect.NewRequest(&querypb.ReadParamsRequest{}))
			return err
		}},
		{"query.SearchUtxos", func() error {
			_, err := h.query.SearchUtxos(ctx,
				connect.NewRequest(&querypb.SearchUtxosRequest{}))
			return err
		}},
		{"query.ReadData", func() error {
			_, err := h.query.ReadData(ctx,
				connect.NewRequest(&querypb.ReadDataRequest{}))
			return err
		}},
		{"query.ReadEraSummary", func() error {
			_, err := h.query.ReadEraSummary(ctx,
				connect.NewRequest(&querypb.ReadEraSummaryRequest{}))
			return err
		}},
		{"query.ReadState", func() error {
			_, err := h.query.ReadState(ctx,
				connect.NewRequest(&querypb.ReadStateRequest{}))
			return err
		}},
		{"submit.EvalTx", func() error {
			_, err := h.submit.EvalTx(ctx,
				connect.NewRequest(&submitpb.EvalTxRequest{}))
			return err
		}},
	}

	for _, tc := range calls {
		err := tc.call()
		require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err),
			"%s", tc.name)
		t.Logf("%s: %s", tc.name, err)
	}
}

// TestUtxorpcHealthAndReflection confirms the endpoints discovery
// tooling relies on are reachable on the same listener.
func TestUtxorpcHealthAndReflection(t *testing.T) {
	h := setupUtxorpcHarness(t, 2)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(h.RPCConfig().Certificates))
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	for _, service := range []string{
		"utxorpc.v1beta.sync.SyncService",
		"utxorpc.v1beta.query.QueryService",
		"utxorpc.v1beta.submit.SubmitService",
	} {
		body := fmt.Sprintf(`{"service":%q}`, service)
		resp, err := client.Post(
			"https://"+h.addr+"/grpc.health.v1.Health/Check",
			"application/json", bytes.NewReader([]byte(body)))
		require.NoError(t, err)
		payload := new(bytes.Buffer)
		_, err = payload.ReadFrom(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		t.Logf("Health %s: HTTP/%d %s", service, resp.ProtoMajor,
			payload.String())
	}

	resp, err := client.Post(
		"https://"+h.addr+
			"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"application/grpc", http.NoBody)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Logf("Reflection: HTTP/%d %d", resp.ProtoMajor, resp.StatusCode)
}
