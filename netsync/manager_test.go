package netsync

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// The package-level log variable is nil by default. Set it to the
// disabled logger so that log calls in the sync manager don't panic.
func init() {
	DisableLog()
}

// noopPeerNotifier is a no-op implementation of PeerNotifier for tests.
type noopPeerNotifier struct{}

func (noopPeerNotifier) AnnounceNewTransactions([]*mempool.TxDesc)            {}
func (noopPeerNotifier) UpdatePeerHeights(*chainhash.Hash, int32, *peer.Peer) {}
func (noopPeerNotifier) RelayInventory(*wire.InvVect, interface{})            {}
func (noopPeerNotifier) TransactionConfirmed(*hnsutil.Tx)                     {}

type recordingPeerNotifier struct {
	noopPeerNotifier

	relayed []*wire.InvVect
	data    []interface{}
}

func (n *recordingPeerNotifier) RelayInventory(iv *wire.InvVect,
	data interface{}) {

	ivCopy := *iv
	n.relayed = append(n.relayed, &ivCopy)
	n.data = append(n.data, data)
}

// dbSetup is used to create a new db with the genesis block already inserted.
// It returns a teardown function the caller should invoke when done testing to
// clean up.  The database is stored under t.TempDir() which is automatically
// removed when the test finishes.
func dbSetup(t *testing.T, params *chaincfg.Params) (database.DB, func(), error) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating db: %v", err)
	}

	teardown := func() {
		db.Close()
	}

	return db, teardown, nil
}

// chainSetup is used to create a new db and chain instance with the genesis
// block already inserted.  In addition to the new chain instance, it returns
// a teardown function the caller should invoke when done testing to clean up.
func chainSetup(t *testing.T, params *chaincfg.Params) (
	*blockchain.BlockChain, func(), error) {

	db, teardown, err := dbSetup(t, params)
	if err != nil {
		return nil, nil, err
	}

	// Copy the chain params to ensure any modifications the tests do to
	// the chain parameters do not affect the global instance.
	paramsCopy := *params

	// Deep-copy deployment starters/enders so that parallel tests don't
	// race on the shared blockClock field written by SynchronizeClock.
	for i := range paramsCopy.Deployments {
		d := &paramsCopy.Deployments[i]
		if s, ok := d.DeploymentStarter.(*chaincfg.MedianTimeDeploymentStarter); ok {
			d.DeploymentStarter = chaincfg.NewMedianTimeDeploymentStarter(
				s.StartTime())
		}
		if e, ok := d.DeploymentEnder.(*chaincfg.MedianTimeDeploymentEnder); ok {
			d.DeploymentEnder = chaincfg.NewMedianTimeDeploymentEnder(
				e.EndTime())
		}
	}

	// Create the main chain instance.
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		Checkpoints: paramsCopy.Checkpoints,
		ChainParams: &paramsCopy,
		TimeSource:  blockchain.NewMedianTime(),
		SigCache:    txscript.NewSigCache(1000),
	})
	if err != nil {
		teardown()
		err := fmt.Errorf("failed to create chain instance: %v", err)
		return nil, nil, err
	}
	return chain, teardown, nil
}

func makeMockSyncManager(t *testing.T,
	params *chaincfg.Params) (*SyncManager, func()) {

	t.Helper()

	chain, tearDown, err := chainSetup(t, params)
	require.NoError(t, err)

	sm, err := New(&Config{
		PeerNotifier: noopPeerNotifier{},
		Chain:        chain,
		ChainParams:  params,
	})
	require.NoError(t, err)

	return sm, tearDown
}

func TestShouldMarkRejectedBlockInvalid(t *testing.T) {
	tests := []struct {
		name string
		code blockchain.ErrorCode
		want bool
	}{
		{
			name: "duplicate",
			code: blockchain.ErrDuplicateBlock,
			want: false,
		},
		{
			name: "future time",
			code: blockchain.ErrTimeTooNew,
			want: false,
		},
		{
			name: "unknown parent",
			code: blockchain.ErrPreviousBlockUnknown,
			want: false,
		},
		{
			name: "invalid ancestor",
			code: blockchain.ErrInvalidAncestorBlock,
			want: false,
		},
		{
			name: "proposal parent not best",
			code: blockchain.ErrPrevBlockNotBest,
			want: false,
		},
		{
			name: "already known invalid",
			code: blockchain.ErrKnownInvalidBlock,
			want: false,
		},
		{
			name: "invalid covenant",
			code: blockchain.ErrInvalidCovenant,
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := shouldMarkRejectedBlockInvalid(blockchain.RuleError{
				ErrorCode: test.code,
			})
			if got != test.want {
				t.Fatalf("shouldMarkRejectedBlockInvalid(%v) = %v, want %v",
					test.code, got, test.want)
			}
		})
	}
}

func connectSyncTestPeer(t *testing.T, params *chaincfg.Params,
	height int32) (*peer.Peer, net.Conn, func()) {

	t.Helper()

	verack := make(chan struct{}, 1)
	p := peer.NewInboundPeer(&peer.Config{
		ChainParams:    params,
		AllowSelfConns: true,
		Listeners: peer.MessageListeners{
			OnVerAck: func(*peer.Peer, *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		p.AssociateConnection(conn)
		accepted <- nil
	}()

	remote, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	select {
	case err := <-accepted:
		require.NoError(t, err)
	case <-time.After(time.Second):
		remote.Close()
		t.Fatal("timed out waiting for inbound peer connection")
	}

	remoteNA := wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), 0,
		wire.SFNodeNetwork)
	remoteVersion := &wire.HnsMsgVersion{
		Version:  peer.MaxProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Time:     uint64(time.Now().Unix()),
		Remote:   wire.NewHnsNetAddress(remoteNA),
		Agent:    wire.DefaultUserAgent,
		Height:   uint32(height),
	}
	remoteVersion.SetNonce(uint64(height) + 1)

	_, err = wire.WriteHnsMessageN(remote, remoteVersion, params.Net)
	require.NoError(t, err)
	require.IsType(t, &wire.HnsMsgVersion{},
		readSyncTestPeerMessage(t, remote, params))
	require.IsType(t, &wire.HnsMsgVerack{},
		readSyncTestPeerMessage(t, remote, params))
	_, err = wire.WriteHnsMessageN(remote, &wire.HnsMsgVerack{},
		params.Net)
	require.NoError(t, err)

	select {
	case <-verack:
	case <-time.After(time.Second):
		remote.Close()
		t.Fatal("timed out waiting for peer negotiation")
	}
	p.UpdateLastBlockHeight(height)

	cleanup := func() {
		p.Disconnect()
		remote.Close()
	}

	return p, remote, cleanup
}

func readSyncTestPeerMessage(t *testing.T, remote net.Conn,
	params *chaincfg.Params) wire.HandshakeMessage {

	t.Helper()

	require.NoError(t, remote.SetReadDeadline(time.Now().Add(time.Second)))
	_, msg, _, err := wire.ReadHandshakeMessageN(remote, params.Net)
	require.NoError(t, err)
	return msg
}

func TestCheckHeadersList(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	blocks := generateTestBlocks(t, &params, 12)

	// Set params to regtest with a generated checkpoint at block 11.
	checkpointHeight := int32(11)
	checkpointHash := blocks[checkpointHeight-1].Hash()
	params.Checkpoints = []chaincfg.Checkpoint{
		{
			Height: checkpointHeight,
			Hash:   checkpointHash,
		},
	}

	// Create mock SyncManager.
	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	// Setup SyncManager with headers processed.
	for _, block := range blocks[:checkpointHeight] {
		isMainChain, err := sm.chain.ProcessBlockHeader(
			&block.MsgBlock().Header, blockchain.BFNone, false)
		if err != nil {
			t.Fatal(err)
		}

		if !isMainChain {
			t.Fatalf("expected block header %v to be in the main chain",
				block.Hash())
		}
	}

	tests := []struct {
		hash              *chainhash.Hash
		isCheckpointBlock bool
		behaviorFlags     blockchain.BehaviorFlags
	}{
		{
			hash:              params.GenesisHash,
			isCheckpointBlock: false,
			behaviorFlags:     blockchain.BFFastAdd,
		},
		{
			// Block 10.
			hash:              blocks[9].Hash(),
			isCheckpointBlock: false,
			behaviorFlags:     blockchain.BFFastAdd,
		},
		{
			// Block 11.
			hash:              blocks[10].Hash(),
			isCheckpointBlock: true,
			behaviorFlags:     blockchain.BFFastAdd,
		},
		{
			// Block 12.
			hash:              blocks[11].Hash(),
			isCheckpointBlock: false,
			behaviorFlags:     blockchain.BFNone,
		},
	}

	for _, test := range tests {
		// Make sure that when the ibd mode is off, we always get
		// false and BFNone.
		sm.ibdMode = false
		isCheckpoint, gotFlags := sm.checkHeadersList(test.hash)
		require.Equal(t, false, isCheckpoint)
		require.Equal(t, blockchain.BFNone, gotFlags)

		// Now check that the test values are correct.
		sm.ibdMode = true
		isCheckpoint, gotFlags = sm.checkHeadersList(test.hash)
		require.Equal(t, test.isCheckpointBlock, isCheckpoint)
		require.Equal(t, test.behaviorFlags, gotFlags)
	}
}

func TestFetchHigherPeers(t *testing.T) {
	// Create mock SyncManager.
	sm, tearDown := makeMockSyncManager(t, &chaincfg.MainNetParams)
	defer tearDown()

	tests := []struct {
		peerHeights       []int32
		peerSyncCandidate []bool
		height            int32
		expectedCnt       int
	}{
		{
			peerHeights:       []int32{9, 10, 10, 10},
			peerSyncCandidate: []bool{true, true, true, true},
			height:            5,
			expectedCnt:       4,
		},

		{
			peerHeights:       []int32{9, 10, 10, 10},
			peerSyncCandidate: []bool{false, false, true, true},
			height:            5,
			expectedCnt:       2,
		},

		{
			peerHeights:       []int32{1, 100, 100, 100, 100},
			peerSyncCandidate: []bool{true, false, true, true, false},
			height:            100,
			expectedCnt:       0,
		},
	}

	for _, test := range tests {
		// Setup peers.
		sm.peerStates = make(map[*peer.Peer]*peerSyncState)
		for i, height := range test.peerHeights {
			peer := peer.NewInboundPeer(&peer.Config{})
			peer.UpdateLastBlockHeight(height)
			sm.peerStates[peer] = &peerSyncState{
				syncCandidate:   test.peerSyncCandidate[i],
				requestedTxns:   make(map[chainhash.Hash]struct{}),
				requestedBlocks: make(map[chainhash.Hash]struct{}),
			}
		}

		// Fetch higher peers and assert.
		peers := sm.fetchHigherPeers(test.height)
		require.Equal(t, test.expectedCnt, len(peers))

		for _, peer := range peers {
			state, found := sm.peerStates[peer]
			require.True(t, found)
			require.True(t, state.syncCandidate)
		}
	}
}

func TestStartSyncChoosesHighestPeer(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	lowPeer := newSyncCandidate(t, sm, 5)
	highPeer := newSyncCandidate(t, sm, 12)
	midPeer := newSyncCandidate(t, sm, 9)

	sm.startSync()

	require.True(t, sm.syncPeer == highPeer,
		"startSync selected peer height %d; low=%d mid=%d high=%d",
		sm.syncPeer.LastBlock(), lowPeer.LastBlock(),
		midPeer.LastBlock(), highPeer.LastBlock())
	require.True(t, sm.ibdMode)
}

func TestStartSyncSendsGetHeadersLocator(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	syncPeer, remote, cleanup := connectSyncTestPeer(t, &params, 12)
	defer cleanup()
	sm.peerStates[syncPeer] = &peerSyncState{
		syncCandidate:   true,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}

	sm.startSync()

	require.True(t, sm.syncPeer == syncPeer)
	require.True(t, sm.ibdMode)

	msg := readSyncTestPeerMessage(t, remote, &params)
	getHeaders, ok := msg.(*wire.HnsMsgGetHeaders)
	require.True(t, ok, "got %T, want *wire.HnsMsgGetHeaders", msg)
	require.NotEmpty(t, getHeaders.Locator)
	gotLocator := chainhash.Hash(getHeaders.Locator[0])
	require.True(t, gotLocator.IsEqual(params.GenesisHash))
	require.Equal(t, [32]byte{}, getHeaders.StopHash)
}

func TestStartSyncSendsGetDataForHeaderBlocks(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	const numBlocks = 3
	blocks := generateTestBlocks(t, &params, numBlocks)
	for _, block := range blocks {
		_, err := sm.chain.ProcessBlockHeader(
			&block.MsgBlock().Header, blockchain.BFNone, false)
		require.NoError(t, err)
	}

	syncPeer, remote, cleanup := connectSyncTestPeer(
		t, &params, numBlocks)
	defer cleanup()
	sm.peerStates[syncPeer] = &peerSyncState{
		syncCandidate:   true,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}

	sm.startSync()

	require.True(t, sm.syncPeer == syncPeer)
	require.True(t, sm.ibdMode)

	msg := readSyncTestPeerMessage(t, remote, &params)
	getData, ok := msg.(*wire.HnsMsgGetData)
	require.True(t, ok, "got %T, want *wire.HnsMsgGetData", msg)
	require.Len(t, getData.Inventory, numBlocks)

	got := make(map[chainhash.Hash]struct{}, len(getData.Inventory))
	for _, item := range getData.Inventory {
		iv := item.InvVect()
		require.Equal(t, wire.InvTypeBlock, iv.Type)
		got[iv.Hash] = struct{}{}
	}
	for _, block := range blocks {
		require.Contains(t, got, *block.Hash())
		require.Contains(t, sm.requestedBlocks, *block.Hash())
		require.Contains(t, sm.peerStates[syncPeer].requestedBlocks,
			*block.Hash())
	}
}

func TestHandleBlockMsgRequestsParentsForOrphanBlock(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	blocks := generateTestBlocks(t, &params, 2)

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	p, remote, cleanup := connectSyncTestPeer(t, &params, 2)
	defer cleanup()
	sm.peerStates[p] = &peerSyncState{
		syncCandidate:   true,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}

	orphan := blocks[1]
	orphanHash := orphan.Hash()
	sm.peerStates[p].requestedBlocks[*orphanHash] = struct{}{}
	sm.requestedBlocks[*orphanHash] = struct{}{}

	sm.handleBlockMsg(&blockMsg{
		block: orphan,
		peer:  p,
	})

	require.True(t, sm.chain.IsKnownOrphan(orphanHash))
	require.NotContains(t, sm.requestedBlocks, *orphanHash)
	require.NotContains(t, sm.peerStates[p].requestedBlocks, *orphanHash)

	msg := readSyncTestPeerMessage(t, remote, &params)
	getBlocks, ok := msg.(*wire.HnsMsgGetBlocks)
	require.True(t, ok, "got %T, want *wire.HnsMsgGetBlocks", msg)
	stopHash := chainhash.Hash(getBlocks.StopHash)
	require.Equal(t, *orphanHash, stopHash)
	locatorHashes := make([]chainhash.Hash, 0,
		len(getBlocks.LocatorHashes()))
	for _, hash := range getBlocks.LocatorHashes() {
		locatorHashes = append(locatorHashes, *hash)
	}
	require.Contains(t, locatorHashes, *params.GenesisHash)
}

func TestHandleBlockMsgClearsRequestedStateForKnownBlock(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	blocks := generateTestBlocks(t, &params, 1)

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	block := blocks[0]
	_, isOrphan, err := sm.chain.ProcessBlock(block, blockchain.BFNone)
	require.NoError(t, err)
	require.False(t, isOrphan)

	p := newSyncCandidate(t, sm, 1)
	blockHash := block.Hash()
	sm.peerStates[p].requestedBlocks[*blockHash] = struct{}{}
	sm.requestedBlocks[*blockHash] = struct{}{}

	sm.handleBlockMsg(&blockMsg{
		block: block,
		peer:  p,
	})

	require.NotContains(t, sm.requestedBlocks, *blockHash)
	require.NotContains(t, sm.peerStates[p].requestedBlocks, *blockHash)
}

func TestHandleBlockMsgStayingCurrentAcceptsForkAndReorg(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()
	sm.ibdMode = false

	mainBlocks := generateTestBlocksFrom(t, &params, *params.GenesisHash,
		params.GenesisBlock.Header.Timestamp, 0, 1, 1)
	forkBlocks := generateTestBlocksFrom(t, &params, *params.GenesisHash,
		params.GenesisBlock.Header.Timestamp, 0, 2, 2)

	p := newSyncCandidate(t, sm, 2)
	requestBlock := func(block *hnsutil.Block) {
		blockHash := block.Hash()
		sm.peerStates[p].requestedBlocks[*blockHash] = struct{}{}
		sm.requestedBlocks[*blockHash] = struct{}{}
		sm.handleBlockMsg(&blockMsg{
			block: block,
			peer:  p,
		})
		require.NotContains(t, sm.requestedBlocks, *blockHash)
		require.NotContains(t, sm.peerStates[p].requestedBlocks,
			*blockHash)
	}

	requestBlock(mainBlocks[0])
	mainTip := mainBlocks[0].Hash()
	best := sm.chain.BestSnapshot()
	require.Equal(t, int32(1), best.Height)
	require.True(t, best.Hash.IsEqual(mainTip))

	requestBlock(forkBlocks[0])
	forkTip := forkBlocks[0].Hash()
	haveFork, err := sm.chain.HaveBlock(forkTip)
	require.NoError(t, err)
	require.True(t, haveFork)
	best = sm.chain.BestSnapshot()
	require.Equal(t, int32(1), best.Height)
	require.True(t, best.Hash.IsEqual(mainTip),
		"equal-work fork should not replace the current best chain")

	requestBlock(forkBlocks[1])
	best = sm.chain.BestSnapshot()
	forkBest := forkBlocks[1].Hash()
	require.Equal(t, int32(2), best.Height)
	require.True(t, best.Hash.IsEqual(forkBest),
		"longer fork should become the best chain")
}

func TestBlockAcceptedNotificationRelaysInventoryWhenCurrent(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	db, tearDown, err := dbSetup(t, &params)
	require.NoError(t, err)
	defer tearDown()

	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		Checkpoints: params.Checkpoints,
		ChainParams: &params,
		TimeSource: &mockTimeSource{
			adjustedTime: params.GenesisBlock.Header.Timestamp.
				Add(time.Hour),
		},
		SigCache: txscript.NewSigCache(1000),
	})
	require.NoError(t, err)

	notifier := &recordingPeerNotifier{}
	sm := &SyncManager{
		peerNotifier: notifier,
		chain:        chain,
	}
	block := hnsutil.NewBlock(params.GenesisBlock)

	sm.handleBlockchainNotification(&blockchain.Notification{
		Type: blockchain.NTBlockAccepted,
		Data: block,
	})

	require.Len(t, notifier.relayed, 1)
	require.Equal(t, wire.InvTypeBlock, notifier.relayed[0].Type)
	require.True(t, notifier.relayed[0].Hash.IsEqual(block.Hash()))
	require.Len(t, notifier.data, 1)
	header, ok := notifier.data[0].(wire.BlockHeader)
	require.True(t, ok)
	require.Equal(t, block.MsgBlock().Header, header)
}

func TestBlockConnectedNotificationRemovesCoinbaseProofs(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	db, tearDown, err := dbSetup(t, &params)
	require.NoError(t, err)
	defer tearDown()

	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		Checkpoints: params.Checkpoints,
		ChainParams: &params,
		TimeSource: &mockTimeSource{
			adjustedTime: params.GenesisBlock.Header.Timestamp.
				Add(time.Hour),
		},
		SigCache: txscript.NewSigCache(1000),
	})
	require.NoError(t, err)

	addrHash := make([]byte, 20)
	addrHash[0] = 0x01
	addr := wire.Address{Version: 0, Hash: addrHash}
	proof := mining.CoinbaseProof{
		Witness: []byte{0xaa, 0xbb},
		Output:  wire.NewTxOut(100, addr, wire.Covenant{}),
		Fee:     7,
	}
	txPool := mempool.New(&mempool.Config{})
	_, err = txPool.AddCoinbaseProof(proof)
	require.NoError(t, err)

	coinbase := wire.NewMsgTx(wire.TxVersion)
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{[]byte{0x01}},
	})
	coinbase.AddTxOut(wire.NewTxOut(1, addr, wire.Covenant{}))
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{proof.Witness},
	})
	coinbase.AddTxOut(proof.Output)

	block := hnsutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{coinbase},
	})
	sm := &SyncManager{
		chain:        chain,
		txMemPool:    txPool,
		peerNotifier: noopPeerNotifier{},
	}
	sm.handleBlockchainNotification(&blockchain.Notification{
		Type: blockchain.NTBlockConnected,
		Data: block,
	})

	proofs, err := txPool.CoinbaseProofs(1)
	require.NoError(t, err)
	require.Empty(t, proofs)
}

func TestBlockDisconnectedNotificationReaddsMempoolTransactions(t *testing.T) {
	t.Parallel()

	params := chaincfg.MainNetParams
	harness := newReorgTxPoolHarness(t, &params)

	fundingTx := harness.addCoinbaseTx(t, 2)
	inputA := reorgSpendableOutput{
		outPoint: wire.OutPoint{Hash: *fundingTx.Hash(), Index: 0},
		amount:   hnsutil.Amount(fundingTx.MsgTx().TxOut[0].Value),
	}
	inputB := reorgSpendableOutput{
		outPoint: wire.OutPoint{Hash: *fundingTx.Hash(), Index: 1},
		amount:   hnsutil.Amount(fundingTx.MsgTx().TxOut[1].Value),
	}

	disconnectedOpen := harness.createSignedCovenantTx(
		t, inputA, 1000, reorgOpenCovenant("phasefive"),
	)
	newerOpen := harness.createSignedCovenantTx(
		t, inputB, 1000, reorgOpenCovenant("phasefive"),
	)

	_, err := harness.txPool.ProcessTransaction(newerOpen, true, false, 0)
	require.NoError(t, err)
	require.True(t, harness.txPool.HaveTransaction(newerOpen.Hash()))

	coinbase, err := harness.createCoinbaseTx(harness.chain.BestHeight()+1, 1)
	require.NoError(t, err)
	block := hnsutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			coinbase.MsgTx(),
			disconnectedOpen.MsgTx(),
		},
	})
	sm := &SyncManager{txMemPool: harness.txPool}
	sm.handleBlockchainNotification(&blockchain.Notification{
		Type: blockchain.NTBlockDisconnected,
		Data: block,
	})

	require.True(t, harness.txPool.HaveTransaction(disconnectedOpen.Hash()))
	require.False(t, harness.txPool.HaveTransaction(newerOpen.Hash()))
}

type reorgTxPoolHarness struct {
	signKey     *btcec.PrivateKey
	payScript   []byte
	payWireAddr wire.Address
	chainParams *chaincfg.Params

	chain  *reorgFakeChain
	txPool *mempool.TxPool
}

type reorgSpendableOutput struct {
	outPoint wire.OutPoint
	amount   hnsutil.Amount
}

func newReorgTxPoolHarness(t *testing.T,
	chainParams *chaincfg.Params) *reorgTxPoolHarness {

	t.Helper()

	keyBytes, err := hex.DecodeString("700868df1838811ffbdf918fb482c1f7e" +
		"ad62db4b97bd7012c23e726485e577d")
	require.NoError(t, err)
	signKey, signPub := btcec.PrivKeyFromBytes(keyBytes)
	pubKeyBytes := signPub.SerializeCompressed()

	payAddr, err := hnsutil.NewAddressPubKeyHash(
		hnsutil.Blake160(pubKeyBytes), chainParams,
	)
	require.NoError(t, err)
	payScript, err := txscript.PayToAddrScript(payAddr)
	require.NoError(t, err)

	payWireAddr := wire.Address{
		Version: 0,
		Hash:    payAddr.ScriptAddress(),
	}
	chain := &reorgFakeChain{utxos: blockchain.NewUtxoViewpoint()}
	harness := &reorgTxPoolHarness{
		signKey:     signKey,
		payScript:   payScript,
		payWireAddr: payWireAddr,
		chainParams: chainParams,
		chain:       chain,
	}
	harness.txPool = mempool.New(&mempool.Config{
		Policy: mempool.Policy{
			DisableRelayPriority: true,
			FreeTxRelayLimit:     15.0,
			MaxOrphanTxs:         5,
			MaxOrphanTxSize:      1000,
			MaxSigOpCostPerTx:    blockchain.MaxBlockSigOpsCost / 4,
			MinRelayTxFee:        1000,
			MaxTxVersion:         1,
		},
		ChainParams:      chainParams,
		FetchUtxoView:    chain.FetchUtxoView,
		BestHeight:       chain.BestHeight,
		MedianTimePast:   chain.MedianTimePast,
		CalcSequenceLock: chain.CalcSequenceLock,
		HashCache:        txscript.NewHashCache(10),
	})

	harness.chain.SetMedianTimePast(time.Now())
	return harness
}

func (h *reorgTxPoolHarness) createCoinbaseTx(blockHeight int32,
	numOutputs uint32) (*hnsutil.Tx, error) {

	coinbaseScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(blockHeight)).AddInt64(0).Script()
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = uint32(blockHeight)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex),
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  [][]byte{coinbaseScript},
	})

	totalInput := blockchain.CalcBlockSubsidy(blockHeight, h.chainParams)
	amountPerOutput := totalInput / int64(numOutputs)
	remainder := totalInput - amountPerOutput*int64(numOutputs)
	for i := uint32(0); i < numOutputs; i++ {
		amount := amountPerOutput
		if i == numOutputs-1 {
			amount += remainder
		}
		tx.AddTxOut(&wire.TxOut{
			Address: h.payWireAddr,
			Value:   amount,
		})
	}

	return hnsutil.NewTx(tx), nil
}

func (h *reorgTxPoolHarness) addCoinbaseTx(t *testing.T,
	numOutputs uint32) *hnsutil.Tx {

	t.Helper()

	coinbaseHeight := h.chain.BestHeight() + 1
	coinbase, err := h.createCoinbaseTx(coinbaseHeight, numOutputs)
	require.NoError(t, err)

	h.chain.utxos.AddTxOuts(coinbase, coinbaseHeight)
	h.chain.SetHeight(coinbaseHeight + int32(h.chainParams.CoinbaseMaturity))
	h.chain.SetMedianTimePast(time.Now())

	return coinbase
}

func (h *reorgTxPoolHarness) createSignedCovenantTx(t *testing.T,
	input reorgSpendableOutput, fee hnsutil.Amount,
	covenant wire.Covenant) *hnsutil.Tx {

	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: input.outPoint,
		Sequence:         wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{
		Address:  h.payWireAddr,
		Value:    int64(input.amount - fee),
		Covenant: covenant,
	})

	sigHashes := txscript.NewTxSigHashes(tx,
		txscript.NewCannedPrevOutputFetcher(
			h.payWireAddr, int64(input.amount),
		),
	)
	witness, err := txscript.WitnessSignature(tx, sigHashes, 0,
		int64(input.amount), h.payScript, txscript.SigHashAll,
		h.signKey, true)
	require.NoError(t, err)
	tx.TxIn[0].Witness = witness

	return hnsutil.NewTx(tx)
}

type reorgFakeChain struct {
	sync.RWMutex
	utxos          *blockchain.UtxoViewpoint
	currentHeight  int32
	medianTimePast time.Time
}

func (c *reorgFakeChain) FetchUtxoView(tx *hnsutil.Tx) (
	*blockchain.UtxoViewpoint, error) {

	c.RLock()
	defer c.RUnlock()

	view := blockchain.NewUtxoViewpoint()
	prevOut := wire.OutPoint{Hash: *tx.Hash()}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)
		entry := c.utxos.LookupEntry(prevOut)
		if entry != nil {
			view.Entries()[prevOut] = entry.Clone()
		} else {
			view.Entries()[prevOut] = nil
		}
	}
	for _, txIn := range tx.MsgTx().TxIn {
		entry := c.utxos.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil {
			view.Entries()[txIn.PreviousOutPoint] = entry.Clone()
		} else {
			view.Entries()[txIn.PreviousOutPoint] = nil
		}
	}

	return view, nil
}

func (c *reorgFakeChain) BestHeight() int32 {
	c.RLock()
	defer c.RUnlock()
	return c.currentHeight
}

func (c *reorgFakeChain) SetHeight(height int32) {
	c.Lock()
	defer c.Unlock()
	c.currentHeight = height
}

func (c *reorgFakeChain) MedianTimePast() time.Time {
	c.RLock()
	defer c.RUnlock()
	return c.medianTimePast
}

func (c *reorgFakeChain) SetMedianTimePast(mtp time.Time) {
	c.Lock()
	defer c.Unlock()
	c.medianTimePast = mtp
}

func (c *reorgFakeChain) CalcSequenceLock(*hnsutil.Tx,
	*blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error) {

	return &blockchain.SequenceLock{
		Seconds:     -1,
		BlockHeight: -1,
	}, nil
}

func reorgOpenCovenant(name string) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantOpen,
		Items: [][]byte{
			reorgHashItem(name),
			reorgU32Item(0),
			[]byte(name),
		},
	}
}

func reorgHashItem(name string) []byte {
	hash := blockchain.HashName([]byte(name))
	item := make([]byte, chainhash.HashSize)
	copy(item, hash[:])
	return item
}

func reorgU32Item(value uint32) []byte {
	var item [4]byte
	binary.LittleEndian.PutUint32(item[:], value)
	return item[:]
}

// mockTimeSource is used to trick the BlockChain instance to think that we're
// in the past.  This is so that we can force it to return true for isCurrent().
type mockTimeSource struct {
	adjustedTime time.Time
}

// AdjustedTime returns the internal adjustedTime.
//
// Part of the MedianTimeSource interface implementation.
func (m *mockTimeSource) AdjustedTime() time.Time {
	return m.adjustedTime
}

// AddTimeSample isn't relevant so we just leave it as emtpy.
//
// Part of the MedianTimeSource interface implementation.
func (m *mockTimeSource) AddTimeSample(id string, timeVal time.Time) {
	// purposely left empty
}

// Offset isn't relevant so we just return 0.
//
// Part of the MedianTimeSource interface implementation.
func (m *mockTimeSource) Offset() time.Duration {
	return 0
}

// TestBuildBlockRequestSkipsInflightBlocks verifies that buildBlockRequest
// does not re-request blocks that are already in sm.requestedBlocks.  When
// the pipeline refill threshold triggers fetchHeaderBlocks while blocks are
// still in-flight, re-requesting them causes the peer to send duplicates.
// The first copy gets processed (removing the hash from requestedBlocks),
// and the second copy then arrives as "unrequested", disconnecting the peer.
func TestBuildBlockRequestSkipsInflightBlocks(t *testing.T) {
	tests := []struct {
		name string
		// inflightHeights are the block heights already in
		// requestedBlocks before calling buildBlockRequest.
		inflightHeights []int32
		// wantRequestedHeights are the block heights that should
		// appear in the returned getdata message.
		wantRequestedHeights []int32
	}{
		{
			name:                 "no blocks in-flight requests all",
			inflightHeights:      nil,
			wantRequestedHeights: []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		},
		{
			name:                 "all blocks in-flight requests none",
			inflightHeights:      []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			wantRequestedHeights: nil,
		},
		{
			name:                 "first 5 in-flight requests remaining 6",
			inflightHeights:      []int32{1, 2, 3, 4, 5},
			wantRequestedHeights: []int32{6, 7, 8, 9, 10, 11},
		},
		{
			name:                 "last 6 in-flight requests first 5",
			inflightHeights:      []int32{6, 7, 8, 9, 10, 11},
			wantRequestedHeights: []int32{1, 2, 3, 4, 5},
		},
		{
			name:                 "scattered in-flight requests gaps",
			inflightHeights:      []int32{2, 4, 6, 8, 10},
			wantRequestedHeights: []int32{1, 3, 5, 7, 9, 11},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := chaincfg.RegressionNetParams
			params.Checkpoints = nil
			sm, tearDown := makeMockSyncManager(t, &params)
			defer tearDown()

			// Process headers 1-11 so the header chain is
			// ahead of the block chain.
			const numBlocks = 11
			blocks := generateTestBlocks(t, &params, numBlocks)
			for _, block := range blocks {
				_, err := sm.chain.ProcessBlockHeader(
					&block.MsgBlock().Header, blockchain.BFNone, false)
				require.NoError(t, err)
			}

			// Set up a disconnected peer as syncPeer.
			syncPeer := peer.NewInboundPeer(&peer.Config{})
			sm.syncPeer = syncPeer
			syncPeerState := &peerSyncState{
				requestedTxns:   make(map[chainhash.Hash]struct{}),
				requestedBlocks: make(map[chainhash.Hash]struct{}),
			}
			sm.peerStates[syncPeer] = syncPeerState

			// Pre-populate in-flight blocks.
			for _, h := range tc.inflightHeights {
				hash, err := sm.chain.HeaderHashByHeight(h)
				require.NoError(t, err)
				sm.requestedBlocks[*hash] = struct{}{}
				syncPeerState.requestedBlocks[*hash] = struct{}{}
			}

			gdmsg := sm.buildBlockRequest(syncPeer)

			// Collect the hashes from the getdata message.
			got := make(map[chainhash.Hash]struct{}, len(gdmsg.Inventory))
			for _, item := range gdmsg.Inventory {
				got[item.InvVect().Hash] = struct{}{}
			}

			require.Equal(t, len(tc.wantRequestedHeights), len(gdmsg.Inventory))
			for _, h := range tc.wantRequestedHeights {
				hash, err := sm.chain.HeaderHashByHeight(h)
				require.NoError(t, err)
				require.Contains(t, got, *hash,
					"block at height %d should be requested", h)
			}
			for _, h := range tc.inflightHeights {
				hash, err := sm.chain.HeaderHashByHeight(h)
				require.NoError(t, err)
				require.NotContains(t, got, *hash,
					"in-flight block at height %d should not be re-requested", h)
			}
		})
	}
}

func TestBuildBlockRequestCapsInflightBlocks(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	totalBlocks := maxInFlightBlocks + 20
	blocks := generateTestBlocks(t, &params, totalBlocks)
	for _, block := range blocks {
		_, err := sm.chain.ProcessBlockHeader(
			&block.MsgBlock().Header, blockchain.BFNone, false)
		require.NoError(t, err)
	}

	syncPeer := peer.NewInboundPeer(&peer.Config{})
	sm.syncPeer = syncPeer
	syncPeerState := &peerSyncState{
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}
	sm.peerStates[syncPeer] = syncPeerState

	gdmsg := sm.buildBlockRequest(syncPeer)
	require.Len(t, gdmsg.Inventory, maxInFlightBlocks)

	for i := 0; i < maxInFlightBlocks; i++ {
		require.Equal(t, *blocks[i].Hash(),
			gdmsg.Inventory[i].InvVect().Hash)
	}

	nextHash := *blocks[maxInFlightBlocks].Hash()
	delete(sm.requestedBlocks, gdmsg.Inventory[0].InvVect().Hash)
	delete(syncPeerState.requestedBlocks, gdmsg.Inventory[0].InvVect().Hash)
	_, _, err := sm.chain.ProcessBlock(blocks[0], blockchain.BFNone)
	require.NoError(t, err)

	gdmsg = sm.buildBlockRequest(syncPeer)
	require.Len(t, gdmsg.Inventory, 1)
	require.Equal(t, nextHash, gdmsg.Inventory[0].InvVect().Hash)
}

func TestRejectedBlockIsNotRequestedAgain(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	blocks := generateTestBlocks(t, &params, 1)
	block := blocks[0]
	_, err := sm.chain.ProcessBlockHeader(
		&block.MsgBlock().Header, blockchain.BFNone, false)
	require.NoError(t, err)

	syncPeer := peer.NewInboundPeer(&peer.Config{})
	sm.syncPeer = syncPeer
	syncPeerState := &peerSyncState{
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}
	sm.peerStates[syncPeer] = syncPeerState

	gdmsg := sm.buildBlockRequest(syncPeer)
	require.Len(t, gdmsg.Inventory, 1)

	badMsg := *block.MsgBlock()
	badMsg.Transactions = append([]*wire.MsgTx{}, badMsg.Transactions...)
	badMsg.Transactions = append(badMsg.Transactions, badMsg.Transactions[0])
	badBlock := hnsutil.NewBlock(&badMsg)

	sm.handleBlockMsg(&blockMsg{
		block: badBlock,
		peer:  syncPeer,
		reply: make(chan struct{}, 1),
	})

	blockHash := *block.Hash()
	require.Contains(t, sm.rejectedBlocks, blockHash)
	require.NotContains(t, sm.requestedBlocks, blockHash)
	require.NotContains(t, syncPeerState.requestedBlocks, blockHash)

	haveInv, err := sm.haveInventory(
		wire.NewInvVect(wire.InvTypeBlock, block.Hash()))
	require.NoError(t, err)
	require.True(t, haveInv)

	gdmsg = sm.buildBlockRequest(syncPeer)
	require.Empty(t, gdmsg.Inventory)
}

func TestIsInIBDMode(t *testing.T) {
	tests := []struct {
		peerState  map[*peer.Peer]*peerSyncState
		params     *chaincfg.Params
		timesource *mockTimeSource
		isIBDMode  bool
	}{
		// Is not current, higher peers.
		{
			params: &chaincfg.MainNetParams,
			peerState: func() map[*peer.Peer]*peerSyncState {
				ps := make(map[*peer.Peer]*peerSyncState)
				peer := peer.NewInboundPeer(&peer.Config{})
				peer.UpdateLastBlockHeight(900_000)
				ps[peer] = &peerSyncState{
					syncCandidate:   true,
					requestedTxns:   make(map[chainhash.Hash]struct{}),
					requestedBlocks: make(map[chainhash.Hash]struct{}),
				}
				return ps
			}(),
			timesource: nil,
			isIBDMode:  true,
		},
		// Is not current, no higher peers.
		{
			params: &chaincfg.MainNetParams,
			peerState: func() map[*peer.Peer]*peerSyncState {
				ps := make(map[*peer.Peer]*peerSyncState)
				peer := peer.NewInboundPeer(&peer.Config{})
				peer.UpdateLastBlockHeight(0)
				ps[peer] = &peerSyncState{
					syncCandidate:   true,
					requestedTxns:   make(map[chainhash.Hash]struct{}),
					requestedBlocks: make(map[chainhash.Hash]struct{}),
				}
				return ps
			}(),
			timesource: nil,
			isIBDMode:  true,
		},
		// Is current, higher peers.
		{
			params: func() *chaincfg.Params {
				params := chaincfg.MainNetParams
				params.Checkpoints = nil
				return &params
			}(),
			peerState: func() map[*peer.Peer]*peerSyncState {
				ps := make(map[*peer.Peer]*peerSyncState)
				peer := peer.NewInboundPeer(&peer.Config{})
				peer.UpdateLastBlockHeight(900_000)
				ps[peer] = &peerSyncState{
					syncCandidate:   true,
					requestedTxns:   make(map[chainhash.Hash]struct{}),
					requestedBlocks: make(map[chainhash.Hash]struct{}),
				}
				return ps
			}(),
			timesource: &mockTimeSource{
				chaincfg.MainNetParams.GenesisBlock.Header.Timestamp,
			},
			isIBDMode: true,
		},
		// Is current, no higher peers.
		{
			params: func() *chaincfg.Params {
				params := chaincfg.MainNetParams
				params.Checkpoints = nil
				return &params
			}(),
			peerState: func() map[*peer.Peer]*peerSyncState {
				ps := make(map[*peer.Peer]*peerSyncState)
				peer := peer.NewInboundPeer(&peer.Config{})
				peer.UpdateLastBlockHeight(0)
				ps[peer] = &peerSyncState{
					syncCandidate:   true,
					requestedTxns:   make(map[chainhash.Hash]struct{}),
					requestedBlocks: make(map[chainhash.Hash]struct{}),
				}
				return ps
			}(),
			timesource: &mockTimeSource{
				chaincfg.MainNetParams.GenesisBlock.Header.Timestamp,
			},
			isIBDMode: false,
		},
	}

	for _, test := range tests {
		db, tearDown, err := dbSetup(t, test.params)
		if err != nil {
			t.Fatal(err)
		}

		timesource := blockchain.NewMedianTime()
		if test.timesource != nil {
			timesource = test.timesource
		}

		// Create the main chain instance.
		chain, err := blockchain.New(&blockchain.Config{
			DB:          db,
			Checkpoints: test.params.Checkpoints,
			ChainParams: test.params,
			TimeSource:  timesource,
			SigCache:    txscript.NewSigCache(1000),
		})
		if err != nil {
			tearDown()
			t.Fatal(err)
		}
		sm, err := New(&Config{
			Chain:       chain,
			ChainParams: test.params,
		})
		if err != nil {
			tearDown()
			t.Fatal(err)
		}

		// Run test and assert.
		sm.peerStates = test.peerState
		got := sm.isInIBDMode()
		require.Equal(t, test.isIBDMode, got)
		tearDown()
	}
}

// createTestCoinbase creates a minimal coinbase transaction for the given
// block height.
func createTestCoinbase(t *testing.T, height int32,
	params *chaincfg.Params) *wire.MsgTx {

	return createTestCoinbaseVariant(t, height, params, 0)
}

func createTestCoinbaseVariant(t *testing.T, height int32,
	params *chaincfg.Params, variant byte) *wire.MsgTx {

	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = uint32(height)

	heightScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(height)).
		AddOp(txscript.OP_0).
		Script()
	require.NoError(t, err)

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{heightScript},
	})

	addrHash := make([]byte, 20)
	addrHash[len(addrHash)-1] = variant
	tx.AddTxOut(&wire.TxOut{
		Value:   blockchain.CalcBlockSubsidy(height, params),
		Address: wire.Address{Version: 0, Hash: addrHash},
	})

	return tx
}

// solveTestBlock finds a nonce that satisfies the proof of work for the given
// header.  With regression test parameters the difficulty is minimal and a
// solution is found almost immediately.
func solveTestBlock(header *wire.BlockHeader, params *chaincfg.Params) bool {
	target := blockchain.CompactToBig(params.PowLimitBits)
	for nonce := uint32(0); nonce < math.MaxUint32; nonce++ {
		header.Nonce = nonce
		hash := header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return true
		}
	}

	return false
}

// generateTestBlocks creates count valid blocks chaining from the genesis
// block of the given params.  Each block contains only a coinbase transaction.
func generateTestBlocks(
	t *testing.T, params *chaincfg.Params, count int) []*hnsutil.Block {

	t.Helper()

	return generateTestBlocksFrom(t, params, *params.GenesisHash,
		params.GenesisBlock.Header.Timestamp, 0, count, 0)
}

func generateTestBlocksFrom(t *testing.T, params *chaincfg.Params,
	parentHash chainhash.Hash, parentTime time.Time, parentHeight int32,
	count int, variant byte) []*hnsutil.Block {

	t.Helper()

	blocks := make([]*hnsutil.Block, 0, count)
	prevHash := &parentHash
	prevTime := params.GenesisBlock.Header.Timestamp

	if !parentTime.IsZero() {
		prevTime = parentTime
	}

	for i := int32(1); i <= int32(count); i++ {
		h := parentHeight + i
		cb := createTestCoinbaseVariant(t, h, params, variant)
		txs := []*hnsutil.Tx{hnsutil.NewTx(cb)}

		header := wire.BlockHeader{
			Version:     2,
			PrevBlock:   *prevHash,
			MerkleRoot:  blockchain.CalcMerkleRoot(txs, false),
			WitnessRoot: blockchain.CalcMerkleRoot(txs, true),
			Timestamp:   prevTime.Add(time.Minute),
			Bits:        params.PowLimitBits,
		}
		require.True(t, solveTestBlock(&header, params),
			"failed to solve block at height %d", h)

		msgBlock := &wire.MsgBlock{
			Header:       header,
			Transactions: []*wire.MsgTx{cb},
		}
		block := hnsutil.NewBlock(msgBlock)
		blocks = append(blocks, block)

		bh := block.Hash()
		prevHash = bh
		prevTime = header.Timestamp
	}

	return blocks
}

// TestSyncStateMachine exercises the end-to-end IBD sync flow:
//
//	┌→ startSync
//	│      ↓
//	│  fetchHeaders
//	│      ↓
//	│  handleHeadersMsg
//	│      ↓
//	│  fetchHeaderBlocks ←┐
//	│      ↓              │ (refill)
//	│  handleBlockMsg ────┘──→ IBD complete
//	│
//	│  (stall detected at any phase above)
//	│      ↓
//	│  handleStallSample
//	│      ↓
//	└── handleDonePeerMsg
//
// It verifies that header processing transitions to block download, that the
// pipeline refill path in handleBlockMsg is exercised, and that IBD mode is
// properly cleared once the chain catches up to the best header.
//
// The "fresh ibd" case tests a complete sync from genesis: headers are fetched
// and then blocks are downloaded.
//
// The "stall before any headers" and "stall mid header download" cases test
// recovery when the sync peer stalls during header download.  A replacement
// peer delivers the remaining (or all) headers and then all blocks.
//
// The "headers complete peer stalls on blocks" case tests recovery when the
// sync peer delivers all headers but stalls before sending any blocks; a
// replacement peer downloads all blocks.
//
// The "stalled sync peer recovery" case tests recovery mid-block-download: a
// sync peer stops responding after some blocks, handleStallSample detects the
// inactivity, the stalled peer is disconnected, and a replacement peer
// finishes IBD.
//
// The "stall mid headers then stall on blocks" case combines both failure
// modes: one peer stalls during headers (peer 2 takes over and finishes
// headers), then peer 2 stalls during block download (peer 3 finishes blocks).
// This exercises recovery across three distinct peers.
func TestSyncStateMachine(t *testing.T) {
	t.Parallel()

	const testTotalBlocks = 2 * minInFlightBlocks

	tests := []struct {
		name        string
		totalBlocks int

		// stallHeadersAfter, when >= 0, triggers a stall during
		// header download: deliver this many headers, then stall
		// the sync peer and verify a replacement finishes header
		// download.  Set to -1 for no header stall.
		stallHeadersAfter int

		// stallAfter, when >= 0, triggers a stall during block
		// download: deliver all headers, then process this many
		// blocks before stalling.  Set to -1 for no block stall.
		stallAfter int
	}{
		{
			name:              "fresh ibd",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: -1,
			stallAfter:        -1,
		},
		{
			name:              "stall before any headers",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: 0,
			stallAfter:        -1,
		},
		{
			name:              "stall mid header download",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: testTotalBlocks / 2,
			stallAfter:        -1,
		},
		{
			name:              "headers complete peer stalls on blocks",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: -1,
			stallAfter:        0,
		},
		{
			name:              "stalled sync peer recovery",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: -1,
			stallAfter:        5,
		},
		{
			name:              "stall mid headers then stall on blocks",
			totalBlocks:       testTotalBlocks,
			stallHeadersAfter: testTotalBlocks / 2,
			stallAfter:        5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			params := chaincfg.RegressionNetParams
			params.Checkpoints = nil

			sm, tearDown := makeMockSyncManager(t, &params)
			defer tearDown()

			blocks := generateTestBlocks(t, &params, tc.totalBlocks)

			// Register a sync candidate and call startSync,
			// which activates IBD mode and sends getheaders.
			peer1 := startIBD(t, sm, tc.totalBlocks)

			if tc.stallHeadersAfter >= 0 {
				// Stall during header download;
				// replacement sends remaining headers.
				peer2 := newSyncCandidate(t, sm,
					int32(tc.totalBlocks))
				syncStalledHeaderRecovery(
					t, sm, peer1, peer2,
					blocks, tc.stallHeadersAfter,
					tc.totalBlocks,
				)

				if tc.stallAfter >= 0 {
					peer3 := newSyncCandidate(t, sm,
						int32(tc.totalBlocks))
					syncStalledPeerRecovery(
						t, sm, peer2,
						peer3, blocks,
						tc.stallAfter,
						tc.totalBlocks,
					)
				} else {
					syncProcessBlocks(t, sm,
						peer2, blocks,
						tc.totalBlocks)
				}
			} else {
				syncSendHeaders(t, sm, peer1,
					blocks, tc.totalBlocks)

				if tc.stallAfter >= 0 {
					peer2 := newSyncCandidate(t, sm,
						int32(tc.totalBlocks))
					syncStalledPeerRecovery(
						t, sm, peer1,
						peer2, blocks,
						tc.stallAfter,
						tc.totalBlocks,
					)
				} else {
					syncProcessBlocks(t, sm,
						peer1, blocks,
						tc.totalBlocks)
				}
			}
		})
	}
}

// newSyncCandidate creates and registers a sync-candidate peer at the
// given height without triggering startSync.
func newSyncCandidate(t *testing.T, sm *SyncManager,
	height int32) *peer.Peer {

	t.Helper()

	p := peer.NewInboundPeer(&peer.Config{
		ChainParams: sm.chainParams,
	})
	p.UpdateLastBlockHeight(height)
	sm.peerStates[p] = &peerSyncState{
		syncCandidate:   true,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}
	return p
}

// assertIBDComplete verifies that IBD finished: chain height matches
// totalBlocks, ibdMode is off, and no blocks remain in-flight.
func assertIBDComplete(t *testing.T, sm *SyncManager,
	peerState *peerSyncState, totalBlocks int) {

	t.Helper()

	best := sm.chain.BestSnapshot()
	require.Equal(t, int32(totalBlocks), best.Height)
	require.False(t, sm.ibdMode,
		"ibdMode should be off after catching up")
	require.Empty(t, sm.requestedBlocks,
		"all requested blocks should be fulfilled")
	require.Empty(t, peerState.requestedBlocks,
		"peer should have no outstanding block requests")
}

// startIBD registers a sync peer and calls startSync, verifying that IBD
// mode is activated and the peer is selected.
func startIBD(t *testing.T, sm *SyncManager,
	peerHeight int) *peer.Peer {

	t.Helper()

	syncPeer := newSyncCandidate(t, sm, int32(peerHeight))

	sm.startSync()

	require.True(t, sm.syncPeer == syncPeer,
		"syncPeer should be set after startSync")
	require.True(t, sm.ibdMode, "ibdMode should be on")
	require.False(t, sm.lastProgressTime.IsZero(),
		"lastProgressTime should be set")

	return syncPeer
}

// syncSendHeaders delivers block headers to the sync manager and verifies
// that block requests are generated.
func syncSendHeaders(t *testing.T, sm *SyncManager,
	syncPeer *peer.Peer, blocks []*hnsutil.Block, totalBlocks int) {

	t.Helper()

	// Record the progress time set by startIBD so we can verify
	// that handleHeadersMsg advances it.
	progressBefore := sm.lastProgressTime

	headers := &wire.HnsMsgHeaders{}
	for _, block := range blocks {
		headers.Headers = append(headers.Headers, &block.MsgBlock().Header)
	}

	sm.handleHeadersMsg(&headersMsg{
		headers: headers,
		peer:    syncPeer,
	})

	_, bestHeaderHeight := sm.chain.BestHeader()
	require.Equal(t, int32(totalBlocks), bestHeaderHeight)

	require.True(t, sm.lastProgressTime.After(progressBefore),
		"handleHeadersMsg should update lastProgressTime")

	wantRequested := make(map[chainhash.Hash]struct{}, len(blocks))
	for _, block := range blocks {
		wantRequested[*block.Hash()] = struct{}{}
	}
	require.Equal(t, wantRequested, sm.requestedBlocks)
	require.Equal(t, wantRequested, sm.peerStates[syncPeer].requestedBlocks)
}

// syncProcessBlocks feeds all blocks to handleBlockMsg and verifies that IBD
// mode remains active until the final block, at which point IBD completes.
func syncProcessBlocks(t *testing.T, sm *SyncManager, syncPeer *peer.Peer,
	blocks []*hnsutil.Block, totalBlocks int) {

	t.Helper()

	peerState := sm.peerStates[syncPeer]

	for i, block := range blocks {
		sm.handleBlockMsg(&blockMsg{
			block: block,
			peer:  syncPeer,
			reply: make(chan struct{}, 1),
		})

		if i < len(blocks)-1 {
			require.True(t, sm.ibdMode,
				"ibdMode should still be on at height %d", i+1)
		}
	}

	assertIBDComplete(t, sm, peerState, totalBlocks)
}

// syncStalledPeerRecovery processes stallAfter blocks from stalledPeer,
// triggers stall detection, verifies that stalledPeer is removed and
// replacementPeer takes over, then feeds remaining blocks and verifies
// IBD completes.
func syncStalledPeerRecovery(t *testing.T, sm *SyncManager,
	stalledPeer, replacementPeer *peer.Peer,
	blocks []*hnsutil.Block, stallAfter, totalBlocks int) {

	t.Helper()

	// Process the first stallAfter blocks from the stalled peer.
	for _, block := range blocks[:stallAfter] {
		sm.handleBlockMsg(&blockMsg{
			block: block,
			peer:  stalledPeer,
			reply: make(chan struct{}, 1),
		})
	}

	best := sm.chain.BestSnapshot()
	require.Equal(t, int32(stallAfter), best.Height)
	require.True(t, sm.ibdMode)

	// Trigger stall detection.
	sm.lastProgressTime = time.Now().Add(
		-(maxStallDuration + time.Minute))
	sm.handleStallSample()

	// Verify that handleStallSample called Disconnect() on the
	// stalled peer (which closes p.quit, making WaitForDisconnect
	// return immediately).
	disconnected := make(chan struct{})
	go func() {
		stalledPeer.WaitForDisconnect()
		close(disconnected)
	}()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("Disconnect() was not called on stalled peer")
	}

	// Snapshot the stalled peer's outstanding requested blocks before
	// disconnection so we can verify they are cleaned up.
	stalledState := sm.peerStates[stalledPeer]
	stalledRequested := make([]chainhash.Hash, 0, len(stalledState.requestedBlocks))
	for hash := range stalledState.requestedBlocks {
		stalledRequested = append(stalledRequested, hash)
	}
	require.NotEmpty(t, stalledRequested,
		"stalled peer should have outstanding requested blocks")

	// In production, Disconnect() triggers handleDonePeerMsg
	// asynchronously via the peer goroutine.  Call it directly to
	// complete the removal.  Note: handleDonePeerMsg first clears the
	// stalled peer's requested blocks from the global map via
	// clearRequestedState, then updateSyncPeer → startSync immediately
	// re-requests them for the replacement peer.
	sm.handleDonePeerMsg(stalledPeer)

	_, stalledTracked := sm.peerStates[stalledPeer]
	require.False(t, stalledTracked,
		"stalled peer should be removed")
	require.True(t, sm.syncPeer == replacementPeer,
		"replacement peer should take over as sync peer")
	require.True(t, sm.ibdMode)

	// Verify that the replacement peer re-requested the exact same
	// blocks that were outstanding from the stalled peer.
	replacementState := sm.peerStates[replacementPeer]
	require.Equal(t, len(stalledRequested),
		len(replacementState.requestedBlocks),
		"replacement peer should request same number of blocks")
	for _, hash := range stalledRequested {
		_, exists := replacementState.requestedBlocks[hash]
		require.True(t, exists,
			"block %v should be requested from replacement peer",
			hash)
	}

	// Feed remaining blocks from the replacement peer.
	for _, block := range blocks[stallAfter:] {
		sm.handleBlockMsg(&blockMsg{
			block: block,
			peer:  replacementPeer,
			reply: make(chan struct{}, 1),
		})
	}

	assertIBDComplete(t, sm, replacementState, totalBlocks)
}

// syncStalledHeaderRecovery simulates a stall during header download.
// It optionally delivers headersSent headers from stalledPeer, triggers stall
// detection, verifies that stalledPeer is removed and replacementPeer takes
// over, then delivers remaining headers and verifies block requests are
// generated.  The caller is responsible for the block-download phase.
func syncStalledHeaderRecovery(t *testing.T, sm *SyncManager,
	stalledPeer, replacementPeer *peer.Peer,
	blocks []*hnsutil.Block, headersSent, totalBlocks int) {

	t.Helper()

	// Deliver partial headers from the stalled peer.  When
	// headersSent is 0, this is a no-op (peer stalls immediately).
	if headersSent > 0 {
		headers := &wire.HnsMsgHeaders{}
		for _, block := range blocks[:headersSent] {
			headers.Headers = append(headers.Headers,
				&block.MsgBlock().Header)
		}

		sm.handleHeadersMsg(&headersMsg{
			headers: headers,
			peer:    stalledPeer,
		})

		_, bestHeaderHeight := sm.chain.BestHeader()
		require.Equal(t, int32(headersSent), bestHeaderHeight)
	}

	// No blocks should have been requested during header download
	// since the headers haven't caught up to the peer's height yet.
	require.Empty(t, sm.requestedBlocks,
		"no blocks should be requested during header download")

	// Trigger stall detection.
	sm.lastProgressTime = time.Now().Add(
		-(maxStallDuration + time.Minute))
	sm.handleStallSample()

	// Verify that handleStallSample called Disconnect() on the
	// stalled peer.
	disconnected := make(chan struct{})
	go func() {
		stalledPeer.WaitForDisconnect()
		close(disconnected)
	}()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("Disconnect() was not called on stalled peer")
	}

	// Complete peer removal.  handleDonePeerMsg clears state and
	// triggers startSync which selects the replacement peer.
	sm.handleDonePeerMsg(stalledPeer)

	_, stalledTracked := sm.peerStates[stalledPeer]
	require.False(t, stalledTracked,
		"stalled peer should be removed")
	require.True(t, sm.syncPeer == replacementPeer,
		"replacement peer should take over as sync peer")
	require.True(t, sm.ibdMode)

	// Deliver remaining headers from the replacement peer.  When
	// headersSent is 0, this is all headers.
	remainingHeaders := &wire.HnsMsgHeaders{}
	for _, block := range blocks[headersSent:] {
		remainingHeaders.Headers = append(remainingHeaders.Headers,
			&block.MsgBlock().Header)
	}
	sm.handleHeadersMsg(&headersMsg{
		headers: remainingHeaders,
		peer:    replacementPeer,
	})

	_, bestHeaderHeight := sm.chain.BestHeader()
	require.Equal(t, int32(totalBlocks), bestHeaderHeight)

	// Verify all blocks were requested from the replacement.
	wantRequested := make(map[chainhash.Hash]struct{}, len(blocks))
	for _, block := range blocks {
		wantRequested[*block.Hash()] = struct{}{}
	}
	require.Equal(t, wantRequested, sm.requestedBlocks)
	replacementState := sm.peerStates[replacementPeer]
	require.Equal(t, wantRequested, replacementState.requestedBlocks)
}

// TestStartSyncBlockFallback verifies the startSync fallback path where
// headers are already caught up but the block chain lags behind.  In this
// case startSync should skip header download and directly request blocks.
func TestStartSyncBlockFallback(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	// Process headers so the header chain is at numBlocks while the
	// block chain stays at genesis.
	const numBlocks = 11
	blocks := generateTestBlocks(t, &params, numBlocks)
	for _, block := range blocks {
		_, err := sm.chain.ProcessBlockHeader(
			&block.MsgBlock().Header, blockchain.BFNone, false)
		require.NoError(t, err)
	}

	// Add a peer whose height equals the header height.
	// fetchHigherPeers(bestHeaderHeight) returns nothing because
	// the peer is not strictly higher than our headers.
	// fetchHigherPeers(bestBlockHeight=0) returns the peer.
	syncPeer := peer.NewInboundPeer(&peer.Config{})
	syncPeer.UpdateLastBlockHeight(int32(numBlocks))
	sm.peerStates[syncPeer] = &peerSyncState{
		syncCandidate:   true,
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
	}

	sm.startSync()

	require.NotNil(t, sm.syncPeer,
		"sync peer should be set for block download")
	require.NotEmpty(t, sm.requestedBlocks,
		"blocks should be requested via fetchHeaderBlocks")
}

func TestNotFoundFromSyncPeerSwitchesBlockDownloadPeer(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	const numBlocks = 11
	blocks := generateTestBlocks(t, &params, numBlocks)
	for _, block := range blocks {
		_, err := sm.chain.ProcessBlockHeader(
			&block.MsgBlock().Header, blockchain.BFNone, false)
		require.NoError(t, err)
	}

	stalePeer := newSyncCandidate(t, sm, numBlocks)
	sm.startSync()
	require.True(t, sm.syncPeer == stalePeer)

	staleState := sm.peerStates[stalePeer]
	require.NotEmpty(t, staleState.requestedBlocks)

	replacementPeer := newSyncCandidate(t, sm, numBlocks)

	missingHash := blocks[0].Hash()
	notFound := wire.NewHnsMsgNotFound()
	require.NoError(t, notFound.AddInvVect(
		wire.NewInvVect(wire.InvTypeBlock, missingHash)))

	sm.handleNotFoundMsg(&notFoundMsg{
		notFound: notFound,
		peer:     stalePeer,
	})

	require.False(t, staleState.syncCandidate)
	require.Empty(t, staleState.requestedBlocks)
	require.True(t, sm.syncPeer == replacementPeer)

	replacementState := sm.peerStates[replacementPeer]
	require.Contains(t, replacementState.requestedBlocks, *missingHash)
	require.Contains(t, sm.requestedBlocks, *missingHash)
	require.Equal(t, sm.requestedBlocks, replacementState.requestedBlocks)
}

func TestHeadersAnnouncementUpdatesPeerAndRequestsBlock(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	blocks := generateTestBlocks(t, &params, 1)
	announcedBlock := blocks[0]
	announcedHash := announcedBlock.Hash()

	p := newSyncCandidate(t, sm, 0)
	sm.ibdMode = false

	sm.handleHeadersMsg(&headersMsg{
		headers: &wire.HnsMsgHeaders{
			Headers: []*wire.BlockHeader{
				&announcedBlock.MsgBlock().Header,
			},
		},
		peer: p,
	})

	require.Equal(t, int32(1), p.LastBlock())
	lastAnnounced := p.LastAnnouncedBlock()
	require.NotNil(t, lastAnnounced)
	require.True(t, lastAnnounced.IsEqual(announcedHash))
	require.Contains(t, sm.requestedBlocks, *announcedHash)
	require.Contains(t, sm.peerStates[p].requestedBlocks, *announcedHash)
}

func TestHandleTxMsgNoMempool(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	p := newSyncCandidate(t, sm, 0)
	tx := hnsutil.NewTx(wire.NewMsgTx(wire.TxVersion))
	txHash := tx.Hash()

	state := sm.peerStates[p]
	state.requestedTxns[*txHash] = struct{}{}
	sm.requestedTxns[*txHash] = struct{}{}

	sm.handleTxMsg(&txMsg{
		tx:   tx,
		peer: p,
	})

	require.NotContains(t, state.requestedTxns, *txHash)
	require.NotContains(t, sm.requestedTxns, *txHash)
}

func TestHaveTransactionInventoryNoMempool(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	hash := chainhash.Hash{0x01}
	have, err := sm.haveInventory(wire.NewInvVect(wire.InvTypeTx, &hash))
	require.NoError(t, err)
	require.False(t, have)
}

// TestStallNoDisconnectAtSameHeight verifies that handleStallSample does
// not disconnect a sync peer whose advertised height equals our own.
func TestStallNoDisconnectAtSameHeight(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	p := peer.NewInboundPeer(&peer.Config{})
	p.UpdateLastBlockHeight(0) // Same height as our genesis chain.
	sm.peerStates[p] = &peerSyncState{}
	sm.syncPeer = p
	sm.ibdMode = true
	sm.lastProgressTime = time.Now().Add(
		-(maxStallDuration + time.Minute))

	sm.handleStallSample()

	_, tracked := sm.peerStates[p]
	require.True(t, tracked,
		"peer at same height should not be disconnected")
	require.Nil(t, sm.syncPeer,
		"we should have nil syncPeer after handleStallSample")
}

// TestStartSyncChainCurrent verifies that startSync does not set syncPeer
// or ibdMode when the chain is current and no peer is strictly higher.
// isInIBDMode sees IsCurrent()==true with no higher peers, returns false,
// and startSync exits immediately.
func TestStartSyncChainCurrent(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	// Mine a single block with a recent timestamp so
	// IsCurrent() returns true.
	cb := createTestCoinbase(t, 1, &params)
	txs := []*hnsutil.Tx{hnsutil.NewTx(cb)}
	header := wire.BlockHeader{
		Version:     2,
		PrevBlock:   *params.GenesisHash,
		MerkleRoot:  blockchain.CalcMerkleRoot(txs, false),
		WitnessRoot: blockchain.CalcMerkleRoot(txs, true),
		Timestamp:   time.Now().Truncate(time.Second),
		Bits:        params.PowLimitBits,
	}
	require.True(t, solveTestBlock(&header, &params))

	block := hnsutil.NewBlock(&wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{cb},
	})
	_, _, err := sm.chain.ProcessBlock(block, blockchain.BFNone)
	require.NoError(t, err)
	require.True(t, sm.chain.IsCurrent())

	// Peer at our height — not higher.
	newSyncCandidate(t, sm, 1)

	sm.startSync()

	require.Nil(t, sm.syncPeer,
		"syncPeer should not be set when chain is already current")
	require.False(t, sm.ibdMode,
		"ibdMode should not be activated when chain is already current")
}

// TestIsSyncCandidateRegtest verifies that isSyncCandidate accepts any peer
// on regtest regardless of address, including non-localhost Docker bridge
// addresses.
func TestIsSyncCandidateRegtest(t *testing.T) {
	t.Parallel()

	params := chaincfg.RegressionNetParams
	sm, tearDown := makeMockSyncManager(t, &params)
	defer tearDown()

	tests := []struct {
		name string
		addr string
		want bool
	}{
		{
			name: "localhost",
			addr: "127.0.0.1:18444",
			want: true,
		},
		{
			name: "docker bridge ip",
			addr: "172.18.0.2:18444",
			want: true,
		},
		{
			name: "remote ip",
			addr: "93.184.216.34:18444",
			want: true,
		},
		{
			name: "ipv6 loopback",
			addr: "[::1]:18444",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := peer.NewInboundPeer(&peer.Config{
				ChainParams: sm.chainParams,
			})

			got := sm.isSyncCandidate(p)
			require.Equal(t, tc.want, got)
		})
	}
}
