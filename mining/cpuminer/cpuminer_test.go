// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cpuminer

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/txscript"
)

type emptyTxSource struct{}

func (emptyTxSource) LastUpdated() time.Time { return time.Time{} }
func (emptyTxSource) MiningDescs() []*mining.TxDesc {
	return nil
}
func (emptyTxSource) HaveTransaction(*chainhash.Hash) bool { return false }

func TestGenerateNBlocksMinesAcceptedRegtestBlock(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	defer db.Close()

	timeSource := blockchain.NewMedianTime()
	sigCache := txscript.NewSigCache(1000)
	hashCache := txscript.NewHashCache(1000)
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: &params,
		TimeSource:  timeSource,
		SigCache:    sigCache,
	})
	if err != nil {
		t.Fatalf("blockchain.New: %v", err)
	}

	addr, err := hnsutil.NewAddressPubKeyHash(make([]byte, 20), &params)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}

	policy := mining.Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := mining.NewBlkTmplGenerator(&policy, &params,
		emptyTxSource{}, chain, timeSource, sigCache, hashCache)

	miner := New(&Config{
		ChainParams:            &params,
		BlockTemplateGenerator: generator,
		MiningAddrs:            []hnsutil.Address{addr},
		ProcessBlock: func(block *hnsutil.Block, flags blockchain.BehaviorFlags) (bool, error) {
			_, isOrphan, err := chain.ProcessBlock(block, flags)
			return isOrphan, err
		},
		ConnectedCount: func() int32 { return 1 },
		IsCurrent:      func() bool { return true },
	})

	hashes, err := miner.GenerateNBlocks(1)
	if err != nil {
		t.Fatalf("GenerateNBlocks: %v", err)
	}
	if len(hashes) != 1 || hashes[0] == nil {
		t.Fatalf("GenerateNBlocks hashes = %#v, want one block hash", hashes)
	}

	best := chain.BestSnapshot()
	if best.Height != 1 {
		t.Fatalf("best height = %d, want 1", best.Height)
	}
	if !best.Hash.IsEqual(hashes[0]) {
		t.Fatalf("best hash = %v, mined hash = %v", best.Hash, hashes[0])
	}
}
