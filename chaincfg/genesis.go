// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
//
// TODO(phase1.5): This contains placeholder data. Replace with the real
// Handshake genesis transaction when network parameters are finalized.
var genesisCoinbaseTx = wire.MsgTx{
	Version: 0,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value:    0x12a05f200,
			Address:  wire.Address{},
			Covenant: wire.Covenant{},
		},
	},
	LockTime: 0,
}

// genesisHash is computed from the genesis block header so it stays
// consistent with any merkle-root changes during the refactor.
//
// TODO(phase1.5): Replace with the real Handshake mainnet genesis hash once
// network parameters and PoW constants are finalized.
var genesisHash chainhash.Hash // set by init()

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.  For a single-transaction block, the merkle root is
// simply the transaction hash.
var genesisMerkleRoot = genesisCoinbaseTx.TxHash()

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,         // computed from genesisCoinbaseTx.TxHash()
		Timestamp:  time.Unix(0x495fab29, 0), // 2009-01-03 18:15:05 +0000 UTC
		Bits:       0x1d00ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x7c2bac1d,               // 2083236893
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// regTestGenesisHash is computed from the regtest genesis block header.
var regTestGenesisHash chainhash.Hash // set by init()

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = genesisMerkleRoot

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot,  // computed from genesisCoinbaseTx.TxHash()
		Timestamp:  time.Unix(1296688602, 0),  // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x207fffff,                // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// testNet3GenesisHash is computed from the testnet3 genesis block header.
var testNet3GenesisHash chainhash.Hash // set by init()

// testNet3GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 3).  It is the same as the merkle root
// for the main network.
var testNet3GenesisMerkleRoot = genesisMerkleRoot

// testNet3GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet3GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet3GenesisMerkleRoot, // computed from genesisCoinbaseTx.TxHash()
		Timestamp:  time.Unix(1296688602, 0),  // 2011-02-02 23:16:42 +0000 UTC
		Bits:       0x1d00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x18aea41a,                // 414098458
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// testNet4GenesisTx is the transaction for the genesis blocks for test network (version 4).
//
// TODO(phase1.5): This contains placeholder data. Replace with the real
// Handshake testnet4 genesis transaction when network parameters are finalized.
var testNet4GenesisTx = wire.MsgTx{
	Version: 0,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value:    0x12a05f200,
			Address:  wire.Address{},
			Covenant: wire.Covenant{},
		},
	},
	LockTime: 0,
}

// testNet4GenesisHash is computed from the testnet4 genesis block header.
var testNet4GenesisHash chainhash.Hash // set by init()

// testNet4GenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network (version 4).  For a single-transaction block, the
// merkle root is simply the transaction hash.
var testNet4GenesisMerkleRoot = testNet4GenesisTx.TxHash()

// testNet4GenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network (version 3).
var testNet4GenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},          // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNet4GenesisMerkleRoot, // computed from testNet4GenesisTx.TxHash()
		Timestamp:  time.Unix(1714777860, 0),  // 2024-05-03 23:11:00 +0000 UTC
		Bits:       0x1d00ffff,                // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0x17780cbb,                // 393743547
	},
	Transactions: []*wire.MsgTx{&testNet4GenesisTx},
}

// simNetGenesisHash is computed from the simnet genesis block header.
var simNetGenesisHash chainhash.Hash // set by init()

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the main network.
var simNetGenesisMerkleRoot = genesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: simNetGenesisMerkleRoot,  // computed from genesisCoinbaseTx.TxHash()
		Timestamp:  time.Unix(1401292357, 0), // 2014-05-28 15:52:37 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// sigNetGenesisHash is computed from the signet genesis block header.
var sigNetGenesisHash chainhash.Hash // set by init()

// sigNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the signet test network. It is the same as the merkle root for
// the main network.
var sigNetGenesisMerkleRoot = genesisMerkleRoot

// sigNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the signet test network.
var sigNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: sigNetGenesisMerkleRoot,  // computed from genesisCoinbaseTx.TxHash()
		Timestamp:  time.Unix(1598918400, 0), // 2020-09-01 00:00:00 +0000 UTC
		Bits:       0x1e0377ae,               // 503543726 [00000377ae000000000000000000000000000000000000000000000000000000]
		Nonce:      52613770,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// init computes genesis block hashes from the block headers so they stay
// consistent with any transaction format changes during the refactor.
//
// TODO(phase1.5): Replace with real Handshake genesis hashes once network
// parameters and PoW constants are finalized.
func init() {
	genesisHash = genesisBlock.Header.BlockHash()
	regTestGenesisHash = regTestGenesisBlock.Header.BlockHash()
	testNet3GenesisHash = testNet3GenesisBlock.Header.BlockHash()
	testNet4GenesisHash = testNet4GenesisBlock.Header.BlockHash()
	simNetGenesisHash = simNetGenesisBlock.Header.BlockHash()
	sigNetGenesisHash = sigNetGenesisBlock.Header.BlockHash()
}
