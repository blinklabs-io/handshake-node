// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

const airdropSpentFieldSize = (airdropTreeLeaves + 7) / 8

var airdropSpentKeyName = []byte("airdropspent")

type airdropSpentField struct {
	bits []byte
}

func dbFetchAirdropSpentField(dbTx database.Tx) (*airdropSpentField, error) {
	serialized := dbTx.Metadata().Get(airdropSpentKeyName)
	if serialized == nil {
		return &airdropSpentField{
			bits: make([]byte, airdropSpentFieldSize),
		}, nil
	}
	if len(serialized) != airdropSpentFieldSize {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt airdrop spent field "+
				"length %d", len(serialized)),
		}
	}

	field := &airdropSpentField{
		bits: make([]byte, airdropSpentFieldSize),
	}
	copy(field.bits, serialized)
	return field, nil
}

func dbPutAirdropSpentField(dbTx database.Tx,
	field *airdropSpentField) error {

	return dbTx.Metadata().Put(airdropSpentKeyName, field.bits)
}

func (f *airdropSpentField) isSpent(position uint32) bool {
	if position >= airdropTreeLeaves {
		return true
	}
	return f.bits[position>>3]&(1<<(7-(position&7))) != 0
}

func (f *airdropSpentField) setSpent(position uint32, spent bool) {
	if position >= airdropTreeLeaves {
		return
	}

	mask := byte(1 << (7 - (position & 7)))
	if spent {
		f.bits[position>>3] |= mask
		return
	}
	f.bits[position>>3] &^= mask
}

func (f *airdropSpentField) spendBlock(block *hnsutil.Block) error {
	txns := block.Transactions()
	if len(txns) == 0 {
		return nil
	}

	return forEachCoinbaseAirdropProof(txns[0], func(_ int,
		proof *airdropProof) error {

		position, err := proof.position()
		if err != nil {
			return badCovenant("airdrop proof position is invalid")
		}
		if f.isSpent(position) {
			return badCovenant("airdrop proof already spent")
		}
		f.setSpent(position, true)
		return nil
	})
}

func (f *airdropSpentField) unspendBlock(block *hnsutil.Block) error {
	txns := block.Transactions()
	if len(txns) == 0 {
		return nil
	}

	return forEachCoinbaseAirdropProof(txns[0], func(_ int,
		proof *airdropProof) error {

		position, err := proof.position()
		if err != nil {
			return badCovenant("airdrop proof position is invalid")
		}
		f.setSpent(position, false)
		return nil
	})
}

func checkCoinbaseAirdropsAvailable(dbTx database.Tx,
	block *hnsutil.Block) error {

	field, err := dbFetchAirdropSpentField(dbTx)
	if err != nil {
		return err
	}
	return field.spendBlock(block)
}

func spendCoinbaseAirdrops(dbTx database.Tx, block *hnsutil.Block) error {
	field, err := dbFetchAirdropSpentField(dbTx)
	if err != nil {
		return err
	}
	if err := field.spendBlock(block); err != nil {
		return err
	}
	return dbPutAirdropSpentField(dbTx, field)
}

func unspendCoinbaseAirdrops(dbTx database.Tx, block *hnsutil.Block) error {
	field, err := dbFetchAirdropSpentField(dbTx)
	if err != nil {
		return err
	}
	if err := field.unspendBlock(block); err != nil {
		return err
	}
	return dbPutAirdropSpentField(dbTx, field)
}

func forEachCoinbaseAirdropProof(tx *hnsutil.Tx,
	fn func(outputIndex int, proof *airdropProof) error) error {

	if tx == nil || !IsCoinBase(tx) {
		return nil
	}

	msgTx := tx.MsgTx()
	for i := 1; i < len(msgTx.TxIn); i++ {
		if i >= len(msgTx.TxOut) {
			return badCovenant("coinbase proof input is unlinked")
		}
		if msgTx.TxOut[i].Covenant.Type != wire.CovenantNone {
			continue
		}
		if len(msgTx.TxIn[i].Witness) != 1 {
			return badCovenant("coinbase airdrop witness is invalid")
		}

		proof, err := parseAirdropProof(msgTx.TxIn[i].Witness[0])
		if err != nil {
			return badCovenant("airdrop proof is invalid")
		}
		if !proof.isSane() {
			return badCovenant("airdrop proof is not sane")
		}
		if err := fn(i, proof); err != nil {
			return err
		}
	}
	return nil
}

// IsAirdropSpent returns whether the airdrop bitfield position has already
// been consumed by the active chain.
func (b *BlockChain) IsAirdropSpent(position uint32) (bool, error) {
	var spent bool
	err := b.db.View(func(dbTx database.Tx) error {
		field, err := dbFetchAirdropSpentField(dbTx)
		if err != nil {
			return err
		}
		spent = field.isSpent(position)
		return nil
	})
	return spent, err
}
