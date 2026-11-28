// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"fmt"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/blockchain/indexers"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

// utxorpcSubmitter adapts the node's transaction acceptance path to
// utxorpc.TxSubmitter. It follows the same sequence as the
// sendrawtransaction RPC so a transaction submitted over either
// interface is validated, relayed, and rebroadcast identically.
type utxorpcSubmitter struct {
	server *server
}

func (u *utxorpcSubmitter) SubmitTransaction(tx *hnsutil.Tx) error {
	// Tag 0 marks the transaction as originating from this node.
	acceptedTxs, err := u.server.txMemPool.ProcessTransaction(
		tx, false, false, 0)
	if err != nil {
		return err
	}

	// The submitted transaction must lead the accepted list. Anything
	// else means the mempool accepted something other than what was
	// asked for, so back the transaction out rather than reporting
	// success for it.
	if len(acceptedTxs) == 0 ||
		!acceptedTxs[0].Tx.Hash().IsEqual(tx.Hash()) {

		u.server.txMemPool.RemoveTransaction(tx, true)
		return fmt.Errorf("transaction %v is not in accepted list",
			tx.Hash())
	}

	u.server.AnnounceNewTransactions(acceptedTxs)

	txD := acceptedTxs[0]
	iv := wire.NewInvVect(wire.InvTypeTx, txD.Tx.Hash())
	u.server.AddRebroadcastInventory(iv, txD)

	return nil
}

// utxorpcTxFetcher adapts the optional transaction index to
// utxorpc.RawTxFetcher.
type utxorpcTxFetcher struct {
	txIndex *indexers.TxIndex
	db      database.DB
}

func (u *utxorpcTxFetcher) FetchRawTx(hash *chainhash.Hash) ([]byte,
	*chainhash.Hash, error) {

	region, err := u.txIndex.TxBlockRegion(hash)
	if err != nil {
		return nil, nil, err
	}
	if region == nil {
		return nil, nil, nil
	}

	var txBytes []byte
	err = u.db.View(func(dbTx database.Tx) error {
		var err error
		txBytes, err = dbTx.FetchBlockRegion(region)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	return txBytes, region.Hash, nil
}

// utxorpcTLSConfig builds the TLS configuration for the UTxO RPC
// listeners from the node's RPC key pair, generating one if it does not
// exist yet. The UTxO RPC server adds the HTTP/2 ALPN protocol itself.
func utxorpcTLSConfig() (*tls.Config, error) {
	if !fileExists(cfg.RPCKey) && !fileExists(cfg.RPCCert) {
		if err := genCertPair(cfg.RPCCert, cfg.RPCKey); err != nil {
			return nil, err
		}
	}
	keypair, err := tls.LoadX509KeyPair(cfg.RPCCert, cfg.RPCKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{keypair},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// handleUtxoRPCBlockchainNotification forwards main chain changes to
// the UTxO RPC server's streaming subscribers.
func (s *server) handleUtxoRPCBlockchainNotification(
	notification *blockchain.Notification) {

	block, ok := notification.Data.(*hnsutil.Block)
	if !ok {
		return
	}

	switch notification.Type {
	case blockchain.NTBlockConnected:
		s.utxorpcServer.NotifyBlockConnected(block)
	case blockchain.NTBlockDisconnected:
		s.utxorpcServer.NotifyBlockDisconnected(block)
	}
}
