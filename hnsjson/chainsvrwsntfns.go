// Copyright (c) 2014-2017 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC websocket notifications that are
// supported by a chain server.

package hnsjson

const (
	// BlockConnectedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a block has been connected.
	//
	// Deprecated: Use FilteredBlockConnectedNtfnMethod instead.
	BlockConnectedNtfnMethod = "blockconnected"

	// BlockDisconnectedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a block has been
	// disconnected.
	//
	// Deprecated: Use FilteredBlockDisconnectedNtfnMethod instead.
	BlockDisconnectedNtfnMethod = "blockdisconnected"

	// FilteredBlockConnectedNtfnMethod is the new method used for
	// notifications from the chain server that a block has been connected.
	FilteredBlockConnectedNtfnMethod = "filteredblockconnected"

	// FilteredBlockDisconnectedNtfnMethod is the new method used for
	// notifications from the chain server that a block has been
	// disconnected.
	FilteredBlockDisconnectedNtfnMethod = "filteredblockdisconnected"

	// RecvTxNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a transaction which pays to
	// a registered address has been processed.
	//
	// Deprecated: Use RelevantTxAcceptedNtfnMethod and
	// FilteredBlockConnectedNtfnMethod instead.
	RecvTxNtfnMethod = "recvtx"

	// RedeemingTxNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a transaction which spends a
	// registered outpoint has been processed.
	//
	// Deprecated: Use RelevantTxAcceptedNtfnMethod and
	// FilteredBlockConnectedNtfnMethod instead.
	RedeemingTxNtfnMethod = "redeemingtx"

	// RescanFinishedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a legacy, deprecated rescan
	// operation has finished.
	//
	// Deprecated: Not used with rescanblocks command.
	RescanFinishedNtfnMethod = "rescanfinished"

	// RescanProgressNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a legacy, deprecated rescan
	// operation this is underway has made progress.
	//
	// Deprecated: Not used with rescanblocks command.
	RescanProgressNtfnMethod = "rescanprogress"

	// TxAcceptedNtfnMethod is the method used for notifications from the
	// chain server that a transaction has been accepted into the mempool.
	TxAcceptedNtfnMethod = "txaccepted"

	// TxAcceptedVerboseNtfnMethod is the method used for notifications from
	// the chain server that a transaction has been accepted into the
	// mempool.  This differs from TxAcceptedNtfnMethod in that it provides
	// more details in the notification.
	TxAcceptedVerboseNtfnMethod = "txacceptedverbose"

	// RelevantTxAcceptedNtfnMethod is the new method used for notifications
	// from the chain server that inform a client that a transaction that
	// matches the loaded filter was accepted by the mempool.
	RelevantTxAcceptedNtfnMethod = "relevanttxaccepted"

	// NameUpdatedNtfnMethod is the method used for notifications from the
	// chain server that a transaction contains a Handshake name covenant.
	NameUpdatedNtfnMethod = "nameupdated"
)

// BlockConnectedNtfn defines the blockconnected JSON-RPC notification.
//
// Deprecated: Use FilteredBlockConnectedNtfn instead.
type BlockConnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewBlockConnectedNtfn returns a new instance which can be used to issue a
// blockconnected JSON-RPC notification.
//
// Deprecated: Use NewFilteredBlockConnectedNtfn instead.
func NewBlockConnectedNtfn(hash string, height int32, time int64) *BlockConnectedNtfn {
	return &BlockConnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// BlockDisconnectedNtfn defines the blockdisconnected JSON-RPC notification.
//
// Deprecated: Use FilteredBlockDisconnectedNtfn instead.
type BlockDisconnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewBlockDisconnectedNtfn returns a new instance which can be used to issue a
// blockdisconnected JSON-RPC notification.
//
// Deprecated: Use NewFilteredBlockDisconnectedNtfn instead.
func NewBlockDisconnectedNtfn(hash string, height int32, time int64) *BlockDisconnectedNtfn {
	return &BlockDisconnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// FilteredBlockConnectedNtfn defines the filteredblockconnected JSON-RPC
// notification.
type FilteredBlockConnectedNtfn struct {
	Height        int32
	Header        string
	SubscribedTxs []string
}

// NewFilteredBlockConnectedNtfn returns a new instance which can be used to
// issue a filteredblockconnected JSON-RPC notification.
func NewFilteredBlockConnectedNtfn(height int32, header string, subscribedTxs []string) *FilteredBlockConnectedNtfn {
	return &FilteredBlockConnectedNtfn{
		Height:        height,
		Header:        header,
		SubscribedTxs: subscribedTxs,
	}
}

// FilteredBlockDisconnectedNtfn defines the filteredblockdisconnected JSON-RPC
// notification.
type FilteredBlockDisconnectedNtfn struct {
	Height int32
	Header string
}

// NewFilteredBlockDisconnectedNtfn returns a new instance which can be used to
// issue a filteredblockdisconnected JSON-RPC notification.
func NewFilteredBlockDisconnectedNtfn(height int32, header string) *FilteredBlockDisconnectedNtfn {
	return &FilteredBlockDisconnectedNtfn{
		Height: height,
		Header: header,
	}
}

// BlockDetails describes details of a tx in a block.
type BlockDetails struct {
	Height int32  `json:"height"`
	Hash   string `json:"hash"`
	Index  int    `json:"index"`
	Time   int64  `json:"time"`
}

// RecvTxNtfn defines the recvtx JSON-RPC notification.
//
// Deprecated: Use RelevantTxAcceptedNtfn and FilteredBlockConnectedNtfn
// instead.
type RecvTxNtfn struct {
	HexTx string
	Block *BlockDetails
}

// NewRecvTxNtfn returns a new instance which can be used to issue a recvtx
// JSON-RPC notification.
//
// Deprecated: Use NewRelevantTxAcceptedNtfn and
// NewFilteredBlockConnectedNtfn instead.
func NewRecvTxNtfn(hexTx string, block *BlockDetails) *RecvTxNtfn {
	return &RecvTxNtfn{
		HexTx: hexTx,
		Block: block,
	}
}

// RedeemingTxNtfn defines the redeemingtx JSON-RPC notification.
//
// Deprecated: Use RelevantTxAcceptedNtfn and FilteredBlockConnectedNtfn
// instead.
type RedeemingTxNtfn struct {
	HexTx string
	Block *BlockDetails
}

// NewRedeemingTxNtfn returns a new instance which can be used to issue a
// redeemingtx JSON-RPC notification.
//
// Deprecated: Use NewRelevantTxAcceptedNtfn and
// NewFilteredBlockConnectedNtfn instead.
func NewRedeemingTxNtfn(hexTx string, block *BlockDetails) *RedeemingTxNtfn {
	return &RedeemingTxNtfn{
		HexTx: hexTx,
		Block: block,
	}
}

// RescanFinishedNtfn defines the rescanfinished JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
type RescanFinishedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewRescanFinishedNtfn returns a new instance which can be used to issue a
// rescanfinished JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
func NewRescanFinishedNtfn(hash string, height int32, time int64) *RescanFinishedNtfn {
	return &RescanFinishedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// RescanProgressNtfn defines the rescanprogress JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
type RescanProgressNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewRescanProgressNtfn returns a new instance which can be used to issue a
// rescanprogress JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
func NewRescanProgressNtfn(hash string, height int32, time int64) *RescanProgressNtfn {
	return &RescanProgressNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// TxAcceptedNtfn defines the txaccepted JSON-RPC notification.
//
// NOTE: As of the HNS/dollarydoo amount migration, Amount is expressed in
// HNS (6 decimal places), produced via hnsutil.Amount(doo).ToHNS().  This
// is a breaking change from the previous btcd-era BTC-style 8-decimal
// encoding; websocket consumers must update their parsers accordingly.
type TxAcceptedNtfn struct {
	TxID   string
	Amount float64
}

// NewTxAcceptedNtfn returns a new instance which can be used to issue a
// txaccepted JSON-RPC notification.  amount must already be in HNS (use
// hnsutil.Amount(doo).ToHNS() to convert from integer dollarydoos).
func NewTxAcceptedNtfn(txHash string, amount float64) *TxAcceptedNtfn {
	return &TxAcceptedNtfn{
		TxID:   txHash,
		Amount: amount,
	}
}

// TxAcceptedVerboseNtfn defines the txacceptedverbose JSON-RPC notification.
type TxAcceptedVerboseNtfn struct {
	RawTx TxRawResult
}

// NewTxAcceptedVerboseNtfn returns a new instance which can be used to issue a
// txacceptedverbose JSON-RPC notification.
func NewTxAcceptedVerboseNtfn(rawTx TxRawResult) *TxAcceptedVerboseNtfn {
	return &TxAcceptedVerboseNtfn{
		RawTx: rawTx,
	}
}

// RelevantTxAcceptedNtfn defines the parameters to the relevanttxaccepted
// JSON-RPC notification.
type RelevantTxAcceptedNtfn struct {
	Transaction string `json:"transaction"`
}

// NewRelevantTxAcceptedNtfn returns a new instance which can be used to issue a
// relevantxaccepted JSON-RPC notification.
func NewRelevantTxAcceptedNtfn(txHex string) *RelevantTxAcceptedNtfn {
	return &RelevantTxAcceptedNtfn{Transaction: txHex}
}

// NameUpdatedNtfn defines the nameupdated JSON-RPC notification.
type NameUpdatedNtfn struct {
	Name         string        `json:"name,omitempty"`
	NameHash     string        `json:"namehash"`
	Covenant     string        `json:"covenant"`
	CovenantType uint8         `json:"covenanttype"`
	TxID         string        `json:"txid"`
	Vout         uint32        `json:"vout"`
	Block        *BlockDetails `json:"block,omitempty"`
}

// NewNameUpdatedNtfn returns a new instance which can be used to issue a
// nameupdated JSON-RPC notification.
func NewNameUpdatedNtfn(name, nameHash, covenant string, covenantType uint8,
	txID string, vout uint32, block *BlockDetails) *NameUpdatedNtfn {

	return &NameUpdatedNtfn{
		Name:         name,
		NameHash:     nameHash,
		Covenant:     covenant,
		CovenantType: covenantType,
		TxID:         txID,
		Vout:         vout,
		Block:        block,
	}
}

func init() {
	// The commands in this file are only usable by websockets and are
	// notifications.
	flags := UFWebsocketOnly | UFNotification

	MustRegisterCmd(BlockConnectedNtfnMethod, (*BlockConnectedNtfn)(nil), flags)
	MustRegisterCmd(BlockDisconnectedNtfnMethod, (*BlockDisconnectedNtfn)(nil), flags)
	MustRegisterCmd(FilteredBlockConnectedNtfnMethod, (*FilteredBlockConnectedNtfn)(nil), flags)
	MustRegisterCmd(FilteredBlockDisconnectedNtfnMethod, (*FilteredBlockDisconnectedNtfn)(nil), flags)
	MustRegisterCmd(RecvTxNtfnMethod, (*RecvTxNtfn)(nil), flags)
	MustRegisterCmd(RedeemingTxNtfnMethod, (*RedeemingTxNtfn)(nil), flags)
	MustRegisterCmd(RescanFinishedNtfnMethod, (*RescanFinishedNtfn)(nil), flags)
	MustRegisterCmd(RescanProgressNtfnMethod, (*RescanProgressNtfn)(nil), flags)
	MustRegisterCmd(TxAcceptedNtfnMethod, (*TxAcceptedNtfn)(nil), flags)
	MustRegisterCmd(TxAcceptedVerboseNtfnMethod, (*TxAcceptedVerboseNtfn)(nil), flags)
	MustRegisterCmd(RelevantTxAcceptedNtfnMethod, (*RelevantTxAcceptedNtfn)(nil), flags)
	MustRegisterCmd(NameUpdatedNtfnMethod, (*NameUpdatedNtfn)(nil), flags)
}
