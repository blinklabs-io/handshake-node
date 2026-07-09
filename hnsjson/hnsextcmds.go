// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC commands that are supported by
// a chain server with handshake-node extensions.

package hnsjson

// NodeSubCmd defines the type used in the addnode JSON-RPC command for the
// sub command field.
type NodeSubCmd string

const (
	// NConnect indicates the specified host that should be connected to.
	NConnect NodeSubCmd = "connect"

	// NRemove indicates the specified peer that should be removed as a
	// persistent peer.
	NRemove NodeSubCmd = "remove"

	// NDisconnect indicates the specified peer should be disconnected.
	NDisconnect NodeSubCmd = "disconnect"
)

// NodeCmd defines the dropnode JSON-RPC command.
type NodeCmd struct {
	SubCmd        NodeSubCmd `jsonrpcusage:"\"connect|remove|disconnect\""`
	Target        string
	ConnectSubCmd *string `jsonrpcusage:"\"perm|temp\""`
}

// NewNodeCmd returns a new instance which can be used to issue a `node`
// JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewNodeCmd(subCmd NodeSubCmd, target string, connectSubCmd *string) *NodeCmd {
	return &NodeCmd{
		SubCmd:        subCmd,
		Target:        target,
		ConnectSubCmd: connectSubCmd,
	}
}

// DebugLevelCmd defines the debuglevel JSON-RPC command.  This command is not a
// standard Bitcoin command.  It is an extension for handshake-node.
type DebugLevelCmd struct {
	LevelSpec string
}

// NewDebugLevelCmd returns a new DebugLevelCmd which can be used to issue a
// debuglevel JSON-RPC command.  This command is not a standard Bitcoin command.
// It is an extension for handshake-node.
func NewDebugLevelCmd(levelSpec string) *DebugLevelCmd {
	return &DebugLevelCmd{
		LevelSpec: levelSpec,
	}
}

// GenerateToAddressCmd defines the generatetoaddress JSON-RPC command.
type GenerateToAddressCmd struct {
	NumBlocks int64
	Address   string
	MaxTries  *int64 `jsonrpcdefault:"1000000"`
}

// NewGenerateToAddressCmd returns a new instance which can be used to issue a
// generatetoaddress JSON-RPC command.
func NewGenerateToAddressCmd(numBlocks int64, address string, maxTries *int64) *GenerateToAddressCmd {
	return &GenerateToAddressCmd{
		NumBlocks: numBlocks,
		Address:   address,
		MaxTries:  maxTries,
	}
}

// GenerateCmd defines the generate JSON-RPC command.
type GenerateCmd struct {
	NumBlocks uint32
}

// NewGenerateCmd returns a new instance which can be used to issue a generate
// JSON-RPC command.
func NewGenerateCmd(numBlocks uint32) *GenerateCmd {
	return &GenerateCmd{
		NumBlocks: numBlocks,
	}
}

// GetBestBlockCmd defines the getbestblock JSON-RPC command.
type GetBestBlockCmd struct{}

// NewGetBestBlockCmd returns a new instance which can be used to issue a
// getbestblock JSON-RPC command.
func NewGetBestBlockCmd() *GetBestBlockCmd {
	return &GetBestBlockCmd{}
}

// GetCurrentNetCmd defines the getcurrentnet JSON-RPC command.
type GetCurrentNetCmd struct{}

// NewGetCurrentNetCmd returns a new instance which can be used to issue a
// getcurrentnet JSON-RPC command.
func NewGetCurrentNetCmd() *GetCurrentNetCmd {
	return &GetCurrentNetCmd{}
}

// GetHeadersCmd defines the getheaders JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type GetHeadersCmd struct {
	BlockLocators []string `json:"blocklocators"`
	HashStop      string   `json:"hashstop"`
}

// NewGetHeadersCmd returns a new instance which can be used to issue a
// getheaders JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
func NewGetHeadersCmd(blockLocators []string, hashStop string) *GetHeadersCmd {
	return &GetHeadersCmd{
		BlockLocators: blockLocators,
		HashStop:      hashStop,
	}
}

// GetNameInfoCmd defines the getnameinfo JSON-RPC command.
type GetNameInfoCmd struct {
	Name string
}

// NewGetNameInfoCmd returns a new instance which can be used to issue a
// getnameinfo JSON-RPC command.
func NewGetNameInfoCmd(name string) *GetNameInfoCmd {
	return &GetNameInfoCmd{Name: name}
}

// GetNameByHashCmd defines the getnamebyhash JSON-RPC command.
type GetNameByHashCmd struct {
	NameHash string
}

// NewGetNameByHashCmd returns a new instance which can be used to issue a
// getnamebyhash JSON-RPC command.
func NewGetNameByHashCmd(nameHash string) *GetNameByHashCmd {
	return &GetNameByHashCmd{NameHash: nameHash}
}

// GetNameResourceCmd defines the getnameresource JSON-RPC command.
type GetNameResourceCmd struct {
	Name string
}

// NewGetNameResourceCmd returns a new instance which can be used to issue a
// getnameresource JSON-RPC command.
func NewGetNameResourceCmd(name string) *GetNameResourceCmd {
	return &GetNameResourceCmd{Name: name}
}

// GetNameProofCmd defines the getnameproof JSON-RPC command.  The optional
// root parameter defaults to the current committed name root.
type GetNameProofCmd struct {
	Name string
	Root *string
}

// NewGetNameProofCmd returns a new instance which can be used to issue a
// getnameproof JSON-RPC command.
func NewGetNameProofCmd(name string, root *string) *GetNameProofCmd {
	return &GetNameProofCmd{
		Name: name,
		Root: root,
	}
}

// GetNamesCmd defines the getnames JSON-RPC command.
type GetNamesCmd struct {
	Offset *int `jsonrpcdefault:"0"`
	Limit  *int `jsonrpcdefault:"0"`
}

// NewGetNamesCmd returns a new instance which can be used to issue a getnames
// JSON-RPC command.
func NewGetNamesCmd() *GetNamesCmd {
	return &GetNamesCmd{}
}

// NewGetNamesCmdWithPagination returns a new instance which can be used to
// issue a paginated getnames JSON-RPC command.
func NewGetNamesCmdWithPagination(offset, limit *int) *GetNamesCmd {
	return &GetNamesCmd{
		Offset: offset,
		Limit:  limit,
	}
}

// GetNamesByHashCmd defines the getnamesbyhash JSON-RPC command.
type GetNamesByHashCmd struct {
	NameHashes []string
}

// NewGetNamesByHashCmd returns a new instance which can be used to issue a
// getnamesbyhash JSON-RPC command.
func NewGetNamesByHashCmd(nameHashes []string) *GetNamesByHashCmd {
	return &GetNamesByHashCmd{NameHashes: nameHashes}
}

// GetAuctionInfoCmd defines the getauctioninfo JSON-RPC command.
type GetAuctionInfoCmd struct {
	Name string
}

// NewGetAuctionInfoCmd returns a new instance which can be used to issue a
// getauctioninfo JSON-RPC command.
func NewGetAuctionInfoCmd(name string) *GetAuctionInfoCmd {
	return &GetAuctionInfoCmd{Name: name}
}

// CreateOpenCmd defines the createopen JSON-RPC command.
type CreateOpenCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	Name     string
	LockTime *int64
}

// NewCreateOpenCmd returns a new instance which can be used to issue a
// createopen JSON-RPC command.
func NewCreateOpenCmd(inputs []TransactionInput, address string, amount float64,
	name string, lockTime *int64) *CreateOpenCmd {

	return &CreateOpenCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		Name:     name,
		LockTime: lockTime,
	}
}

// CreateBidCmd defines the createbid JSON-RPC command.
type CreateBidCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	Name     string
	Start    uint32
	Blind    string
	LockTime *int64
}

// NewCreateBidCmd returns a new instance which can be used to issue a
// createbid JSON-RPC command.
func NewCreateBidCmd(inputs []TransactionInput, address string, amount float64,
	name string, start uint32, blind string, lockTime *int64) *CreateBidCmd {

	return &CreateBidCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		Name:     name,
		Start:    start,
		Blind:    blind,
		LockTime: lockTime,
	}
}

// CreateRevealCmd defines the createreveal JSON-RPC command.
type CreateRevealCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	NameHash string
	Start    uint32
	Nonce    string
	LockTime *int64
}

// NewCreateRevealCmd returns a new instance which can be used to issue a
// createreveal JSON-RPC command.
func NewCreateRevealCmd(inputs []TransactionInput, address string, amount float64,
	nameHash string, start uint32, nonce string,
	lockTime *int64) *CreateRevealCmd {

	return &CreateRevealCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		NameHash: nameHash,
		Start:    start,
		Nonce:    nonce,
		LockTime: lockTime,
	}
}

// CreateRedeemCmd defines the createredeem JSON-RPC command.
type CreateRedeemCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	NameHash string
	Start    uint32
	LockTime *int64
}

// NewCreateRedeemCmd returns a new instance which can be used to issue a
// createredeem JSON-RPC command.
func NewCreateRedeemCmd(inputs []TransactionInput, address string, amount float64,
	nameHash string, start uint32, lockTime *int64) *CreateRedeemCmd {

	return &CreateRedeemCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		NameHash: nameHash,
		Start:    start,
		LockTime: lockTime,
	}
}

// CreateRegisterCmd defines the createregister JSON-RPC command.
type CreateRegisterCmd struct {
	Inputs      []TransactionInput
	Address     string
	Amount      float64
	NameHash    string
	Start       uint32
	Resource    string
	RenewalHash *string
	LockTime    *int64
}

// NewCreateRegisterCmd returns a new instance which can be used to issue a
// createregister JSON-RPC command.
func NewCreateRegisterCmd(inputs []TransactionInput, address string,
	amount float64, nameHash string, start uint32, resource string,
	renewalHash *string, lockTime *int64) *CreateRegisterCmd {

	return &CreateRegisterCmd{
		Inputs:      inputs,
		Address:     address,
		Amount:      amount,
		NameHash:    nameHash,
		Start:       start,
		Resource:    resource,
		RenewalHash: renewalHash,
		LockTime:    lockTime,
	}
}

// CreateUpdateCmd defines the createupdate JSON-RPC command.
type CreateUpdateCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	NameHash string
	Start    uint32
	Resource string
	LockTime *int64
}

// NewCreateUpdateCmd returns a new instance which can be used to issue a
// createupdate JSON-RPC command.
func NewCreateUpdateCmd(inputs []TransactionInput, address string, amount float64,
	nameHash string, start uint32, resource string,
	lockTime *int64) *CreateUpdateCmd {

	return &CreateUpdateCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		NameHash: nameHash,
		Start:    start,
		Resource: resource,
		LockTime: lockTime,
	}
}

// CreateRenewCmd defines the createrenew JSON-RPC command.
type CreateRenewCmd struct {
	Inputs      []TransactionInput
	Address     string
	Amount      float64
	NameHash    string
	Start       uint32
	RenewalHash *string
	LockTime    *int64
}

// NewCreateRenewCmd returns a new instance which can be used to issue a
// createrenew JSON-RPC command.
func NewCreateRenewCmd(inputs []TransactionInput, address string, amount float64,
	nameHash string, start uint32, renewalHash *string,
	lockTime *int64) *CreateRenewCmd {

	return &CreateRenewCmd{
		Inputs:      inputs,
		Address:     address,
		Amount:      amount,
		NameHash:    nameHash,
		Start:       start,
		RenewalHash: renewalHash,
		LockTime:    lockTime,
	}
}

// CreateTransferCmd defines the createtransfer JSON-RPC command.
type CreateTransferCmd struct {
	Inputs          []TransactionInput
	Address         string
	Amount          float64
	NameHash        string
	Start           uint32
	TransferAddress string
	LockTime        *int64
}

// NewCreateTransferCmd returns a new instance which can be used to issue a
// createtransfer JSON-RPC command.
func NewCreateTransferCmd(inputs []TransactionInput, address string,
	amount float64, nameHash string, start uint32, transferAddress string,
	lockTime *int64) *CreateTransferCmd {

	return &CreateTransferCmd{
		Inputs:          inputs,
		Address:         address,
		Amount:          amount,
		NameHash:        nameHash,
		Start:           start,
		TransferAddress: transferAddress,
		LockTime:        lockTime,
	}
}

// CreateFinalizeCmd defines the createfinalize JSON-RPC command.
type CreateFinalizeCmd struct {
	Inputs      []TransactionInput
	Address     string
	Amount      float64
	Name        string
	Start       uint32
	Flags       uint8
	Claimed     uint32
	Renewals    uint32
	RenewalHash *string
	LockTime    *int64
}

// NewCreateFinalizeCmd returns a new instance which can be used to issue a
// createfinalize JSON-RPC command.
func NewCreateFinalizeCmd(inputs []TransactionInput, address string,
	amount float64, name string, start uint32, flags uint8, claimed uint32,
	renewals uint32, renewalHash *string,
	lockTime *int64) *CreateFinalizeCmd {

	return &CreateFinalizeCmd{
		Inputs:      inputs,
		Address:     address,
		Amount:      amount,
		Name:        name,
		Start:       start,
		Flags:       flags,
		Claimed:     claimed,
		Renewals:    renewals,
		RenewalHash: renewalHash,
		LockTime:    lockTime,
	}
}

// CreateRevokeCmd defines the createrevoke JSON-RPC command.
type CreateRevokeCmd struct {
	Inputs   []TransactionInput
	Address  string
	Amount   float64
	NameHash string
	Start    uint32
	LockTime *int64
}

// NewCreateRevokeCmd returns a new instance which can be used to issue a
// createrevoke JSON-RPC command.
func NewCreateRevokeCmd(inputs []TransactionInput, address string, amount float64,
	nameHash string, start uint32, lockTime *int64) *CreateRevokeCmd {

	return &CreateRevokeCmd{
		Inputs:   inputs,
		Address:  address,
		Amount:   amount,
		NameHash: nameHash,
		Start:    start,
		LockTime: lockTime,
	}
}

// VerifyNameProofCmd defines the verifynameproof JSON-RPC command.
type VerifyNameProofCmd struct {
	Root     string
	NameHash string
	Proof    string
}

// NewVerifyNameProofCmd returns a new instance which can be used to issue a
// verifynameproof JSON-RPC command.
func NewVerifyNameProofCmd(root, nameHash, proof string) *VerifyNameProofCmd {
	return &VerifyNameProofCmd{
		Root:     root,
		NameHash: nameHash,
		Proof:    proof,
	}
}

// VersionCmd defines the version JSON-RPC command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type VersionCmd struct{}

// NewVersionCmd returns a new instance which can be used to issue a JSON-RPC
// version command.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
func NewVersionCmd() *VersionCmd { return new(VersionCmd) }

func init() {
	// No special flags for commands in this file.
	flags := UsageFlag(0)

	MustRegisterCmd("debuglevel", (*DebugLevelCmd)(nil), flags)
	MustRegisterCmd("node", (*NodeCmd)(nil), flags)
	MustRegisterCmd("generate", (*GenerateCmd)(nil), flags)
	MustRegisterCmd("generatetoaddress", (*GenerateToAddressCmd)(nil), flags)
	MustRegisterCmd("getbestblock", (*GetBestBlockCmd)(nil), flags)
	MustRegisterCmd("getcurrentnet", (*GetCurrentNetCmd)(nil), flags)
	MustRegisterCmd("getheaders", (*GetHeadersCmd)(nil), flags)
	MustRegisterCmd("getnameinfo", (*GetNameInfoCmd)(nil), flags)
	MustRegisterCmd("getnamebyhash", (*GetNameByHashCmd)(nil), flags)
	MustRegisterCmd("getnameresource", (*GetNameResourceCmd)(nil), flags)
	MustRegisterCmd("getnameproof", (*GetNameProofCmd)(nil), flags)
	MustRegisterCmd("getnames", (*GetNamesCmd)(nil), flags)
	MustRegisterCmd("getnamesbyhash", (*GetNamesByHashCmd)(nil), flags)
	MustRegisterCmd("getauctioninfo", (*GetAuctionInfoCmd)(nil), flags)
	MustRegisterCmd("createopen", (*CreateOpenCmd)(nil), flags)
	MustRegisterCmd("createbid", (*CreateBidCmd)(nil), flags)
	MustRegisterCmd("createreveal", (*CreateRevealCmd)(nil), flags)
	MustRegisterCmd("createredeem", (*CreateRedeemCmd)(nil), flags)
	MustRegisterCmd("createregister", (*CreateRegisterCmd)(nil), flags)
	MustRegisterCmd("createupdate", (*CreateUpdateCmd)(nil), flags)
	MustRegisterCmd("createrenew", (*CreateRenewCmd)(nil), flags)
	MustRegisterCmd("createtransfer", (*CreateTransferCmd)(nil), flags)
	MustRegisterCmd("createfinalize", (*CreateFinalizeCmd)(nil), flags)
	MustRegisterCmd("createrevoke", (*CreateRevokeCmd)(nil), flags)
	MustRegisterCmd("verifynameproof", (*VerifyNameProofCmd)(nil), flags)
	MustRegisterCmd("version", (*VersionCmd)(nil), flags)
}
