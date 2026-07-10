// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcclient

import (
	"encoding/hex"
	"encoding/json"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsjson"
)

// FutureGetNameInfoResult is a future promise to deliver the result of a
// GetNameInfoAsync RPC invocation.
type FutureGetNameInfoResult chan *Response

// Receive waits for the Response promised by the future and returns the name
// state lookup result.
func (r FutureGetNameInfoResult) Receive() (*hnsjson.GetNameInfoResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result hnsjson.GetNameInfoResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNameInfoAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetNameInfoAsync(name string) FutureGetNameInfoResult {
	return c.SendCmd(hnsjson.NewGetNameInfoCmd(name))
}

// GetNameInfo returns the current chain state for a Handshake name.
func (c *Client) GetNameInfo(name string) (*hnsjson.GetNameInfoResult, error) {
	return c.GetNameInfoAsync(name).Receive()
}

// GetNameByHashAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetNameByHashAsync(nameHash chainhash.Hash) FutureGetNameInfoResult {
	return c.SendCmd(hnsjson.NewGetNameByHashCmd(nameHash.String()))
}

// GetNameByHash returns the current chain state for a Handshake name hash.
func (c *Client) GetNameByHash(nameHash chainhash.Hash) (*hnsjson.GetNameInfoResult, error) {
	return c.GetNameByHashAsync(nameHash).Receive()
}

// FutureGetNameResourceResult is a future promise to deliver the result of a
// GetNameResourceAsync RPC invocation.
type FutureGetNameResourceResult chan *Response

// Receive waits for the Response promised by the future and returns decoded
// resource data for the requested name.
func (r FutureGetNameResourceResult) Receive() (*hnsjson.GetNameResourceResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result hnsjson.GetNameResourceResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNameResourceAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
func (c *Client) GetNameResourceAsync(name string) FutureGetNameResourceResult {
	return c.SendCmd(hnsjson.NewGetNameResourceCmd(name))
}

// GetNameResource returns decoded resource data for a Handshake name.
func (c *Client) GetNameResource(name string) (*hnsjson.GetNameResourceResult, error) {
	return c.GetNameResourceAsync(name).Receive()
}

// FutureGetNameProofResult is a future promise to deliver the result of a
// GetNameProofAsync RPC invocation.
type FutureGetNameProofResult chan *Response

// Receive waits for the Response promised by the future and returns an Urkel
// proof for the requested name.
func (r FutureGetNameProofResult) Receive() (*hnsjson.GetNameProofResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result hnsjson.GetNameProofResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetNameProofAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetNameProofAsync(name string, root *chainhash.Hash) FutureGetNameProofResult {
	var rootStr *string
	if root != nil {
		hash := root.String()
		rootStr = &hash
	}
	return c.SendCmd(hnsjson.NewGetNameProofCmd(name, rootStr))
}

// GetNameProof returns an Urkel proof for a Handshake name.  Passing a nil root
// uses the server's current committed name root.
func (c *Client) GetNameProof(name string, root *chainhash.Hash) (*hnsjson.GetNameProofResult, error) {
	return c.GetNameProofAsync(name, root).Receive()
}

// FutureGetNamesResult is a future promise to deliver the result of a
// GetNamesAsync RPC invocation.
type FutureGetNamesResult chan *Response

// Receive waits for the Response promised by the future and returns all
// persisted name states.
func (r FutureGetNamesResult) Receive() ([]*hnsjson.NameStateResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result []*hnsjson.NameStateResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetNamesAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetNamesAsync() FutureGetNamesResult {
	return c.SendCmd(hnsjson.NewGetNamesCmd())
}

// GetNamesPageAsync returns an instance of a type that can be used to get a
// paginated getnames result.
func (c *Client) GetNamesPageAsync(offset, limit int) FutureGetNamesResult {
	return c.SendCmd(hnsjson.NewGetNamesCmdWithPagination(&offset, &limit))
}

// GetNames returns all persisted Handshake name states.
func (c *Client) GetNames() ([]*hnsjson.NameStateResult, error) {
	return c.GetNamesAsync().Receive()
}

// GetNamesPage returns a page of persisted Handshake name states.
func (c *Client) GetNamesPage(offset, limit int) ([]*hnsjson.NameStateResult, error) {
	return c.GetNamesPageAsync(offset, limit).Receive()
}

// FutureGetNamesByHashResult is a future promise to deliver the result of a
// GetNamesByHashAsync RPC invocation.
type FutureGetNamesByHashResult chan *Response

// Receive waits for the Response promised by the future and returns name state
// lookup results in request order.
func (r FutureGetNamesByHashResult) Receive() ([]*hnsjson.GetNameInfoResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result []*hnsjson.GetNameInfoResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetNamesByHashAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetNamesByHashAsync(nameHashes []chainhash.Hash) FutureGetNamesByHashResult {
	hashes := make([]string, 0, len(nameHashes))
	for _, hash := range nameHashes {
		hashes = append(hashes, hash.String())
	}
	return c.SendCmd(hnsjson.NewGetNamesByHashCmd(hashes))
}

// GetNamesByHash returns name state lookup results for the provided hashes in
// request order.
func (c *Client) GetNamesByHash(nameHashes []chainhash.Hash) ([]*hnsjson.GetNameInfoResult, error) {
	return c.GetNamesByHashAsync(nameHashes).Receive()
}

// FutureGetAuctionInfoResult is a future promise to deliver the result of a
// GetAuctionInfoAsync RPC invocation.
type FutureGetAuctionInfoResult chan *Response

// Receive waits for the Response promised by the future and returns the current
// auction lifecycle summary.
func (r FutureGetAuctionInfoResult) Receive() (*hnsjson.GetAuctionInfoResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result hnsjson.GetAuctionInfoResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAuctionInfoAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) GetAuctionInfoAsync(name string) FutureGetAuctionInfoResult {
	return c.SendCmd(hnsjson.NewGetAuctionInfoCmd(name))
}

// GetAuctionInfo returns the current auction lifecycle summary for a Handshake
// name.
func (c *Client) GetAuctionInfo(name string) (*hnsjson.GetAuctionInfoResult, error) {
	return c.GetAuctionInfoAsync(name).Receive()
}

// FutureCreateCovenantTxResult is a future promise to deliver the result of a
// covenant transaction construction RPC invocation.
type FutureCreateCovenantTxResult chan *Response

// Receive waits for the Response promised by the future and returns the
// hex-encoded unsigned transaction.
func (r FutureCreateCovenantTxResult) Receive() (string, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return "", err
	}

	var result string
	if err := json.Unmarshal(res, &result); err != nil {
		return "", err
	}
	return result, nil
}

// CreateOpenAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateOpenAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, name string,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateOpenCmd(inputs, address, amount,
		name, lockTime))
}

// CreateOpen returns unsigned transaction hex with an OPEN covenant output.
func (c *Client) CreateOpen(inputs []hnsjson.TransactionInput, address string,
	amount float64, name string, lockTime *int64) (string, error) {

	return c.CreateOpenAsync(inputs, address, amount, name, lockTime).Receive()
}

// CreateBidAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateBidAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, name string, start uint32, blind string,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateBidCmd(inputs, address, amount,
		name, start, blind, lockTime))
}

// CreateBid returns unsigned transaction hex with a BID covenant output.
func (c *Client) CreateBid(inputs []hnsjson.TransactionInput, address string,
	amount float64, name string, start uint32, blind string,
	lockTime *int64) (string, error) {

	return c.CreateBidAsync(inputs, address, amount, name, start, blind,
		lockTime).Receive()
}

// CreateRevealAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateRevealAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	nonce string, lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateRevealCmd(inputs, address, amount,
		nameHash, start, nonce, lockTime))
}

// CreateReveal returns unsigned transaction hex with a REVEAL covenant output.
func (c *Client) CreateReveal(inputs []hnsjson.TransactionInput, address string,
	amount float64, nameHash string, start uint32, nonce string,
	lockTime *int64) (string, error) {

	return c.CreateRevealAsync(inputs, address, amount, nameHash, start,
		nonce, lockTime).Receive()
}

// CreateRedeemAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateRedeemAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateRedeemCmd(inputs, address, amount,
		nameHash, start, lockTime))
}

// CreateRedeem returns unsigned transaction hex with a REDEEM covenant output.
func (c *Client) CreateRedeem(inputs []hnsjson.TransactionInput, address string,
	amount float64, nameHash string, start uint32,
	lockTime *int64) (string, error) {

	return c.CreateRedeemAsync(inputs, address, amount, nameHash, start,
		lockTime).Receive()
}

// CreateRegisterAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateRegisterAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	resource string, renewalHash *string,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateRegisterCmd(inputs, address, amount,
		nameHash, start, resource, renewalHash, lockTime))
}

// CreateRegister returns unsigned transaction hex with a REGISTER covenant
// output.
func (c *Client) CreateRegister(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	resource string, renewalHash *string, lockTime *int64) (string, error) {

	return c.CreateRegisterAsync(inputs, address, amount, nameHash, start,
		resource, renewalHash, lockTime).Receive()
}

// CreateUpdateAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateUpdateAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	resource string, lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateUpdateCmd(inputs, address, amount,
		nameHash, start, resource, lockTime))
}

// CreateUpdate returns unsigned transaction hex with an UPDATE covenant output.
func (c *Client) CreateUpdate(inputs []hnsjson.TransactionInput, address string,
	amount float64, nameHash string, start uint32, resource string,
	lockTime *int64) (string, error) {

	return c.CreateUpdateAsync(inputs, address, amount, nameHash, start,
		resource, lockTime).Receive()
}

// CreateRenewAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateRenewAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	renewalHash *string, lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateRenewCmd(inputs, address, amount,
		nameHash, start, renewalHash, lockTime))
}

// CreateRenew returns unsigned transaction hex with a RENEW covenant output.
func (c *Client) CreateRenew(inputs []hnsjson.TransactionInput, address string,
	amount float64, nameHash string, start uint32, renewalHash *string,
	lockTime *int64) (string, error) {

	return c.CreateRenewAsync(inputs, address, amount, nameHash, start,
		renewalHash, lockTime).Receive()
}

// CreateTransferAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateTransferAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	transferAddress string, lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateTransferCmd(inputs, address, amount,
		nameHash, start, transferAddress, lockTime))
}

// CreateTransfer returns unsigned transaction hex with a TRANSFER covenant
// output.
func (c *Client) CreateTransfer(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	transferAddress string, lockTime *int64) (string, error) {

	return c.CreateTransferAsync(inputs, address, amount, nameHash, start,
		transferAddress, lockTime).Receive()
}

// CreateFinalizeAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateFinalizeAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, name string, start uint32, flags uint8,
	claimed uint32, renewals uint32, renewalHash *string,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateFinalizeCmd(inputs, address, amount,
		name, start, flags, claimed, renewals, renewalHash, lockTime))
}

// CreateFinalize returns unsigned transaction hex with a FINALIZE covenant
// output.
func (c *Client) CreateFinalize(inputs []hnsjson.TransactionInput,
	address string, amount float64, name string, start uint32, flags uint8,
	claimed uint32, renewals uint32, renewalHash *string,
	lockTime *int64) (string, error) {

	return c.CreateFinalizeAsync(inputs, address, amount, name, start, flags,
		claimed, renewals, renewalHash, lockTime).Receive()
}

// CreateRevokeAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
func (c *Client) CreateRevokeAsync(inputs []hnsjson.TransactionInput,
	address string, amount float64, nameHash string, start uint32,
	lockTime *int64) FutureCreateCovenantTxResult {

	return c.SendCmd(hnsjson.NewCreateRevokeCmd(inputs, address, amount,
		nameHash, start, lockTime))
}

// CreateRevoke returns unsigned transaction hex with a REVOKE covenant output.
func (c *Client) CreateRevoke(inputs []hnsjson.TransactionInput, address string,
	amount float64, nameHash string, start uint32,
	lockTime *int64) (string, error) {

	return c.CreateRevokeAsync(inputs, address, amount, nameHash, start,
		lockTime).Receive()
}

// FutureVerifyNameProofResult is a future promise to deliver the result of a
// VerifyNameProofAsync RPC invocation.
type FutureVerifyNameProofResult chan *Response

// Receive waits for the Response promised by the future and returns the proof
// verification result.
func (r FutureVerifyNameProofResult) Receive() (*hnsjson.VerifyNameProofResult, error) {
	res, err := ReceiveFuture(r)
	if err != nil {
		return nil, err
	}

	var result hnsjson.VerifyNameProofResult
	if err := json.Unmarshal(res, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyNameProofAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
func (c *Client) VerifyNameProofAsync(root, nameHash chainhash.Hash, proof []byte) FutureVerifyNameProofResult {
	return c.SendCmd(hnsjson.NewVerifyNameProofCmd(root.String(),
		nameHash.String(), hex.EncodeToString(proof)))
}

// VerifyNameProof verifies a serialized Urkel name proof against a root and
// name hash.
func (c *Client) VerifyNameProof(root, nameHash chainhash.Hash, proof []byte) (*hnsjson.VerifyNameProofResult, error) {
	return c.VerifyNameProofAsync(root, nameHash, proof).Receive()
}
