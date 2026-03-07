// Copyright (c) 2014-2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsjson_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/hnsutil"
)

// TestWalletSvrCmds tests all of the wallet server commands marshal and
// unmarshal into valid results include handling of optional fields being
// omitted in the marshalled command, while optional fields with defaults have
// the default assigned on unmarshalled commands.
func TestWalletSvrCmds(t *testing.T) {
	t.Parallel()

	testID := int(1)
	tests := []struct {
		name         string
		newCmd       func() (interface{}, error)
		staticCmd    func() interface{}
		marshalled   string
		unmarshalled interface{}
	}{
		{
			name: "addmultisigaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("addmultisigaddress", 2, []string{"031234", "035678"})
			},
			staticCmd: func() interface{} {
				keys := []string{"031234", "035678"}
				return hnsjson.NewAddMultisigAddressCmd(2, keys, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"addmultisigaddress","params":[2,["031234","035678"]],"id":1}`,
			unmarshalled: &hnsjson.AddMultisigAddressCmd{
				NRequired: 2,
				Keys:      []string{"031234", "035678"},
				Account:   nil,
			},
		},
		{
			name: "addmultisigaddress optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("addmultisigaddress", 2, []string{"031234", "035678"}, "test")
			},
			staticCmd: func() interface{} {
				keys := []string{"031234", "035678"}
				return hnsjson.NewAddMultisigAddressCmd(2, keys, hnsjson.String("test"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"addmultisigaddress","params":[2,["031234","035678"],"test"],"id":1}`,
			unmarshalled: &hnsjson.AddMultisigAddressCmd{
				NRequired: 2,
				Keys:      []string{"031234", "035678"},
				Account:   hnsjson.String("test"),
			},
		},
		{
			name: "createwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createwallet", "mywallet", true, true, "secret", true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateWalletCmd("mywallet",
					hnsjson.Bool(true), hnsjson.Bool(true),
					hnsjson.String("secret"), hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createwallet","params":["mywallet",true,true,"secret",true],"id":1}`,
			unmarshalled: &hnsjson.CreateWalletCmd{
				WalletName:         "mywallet",
				DisablePrivateKeys: hnsjson.Bool(true),
				Blank:              hnsjson.Bool(true),
				Passphrase:         hnsjson.String("secret"),
				AvoidReuse:         hnsjson.Bool(true),
			},
		},
		{
			name: "createwallet - optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createwallet", "mywallet")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateWalletCmd("mywallet",
					nil, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createwallet","params":["mywallet"],"id":1}`,
			unmarshalled: &hnsjson.CreateWalletCmd{
				WalletName:         "mywallet",
				DisablePrivateKeys: hnsjson.Bool(false),
				Blank:              hnsjson.Bool(false),
				Passphrase:         hnsjson.String(""),
				AvoidReuse:         hnsjson.Bool(false),
			},
		},
		{
			name: "createwallet - optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createwallet", "mywallet", "null", "null", "secret")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateWalletCmd("mywallet",
					nil, nil, hnsjson.String("secret"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createwallet","params":["mywallet",null,null,"secret"],"id":1}`,
			unmarshalled: &hnsjson.CreateWalletCmd{
				WalletName:         "mywallet",
				DisablePrivateKeys: nil,
				Blank:              nil,
				Passphrase:         hnsjson.String("secret"),
				AvoidReuse:         hnsjson.Bool(false),
			},
		},
		{
			name: "addwitnessaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("addwitnessaddress", "1address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewAddWitnessAddressCmd("1address")
			},
			marshalled: `{"jsonrpc":"1.0","method":"addwitnessaddress","params":["1address"],"id":1}`,
			unmarshalled: &hnsjson.AddWitnessAddressCmd{
				Address: "1address",
			},
		},
		{
			name: "backupwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("backupwallet", "backup.dat")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewBackupWalletCmd("backup.dat")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"backupwallet","params":["backup.dat"],"id":1}`,
			unmarshalled: &hnsjson.BackupWalletCmd{Destination: "backup.dat"},
		},
		{
			name: "loadwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("loadwallet", "wallet.dat")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewLoadWalletCmd("wallet.dat")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"loadwallet","params":["wallet.dat"],"id":1}`,
			unmarshalled: &hnsjson.LoadWalletCmd{WalletName: "wallet.dat"},
		},
		{
			name: "unloadwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("unloadwallet", "default")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewUnloadWalletCmd(hnsjson.String("default"))
			},
			marshalled:   `{"jsonrpc":"1.0","method":"unloadwallet","params":["default"],"id":1}`,
			unmarshalled: &hnsjson.UnloadWalletCmd{WalletName: hnsjson.String("default")},
		},
		{name: "unloadwallet - nil arg",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("unloadwallet")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewUnloadWalletCmd(nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"unloadwallet","params":[],"id":1}`,
			unmarshalled: &hnsjson.UnloadWalletCmd{WalletName: nil},
		},
		{
			name: "createmultisig",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createmultisig", 2, []string{"031234", "035678"})
			},
			staticCmd: func() interface{} {
				keys := []string{"031234", "035678"}
				return hnsjson.NewCreateMultisigCmd(2, keys)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createmultisig","params":[2,["031234","035678"]],"id":1}`,
			unmarshalled: &hnsjson.CreateMultisigCmd{
				NRequired: 2,
				Keys:      []string{"031234", "035678"},
			},
		},
		{
			name: "dumpprivkey",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("dumpprivkey", "1Address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDumpPrivKeyCmd("1Address")
			},
			marshalled: `{"jsonrpc":"1.0","method":"dumpprivkey","params":["1Address"],"id":1}`,
			unmarshalled: &hnsjson.DumpPrivKeyCmd{
				Address: "1Address",
			},
		},
		{
			name: "encryptwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("encryptwallet", "pass")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewEncryptWalletCmd("pass")
			},
			marshalled: `{"jsonrpc":"1.0","method":"encryptwallet","params":["pass"],"id":1}`,
			unmarshalled: &hnsjson.EncryptWalletCmd{
				Passphrase: "pass",
			},
		},
		{
			name: "estimatefee",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("estimatefee", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewEstimateFeeCmd(6)
			},
			marshalled: `{"jsonrpc":"1.0","method":"estimatefee","params":[6],"id":1}`,
			unmarshalled: &hnsjson.EstimateFeeCmd{
				NumBlocks: 6,
			},
		},
		{
			name: "estimatesmartfee - no mode",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("estimatesmartfee", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewEstimateSmartFeeCmd(6, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"estimatesmartfee","params":[6],"id":1}`,
			unmarshalled: &hnsjson.EstimateSmartFeeCmd{
				ConfTarget:   6,
				EstimateMode: &hnsjson.EstimateModeConservative,
			},
		},
		{
			name: "estimatesmartfee - economical mode",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("estimatesmartfee", 6, hnsjson.EstimateModeEconomical)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewEstimateSmartFeeCmd(6, &hnsjson.EstimateModeEconomical)
			},
			marshalled: `{"jsonrpc":"1.0","method":"estimatesmartfee","params":[6,"ECONOMICAL"],"id":1}`,
			unmarshalled: &hnsjson.EstimateSmartFeeCmd{
				ConfTarget:   6,
				EstimateMode: &hnsjson.EstimateModeEconomical,
			},
		},
		{
			name: "estimatepriority",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("estimatepriority", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewEstimatePriorityCmd(6)
			},
			marshalled: `{"jsonrpc":"1.0","method":"estimatepriority","params":[6],"id":1}`,
			unmarshalled: &hnsjson.EstimatePriorityCmd{
				NumBlocks: 6,
			},
		},
		{
			name: "getaccount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaccount", "1Address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAccountCmd("1Address")
			},
			marshalled: `{"jsonrpc":"1.0","method":"getaccount","params":["1Address"],"id":1}`,
			unmarshalled: &hnsjson.GetAccountCmd{
				Address: "1Address",
			},
		},
		{
			name: "getaccountaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaccountaddress", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAccountAddressCmd("acct")
			},
			marshalled: `{"jsonrpc":"1.0","method":"getaccountaddress","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetAccountAddressCmd{
				Account: "acct",
			},
		},
		{
			name: "getaddressesbyaccount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaddressesbyaccount", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAddressesByAccountCmd("acct")
			},
			marshalled: `{"jsonrpc":"1.0","method":"getaddressesbyaccount","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetAddressesByAccountCmd{
				Account: "acct",
			},
		},
		{
			name: "getaddressinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaddressinfo", "1234")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAddressInfoCmd("1234")
			},
			marshalled: `{"jsonrpc":"1.0","method":"getaddressinfo","params":["1234"],"id":1}`,
			unmarshalled: &hnsjson.GetAddressInfoCmd{
				Address: "1234",
			},
		},
		{
			name: "getbalance",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getbalance")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBalanceCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getbalance","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBalanceCmd{
				Account: nil,
				MinConf: hnsjson.Int(1),
			},
		},
		{
			name: "getbalance optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getbalance", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBalanceCmd(hnsjson.String("acct"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getbalance","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetBalanceCmd{
				Account: hnsjson.String("acct"),
				MinConf: hnsjson.Int(1),
			},
		},
		{
			name: "getbalance optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getbalance", "acct", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBalanceCmd(hnsjson.String("acct"), hnsjson.Int(6))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getbalance","params":["acct",6],"id":1}`,
			unmarshalled: &hnsjson.GetBalanceCmd{
				Account: hnsjson.String("acct"),
				MinConf: hnsjson.Int(6),
			},
		},
		{
			name: "getbalances",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getbalances")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBalancesCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getbalances","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBalancesCmd{},
		},
		{
			name: "getnewaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnewaddress")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNewAddressCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnewaddress","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNewAddressCmd{
				Account:     nil,
				AddressType: nil,
			},
		},
		{
			name: "getnewaddress optional acct",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnewaddress", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNewAddressCmd(hnsjson.String("acct"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnewaddress","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetNewAddressCmd{
				Account:     hnsjson.String("acct"),
				AddressType: nil,
			},
		},
		{
			name: "getnewaddress optional acct and type",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnewaddress", "acct", "legacy")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNewAddressCmd(hnsjson.String("acct"), hnsjson.String("legacy"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnewaddress","params":["acct","legacy"],"id":1}`,
			unmarshalled: &hnsjson.GetNewAddressCmd{
				Account:     hnsjson.String("acct"),
				AddressType: hnsjson.String("legacy"),
			},
		},
		{
			name: "getrawchangeaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawchangeaddress")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawChangeAddressCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawchangeaddress","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetRawChangeAddressCmd{
				Account:     nil,
				AddressType: nil,
			},
		},
		{
			name: "getrawchangeaddress optional acct",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawchangeaddress", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawChangeAddressCmd(hnsjson.String("acct"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawchangeaddress","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetRawChangeAddressCmd{
				Account:     hnsjson.String("acct"),
				AddressType: nil,
			},
		},
		{
			name: "getrawchangeaddress optional acct and type",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawchangeaddress", "acct", "legacy")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawChangeAddressCmd(hnsjson.String("acct"), hnsjson.String("legacy"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawchangeaddress","params":["acct","legacy"],"id":1}`,
			unmarshalled: &hnsjson.GetRawChangeAddressCmd{
				Account:     hnsjson.String("acct"),
				AddressType: hnsjson.String("legacy"),
			},
		},
		{
			name: "getreceivedbyaccount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getreceivedbyaccount", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetReceivedByAccountCmd("acct", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getreceivedbyaccount","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.GetReceivedByAccountCmd{
				Account: "acct",
				MinConf: hnsjson.Int(1),
			},
		},
		{
			name: "getreceivedbyaccount optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getreceivedbyaccount", "acct", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetReceivedByAccountCmd("acct", hnsjson.Int(6))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getreceivedbyaccount","params":["acct",6],"id":1}`,
			unmarshalled: &hnsjson.GetReceivedByAccountCmd{
				Account: "acct",
				MinConf: hnsjson.Int(6),
			},
		},
		{
			name: "getreceivedbyaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getreceivedbyaddress", "1Address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetReceivedByAddressCmd("1Address", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getreceivedbyaddress","params":["1Address"],"id":1}`,
			unmarshalled: &hnsjson.GetReceivedByAddressCmd{
				Address: "1Address",
				MinConf: hnsjson.Int(1),
			},
		},
		{
			name: "getreceivedbyaddress optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getreceivedbyaddress", "1Address", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetReceivedByAddressCmd("1Address", hnsjson.Int(6))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getreceivedbyaddress","params":["1Address",6],"id":1}`,
			unmarshalled: &hnsjson.GetReceivedByAddressCmd{
				Address: "1Address",
				MinConf: hnsjson.Int(6),
			},
		},
		{
			name: "gettransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettransaction", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTransactionCmd("123", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettransaction","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.GetTransactionCmd{
				Txid:             "123",
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "gettransaction optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettransaction", "123", true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTransactionCmd("123", hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettransaction","params":["123",true],"id":1}`,
			unmarshalled: &hnsjson.GetTransactionCmd{
				Txid:             "123",
				IncludeWatchOnly: hnsjson.Bool(true),
			},
		},
		{
			name: "getwalletinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getwalletinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetWalletInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getwalletinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetWalletInfoCmd{},
		},
		{
			name: "importprivkey",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("importprivkey", "abc")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewImportPrivKeyCmd("abc", nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importprivkey","params":["abc"],"id":1}`,
			unmarshalled: &hnsjson.ImportPrivKeyCmd{
				PrivKey: "abc",
				Label:   nil,
				Rescan:  hnsjson.Bool(true),
			},
		},
		{
			name: "importprivkey optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("importprivkey", "abc", "label")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewImportPrivKeyCmd("abc", hnsjson.String("label"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importprivkey","params":["abc","label"],"id":1}`,
			unmarshalled: &hnsjson.ImportPrivKeyCmd{
				PrivKey: "abc",
				Label:   hnsjson.String("label"),
				Rescan:  hnsjson.Bool(true),
			},
		},
		{
			name: "importprivkey optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("importprivkey", "abc", "label", false)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewImportPrivKeyCmd("abc", hnsjson.String("label"), hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"importprivkey","params":["abc","label",false],"id":1}`,
			unmarshalled: &hnsjson.ImportPrivKeyCmd{
				PrivKey: "abc",
				Label:   hnsjson.String("label"),
				Rescan:  hnsjson.Bool(false),
			},
		},
		{
			name: "keypoolrefill",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("keypoolrefill")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewKeyPoolRefillCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"keypoolrefill","params":[],"id":1}`,
			unmarshalled: &hnsjson.KeyPoolRefillCmd{
				NewSize: hnsjson.Uint(100),
			},
		},
		{
			name: "keypoolrefill optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("keypoolrefill", 200)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewKeyPoolRefillCmd(hnsjson.Uint(200))
			},
			marshalled: `{"jsonrpc":"1.0","method":"keypoolrefill","params":[200],"id":1}`,
			unmarshalled: &hnsjson.KeyPoolRefillCmd{
				NewSize: hnsjson.Uint(200),
			},
		},
		{
			name: "listaccounts",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listaccounts")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListAccountsCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listaccounts","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListAccountsCmd{
				MinConf: hnsjson.Int(1),
			},
		},
		{
			name: "listaccounts optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listaccounts", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListAccountsCmd(hnsjson.Int(6))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listaccounts","params":[6],"id":1}`,
			unmarshalled: &hnsjson.ListAccountsCmd{
				MinConf: hnsjson.Int(6),
			},
		},
		{
			name: "listaddressgroupings",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listaddressgroupings")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListAddressGroupingsCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"listaddressgroupings","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListAddressGroupingsCmd{},
		},
		{
			name: "listlockunspent",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listlockunspent")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListLockUnspentCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"listlockunspent","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListLockUnspentCmd{},
		},
		{
			name: "listreceivedbyaccount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaccount")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAccountCmd(nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaccount","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAccountCmd{
				MinConf:          hnsjson.Int(1),
				IncludeEmpty:     hnsjson.Bool(false),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaccount optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaccount", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAccountCmd(hnsjson.Int(6), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaccount","params":[6],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAccountCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(false),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaccount optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaccount", 6, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAccountCmd(hnsjson.Int(6), hnsjson.Bool(true), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaccount","params":[6,true],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAccountCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(true),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaccount optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaccount", 6, true, false)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAccountCmd(hnsjson.Int(6), hnsjson.Bool(true), hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaccount","params":[6,true,false],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAccountCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(true),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaddress")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAddressCmd(nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaddress","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAddressCmd{
				MinConf:          hnsjson.Int(1),
				IncludeEmpty:     hnsjson.Bool(false),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaddress optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaddress", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAddressCmd(hnsjson.Int(6), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaddress","params":[6],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAddressCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(false),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaddress optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaddress", 6, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAddressCmd(hnsjson.Int(6), hnsjson.Bool(true), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaddress","params":[6,true],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAddressCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(true),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listreceivedbyaddress optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listreceivedbyaddress", 6, true, false)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListReceivedByAddressCmd(hnsjson.Int(6), hnsjson.Bool(true), hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listreceivedbyaddress","params":[6,true,false],"id":1}`,
			unmarshalled: &hnsjson.ListReceivedByAddressCmd{
				MinConf:          hnsjson.Int(6),
				IncludeEmpty:     hnsjson.Bool(true),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listsinceblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listsinceblock")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListSinceBlockCmd(nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listsinceblock","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListSinceBlockCmd{
				BlockHash:           nil,
				TargetConfirmations: hnsjson.Int(1),
				IncludeWatchOnly:    hnsjson.Bool(false),
			},
		},
		{
			name: "listsinceblock optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listsinceblock", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListSinceBlockCmd(hnsjson.String("123"), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listsinceblock","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.ListSinceBlockCmd{
				BlockHash:           hnsjson.String("123"),
				TargetConfirmations: hnsjson.Int(1),
				IncludeWatchOnly:    hnsjson.Bool(false),
			},
		},
		{
			name: "listsinceblock optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listsinceblock", "123", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListSinceBlockCmd(hnsjson.String("123"), hnsjson.Int(6), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listsinceblock","params":["123",6],"id":1}`,
			unmarshalled: &hnsjson.ListSinceBlockCmd{
				BlockHash:           hnsjson.String("123"),
				TargetConfirmations: hnsjson.Int(6),
				IncludeWatchOnly:    hnsjson.Bool(false),
			},
		},
		{
			name: "listsinceblock optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listsinceblock", "123", 6, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListSinceBlockCmd(hnsjson.String("123"), hnsjson.Int(6), hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listsinceblock","params":["123",6,true],"id":1}`,
			unmarshalled: &hnsjson.ListSinceBlockCmd{
				BlockHash:           hnsjson.String("123"),
				TargetConfirmations: hnsjson.Int(6),
				IncludeWatchOnly:    hnsjson.Bool(true),
			},
		},
		{
			name: "listsinceblock pad null",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listsinceblock", "null", 1, false)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListSinceBlockCmd(nil, hnsjson.Int(1), hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listsinceblock","params":[null,1,false],"id":1}`,
			unmarshalled: &hnsjson.ListSinceBlockCmd{
				BlockHash:           nil,
				TargetConfirmations: hnsjson.Int(1),
				IncludeWatchOnly:    hnsjson.Bool(false),
			},
		},
		{
			name: "listtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listtransactions")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListTransactionsCmd(nil, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listtransactions","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListTransactionsCmd{
				Account:          nil,
				Count:            hnsjson.Int(10),
				From:             hnsjson.Int(0),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listtransactions optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listtransactions", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListTransactionsCmd(hnsjson.String("acct"), nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listtransactions","params":["acct"],"id":1}`,
			unmarshalled: &hnsjson.ListTransactionsCmd{
				Account:          hnsjson.String("acct"),
				Count:            hnsjson.Int(10),
				From:             hnsjson.Int(0),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listtransactions optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listtransactions", "acct", 20)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListTransactionsCmd(hnsjson.String("acct"), hnsjson.Int(20), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listtransactions","params":["acct",20],"id":1}`,
			unmarshalled: &hnsjson.ListTransactionsCmd{
				Account:          hnsjson.String("acct"),
				Count:            hnsjson.Int(20),
				From:             hnsjson.Int(0),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listtransactions optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listtransactions", "acct", 20, 1)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListTransactionsCmd(hnsjson.String("acct"), hnsjson.Int(20),
					hnsjson.Int(1), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listtransactions","params":["acct",20,1],"id":1}`,
			unmarshalled: &hnsjson.ListTransactionsCmd{
				Account:          hnsjson.String("acct"),
				Count:            hnsjson.Int(20),
				From:             hnsjson.Int(1),
				IncludeWatchOnly: hnsjson.Bool(false),
			},
		},
		{
			name: "listtransactions optional4",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listtransactions", "acct", 20, 1, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListTransactionsCmd(hnsjson.String("acct"), hnsjson.Int(20),
					hnsjson.Int(1), hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"listtransactions","params":["acct",20,1,true],"id":1}`,
			unmarshalled: &hnsjson.ListTransactionsCmd{
				Account:          hnsjson.String("acct"),
				Count:            hnsjson.Int(20),
				From:             hnsjson.Int(1),
				IncludeWatchOnly: hnsjson.Bool(true),
			},
		},
		{
			name: "listunspent",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listunspent")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListUnspentCmd(nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listunspent","params":[],"id":1}`,
			unmarshalled: &hnsjson.ListUnspentCmd{
				MinConf:   hnsjson.Int(1),
				MaxConf:   hnsjson.Int(9999999),
				Addresses: nil,
			},
		},
		{
			name: "listunspent optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listunspent", 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListUnspentCmd(hnsjson.Int(6), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listunspent","params":[6],"id":1}`,
			unmarshalled: &hnsjson.ListUnspentCmd{
				MinConf:   hnsjson.Int(6),
				MaxConf:   hnsjson.Int(9999999),
				Addresses: nil,
			},
		},
		{
			name: "listunspent optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listunspent", 6, 100)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListUnspentCmd(hnsjson.Int(6), hnsjson.Int(100), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"listunspent","params":[6,100],"id":1}`,
			unmarshalled: &hnsjson.ListUnspentCmd{
				MinConf:   hnsjson.Int(6),
				MaxConf:   hnsjson.Int(100),
				Addresses: nil,
			},
		},
		{
			name: "listunspent optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("listunspent", 6, 100, []string{"1Address", "1Address2"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewListUnspentCmd(hnsjson.Int(6), hnsjson.Int(100),
					&[]string{"1Address", "1Address2"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"listunspent","params":[6,100,["1Address","1Address2"]],"id":1}`,
			unmarshalled: &hnsjson.ListUnspentCmd{
				MinConf:   hnsjson.Int(6),
				MaxConf:   hnsjson.Int(100),
				Addresses: &[]string{"1Address", "1Address2"},
			},
		},
		{
			name: "lockunspent",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("lockunspent", true, `[{"txid":"123","vout":1}]`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.TransactionInput{
					{Txid: "123", Vout: 1},
				}
				return hnsjson.NewLockUnspentCmd(true, txInputs)
			},
			marshalled: `{"jsonrpc":"1.0","method":"lockunspent","params":[true,[{"txid":"123","vout":1}]],"id":1}`,
			unmarshalled: &hnsjson.LockUnspentCmd{
				Unlock: true,
				Transactions: []hnsjson.TransactionInput{
					{Txid: "123", Vout: 1},
				},
			},
		},
		{
			name: "move",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("move", "from", "to", 0.5)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewMoveCmd("from", "to", 0.5, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"move","params":["from","to",0.5],"id":1}`,
			unmarshalled: &hnsjson.MoveCmd{
				FromAccount: "from",
				ToAccount:   "to",
				Amount:      0.5,
				MinConf:     hnsjson.Int(1),
				Comment:     nil,
			},
		},
		{
			name: "move optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("move", "from", "to", 0.5, 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewMoveCmd("from", "to", 0.5, hnsjson.Int(6), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"move","params":["from","to",0.5,6],"id":1}`,
			unmarshalled: &hnsjson.MoveCmd{
				FromAccount: "from",
				ToAccount:   "to",
				Amount:      0.5,
				MinConf:     hnsjson.Int(6),
				Comment:     nil,
			},
		},
		{
			name: "move optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("move", "from", "to", 0.5, 6, "comment")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewMoveCmd("from", "to", 0.5, hnsjson.Int(6), hnsjson.String("comment"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"move","params":["from","to",0.5,6,"comment"],"id":1}`,
			unmarshalled: &hnsjson.MoveCmd{
				FromAccount: "from",
				ToAccount:   "to",
				Amount:      0.5,
				MinConf:     hnsjson.Int(6),
				Comment:     hnsjson.String("comment"),
			},
		},
		{
			name: "sendfrom",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendfrom", "from", "1Address", 0.5)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendFromCmd("from", "1Address", 0.5, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendfrom","params":["from","1Address",0.5],"id":1}`,
			unmarshalled: &hnsjson.SendFromCmd{
				FromAccount: "from",
				ToAddress:   "1Address",
				Amount:      0.5,
				MinConf:     hnsjson.Int(1),
				Comment:     nil,
				CommentTo:   nil,
			},
		},
		{
			name: "sendfrom optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendfrom", "from", "1Address", 0.5, 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendFromCmd("from", "1Address", 0.5, hnsjson.Int(6), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendfrom","params":["from","1Address",0.5,6],"id":1}`,
			unmarshalled: &hnsjson.SendFromCmd{
				FromAccount: "from",
				ToAddress:   "1Address",
				Amount:      0.5,
				MinConf:     hnsjson.Int(6),
				Comment:     nil,
				CommentTo:   nil,
			},
		},
		{
			name: "sendfrom optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendfrom", "from", "1Address", 0.5, 6, "comment")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendFromCmd("from", "1Address", 0.5, hnsjson.Int(6),
					hnsjson.String("comment"), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendfrom","params":["from","1Address",0.5,6,"comment"],"id":1}`,
			unmarshalled: &hnsjson.SendFromCmd{
				FromAccount: "from",
				ToAddress:   "1Address",
				Amount:      0.5,
				MinConf:     hnsjson.Int(6),
				Comment:     hnsjson.String("comment"),
				CommentTo:   nil,
			},
		},
		{
			name: "sendfrom optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendfrom", "from", "1Address", 0.5, 6, "comment", "commentto")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendFromCmd("from", "1Address", 0.5, hnsjson.Int(6),
					hnsjson.String("comment"), hnsjson.String("commentto"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendfrom","params":["from","1Address",0.5,6,"comment","commentto"],"id":1}`,
			unmarshalled: &hnsjson.SendFromCmd{
				FromAccount: "from",
				ToAddress:   "1Address",
				Amount:      0.5,
				MinConf:     hnsjson.Int(6),
				Comment:     hnsjson.String("comment"),
				CommentTo:   hnsjson.String("commentto"),
			},
		},
		{
			name: "sendmany",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendmany", "from", `{"1Address":0.5}`)
			},
			staticCmd: func() interface{} {
				amounts := map[string]float64{"1Address": 0.5}
				return hnsjson.NewSendManyCmd("from", amounts, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendmany","params":["from",{"1Address":0.5}],"id":1}`,
			unmarshalled: &hnsjson.SendManyCmd{
				FromAccount: "from",
				Amounts:     map[string]float64{"1Address": 0.5},
				MinConf:     hnsjson.Int(1),
				Comment:     nil,
			},
		},
		{
			name: "sendmany optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendmany", "from", `{"1Address":0.5}`, 6)
			},
			staticCmd: func() interface{} {
				amounts := map[string]float64{"1Address": 0.5}
				return hnsjson.NewSendManyCmd("from", amounts, hnsjson.Int(6), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendmany","params":["from",{"1Address":0.5},6],"id":1}`,
			unmarshalled: &hnsjson.SendManyCmd{
				FromAccount: "from",
				Amounts:     map[string]float64{"1Address": 0.5},
				MinConf:     hnsjson.Int(6),
				Comment:     nil,
			},
		},
		{
			name: "sendmany optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendmany", "from", `{"1Address":0.5}`, 6, "comment")
			},
			staticCmd: func() interface{} {
				amounts := map[string]float64{"1Address": 0.5}
				return hnsjson.NewSendManyCmd("from", amounts, hnsjson.Int(6), hnsjson.String("comment"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendmany","params":["from",{"1Address":0.5},6,"comment"],"id":1}`,
			unmarshalled: &hnsjson.SendManyCmd{
				FromAccount: "from",
				Amounts:     map[string]float64{"1Address": 0.5},
				MinConf:     hnsjson.Int(6),
				Comment:     hnsjson.String("comment"),
			},
		},
		{
			name: "sendtoaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendtoaddress", "1Address", 0.5)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendToAddressCmd("1Address", 0.5, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendtoaddress","params":["1Address",0.5],"id":1}`,
			unmarshalled: &hnsjson.SendToAddressCmd{
				Address:   "1Address",
				Amount:    0.5,
				Comment:   nil,
				CommentTo: nil,
			},
		},
		{
			name: "sendtoaddress optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendtoaddress", "1Address", 0.5, "comment", "commentto")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendToAddressCmd("1Address", 0.5, hnsjson.String("comment"),
					hnsjson.String("commentto"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendtoaddress","params":["1Address",0.5,"comment","commentto"],"id":1}`,
			unmarshalled: &hnsjson.SendToAddressCmd{
				Address:   "1Address",
				Amount:    0.5,
				Comment:   hnsjson.String("comment"),
				CommentTo: hnsjson.String("commentto"),
			},
		},
		{
			name: "setaccount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("setaccount", "1Address", "acct")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSetAccountCmd("1Address", "acct")
			},
			marshalled: `{"jsonrpc":"1.0","method":"setaccount","params":["1Address","acct"],"id":1}`,
			unmarshalled: &hnsjson.SetAccountCmd{
				Address: "1Address",
				Account: "acct",
			},
		},
		{
			name: "settxfee",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("settxfee", 0.0001)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSetTxFeeCmd(0.0001)
			},
			marshalled: `{"jsonrpc":"1.0","method":"settxfee","params":[0.0001],"id":1}`,
			unmarshalled: &hnsjson.SetTxFeeCmd{
				Amount: 0.0001,
			},
		},
		{
			name: "signmessage",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signmessage", "1Address", "message")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSignMessageCmd("1Address", "message")
			},
			marshalled: `{"jsonrpc":"1.0","method":"signmessage","params":["1Address","message"],"id":1}`,
			unmarshalled: &hnsjson.SignMessageCmd{
				Address: "1Address",
				Message: "message",
			},
		},
		{
			name: "signrawtransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransaction", "001122")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSignRawTransactionCmd("001122", nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransaction","params":["001122"],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionCmd{
				RawTx:    "001122",
				Inputs:   nil,
				PrivKeys: nil,
				Flags:    hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransaction optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransaction", "001122", `[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01"}]`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxInput{
					{
						Txid:         "123",
						Vout:         1,
						ScriptPubKey: "00",
						RedeemScript: "01",
					},
				}

				return hnsjson.NewSignRawTransactionCmd("001122", &txInputs, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransaction","params":["001122",[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01"}]],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionCmd{
				RawTx: "001122",
				Inputs: &[]hnsjson.RawTxInput{
					{
						Txid:         "123",
						Vout:         1,
						ScriptPubKey: "00",
						RedeemScript: "01",
					},
				},
				PrivKeys: nil,
				Flags:    hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransaction optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransaction", "001122", `[]`, `["abc"]`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxInput{}
				privKeys := []string{"abc"}
				return hnsjson.NewSignRawTransactionCmd("001122", &txInputs, &privKeys, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransaction","params":["001122",[],["abc"]],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionCmd{
				RawTx:    "001122",
				Inputs:   &[]hnsjson.RawTxInput{},
				PrivKeys: &[]string{"abc"},
				Flags:    hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransaction optional3",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransaction", "001122", `[]`, `[]`, "ALL")
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxInput{}
				privKeys := []string{}
				return hnsjson.NewSignRawTransactionCmd("001122", &txInputs, &privKeys,
					hnsjson.String("ALL"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransaction","params":["001122",[],[],"ALL"],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionCmd{
				RawTx:    "001122",
				Inputs:   &[]hnsjson.RawTxInput{},
				PrivKeys: &[]string{},
				Flags:    hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransactionwithwallet",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransactionwithwallet", "001122")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSignRawTransactionWithWalletCmd("001122", nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransactionwithwallet","params":["001122"],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionWithWalletCmd{
				RawTx:       "001122",
				Inputs:      nil,
				SigHashType: hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransactionwithwallet optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransactionwithwallet", "001122", `[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01","witnessScript":"02","amount":1.5}]`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxWitnessInput{
					{
						Txid:          "123",
						Vout:          1,
						ScriptPubKey:  "00",
						RedeemScript:  hnsjson.String("01"),
						WitnessScript: hnsjson.String("02"),
						Amount:        hnsjson.Float64(1.5),
					},
				}

				return hnsjson.NewSignRawTransactionWithWalletCmd("001122", &txInputs, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransactionwithwallet","params":["001122",[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01","witnessScript":"02","amount":1.5}]],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionWithWalletCmd{
				RawTx: "001122",
				Inputs: &[]hnsjson.RawTxWitnessInput{
					{
						Txid:          "123",
						Vout:          1,
						ScriptPubKey:  "00",
						RedeemScript:  hnsjson.String("01"),
						WitnessScript: hnsjson.String("02"),
						Amount:        hnsjson.Float64(1.5),
					},
				},
				SigHashType: hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransactionwithwallet optional1 with blank fields in input",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransactionwithwallet", "001122", `[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01"}]`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxWitnessInput{
					{
						Txid:         "123",
						Vout:         1,
						ScriptPubKey: "00",
						RedeemScript: hnsjson.String("01"),
					},
				}

				return hnsjson.NewSignRawTransactionWithWalletCmd("001122", &txInputs, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransactionwithwallet","params":["001122",[{"txid":"123","vout":1,"scriptPubKey":"00","redeemScript":"01"}]],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionWithWalletCmd{
				RawTx: "001122",
				Inputs: &[]hnsjson.RawTxWitnessInput{
					{
						Txid:         "123",
						Vout:         1,
						ScriptPubKey: "00",
						RedeemScript: hnsjson.String("01"),
					},
				},
				SigHashType: hnsjson.String("ALL"),
			},
		},
		{
			name: "signrawtransactionwithwallet optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signrawtransactionwithwallet", "001122", `[]`, "ALL")
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.RawTxWitnessInput{}
				return hnsjson.NewSignRawTransactionWithWalletCmd("001122", &txInputs, hnsjson.String("ALL"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"signrawtransactionwithwallet","params":["001122",[],"ALL"],"id":1}`,
			unmarshalled: &hnsjson.SignRawTransactionWithWalletCmd{
				RawTx:       "001122",
				Inputs:      &[]hnsjson.RawTxWitnessInput{},
				SigHashType: hnsjson.String("ALL"),
			},
		},
		{
			name: "walletlock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("walletlock")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewWalletLockCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"walletlock","params":[],"id":1}`,
			unmarshalled: &hnsjson.WalletLockCmd{},
		},
		{
			name: "walletpassphrase",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("walletpassphrase", "pass", 60)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewWalletPassphraseCmd("pass", 60)
			},
			marshalled: `{"jsonrpc":"1.0","method":"walletpassphrase","params":["pass",60],"id":1}`,
			unmarshalled: &hnsjson.WalletPassphraseCmd{
				Passphrase: "pass",
				Timeout:    60,
			},
		},
		{
			name: "walletpassphrasechange",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("walletpassphrasechange", "old", "new")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewWalletPassphraseChangeCmd("old", "new")
			},
			marshalled: `{"jsonrpc":"1.0","method":"walletpassphrasechange","params":["old","new"],"id":1}`,
			unmarshalled: &hnsjson.WalletPassphraseChangeCmd{
				OldPassphrase: "old",
				NewPassphrase: "new",
			},
		},
		{
			name: "importmulti with descriptor + options",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp.
					[]hnsjson.ImportMultiRequest{
						{Descriptor: hnsjson.String("123"), Timestamp: hnsjson.TimestampOrNow{Value: 0}},
					},
					`{"rescan": true}`,
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{Descriptor: hnsjson.String("123"), Timestamp: hnsjson.TimestampOrNow{Value: 0}},
				}
				options := hnsjson.ImportMultiOptions{Rescan: true}
				return hnsjson.NewImportMultiCmd(requests, &options)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"desc":"123","timestamp":0}],{"rescan":true}],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
					},
				},
				Options: &hnsjson.ImportMultiOptions{Rescan: true},
			},
		},
		{
			name: "importmulti with descriptor + no options",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp.
					[]hnsjson.ImportMultiRequest{
						{
							Descriptor: hnsjson.String("123"),
							Timestamp:  hnsjson.TimestampOrNow{Value: 0},
							WatchOnly:  hnsjson.Bool(false),
							Internal:   hnsjson.Bool(true),
							Label:      hnsjson.String("aaa"),
							KeyPool:    hnsjson.Bool(false),
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						WatchOnly:  hnsjson.Bool(false),
						Internal:   hnsjson.Bool(true),
						Label:      hnsjson.String("aaa"),
						KeyPool:    hnsjson.Bool(false),
					},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"desc":"123","timestamp":0,"internal":true,"watchonly":false,"label":"aaa","keypool":false}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						WatchOnly:  hnsjson.Bool(false),
						Internal:   hnsjson.Bool(true),
						Label:      hnsjson.String("aaa"),
						KeyPool:    hnsjson.Bool(false),
					},
				},
			},
		},
		{
			name: "importmulti with descriptor + string timestamp",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp.
					[]hnsjson.ImportMultiRequest{
						{
							Descriptor: hnsjson.String("123"),
							Timestamp:  hnsjson.TimestampOrNow{Value: "now"},
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{Descriptor: hnsjson.String("123"), Timestamp: hnsjson.TimestampOrNow{Value: "now"}},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"desc":"123","timestamp":"now"}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{Descriptor: hnsjson.String("123"), Timestamp: hnsjson.TimestampOrNow{Value: "now"}},
				},
			},
		},
		{
			name: "importmulti with scriptPubKey script",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp and scriptPubKey
					[]hnsjson.ImportMultiRequest{
						{
							ScriptPubKey: &hnsjson.ScriptPubKey{Value: "script"},
							RedeemScript: hnsjson.String("123"),
							Timestamp:    hnsjson.TimestampOrNow{Value: 0},
							PubKeys:      &[]string{"aaa"},
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{
						ScriptPubKey: &hnsjson.ScriptPubKey{Value: "script"},
						RedeemScript: hnsjson.String("123"),
						Timestamp:    hnsjson.TimestampOrNow{Value: 0},
						PubKeys:      &[]string{"aaa"},
					},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"scriptPubKey":"script","timestamp":0,"redeemscript":"123","pubkeys":["aaa"]}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						ScriptPubKey: &hnsjson.ScriptPubKey{Value: "script"},
						RedeemScript: hnsjson.String("123"),
						Timestamp:    hnsjson.TimestampOrNow{Value: 0},
						PubKeys:      &[]string{"aaa"},
					},
				},
			},
		},
		{
			name: "importmulti with scriptPubKey address",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp and scriptPubKey
					[]hnsjson.ImportMultiRequest{
						{
							ScriptPubKey:  &hnsjson.ScriptPubKey{Value: hnsjson.ScriptPubKeyAddress{Address: "addr"}},
							WitnessScript: hnsjson.String("123"),
							Timestamp:     hnsjson.TimestampOrNow{Value: 0},
							Keys:          &[]string{"aaa"},
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{
						ScriptPubKey:  &hnsjson.ScriptPubKey{Value: hnsjson.ScriptPubKeyAddress{Address: "addr"}},
						WitnessScript: hnsjson.String("123"),
						Timestamp:     hnsjson.TimestampOrNow{Value: 0},
						Keys:          &[]string{"aaa"},
					},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"scriptPubKey":{"address":"addr"},"timestamp":0,"witnessscript":"123","keys":["aaa"]}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						ScriptPubKey:  &hnsjson.ScriptPubKey{Value: hnsjson.ScriptPubKeyAddress{Address: "addr"}},
						WitnessScript: hnsjson.String("123"),
						Timestamp:     hnsjson.TimestampOrNow{Value: 0},
						Keys:          &[]string{"aaa"},
					},
				},
			},
		},
		{
			name: "importmulti with ranged (int) descriptor",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp.
					[]hnsjson.ImportMultiRequest{
						{
							Descriptor: hnsjson.String("123"),
							Timestamp:  hnsjson.TimestampOrNow{Value: 0},
							Range:      &hnsjson.DescriptorRange{Value: 7},
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						Range:      &hnsjson.DescriptorRange{Value: 7},
					},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"desc":"123","timestamp":0,"range":7}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						Range:      &hnsjson.DescriptorRange{Value: 7},
					},
				},
			},
		},
		{
			name: "importmulti with ranged (slice) descriptor",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"importmulti",
					// Cannot use a native string, due to special types like timestamp.
					[]hnsjson.ImportMultiRequest{
						{
							Descriptor: hnsjson.String("123"),
							Timestamp:  hnsjson.TimestampOrNow{Value: 0},
							Range:      &hnsjson.DescriptorRange{Value: []int{1, 7}},
						},
					},
				)
			},
			staticCmd: func() interface{} {
				requests := []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						Range:      &hnsjson.DescriptorRange{Value: []int{1, 7}},
					},
				}
				return hnsjson.NewImportMultiCmd(requests, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"importmulti","params":[[{"desc":"123","timestamp":0,"range":[1,7]}]],"id":1}`,
			unmarshalled: &hnsjson.ImportMultiCmd{
				Requests: []hnsjson.ImportMultiRequest{
					{
						Descriptor: hnsjson.String("123"),
						Timestamp:  hnsjson.TimestampOrNow{Value: 0},
						Range:      &hnsjson.DescriptorRange{Value: []int{1, 7}},
					},
				},
			},
		},
		{
			name: "walletcreatefundedpsbt",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"walletcreatefundedpsbt",
					[]hnsjson.PsbtInput{
						{
							Txid:     "1234",
							Vout:     0,
							Sequence: 0,
						},
					},
					[]hnsjson.PsbtOutput{
						hnsjson.NewPsbtOutput("1234", hnsutil.Amount(1234)),
						hnsjson.NewPsbtDataOutput([]byte{1, 2, 3, 4}),
					},
					hnsjson.Uint32(1),
					hnsjson.WalletCreateFundedPsbtOpts{},
					hnsjson.Bool(true),
				)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewWalletCreateFundedPsbtCmd(
					[]hnsjson.PsbtInput{
						{
							Txid:     "1234",
							Vout:     0,
							Sequence: 0,
						},
					},
					[]hnsjson.PsbtOutput{
						hnsjson.NewPsbtOutput("1234", hnsutil.Amount(1234)),
						hnsjson.NewPsbtDataOutput([]byte{1, 2, 3, 4}),
					},
					hnsjson.Uint32(1),
					&hnsjson.WalletCreateFundedPsbtOpts{},
					hnsjson.Bool(true),
				)
			},
			marshalled: `{"jsonrpc":"1.0","method":"walletcreatefundedpsbt","params":[[{"txid":"1234","vout":0,"sequence":0}],[{"1234":0.00001234},{"data":"01020304"}],1,{},true],"id":1}`,
			unmarshalled: &hnsjson.WalletCreateFundedPsbtCmd{
				Inputs: []hnsjson.PsbtInput{
					{
						Txid:     "1234",
						Vout:     0,
						Sequence: 0,
					},
				},
				Outputs: []hnsjson.PsbtOutput{
					hnsjson.NewPsbtOutput("1234", hnsutil.Amount(1234)),
					hnsjson.NewPsbtDataOutput([]byte{1, 2, 3, 4}),
				},
				Locktime:    hnsjson.Uint32(1),
				Options:     &hnsjson.WalletCreateFundedPsbtOpts{},
				Bip32Derivs: hnsjson.Bool(true),
			},
		},
		{
			name: "walletprocesspsbt",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"walletprocesspsbt", "1234", hnsjson.Bool(true), hnsjson.String("ALL"), hnsjson.Bool(true))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewWalletProcessPsbtCmd(
					"1234", hnsjson.Bool(true), hnsjson.String("ALL"), hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"walletprocesspsbt","params":["1234",true,"ALL",true],"id":1}`,
			unmarshalled: &hnsjson.WalletProcessPsbtCmd{
				Psbt:        "1234",
				Sign:        hnsjson.Bool(true),
				SighashType: hnsjson.String("ALL"),
				Bip32Derivs: hnsjson.Bool(true),
			},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Marshal the command as created by the new static command
		// creation function.
		marshalled, err := hnsjson.MarshalCmd(hnsjson.RpcVersion1, testID, test.staticCmd())
		if err != nil {
			t.Errorf("MarshalCmd #%d (%s) unexpected error: %v", i,
				test.name, err)
			continue
		}

		if !bytes.Equal(marshalled, []byte(test.marshalled)) {
			t.Errorf("Test #%d (%s) unexpected marshalled data - "+
				"got %s, want %s", i, test.name, marshalled,
				test.marshalled)
			continue
		}

		// Ensure the command is created without error via the generic
		// new command creation function.
		cmd, err := test.newCmd()
		if err != nil {
			t.Errorf("Test #%d (%s) unexpected NewCmd error: %v ",
				i, test.name, err)
		}

		// Marshal the command as created by the generic new command
		// creation function.
		marshalled, err = hnsjson.MarshalCmd(hnsjson.RpcVersion1, testID, cmd)
		if err != nil {
			t.Errorf("MarshalCmd #%d (%s) unexpected error: %v", i,
				test.name, err)
			continue
		}

		if !bytes.Equal(marshalled, []byte(test.marshalled)) {
			t.Errorf("Test #%d (%s) unexpected marshalled data - "+
				"got %s, want %s", i, test.name, marshalled,
				test.marshalled)
			continue
		}

		var request hnsjson.Request
		if err := json.Unmarshal(marshalled, &request); err != nil {
			t.Errorf("Test #%d (%s) unexpected error while "+
				"unmarshalling JSON-RPC request: %v", i,
				test.name, err)
			continue
		}

		cmd, err = hnsjson.UnmarshalCmd(&request)
		if err != nil {
			t.Errorf("UnmarshalCmd #%d (%s) unexpected error: %v", i,
				test.name, err)
			continue
		}

		if !reflect.DeepEqual(cmd, test.unmarshalled) {
			t.Errorf("Test #%d (%s) unexpected unmarshalled command "+
				"- got %s, want %s", i, test.name,
				fmt.Sprintf("(%T) %+[1]v", cmd),
				fmt.Sprintf("(%T) %+[1]v\n", test.unmarshalled))
			continue
		}
	}
}
