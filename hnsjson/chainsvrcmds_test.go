// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsjson_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

// TestChainSvrCmds tests all of the chain server commands marshal and unmarshal
// into valid results include handling of optional fields being omitted in the
// marshalled command, while optional fields with defaults have the default
// assigned on unmarshalled commands.
func TestChainSvrCmds(t *testing.T) {
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
			name: "addnode",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("addnode", "127.0.0.1", hnsjson.ANRemove)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewAddNodeCmd("127.0.0.1", hnsjson.ANRemove)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"addnode","params":["127.0.0.1","remove"],"id":1}`,
			unmarshalled: &hnsjson.AddNodeCmd{Addr: "127.0.0.1", SubCmd: hnsjson.ANRemove},
		},
		{
			name: "createrawtransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createrawtransaction", `[{"txid":"123","vout":1}]`,
					`{"456":0.0123}`)
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.TransactionInput{
					{Txid: "123", Vout: 1},
				}
				amounts := map[string]float64{"456": .0123}
				return hnsjson.NewCreateRawTransactionCmd(txInputs, amounts, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createrawtransaction","params":[[{"txid":"123","vout":1}],{"456":0.0123}],"id":1}`,
			unmarshalled: &hnsjson.CreateRawTransactionCmd{
				Inputs:  []hnsjson.TransactionInput{{Txid: "123", Vout: 1}},
				Amounts: map[string]float64{"456": .0123},
			},
		},
		{
			name: "createrawtransaction - no inputs",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createrawtransaction", `[]`, `{"456":0.0123}`)
			},
			staticCmd: func() interface{} {
				amounts := map[string]float64{"456": .0123}
				return hnsjson.NewCreateRawTransactionCmd(nil, amounts, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createrawtransaction","params":[[],{"456":0.0123}],"id":1}`,
			unmarshalled: &hnsjson.CreateRawTransactionCmd{
				Inputs:  []hnsjson.TransactionInput{},
				Amounts: map[string]float64{"456": .0123},
			},
		},
		{
			name: "createrawtransaction optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createrawtransaction", `[{"txid":"123","vout":1}]`,
					`{"456":0.0123}`, int64(12312333333))
			},
			staticCmd: func() interface{} {
				txInputs := []hnsjson.TransactionInput{
					{Txid: "123", Vout: 1},
				}
				amounts := map[string]float64{"456": .0123}
				return hnsjson.NewCreateRawTransactionCmd(txInputs, amounts, hnsjson.Int64(12312333333))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createrawtransaction","params":[[{"txid":"123","vout":1}],{"456":0.0123},12312333333],"id":1}`,
			unmarshalled: &hnsjson.CreateRawTransactionCmd{
				Inputs:   []hnsjson.TransactionInput{{Txid: "123", Vout: 1}},
				Amounts:  map[string]float64{"456": .0123},
				LockTime: hnsjson.Int64(12312333333),
			},
		},
		{
			name: "fundrawtransaction - empty opts",
			newCmd: func() (i interface{}, e error) {
				return hnsjson.NewCmd("fundrawtransaction", "deadbeef", "{}")
			},
			staticCmd: func() interface{} {
				deadbeef, err := hex.DecodeString("deadbeef")
				if err != nil {
					panic(err)
				}
				return hnsjson.NewFundRawTransactionCmd(deadbeef, hnsjson.FundRawTransactionOpts{}, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"fundrawtransaction","params":["deadbeef",{}],"id":1}`,
			unmarshalled: &hnsjson.FundRawTransactionCmd{
				HexTx:     "deadbeef",
				Options:   hnsjson.FundRawTransactionOpts{},
				IsWitness: nil,
			},
		},
		{
			name: "fundrawtransaction - full opts",
			newCmd: func() (i interface{}, e error) {
				return hnsjson.NewCmd("fundrawtransaction", "deadbeef", `{"changeAddress":"bcrt1qeeuctq9wutlcl5zatge7rjgx0k45228cxez655","changePosition":1,"change_type":"legacy","includeWatching":true,"lockUnspents":true,"feeRate":0.7,"subtractFeeFromOutputs":[0],"replaceable":true,"conf_target":8,"estimate_mode":"ECONOMICAL"}`)
			},
			staticCmd: func() interface{} {
				deadbeef, err := hex.DecodeString("deadbeef")
				if err != nil {
					panic(err)
				}
				changeAddress := "bcrt1qeeuctq9wutlcl5zatge7rjgx0k45228cxez655"
				change := 1
				changeType := hnsjson.ChangeTypeLegacy
				watching := true
				lockUnspents := true
				feeRate := 0.7
				replaceable := true
				confTarget := 8

				return hnsjson.NewFundRawTransactionCmd(deadbeef, hnsjson.FundRawTransactionOpts{
					ChangeAddress:          &changeAddress,
					ChangePosition:         &change,
					ChangeType:             &changeType,
					IncludeWatching:        &watching,
					LockUnspents:           &lockUnspents,
					FeeRate:                &feeRate,
					SubtractFeeFromOutputs: []int{0},
					Replaceable:            &replaceable,
					ConfTarget:             &confTarget,
					EstimateMode:           &hnsjson.EstimateModeEconomical,
				}, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"fundrawtransaction","params":["deadbeef",{"changeAddress":"bcrt1qeeuctq9wutlcl5zatge7rjgx0k45228cxez655","changePosition":1,"change_type":"legacy","includeWatching":true,"lockUnspents":true,"feeRate":0.7,"subtractFeeFromOutputs":[0],"replaceable":true,"conf_target":8,"estimate_mode":"ECONOMICAL"}],"id":1}`,
			unmarshalled: func() interface{} {
				changeAddress := "bcrt1qeeuctq9wutlcl5zatge7rjgx0k45228cxez655"
				change := 1
				changeType := hnsjson.ChangeTypeLegacy
				watching := true
				lockUnspents := true
				feeRate := 0.7
				replaceable := true
				confTarget := 8
				return &hnsjson.FundRawTransactionCmd{
					HexTx: "deadbeef",
					Options: hnsjson.FundRawTransactionOpts{
						ChangeAddress:          &changeAddress,
						ChangePosition:         &change,
						ChangeType:             &changeType,
						IncludeWatching:        &watching,
						LockUnspents:           &lockUnspents,
						FeeRate:                &feeRate,
						SubtractFeeFromOutputs: []int{0},
						Replaceable:            &replaceable,
						ConfTarget:             &confTarget,
						EstimateMode:           &hnsjson.EstimateModeEconomical,
					},
					IsWitness: nil,
				}
			}(),
		},
		{
			name: "fundrawtransaction - iswitness",
			newCmd: func() (i interface{}, e error) {
				return hnsjson.NewCmd("fundrawtransaction", "deadbeef", "{}", true)
			},
			staticCmd: func() interface{} {
				deadbeef, err := hex.DecodeString("deadbeef")
				if err != nil {
					panic(err)
				}
				t := true
				return hnsjson.NewFundRawTransactionCmd(deadbeef, hnsjson.FundRawTransactionOpts{}, &t)
			},
			marshalled: `{"jsonrpc":"1.0","method":"fundrawtransaction","params":["deadbeef",{},true],"id":1}`,
			unmarshalled: &hnsjson.FundRawTransactionCmd{
				HexTx:   "deadbeef",
				Options: hnsjson.FundRawTransactionOpts{},
				IsWitness: func() *bool {
					t := true
					return &t
				}(),
			},
		},
		{
			name: "decoderawtransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("decoderawtransaction", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDecodeRawTransactionCmd("123")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"decoderawtransaction","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.DecodeRawTransactionCmd{HexTx: "123"},
		},
		{
			name: "decodescript",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("decodescript", "00")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDecodeScriptCmd("00")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"decodescript","params":["00"],"id":1}`,
			unmarshalled: &hnsjson.DecodeScriptCmd{HexScript: "00"},
		},
		{
			name: "deriveaddresses no range",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("deriveaddresses", "00")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDeriveAddressesCmd("00", nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"deriveaddresses","params":["00"],"id":1}`,
			unmarshalled: &hnsjson.DeriveAddressesCmd{Descriptor: "00"},
		},
		{
			name: "deriveaddresses int range",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"deriveaddresses", "00", hnsjson.DescriptorRange{Value: 2})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDeriveAddressesCmd(
					"00", &hnsjson.DescriptorRange{Value: 2})
			},
			marshalled: `{"jsonrpc":"1.0","method":"deriveaddresses","params":["00",2],"id":1}`,
			unmarshalled: &hnsjson.DeriveAddressesCmd{
				Descriptor: "00",
				Range:      &hnsjson.DescriptorRange{Value: 2},
			},
		},
		{
			name: "deriveaddresses slice range",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"deriveaddresses", "00",
					hnsjson.DescriptorRange{Value: []int{0, 2}},
				)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDeriveAddressesCmd(
					"00", &hnsjson.DescriptorRange{Value: []int{0, 2}})
			},
			marshalled: `{"jsonrpc":"1.0","method":"deriveaddresses","params":["00",[0,2]],"id":1}`,
			unmarshalled: &hnsjson.DeriveAddressesCmd{
				Descriptor: "00",
				Range:      &hnsjson.DescriptorRange{Value: []int{0, 2}},
			},
		},
		{
			name: "getaddednodeinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaddednodeinfo", true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAddedNodeInfoCmd(true, nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getaddednodeinfo","params":[true],"id":1}`,
			unmarshalled: &hnsjson.GetAddedNodeInfoCmd{DNS: true, Node: nil},
		},
		{
			name: "getaddednodeinfo optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getaddednodeinfo", true, "127.0.0.1")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAddedNodeInfoCmd(true, hnsjson.String("127.0.0.1"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getaddednodeinfo","params":[true,"127.0.0.1"],"id":1}`,
			unmarshalled: &hnsjson.GetAddedNodeInfoCmd{
				DNS:  true,
				Node: hnsjson.String("127.0.0.1"),
			},
		},
		{
			name: "getbestblockhash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getbestblockhash")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBestBlockHashCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getbestblockhash","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBestBlockHashCmd{},
		},
		{
			name: "getblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblock", "123", hnsjson.Int(0))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockCmd("123", hnsjson.Int(0))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblock","params":["123",0],"id":1}`,
			unmarshalled: &hnsjson.GetBlockCmd{
				Hash:      "123",
				Verbosity: hnsjson.Int(0),
			},
		},
		{
			name: "getblock default verbosity",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblock", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockCmd("123", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblock","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.GetBlockCmd{
				Hash:      "123",
				Verbosity: hnsjson.Int(1),
			},
		},
		{
			name: "getblock required optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblock", "123", hnsjson.Int(1))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockCmd("123", hnsjson.Int(1))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblock","params":["123",1],"id":1}`,
			unmarshalled: &hnsjson.GetBlockCmd{
				Hash:      "123",
				Verbosity: hnsjson.Int(1),
			},
		},
		{
			name: "getblock required optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblock", "123", hnsjson.Int(2))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockCmd("123", hnsjson.Int(2))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblock","params":["123",2],"id":1}`,
			unmarshalled: &hnsjson.GetBlockCmd{
				Hash:      "123",
				Verbosity: hnsjson.Int(2),
			},
		},
		{
			name: "getblockchaininfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockchaininfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockChainInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblockchaininfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBlockChainInfoCmd{},
		},
		{
			name: "getblockcount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockcount")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockCountCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBlockCountCmd{},
		},
		{
			name: "getblockfilter",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockfilter", "0000afaf")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockFilterCmd("0000afaf", nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblockfilter","params":["0000afaf"],"id":1}`,
			unmarshalled: &hnsjson.GetBlockFilterCmd{"0000afaf", nil},
		},
		{
			name: "getblockfilter optional filtertype",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockfilter", "0000afaf", "basic")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockFilterCmd("0000afaf", hnsjson.NewFilterTypeName(hnsjson.FilterTypeBasic))
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblockfilter","params":["0000afaf","basic"],"id":1}`,
			unmarshalled: &hnsjson.GetBlockFilterCmd{"0000afaf", hnsjson.NewFilterTypeName(hnsjson.FilterTypeBasic)},
		},
		{
			name: "getblockhash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockhash", 123)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockHashCmd(123)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblockhash","params":[123],"id":1}`,
			unmarshalled: &hnsjson.GetBlockHashCmd{Index: 123},
		},
		{
			name: "getblockheader",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockheader", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockHeaderCmd("123", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblockheader","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.GetBlockHeaderCmd{
				Hash:    "123",
				Verbose: hnsjson.Bool(true),
			},
		},
		{
			name: "getblockstats height",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockstats", hnsjson.HashOrHeight{Value: 123})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockStatsCmd(hnsjson.HashOrHeight{Value: 123}, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblockstats","params":[123],"id":1}`,
			unmarshalled: &hnsjson.GetBlockStatsCmd{
				HashOrHeight: hnsjson.HashOrHeight{Value: 123},
			},
		},
		{
			name: "getblockstats hash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockstats", hnsjson.HashOrHeight{Value: "deadbeef"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockStatsCmd(hnsjson.HashOrHeight{Value: "deadbeef"}, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblockstats","params":["deadbeef"],"id":1}`,
			unmarshalled: &hnsjson.GetBlockStatsCmd{
				HashOrHeight: hnsjson.HashOrHeight{Value: "deadbeef"},
			},
		},
		{
			name: "getblockstats height optional stats",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockstats", hnsjson.HashOrHeight{Value: 123}, []string{"avgfee", "maxfee"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockStatsCmd(hnsjson.HashOrHeight{Value: 123}, &[]string{"avgfee", "maxfee"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblockstats","params":[123,["avgfee","maxfee"]],"id":1}`,
			unmarshalled: &hnsjson.GetBlockStatsCmd{
				HashOrHeight: hnsjson.HashOrHeight{Value: 123},
				Stats:        &[]string{"avgfee", "maxfee"},
			},
		},
		{
			name: "getblockstats hash optional stats",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblockstats", hnsjson.HashOrHeight{Value: "deadbeef"}, []string{"avgfee", "maxfee"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockStatsCmd(hnsjson.HashOrHeight{Value: "deadbeef"}, &[]string{"avgfee", "maxfee"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblockstats","params":["deadbeef",["avgfee","maxfee"]],"id":1}`,
			unmarshalled: &hnsjson.GetBlockStatsCmd{
				HashOrHeight: hnsjson.HashOrHeight{Value: "deadbeef"},
				Stats:        &[]string{"avgfee", "maxfee"},
			},
		},
		{
			name: "getblocktemplate",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblocktemplate")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetBlockTemplateCmd(nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getblocktemplate","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetBlockTemplateCmd{Request: nil},
		},
		{
			name: "getblocktemplate optional - template request",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblocktemplate", `{"mode":"template","capabilities":["longpoll","coinbasetxn"]}`)
			},
			staticCmd: func() interface{} {
				template := hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
				}
				return hnsjson.NewGetBlockTemplateCmd(&template)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblocktemplate","params":[{"mode":"template","capabilities":["longpoll","coinbasetxn"]}],"id":1}`,
			unmarshalled: &hnsjson.GetBlockTemplateCmd{
				Request: &hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
				},
			},
		},
		{
			name: "getblocktemplate optional - template request with tweaks",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblocktemplate", `{"mode":"template","capabilities":["longpoll","coinbasetxn"],"sigoplimit":500,"sizelimit":100000000,"maxversion":2}`)
			},
			staticCmd: func() interface{} {
				template := hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
					SigOpLimit:   500,
					SizeLimit:    100000000,
					MaxVersion:   2,
				}
				return hnsjson.NewGetBlockTemplateCmd(&template)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblocktemplate","params":[{"mode":"template","capabilities":["longpoll","coinbasetxn"],"sigoplimit":500,"sizelimit":100000000,"maxversion":2}],"id":1}`,
			unmarshalled: &hnsjson.GetBlockTemplateCmd{
				Request: &hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
					SigOpLimit:   int64(500),
					SizeLimit:    int64(100000000),
					MaxVersion:   2,
				},
			},
		},
		{
			name: "getblocktemplate optional - template request with tweaks 2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getblocktemplate", `{"mode":"template","capabilities":["longpoll","coinbasetxn"],"sigoplimit":true,"sizelimit":100000000,"maxversion":2}`)
			},
			staticCmd: func() interface{} {
				template := hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
					SigOpLimit:   true,
					SizeLimit:    100000000,
					MaxVersion:   2,
				}
				return hnsjson.NewGetBlockTemplateCmd(&template)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getblocktemplate","params":[{"mode":"template","capabilities":["longpoll","coinbasetxn"],"sigoplimit":true,"sizelimit":100000000,"maxversion":2}],"id":1}`,
			unmarshalled: &hnsjson.GetBlockTemplateCmd{
				Request: &hnsjson.TemplateRequest{
					Mode:         "template",
					Capabilities: []string{"longpoll", "coinbasetxn"},
					SigOpLimit:   true,
					SizeLimit:    int64(100000000),
					MaxVersion:   2,
				},
			},
		},
		{
			name: "getcfilter",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getcfilter", "123",
					wire.GCSFilterRegular)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetCFilterCmd("123",
					wire.GCSFilterRegular)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getcfilter","params":["123",0],"id":1}`,
			unmarshalled: &hnsjson.GetCFilterCmd{
				Hash:       "123",
				FilterType: wire.GCSFilterRegular,
			},
		},
		{
			name: "getcfilterheader",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getcfilterheader", "123",
					wire.GCSFilterRegular)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetCFilterHeaderCmd("123",
					wire.GCSFilterRegular)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getcfilterheader","params":["123",0],"id":1}`,
			unmarshalled: &hnsjson.GetCFilterHeaderCmd{
				Hash:       "123",
				FilterType: wire.GCSFilterRegular,
			},
		},
		{
			name: "getchaintips",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getchaintips")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetChainTipsCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getchaintips","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetChainTipsCmd{},
		},
		{
			name: "getchaintxstats",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getchaintxstats")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetChainTxStatsCmd(nil, nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getchaintxstats","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetChainTxStatsCmd{},
		},
		{
			name: "getchaintxstats optional nblocks",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getchaintxstats", hnsjson.Int32(1000))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetChainTxStatsCmd(hnsjson.Int32(1000), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getchaintxstats","params":[1000],"id":1}`,
			unmarshalled: &hnsjson.GetChainTxStatsCmd{
				NBlocks: hnsjson.Int32(1000),
			},
		},
		{
			name: "getchaintxstats optional nblocks and blockhash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getchaintxstats", hnsjson.Int32(1000), hnsjson.String("0000afaf"))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetChainTxStatsCmd(hnsjson.Int32(1000), hnsjson.String("0000afaf"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getchaintxstats","params":[1000,"0000afaf"],"id":1}`,
			unmarshalled: &hnsjson.GetChainTxStatsCmd{
				NBlocks:   hnsjson.Int32(1000),
				BlockHash: hnsjson.String("0000afaf"),
			},
		},
		{
			name: "getconnectioncount",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getconnectioncount")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetConnectionCountCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getconnectioncount","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetConnectionCountCmd{},
		},
		{
			name: "getdifficulty",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getdifficulty")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetDifficultyCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getdifficulty","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetDifficultyCmd{},
		},
		{
			name: "getgenerate",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getgenerate")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetGenerateCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getgenerate","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetGenerateCmd{},
		},
		{
			name: "gethashespersec",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gethashespersec")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetHashesPerSecCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"gethashespersec","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetHashesPerSecCmd{},
		},
		{
			name: "getinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetInfoCmd{},
		},
		{
			name: "getmempoolentry",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getmempoolentry", "txhash")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetMempoolEntryCmd("txhash")
			},
			marshalled: `{"jsonrpc":"1.0","method":"getmempoolentry","params":["txhash"],"id":1}`,
			unmarshalled: &hnsjson.GetMempoolEntryCmd{
				TxID: "txhash",
			},
		},
		{
			name: "getmempoolinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getmempoolinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetMempoolInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getmempoolinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetMempoolInfoCmd{},
		},
		{
			name: "getmininginfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getmininginfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetMiningInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getmininginfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetMiningInfoCmd{},
		},
		{
			name: "getnetworkinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnetworkinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNetworkInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getnetworkinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNetworkInfoCmd{},
		},
		{
			name: "getnettotals",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnettotals")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNetTotalsCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getnettotals","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNetTotalsCmd{},
		},
		{
			name: "getnetworkhashps",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnetworkhashps")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNetworkHashPSCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnetworkhashps","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNetworkHashPSCmd{
				Blocks: hnsjson.Int(120),
				Height: hnsjson.Int(-1),
			},
		},
		{
			name: "getnetworkhashps optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnetworkhashps", 200)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNetworkHashPSCmd(hnsjson.Int(200), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnetworkhashps","params":[200],"id":1}`,
			unmarshalled: &hnsjson.GetNetworkHashPSCmd{
				Blocks: hnsjson.Int(200),
				Height: hnsjson.Int(-1),
			},
		},
		{
			name: "getnetworkhashps optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnetworkhashps", 200, 123)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNetworkHashPSCmd(hnsjson.Int(200), hnsjson.Int(123))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnetworkhashps","params":[200,123],"id":1}`,
			unmarshalled: &hnsjson.GetNetworkHashPSCmd{
				Blocks: hnsjson.Int(200),
				Height: hnsjson.Int(123),
			},
		},
		{
			name: "getnodeaddresses",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnodeaddresses")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNodeAddressesCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnodeaddresses","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNodeAddressesCmd{
				Count: hnsjson.Int32(1),
			},
		},
		{
			name: "getnodeaddresses optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnodeaddresses", 10)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNodeAddressesCmd(hnsjson.Int32(10))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnodeaddresses","params":[10],"id":1}`,
			unmarshalled: &hnsjson.GetNodeAddressesCmd{
				Count: hnsjson.Int32(10),
			},
		},
		{
			name: "getpeerinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getpeerinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetPeerInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getpeerinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetPeerInfoCmd{},
		},
		{
			name: "getrawmempool",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawmempool")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawMempoolCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawmempool","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetRawMempoolCmd{
				Verbose: hnsjson.Bool(false),
			},
		},
		{
			name: "getrawmempool optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawmempool", false)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawMempoolCmd(hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawmempool","params":[false],"id":1}`,
			unmarshalled: &hnsjson.GetRawMempoolCmd{
				Verbose: hnsjson.Bool(false),
			},
		},
		{
			name: "getrawtransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawtransaction", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawTransactionCmd("123", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawtransaction","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.GetRawTransactionCmd{
				Txid:    "123",
				Verbose: hnsjson.Int(0),
			},
		},
		{
			name: "getrawtransaction optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getrawtransaction", "123", 1)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetRawTransactionCmd("123", hnsjson.Int(1))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getrawtransaction","params":["123",1],"id":1}`,
			unmarshalled: &hnsjson.GetRawTransactionCmd{
				Txid:    "123",
				Verbose: hnsjson.Int(1),
			},
		},
		{
			name: "gettxout",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettxout", "123", 1)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTxOutCmd("123", 1, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettxout","params":["123",1],"id":1}`,
			unmarshalled: &hnsjson.GetTxOutCmd{
				Txid:           "123",
				Vout:           1,
				IncludeMempool: hnsjson.Bool(true),
			},
		},
		{
			name: "gettxout optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettxout", "123", 1, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTxOutCmd("123", 1, hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettxout","params":["123",1,true],"id":1}`,
			unmarshalled: &hnsjson.GetTxOutCmd{
				Txid:           "123",
				Vout:           1,
				IncludeMempool: hnsjson.Bool(true),
			},
		},
		{
			name: "gettxoutproof",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettxoutproof", []string{"123", "456"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTxOutProofCmd([]string{"123", "456"}, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettxoutproof","params":[["123","456"]],"id":1}`,
			unmarshalled: &hnsjson.GetTxOutProofCmd{
				TxIDs: []string{"123", "456"},
			},
		},
		{
			name: "gettxoutproof optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettxoutproof", []string{"123", "456"},
					hnsjson.String("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTxOutProofCmd([]string{"123", "456"},
					hnsjson.String("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettxoutproof","params":[["123","456"],` +
				`"000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"],"id":1}`,
			unmarshalled: &hnsjson.GetTxOutProofCmd{
				TxIDs:     []string{"123", "456"},
				BlockHash: hnsjson.String("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"),
			},
		},
		{
			name: "gettxoutsetinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("gettxoutsetinfo")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetTxOutSetInfoCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"gettxoutsetinfo","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetTxOutSetInfoCmd{},
		},
		{
			name: "getwork",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getwork")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetWorkCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getwork","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetWorkCmd{
				Data: nil,
			},
		},
		{
			name: "getwork optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getwork", "00112233")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetWorkCmd(hnsjson.String("00112233"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getwork","params":["00112233"],"id":1}`,
			unmarshalled: &hnsjson.GetWorkCmd{
				Data: hnsjson.String("00112233"),
			},
		},
		{
			name: "help",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("help")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewHelpCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"help","params":[],"id":1}`,
			unmarshalled: &hnsjson.HelpCmd{
				Command: nil,
			},
		},
		{
			name: "help optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("help", "getblock")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewHelpCmd(hnsjson.String("getblock"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"help","params":["getblock"],"id":1}`,
			unmarshalled: &hnsjson.HelpCmd{
				Command: hnsjson.String("getblock"),
			},
		},
		{
			name: "invalidateblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("invalidateblock", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewInvalidateBlockCmd("123")
			},
			marshalled: `{"jsonrpc":"1.0","method":"invalidateblock","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.InvalidateBlockCmd{
				BlockHash: "123",
			},
		},
		{
			name: "ping",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("ping")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewPingCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"ping","params":[],"id":1}`,
			unmarshalled: &hnsjson.PingCmd{},
		},
		{
			name: "preciousblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("preciousblock", "0123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewPreciousBlockCmd("0123")
			},
			marshalled: `{"jsonrpc":"1.0","method":"preciousblock","params":["0123"],"id":1}`,
			unmarshalled: &hnsjson.PreciousBlockCmd{
				BlockHash: "0123",
			},
		},
		{
			name: "reconsiderblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("reconsiderblock", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewReconsiderBlockCmd("123")
			},
			marshalled: `{"jsonrpc":"1.0","method":"reconsiderblock","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.ReconsiderBlockCmd{
				BlockHash: "123",
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address", nil, nil, nil, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address"],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(1),
				Skip:        hnsjson.Int(0),
				Count:       hnsjson.Int(100),
				VinExtra:    hnsjson.Int(0),
				Reverse:     hnsjson.Bool(false),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), nil, nil, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(0),
				Count:       hnsjson.Int(100),
				VinExtra:    hnsjson.Int(0),
				Reverse:     hnsjson.Bool(false),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), nil, nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(100),
				VinExtra:    hnsjson.Int(0),
				Reverse:     hnsjson.Bool(false),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5, 10)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), hnsjson.Int(10), nil, nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5,10],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(10),
				VinExtra:    hnsjson.Int(0),
				Reverse:     hnsjson.Bool(false),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5, 10, 1)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), hnsjson.Int(10), hnsjson.Int(1), nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5,10,1],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(10),
				VinExtra:    hnsjson.Int(1),
				Reverse:     hnsjson.Bool(false),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5, 10, 1, true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), hnsjson.Int(10), hnsjson.Int(1), hnsjson.Bool(true), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5,10,1,true],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(10),
				VinExtra:    hnsjson.Int(1),
				Reverse:     hnsjson.Bool(true),
				FilterAddrs: nil,
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5, 10, 1, true, []string{"1Address"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), hnsjson.Int(10), hnsjson.Int(1), hnsjson.Bool(true), &[]string{"1Address"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5,10,1,true,["1Address"]],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(10),
				VinExtra:    hnsjson.Int(1),
				Reverse:     hnsjson.Bool(true),
				FilterAddrs: &[]string{"1Address"},
			},
		},
		{
			name: "searchrawtransactions",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("searchrawtransactions", "1Address", 0, 5, 10, "null", true, []string{"1Address"})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSearchRawTransactionsCmd("1Address",
					hnsjson.Int(0), hnsjson.Int(5), hnsjson.Int(10), nil, hnsjson.Bool(true), &[]string{"1Address"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"searchrawtransactions","params":["1Address",0,5,10,null,true,["1Address"]],"id":1}`,
			unmarshalled: &hnsjson.SearchRawTransactionsCmd{
				Address:     "1Address",
				Verbose:     hnsjson.Int(0),
				Skip:        hnsjson.Int(5),
				Count:       hnsjson.Int(10),
				VinExtra:    nil,
				Reverse:     hnsjson.Bool(true),
				FilterAddrs: &[]string{"1Address"},
			},
		},
		{
			name: "sendrawtransaction",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendrawtransaction", "1122", &hnsjson.AllowHighFeesOrMaxFeeRate{})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendRawTransactionCmd("1122", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendrawtransaction","params":["1122",false],"id":1}`,
			unmarshalled: &hnsjson.SendRawTransactionCmd{
				HexTx: "1122",
				FeeSetting: &hnsjson.AllowHighFeesOrMaxFeeRate{
					Value: hnsjson.Bool(false),
				},
			},
		},
		{
			name: "sendrawtransaction optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendrawtransaction", "1122", &hnsjson.AllowHighFeesOrMaxFeeRate{Value: hnsjson.Bool(false)})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSendRawTransactionCmd("1122", hnsjson.Bool(false))
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendrawtransaction","params":["1122",false],"id":1}`,
			unmarshalled: &hnsjson.SendRawTransactionCmd{
				HexTx: "1122",
				FeeSetting: &hnsjson.AllowHighFeesOrMaxFeeRate{
					Value: hnsjson.Bool(false),
				},
			},
		},
		{
			name: "sendrawtransaction optional, bitcoind >= 0.19.0",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("sendrawtransaction", "1122", &hnsjson.AllowHighFeesOrMaxFeeRate{Value: hnsjson.Float64(0.1234)})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewBitcoindSendRawTransactionCmd("1122", 0.1234)
			},
			marshalled: `{"jsonrpc":"1.0","method":"sendrawtransaction","params":["1122",0.1234],"id":1}`,
			unmarshalled: &hnsjson.SendRawTransactionCmd{
				HexTx: "1122",
				FeeSetting: &hnsjson.AllowHighFeesOrMaxFeeRate{
					Value: hnsjson.Float64(0.1234),
				},
			},
		},
		{
			name: "setgenerate",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("setgenerate", true)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSetGenerateCmd(true, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"setgenerate","params":[true],"id":1}`,
			unmarshalled: &hnsjson.SetGenerateCmd{
				Generate:     true,
				GenProcLimit: hnsjson.Int(-1),
			},
		},
		{
			name: "setgenerate optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("setgenerate", true, 6)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSetGenerateCmd(true, hnsjson.Int(6))
			},
			marshalled: `{"jsonrpc":"1.0","method":"setgenerate","params":[true,6],"id":1}`,
			unmarshalled: &hnsjson.SetGenerateCmd{
				Generate:     true,
				GenProcLimit: hnsjson.Int(6),
			},
		},
		{
			name: "signmessagewithprivkey",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("signmessagewithprivkey", "5Hue", "Hey")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSignMessageWithPrivKey("5Hue", "Hey")
			},
			marshalled: `{"jsonrpc":"1.0","method":"signmessagewithprivkey","params":["5Hue","Hey"],"id":1}`,
			unmarshalled: &hnsjson.SignMessageWithPrivKeyCmd{
				PrivKey: "5Hue",
				Message: "Hey",
			},
		},
		{
			name: "stop",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("stop")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewStopCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"stop","params":[],"id":1}`,
			unmarshalled: &hnsjson.StopCmd{},
		},
		{
			name: "submitblock",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("submitblock", "112233")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewSubmitBlockCmd("112233", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"submitblock","params":["112233"],"id":1}`,
			unmarshalled: &hnsjson.SubmitBlockCmd{
				HexBlock: "112233",
				Options:  nil,
			},
		},
		{
			name: "submitblock optional",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("submitblock", "112233", `{"workid":"12345"}`)
			},
			staticCmd: func() interface{} {
				options := hnsjson.SubmitBlockOptions{
					WorkID: "12345",
				}
				return hnsjson.NewSubmitBlockCmd("112233", &options)
			},
			marshalled: `{"jsonrpc":"1.0","method":"submitblock","params":["112233",{"workid":"12345"}],"id":1}`,
			unmarshalled: &hnsjson.SubmitBlockCmd{
				HexBlock: "112233",
				Options: &hnsjson.SubmitBlockOptions{
					WorkID: "12345",
				},
			},
		},
		{
			name: "uptime",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("uptime")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewUptimeCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"uptime","params":[],"id":1}`,
			unmarshalled: &hnsjson.UptimeCmd{},
		},
		{
			name: "validateaddress",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("validateaddress", "1Address")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewValidateAddressCmd("1Address")
			},
			marshalled: `{"jsonrpc":"1.0","method":"validateaddress","params":["1Address"],"id":1}`,
			unmarshalled: &hnsjson.ValidateAddressCmd{
				Address: "1Address",
			},
		},
		{
			name: "verifychain",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifychain")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyChainCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifychain","params":[],"id":1}`,
			unmarshalled: &hnsjson.VerifyChainCmd{
				CheckLevel: hnsjson.Int32(3),
				CheckDepth: hnsjson.Int32(288),
			},
		},
		{
			name: "verifychain optional1",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifychain", 2)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyChainCmd(hnsjson.Int32(2), nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifychain","params":[2],"id":1}`,
			unmarshalled: &hnsjson.VerifyChainCmd{
				CheckLevel: hnsjson.Int32(2),
				CheckDepth: hnsjson.Int32(288),
			},
		},
		{
			name: "verifychain optional2",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifychain", 2, 500)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyChainCmd(hnsjson.Int32(2), hnsjson.Int32(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifychain","params":[2,500],"id":1}`,
			unmarshalled: &hnsjson.VerifyChainCmd{
				CheckLevel: hnsjson.Int32(2),
				CheckDepth: hnsjson.Int32(500),
			},
		},
		{
			name: "verifymessage",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifymessage", "1Address", "301234", "test")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyMessageCmd("1Address", "301234", "test")
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifymessage","params":["1Address","301234","test"],"id":1}`,
			unmarshalled: &hnsjson.VerifyMessageCmd{
				Address:   "1Address",
				Signature: "301234",
				Message:   "test",
			},
		},
		{
			name: "verifytxoutproof",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifytxoutproof", "test")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyTxOutProofCmd("test")
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifytxoutproof","params":["test"],"id":1}`,
			unmarshalled: &hnsjson.VerifyTxOutProofCmd{
				Proof: "test",
			},
		},
		{
			name: "getdescriptorinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getdescriptorinfo", "123")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetDescriptorInfoCmd("123")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getdescriptorinfo","params":["123"],"id":1}`,
			unmarshalled: &hnsjson.GetDescriptorInfoCmd{Descriptor: "123"},
		},
		{
			name: "getzmqnotifications",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getzmqnotifications")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetZmqNotificationsCmd()
			},

			marshalled:   `{"jsonrpc":"1.0","method":"getzmqnotifications","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetZmqNotificationsCmd{},
		},
		{
			name: "testmempoolaccept",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("testmempoolaccept", []string{"rawhex"}, 0.1)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewTestMempoolAcceptCmd([]string{"rawhex"}, 0.1)
			},
			marshalled: `{"jsonrpc":"1.0","method":"testmempoolaccept","params":[["rawhex"],0.1],"id":1}`,
			unmarshalled: &hnsjson.TestMempoolAcceptCmd{
				RawTxns:    []string{"rawhex"},
				MaxFeeRate: 0.1,
			},
		},
		{
			name: "testmempoolaccept with maxfeerate",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("testmempoolaccept", []string{"rawhex"}, 0.01)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewTestMempoolAcceptCmd([]string{"rawhex"}, 0.01)
			},
			marshalled: `{"jsonrpc":"1.0","method":"testmempoolaccept","params":[["rawhex"],0.01],"id":1}`,
			unmarshalled: &hnsjson.TestMempoolAcceptCmd{
				RawTxns:    []string{"rawhex"},
				MaxFeeRate: 0.01,
			},
		},
		{
			name: "gettxspendingprevout",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd(
					"gettxspendingprevout",
					[]*hnsjson.GetTxSpendingPrevOutCmdOutput{
						{Txid: "0000000000000000000000000000000000000000000000000000000000000001", Vout: 0},
					})
			},
			staticCmd: func() interface{} {
				outputs := []wire.OutPoint{
					{Hash: chainhash.Hash{1}, Index: 0},
				}
				return hnsjson.NewGetTxSpendingPrevOutCmd(outputs)
			},
			marshalled: `{"jsonrpc":"1.0","method":"gettxspendingprevout","params":[[{"txid":"0000000000000000000000000000000000000000000000000000000000000001","vout":0}]],"id":1}`,
			unmarshalled: &hnsjson.GetTxSpendingPrevOutCmd{
				Outputs: []*hnsjson.GetTxSpendingPrevOutCmdOutput{{
					Txid: "0000000000000000000000000000000000000000000000000000000000000001",
					Vout: 0,
				}},
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
			t.Errorf("\n%s\n%s", marshalled, test.marshalled)
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

// TestChainSvrCmdErrors ensures any errors that occur in the command during
// custom mashal and unmarshal are as expected.
func TestChainSvrCmdErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		result     interface{}
		marshalled string
		err        error
	}{
		{
			name:       "template request with invalid type",
			result:     &hnsjson.TemplateRequest{},
			marshalled: `{"mode":1}`,
			err:        &json.UnmarshalTypeError{},
		},
		{
			name:       "invalid template request sigoplimit field",
			result:     &hnsjson.TemplateRequest{},
			marshalled: `{"sigoplimit":"invalid"}`,
			err:        hnsjson.Error{ErrorCode: hnsjson.ErrInvalidType},
		},
		{
			name:       "invalid template request sizelimit field",
			result:     &hnsjson.TemplateRequest{},
			marshalled: `{"sizelimit":"invalid"}`,
			err:        hnsjson.Error{ErrorCode: hnsjson.ErrInvalidType},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		err := json.Unmarshal([]byte(test.marshalled), &test.result)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Test #%d (%s) wrong error - got %T (%v), "+
				"want %T", i, test.name, err, err, test.err)
			continue
		}

		if terr, ok := test.err.(hnsjson.Error); ok {
			gotErrorCode := err.(hnsjson.Error).ErrorCode
			if gotErrorCode != terr.ErrorCode {
				t.Errorf("Test #%d (%s) mismatched error code "+
					"- got %v (%v), want %v", i, test.name,
					gotErrorCode, terr, terr.ErrorCode)
				continue
			}
		}
	}
}
