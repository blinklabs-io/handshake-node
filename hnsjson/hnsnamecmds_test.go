// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsjson_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsjson"
)

// TestHNSExtNameCmds tests Handshake name extension commands marshal and
// unmarshal with the expected JSON-RPC parameter shape.
func TestHNSExtNameCmds(t *testing.T) {
	t.Parallel()

	testID := int(1)
	zeroHash := "0000000000000000000000000000000000000000000000000000000000000000"
	address := "hs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	transferAddress := "hs1qtransferqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	inputs := []hnsjson.TransactionInput{{Txid: zeroHash, Vout: 1}}
	inputJSON := `{"txid":"` + zeroHash + `","vout":1}`
	tests := []struct {
		name         string
		newCmd       func() (interface{}, error)
		staticCmd    func() interface{}
		marshalled   string
		unmarshalled interface{}
	}{
		{
			name: "getnameinfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnameinfo", "example")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNameInfoCmd("example")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getnameinfo","params":["example"],"id":1}`,
			unmarshalled: &hnsjson.GetNameInfoCmd{Name: "example"},
		},
		{
			name: "getnamebyhash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnamebyhash", zeroHash)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNameByHashCmd(zeroHash)
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnamebyhash","params":["` + zeroHash + `"],"id":1}`,
			unmarshalled: &hnsjson.GetNameByHashCmd{
				NameHash: zeroHash,
			},
		},
		{
			name: "getnameresource",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnameresource", "example")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNameResourceCmd("example")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getnameresource","params":["example"],"id":1}`,
			unmarshalled: &hnsjson.GetNameResourceCmd{Name: "example"},
		},
		{
			name: "decoderesource",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("decoderesource", "00")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewDecodeResourceCmd("00")
			},
			marshalled: `{"jsonrpc":"1.0","method":"decoderesource","params":["00"],"id":1}`,
			unmarshalled: &hnsjson.DecodeResourceCmd{
				HexResource: "00",
			},
		},
		{
			name: "getnameproof",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnameproof", "example")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNameProofCmd("example", nil)
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getnameproof","params":["example"],"id":1}`,
			unmarshalled: &hnsjson.GetNameProofCmd{Name: "example"},
		},
		{
			name: "getnameproof root",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnameproof", "example", zeroHash)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNameProofCmd("example",
					hnsjson.String(zeroHash))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnameproof","params":["example","` + zeroHash + `"],"id":1}`,
			unmarshalled: &hnsjson.GetNameProofCmd{
				Name: "example",
				Root: hnsjson.String(zeroHash),
			},
		},
		{
			name: "getnames",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnames")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNamesCmd()
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnames","params":[],"id":1}`,
			unmarshalled: &hnsjson.GetNamesCmd{
				Offset: hnsjson.Int(0),
				Limit:  hnsjson.Int(0),
			},
		},
		{
			name: "getnames paginated",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnames", 10, 25)
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNamesCmdWithPagination(
					hnsjson.Int(10), hnsjson.Int(25))
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnames","params":[10,25],"id":1}`,
			unmarshalled: &hnsjson.GetNamesCmd{
				Offset: hnsjson.Int(10),
				Limit:  hnsjson.Int(25),
			},
		},
		{
			name: "getnamesbyhash",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getnamesbyhash", []string{zeroHash})
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetNamesByHashCmd([]string{zeroHash})
			},
			marshalled: `{"jsonrpc":"1.0","method":"getnamesbyhash","params":[["` + zeroHash + `"]],"id":1}`,
			unmarshalled: &hnsjson.GetNamesByHashCmd{
				NameHashes: []string{zeroHash},
			},
		},
		{
			name: "getauctioninfo",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("getauctioninfo", "example")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewGetAuctionInfoCmd("example")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"getauctioninfo","params":["example"],"id":1}`,
			unmarshalled: &hnsjson.GetAuctionInfoCmd{Name: "example"},
		},
		{
			name: "createopen",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createopen", inputs, address,
					0.0, "example")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateOpenCmd(inputs, address, 0,
					"example", nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"createopen","params":[[` + inputJSON + `],"` + address + `",0,"example"],"id":1}`,
			unmarshalled: &hnsjson.CreateOpenCmd{
				Inputs:  inputs,
				Address: address,
				Amount:  0,
				Name:    "example",
			},
		},
		{
			name: "createbid",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createbid", inputs, address,
					1.25, "example", uint32(7), zeroHash,
					hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateBidCmd(inputs, address, 1.25,
					"example", 7, zeroHash, hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createbid","params":[[` + inputJSON + `],"` + address + `",1.25,"example",7,"` + zeroHash + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateBidCmd{
				Inputs:   inputs,
				Address:  address,
				Amount:   1.25,
				Name:     "example",
				Start:    7,
				Blind:    zeroHash,
				LockTime: hnsjson.Int64(500),
			},
		},
		{
			name: "createreveal",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createreveal", inputs, address,
					1.25, zeroHash, uint32(7), zeroHash,
					hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateRevealCmd(inputs, address, 1.25,
					zeroHash, 7, zeroHash, hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createreveal","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,"` + zeroHash + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateRevealCmd{
				Inputs:   inputs,
				Address:  address,
				Amount:   1.25,
				NameHash: zeroHash,
				Start:    7,
				Nonce:    zeroHash,
				LockTime: hnsjson.Int64(500),
			},
		},
		{
			name: "createredeem",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createredeem", inputs, address,
					1.25, zeroHash, uint32(7), hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateRedeemCmd(inputs, address, 1.25,
					zeroHash, 7, hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createredeem","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,500],"id":1}`,
			unmarshalled: &hnsjson.CreateRedeemCmd{
				Inputs:   inputs,
				Address:  address,
				Amount:   1.25,
				NameHash: zeroHash,
				Start:    7,
				LockTime: hnsjson.Int64(500),
			},
		},
		{
			name: "createregister",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createregister", inputs, address,
					1.25, zeroHash, uint32(7), "00",
					hnsjson.String(zeroHash), hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateRegisterCmd(inputs, address,
					1.25, zeroHash, 7, "00",
					hnsjson.String(zeroHash), hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createregister","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,"00","` + zeroHash + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateRegisterCmd{
				Inputs:      inputs,
				Address:     address,
				Amount:      1.25,
				NameHash:    zeroHash,
				Start:       7,
				Resource:    "00",
				RenewalHash: hnsjson.String(zeroHash),
				LockTime:    hnsjson.Int64(500),
			},
		},
		{
			name: "createupdate",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createupdate", inputs, address,
					1.25, zeroHash, uint32(7), "00",
					hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateUpdateCmd(inputs, address, 1.25,
					zeroHash, 7, "00", hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createupdate","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,"00",500],"id":1}`,
			unmarshalled: &hnsjson.CreateUpdateCmd{
				Inputs:   inputs,
				Address:  address,
				Amount:   1.25,
				NameHash: zeroHash,
				Start:    7,
				Resource: "00",
				LockTime: hnsjson.Int64(500),
			},
		},
		{
			name: "createrenew",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createrenew", inputs, address,
					1.25, zeroHash, uint32(7),
					hnsjson.String(zeroHash), hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateRenewCmd(inputs, address, 1.25,
					zeroHash, 7, hnsjson.String(zeroHash),
					hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createrenew","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,"` + zeroHash + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateRenewCmd{
				Inputs:      inputs,
				Address:     address,
				Amount:      1.25,
				NameHash:    zeroHash,
				Start:       7,
				RenewalHash: hnsjson.String(zeroHash),
				LockTime:    hnsjson.Int64(500),
			},
		},
		{
			name: "createtransfer",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createtransfer", inputs, address,
					1.25, zeroHash, uint32(7), transferAddress,
					hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateTransferCmd(inputs, address,
					1.25, zeroHash, 7, transferAddress,
					hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createtransfer","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,"` + transferAddress + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateTransferCmd{
				Inputs:          inputs,
				Address:         address,
				Amount:          1.25,
				NameHash:        zeroHash,
				Start:           7,
				TransferAddress: transferAddress,
				LockTime:        hnsjson.Int64(500),
			},
		},
		{
			name: "createfinalize",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createfinalize", inputs, address,
					1.25, "example", uint32(7), uint8(1),
					uint32(2), uint32(3), hnsjson.String(zeroHash),
					hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateFinalizeCmd(inputs, address,
					1.25, "example", 7, 1, 2, 3,
					hnsjson.String(zeroHash), hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createfinalize","params":[[` + inputJSON + `],"` + address + `",1.25,"example",7,1,2,3,"` + zeroHash + `",500],"id":1}`,
			unmarshalled: &hnsjson.CreateFinalizeCmd{
				Inputs:      inputs,
				Address:     address,
				Amount:      1.25,
				Name:        "example",
				Start:       7,
				Flags:       1,
				Claimed:     2,
				Renewals:    3,
				RenewalHash: hnsjson.String(zeroHash),
				LockTime:    hnsjson.Int64(500),
			},
		},
		{
			name: "createrevoke",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("createrevoke", inputs, address,
					1.25, zeroHash, uint32(7), hnsjson.Int64(500))
			},
			staticCmd: func() interface{} {
				return hnsjson.NewCreateRevokeCmd(inputs, address, 1.25,
					zeroHash, 7, hnsjson.Int64(500))
			},
			marshalled: `{"jsonrpc":"1.0","method":"createrevoke","params":[[` + inputJSON + `],"` + address + `",1.25,"` + zeroHash + `",7,500],"id":1}`,
			unmarshalled: &hnsjson.CreateRevokeCmd{
				Inputs:   inputs,
				Address:  address,
				Amount:   1.25,
				NameHash: zeroHash,
				Start:    7,
				LockTime: hnsjson.Int64(500),
			},
		},
		{
			name: "verifynameproof",
			newCmd: func() (interface{}, error) {
				return hnsjson.NewCmd("verifynameproof", zeroHash,
					zeroHash, "00")
			},
			staticCmd: func() interface{} {
				return hnsjson.NewVerifyNameProofCmd(zeroHash,
					zeroHash, "00")
			},
			marshalled: `{"jsonrpc":"1.0","method":"verifynameproof","params":["` + zeroHash + `","` + zeroHash + `","00"],"id":1}`,
			unmarshalled: &hnsjson.VerifyNameProofCmd{
				Root:     zeroHash,
				NameHash: zeroHash,
				Proof:    "00",
			},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		cmd, err := test.newCmd()
		if err != nil {
			t.Errorf("Test #%d (%s) unexpected NewCmd error: %v",
				i, test.name, err)
			continue
		}
		if !reflect.DeepEqual(cmd, test.staticCmd()) {
			t.Errorf("Test #%d (%s) unexpected NewCmd result - got %s, want %s",
				i, test.name, fmt.Sprintf("(%T) %+[1]v", cmd),
				fmt.Sprintf("(%T) %+[1]v", test.staticCmd()))
			continue
		}

		marshalled, err := hnsjson.MarshalCmd("1.0", testID, cmd)
		if err != nil {
			t.Errorf("Test #%d (%s) unexpected MarshalCmd error: %v",
				i, test.name, err)
			continue
		}
		if string(marshalled) != test.marshalled {
			t.Errorf("Test #%d (%s) unexpected marshalled command - got %s, want %s",
				i, test.name, marshalled, test.marshalled)
			continue
		}

		var request hnsjson.Request
		if err := json.Unmarshal(marshalled, &request); err != nil {
			t.Errorf("Test #%d (%s) unexpected request unmarshal error: %v",
				i, test.name, err)
			continue
		}
		cmd, err = hnsjson.UnmarshalCmd(&request)
		if err != nil {
			t.Errorf("Test #%d (%s) unexpected UnmarshalCmd error: %v",
				i, test.name, err)
			continue
		}
		if !reflect.DeepEqual(cmd, test.unmarshalled) {
			t.Errorf("Test #%d (%s) unexpected unmarshalled command - got %s, want %s",
				i, test.name, fmt.Sprintf("(%T) %+[1]v", cmd),
				fmt.Sprintf("(%T) %+[1]v", test.unmarshalled))
		}
	}
}
