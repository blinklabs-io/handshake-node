// Copyright (c) 2014-2017 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
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
)

// TestChainSvrWsCmds tests all of the chain server websocket-specific commands
// marshal and unmarshal into valid results include handling of optional fields
// being omitted in the marshalled command, while optional fields with defaults
// have the default assigned on unmarshalled commands.
func TestChainSvrWsCmds(t *testing.T) {
	t.Parallel()

	testID := int(1)
	tests := []struct {
		name         string
		newCmd       func() (any, error)
		staticCmd    func() any
		marshalled   string
		unmarshalled any
	}{
		{
			name: "authenticate",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("authenticate", "user", "pass")
			},
			staticCmd: func() any {
				return hnsjson.NewAuthenticateCmd("user", "pass")
			},
			marshalled:   `{"jsonrpc":"1.0","method":"authenticate","params":["user","pass"],"id":1}`,
			unmarshalled: &hnsjson.AuthenticateCmd{Username: "user", Passphrase: "pass"},
		},
		{
			name: "notifyblocks",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifyblocks")
			},
			staticCmd: func() any {
				return hnsjson.NewNotifyBlocksCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"notifyblocks","params":[],"id":1}`,
			unmarshalled: &hnsjson.NotifyBlocksCmd{},
		},
		{
			name: "stopnotifyblocks",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("stopnotifyblocks")
			},
			staticCmd: func() any {
				return hnsjson.NewStopNotifyBlocksCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"stopnotifyblocks","params":[],"id":1}`,
			unmarshalled: &hnsjson.StopNotifyBlocksCmd{},
		},
		{
			name: "notifynames",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifynames")
			},
			staticCmd: func() any {
				return hnsjson.NewNotifyNamesCmd(nil, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifynames","params":[],"id":1}`,
			unmarshalled: &hnsjson.NotifyNamesCmd{
				Names:      &[]string{},
				NameHashes: &[]string{},
			},
		},
		{
			name: "notifynames optional",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifynames", `["example"]`, `["0000000000000000000000000000000000000000000000000000000000000001"]`)
			},
			staticCmd: func() any {
				names := []string{"example"}
				nameHashes := []string{"0000000000000000000000000000000000000000000000000000000000000001"}
				return hnsjson.NewNotifyNamesCmd(&names, &nameHashes)
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifynames","params":[["example"],["0000000000000000000000000000000000000000000000000000000000000001"]],"id":1}`,
			unmarshalled: &hnsjson.NotifyNamesCmd{
				Names:      &[]string{"example"},
				NameHashes: &[]string{"0000000000000000000000000000000000000000000000000000000000000001"},
			},
		},
		{
			name: "stopnotifynames",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("stopnotifynames")
			},
			staticCmd: func() any {
				return hnsjson.NewStopNotifyNamesCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"stopnotifynames","params":[],"id":1}`,
			unmarshalled: &hnsjson.StopNotifyNamesCmd{},
		},
		{
			name: "notifynewtransactions",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifynewtransactions")
			},
			staticCmd: func() any {
				return hnsjson.NewNotifyNewTransactionsCmd(nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifynewtransactions","params":[],"id":1}`,
			unmarshalled: &hnsjson.NotifyNewTransactionsCmd{
				Verbose: hnsjson.Bool(false),
			},
		},
		{
			name: "notifynewtransactions optional",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifynewtransactions", true)
			},
			staticCmd: func() any {
				return hnsjson.NewNotifyNewTransactionsCmd(hnsjson.Bool(true))
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifynewtransactions","params":[true],"id":1}`,
			unmarshalled: &hnsjson.NotifyNewTransactionsCmd{
				Verbose: hnsjson.Bool(true),
			},
		},
		{
			name: "stopnotifynewtransactions",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("stopnotifynewtransactions")
			},
			staticCmd: func() any {
				return hnsjson.NewStopNotifyNewTransactionsCmd()
			},
			marshalled:   `{"jsonrpc":"1.0","method":"stopnotifynewtransactions","params":[],"id":1}`,
			unmarshalled: &hnsjson.StopNotifyNewTransactionsCmd{},
		},
		{
			name: "notifyreceived",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifyreceived", []string{"1Address"})
			},
			staticCmd: func() any {
				return hnsjson.NewNotifyReceivedCmd([]string{"1Address"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifyreceived","params":[["1Address"]],"id":1}`,
			unmarshalled: &hnsjson.NotifyReceivedCmd{
				Addresses: []string{"1Address"},
			},
		},
		{
			name: "stopnotifyreceived",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("stopnotifyreceived", []string{"1Address"})
			},
			staticCmd: func() any {
				return hnsjson.NewStopNotifyReceivedCmd([]string{"1Address"})
			},
			marshalled: `{"jsonrpc":"1.0","method":"stopnotifyreceived","params":[["1Address"]],"id":1}`,
			unmarshalled: &hnsjson.StopNotifyReceivedCmd{
				Addresses: []string{"1Address"},
			},
		},
		{
			name: "notifyspent",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("notifyspent", `[{"hash":"123","index":0}]`)
			},
			staticCmd: func() any {
				ops := []hnsjson.OutPoint{{Hash: "123", Index: 0}}
				return hnsjson.NewNotifySpentCmd(ops)
			},
			marshalled: `{"jsonrpc":"1.0","method":"notifyspent","params":[[{"hash":"123","index":0}]],"id":1}`,
			unmarshalled: &hnsjson.NotifySpentCmd{
				OutPoints: []hnsjson.OutPoint{{Hash: "123", Index: 0}},
			},
		},
		{
			name: "stopnotifyspent",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("stopnotifyspent", `[{"hash":"123","index":0}]`)
			},
			staticCmd: func() any {
				ops := []hnsjson.OutPoint{{Hash: "123", Index: 0}}
				return hnsjson.NewStopNotifySpentCmd(ops)
			},
			marshalled: `{"jsonrpc":"1.0","method":"stopnotifyspent","params":[[{"hash":"123","index":0}]],"id":1}`,
			unmarshalled: &hnsjson.StopNotifySpentCmd{
				OutPoints: []hnsjson.OutPoint{{Hash: "123", Index: 0}},
			},
		},
		{
			name: "rescan",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("rescan", "123", `["1Address"]`, `[{"hash":"0000000000000000000000000000000000000000000000000000000000000123","index":0}]`)
			},
			staticCmd: func() any {
				addrs := []string{"1Address"}
				ops := []hnsjson.OutPoint{{
					Hash:  "0000000000000000000000000000000000000000000000000000000000000123",
					Index: 0,
				}}
				return hnsjson.NewRescanCmd("123", addrs, ops, nil)
			},
			marshalled: `{"jsonrpc":"1.0","method":"rescan","params":["123",["1Address"],[{"hash":"0000000000000000000000000000000000000000000000000000000000000123","index":0}]],"id":1}`,
			unmarshalled: &hnsjson.RescanCmd{
				BeginBlock: "123",
				Addresses:  []string{"1Address"},
				OutPoints:  []hnsjson.OutPoint{{Hash: "0000000000000000000000000000000000000000000000000000000000000123", Index: 0}},
				EndBlock:   nil,
			},
		},
		{
			name: "rescan optional",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("rescan", "123", `["1Address"]`, `[{"hash":"123","index":0}]`, "456")
			},
			staticCmd: func() any {
				addrs := []string{"1Address"}
				ops := []hnsjson.OutPoint{{Hash: "123", Index: 0}}
				return hnsjson.NewRescanCmd("123", addrs, ops, hnsjson.String("456"))
			},
			marshalled: `{"jsonrpc":"1.0","method":"rescan","params":["123",["1Address"],[{"hash":"123","index":0}],"456"],"id":1}`,
			unmarshalled: &hnsjson.RescanCmd{
				BeginBlock: "123",
				Addresses:  []string{"1Address"},
				OutPoints:  []hnsjson.OutPoint{{Hash: "123", Index: 0}},
				EndBlock:   hnsjson.String("456"),
			},
		},
		{
			name: "loadtxfilter",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("loadtxfilter", false, `["1Address"]`, `[{"hash":"0000000000000000000000000000000000000000000000000000000000000123","index":0}]`)
			},
			staticCmd: func() any {
				addrs := []string{"1Address"}
				ops := []hnsjson.OutPoint{{
					Hash:  "0000000000000000000000000000000000000000000000000000000000000123",
					Index: 0,
				}}
				return hnsjson.NewLoadTxFilterCmd(false, addrs, ops)
			},
			marshalled: `{"jsonrpc":"1.0","method":"loadtxfilter","params":[false,["1Address"],[{"hash":"0000000000000000000000000000000000000000000000000000000000000123","index":0}]],"id":1}`,
			unmarshalled: &hnsjson.LoadTxFilterCmd{
				Reload:    false,
				Addresses: []string{"1Address"},
				OutPoints: []hnsjson.OutPoint{{Hash: "0000000000000000000000000000000000000000000000000000000000000123", Index: 0}},
			},
		},
		{
			name: "rescanblocks",
			newCmd: func() (any, error) {
				return hnsjson.NewCmd("rescanblocks", `["0000000000000000000000000000000000000000000000000000000000000123"]`)
			},
			staticCmd: func() any {
				blockhashes := []string{"0000000000000000000000000000000000000000000000000000000000000123"}
				return hnsjson.NewRescanBlocksCmd(blockhashes)
			},
			marshalled: `{"jsonrpc":"1.0","method":"rescanblocks","params":[["0000000000000000000000000000000000000000000000000000000000000123"]],"id":1}`,
			unmarshalled: &hnsjson.RescanBlocksCmd{
				BlockHashes: []string{"0000000000000000000000000000000000000000000000000000000000000123"},
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
