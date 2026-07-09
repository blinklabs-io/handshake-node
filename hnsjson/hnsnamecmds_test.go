// Copyright (c) 2026 The blinklabs-io developers
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
