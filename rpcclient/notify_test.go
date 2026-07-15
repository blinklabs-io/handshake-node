// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcclient

import (
	"container/list"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsjson"
)

func TestParseNameUpdatedNtfnParams(t *testing.T) {
	t.Parallel()

	rawParams := []string{
		`"example"`,
		`"0000000000000000000000000000000000000000000000000000000000000001"`,
		`"OPEN"`,
		`2`,
		`"123"`,
		`0`,
		`{"height":100000,"hash":"456","index":1,"time":12345678}`,
	}
	params := make([]json.RawMessage, 0, len(rawParams))
	for _, raw := range rawParams {
		params = append(params, json.RawMessage(raw))
	}

	ntfn, err := parseNameUpdatedNtfnParams(params)
	if err != nil {
		t.Fatalf("parseNameUpdatedNtfnParams unexpected error: %v", err)
	}

	want := &hnsjson.NameUpdatedNtfn{
		Name:         "example",
		NameHash:     "0000000000000000000000000000000000000000000000000000000000000001",
		Covenant:     "OPEN",
		CovenantType: 2,
		TxID:         "123",
		Vout:         0,
		Block: &hnsjson.BlockDetails{
			Height: 100000,
			Hash:   "456",
			Index:  1,
			Time:   12345678,
		},
	}
	if !reflect.DeepEqual(ntfn, want) {
		t.Fatalf("unexpected notification: got %+v, want %+v", ntfn, want)
	}

	ntfn, err = parseNameUpdatedNtfnParams(params[:6])
	if err != nil {
		t.Fatalf("parseNameUpdatedNtfnParams mempool event error: %v", err)
	}
	if ntfn.Block != nil {
		t.Fatalf("mempool event block details: got %+v, want nil", ntfn.Block)
	}
}

func TestHashStringUsesHandshakeByteOrder(t *testing.T) {
	t.Parallel()

	var hash chainhash.Hash
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	want := hex.EncodeToString(hash[:])

	if got := hash.String(); got != want {
		t.Fatalf("Hash.String = %q, want native-order %q", got, want)
	}
}

func TestNotificationRegistrationTrackedOnlyAfterSuccess(t *testing.T) {
	t.Parallel()

	client := &Client{
		requestMap:   make(map[uint64]*list.Element),
		requestList:  list.New(),
		ntfnHandlers: &NotificationHandlers{},
		ntfnState:    newNotificationState(),
		shutdown:     make(chan struct{}),
	}

	badNames := []string{"bad"}
	badResponse := make(chan *Response, 1)
	err := client.addRequest(&jsonRequest{
		id:           1,
		cmd:          hnsjson.NewNotifyNamesCmd(&badNames, nil),
		responseChan: badResponse,
	})
	if err != nil {
		t.Fatalf("addRequest failed: %v", err)
	}
	client.handleMessage([]byte(
		`{"jsonrpc":"1.0","result":null,"error":{"code":-8,"message":"bad filter"},"id":1}`))
	if resp := <-badResponse; resp.err == nil {
		t.Fatalf("failed registration returned nil error")
	}
	if _, ok := client.ntfnState.notifyNames["bad"]; ok {
		t.Fatalf("failed registration was tracked")
	}

	goodNames := []string{"good"}
	goodResponse := make(chan *Response, 1)
	err = client.addRequest(&jsonRequest{
		id:           2,
		cmd:          hnsjson.NewNotifyNamesCmd(&goodNames, nil),
		responseChan: goodResponse,
	})
	if err != nil {
		t.Fatalf("addRequest failed: %v", err)
	}
	client.handleMessage([]byte(
		`{"jsonrpc":"1.0","result":null,"error":null,"id":2}`))
	if resp := <-goodResponse; resp.err != nil {
		t.Fatalf("successful registration returned error: %v", resp.err)
	}
	if _, ok := client.ntfnState.notifyNames["good"]; !ok {
		t.Fatalf("successful registration was not tracked")
	}
}
