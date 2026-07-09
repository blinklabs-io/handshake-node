package rpcclient

import (
	"encoding/json"
	"reflect"
	"testing"

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
