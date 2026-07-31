// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blinklabs-io/handshake-node/database/internal/treap"
)

type batchReplayRecorder struct {
	values  map[string][]byte
	deleted map[string]struct{}
}

func (r *batchReplayRecorder) Put(key, value []byte) {
	r.values[string(key)] = append([]byte(nil), value...)
}

func (r *batchReplayRecorder) Delete(key []byte) {
	r.deleted[string(key)] = struct{}{}
}

func TestTreapsToBatchPreallocatesEncodedData(t *testing.T) {
	const (
		putCount    = 20_000
		deleteCount = 10_000
	)

	putPairs := make([]treap.KVPair, 0, putCount)
	deletePairs := make([]treap.KVPair, 0, deleteCount)
	wantValues := make(map[string][]byte, putCount)
	wantDeleted := make(map[string]struct{}, deleteCount)
	for i := range putCount {
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(i))
		// Cross the one-byte varint boundary used by the batch format.
		value := bytes.Repeat([]byte{byte(i)}, 32+i%256)
		putPairs = append(putPairs, treap.KVPair{Key: key, Value: value})
		wantValues[string(key)] = value
	}
	for i := range deleteCount {
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, uint64(putCount+i))
		deletePairs = append(deletePairs, treap.KVPair{Key: key})
		wantDeleted[string(key)] = struct{}{}
	}

	pendingKeys := treap.NewImmutable().Put(putPairs...)
	pendingRemove := treap.NewImmutable().Put(deletePairs...)
	batch, err := treapsToBatch(pendingKeys, pendingRemove)
	if err != nil {
		t.Fatalf("build batch: %v", err)
	}

	if got, want := batch.Len(), putCount+deleteCount; got != want {
		t.Fatalf("batch record count: got %d, want %d", got, want)
	}
	encoded := batch.Dump()
	if cap(encoded) != len(encoded) {
		t.Fatalf("batch data was not exactly allocated: len=%d cap=%d",
			len(encoded), cap(encoded))
	}

	got := &batchReplayRecorder{
		values:  make(map[string][]byte, putCount),
		deleted: make(map[string]struct{}, deleteCount),
	}
	if err := batch.Replay(got); err != nil {
		t.Fatalf("replay batch: %v", err)
	}
	if len(got.values) != len(wantValues) {
		t.Fatalf("replayed values: got %d, want %d",
			len(got.values), len(wantValues))
	}
	for key, want := range wantValues {
		if value := got.values[key]; !bytes.Equal(value, want) {
			t.Fatalf("replayed value for %x does not match", key)
		}
	}
	if len(got.deleted) != len(wantDeleted) {
		t.Fatalf("replayed deletes: got %d, want %d",
			len(got.deleted), len(wantDeleted))
	}
	for key := range wantDeleted {
		if _, ok := got.deleted[key]; !ok {
			t.Fatalf("missing replayed delete for %x", key)
		}
	}
}
