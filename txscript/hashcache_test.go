// Copyright (c) 2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"errors"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/davecgh/go-spew/spew"
)

func init() {
	rand.Seed(time.Now().Unix())
}

func TestHnsHashRawPanicsOnSerializationError(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatalf("expected hnsHashRaw to panic")
		}
	}()

	hnsHashRaw(func(io.Writer) error {
		return errors.New("serialize failed")
	})
}

// genTestTx creates a random transaction for uses within test cases.
func genTestTx() (*wire.MsgTx, *MultiPrevOutFetcher, error) {
	tx := wire.NewMsgTx(2)
	tx.Version = uint32(rand.Int31())

	prevOuts := NewMultiPrevOutFetcher(nil)

	numTxins := 1 + rand.Intn(11)
	for i := 0; i < numTxins; i++ {
		randTxIn := wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Index: uint32(rand.Int31()),
			},
			Sequence: uint32(rand.Int31()),
		}
		_, err := rand.Read(randTxIn.PreviousOutPoint.Hash[:])
		if err != nil {
			return nil, nil, err
		}

		tx.TxIn = append(tx.TxIn, &randTxIn)

		prevOuts.AddPrevOut(
			randTxIn.PreviousOutPoint, &wire.TxOut{},
		)
	}

	numTxouts := 1 + rand.Intn(11)
	for i := 0; i < numTxouts; i++ {
		randHash := make([]byte, 20)
		if _, err := rand.Read(randHash); err != nil {
			return nil, nil, err
		}
		randTxOut := wire.TxOut{
			Value:   rand.Int63(),
			Address: wire.Address{Version: 0, Hash: randHash},
		}
		tx.TxOut = append(tx.TxOut, &randTxOut)
	}

	return tx, prevOuts, nil
}

// TestHashCacheAddContainsHashes tests that after items have been added to the
// hash cache, the ContainsHashes method returns true for all the items
// inserted.  Conversely, ContainsHashes should return false for any items
// _not_ in the hash cache.
func TestHashCacheAddContainsHashes(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	var (
		err          error
		randPrevOuts *MultiPrevOutFetcher
	)
	prevOuts := NewMultiPrevOutFetcher(nil)

	// First, we'll generate 10 random transactions for use within our
	// tests.
	const numTxns = 10
	txns := make([]*wire.MsgTx, numTxns)
	for i := 0; i < numTxns; i++ {
		txns[i], randPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}

		prevOuts.Merge(randPrevOuts)
	}

	// With the transactions generated, we'll add each of them to the hash
	// cache.
	for _, tx := range txns {
		cache.AddSigHashes(tx, prevOuts)
	}

	// Next, we'll ensure that each of the transactions inserted into the
	// cache are properly located by the ContainsHashes method.
	for _, tx := range txns {
		txid := tx.TxHash()
		if ok := cache.ContainsHashes(&txid); !ok {
			t.Fatalf("txid %v not found in cache but should be: ",
				txid)
		}
	}

	randTx, _, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate tx: %v", err)
	}

	// Finally, we'll assert that a transaction that wasn't added to the
	// cache won't be reported as being present by the ContainsHashes
	// method.
	randTxid := randTx.TxHash()
	if ok := cache.ContainsHashes(&randTxid); ok {
		t.Fatalf("txid %v wasn't inserted into cache but was found",
			randTxid)
	}
}

// TestHashCacheAddGet tests that the sighashes for a particular transaction
// are properly retrieved by the GetSigHashes function.
func TestHashCacheAddGet(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	// To start, we'll generate a random transaction and compute the set of
	// sighashes for the transaction.
	randTx, prevOuts, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate tx: %v", err)
	}
	sigHashes := NewTxSigHashes(randTx, prevOuts)

	// Next, add the transaction to the hash cache.
	cache.AddSigHashes(randTx, prevOuts)

	// The transaction inserted into the cache above should be found.
	txid := randTx.TxHash()
	cacheHashes, ok := cache.GetSigHashes(&txid)
	if !ok {
		t.Fatalf("tx %v wasn't found in cache", txid)
	}

	// Finally, the sighashes retrieved should exactly match the sighash
	// originally inserted into the cache.
	if *sigHashes != *cacheHashes {
		t.Fatalf("sighashes don't match: expected %v, got %v",
			spew.Sdump(sigHashes), spew.Sdump(cacheHashes))
	}
}

// TestHashCachePurge tests that items are able to be properly removed from the
// hash cache.
func TestHashCachePurge(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	var (
		err          error
		randPrevOuts *MultiPrevOutFetcher
	)
	prevOuts := NewMultiPrevOutFetcher(nil)

	// First we'll start by inserting numTxns transactions into the hash cache.
	const numTxns = 10
	txns := make([]*wire.MsgTx, numTxns)
	for i := 0; i < numTxns; i++ {
		txns[i], randPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}

		prevOuts.Merge(randPrevOuts)
	}
	for _, tx := range txns {
		cache.AddSigHashes(tx, prevOuts)
	}

	// Once all the transactions have been inserted, we'll purge them from
	// the hash cache.
	for _, tx := range txns {
		txid := tx.TxHash()
		cache.PurgeSigHashes(&txid)
	}

	// At this point, none of the transactions inserted into the hash cache
	// should be found within the cache.
	for _, tx := range txns {
		txid := tx.TxHash()
		if ok := cache.ContainsHashes(&txid); ok {
			t.Fatalf("tx %v found in cache but should have "+
				"been purged: ", txid)
		}
	}
}

// TestHashCacheBoundedFIFO ensures the cache never exceeds its configured
// capacity and evicts entries in deterministic insertion order.
func TestHashCacheBoundedFIFO(t *testing.T) {
	t.Parallel()

	const cacheSize = 2
	cache := NewHashCache(cacheSize)
	prevOuts := NewMultiPrevOutFetcher(nil)
	txns := make([]*wire.MsgTx, cacheSize+1)
	for i := range txns {
		var txPrevOuts *MultiPrevOutFetcher
		var err error
		txns[i], txPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}
		prevOuts.Merge(txPrevOuts)
	}

	cache.AddSigHashes(txns[0], prevOuts)
	cache.AddSigHashes(txns[1], prevOuts)

	// Updating an existing entry must not refresh its insertion position.
	cache.AddSigHashes(txns[0], prevOuts)
	cache.AddSigHashes(txns[2], prevOuts)

	firstTxID := txns[0].TxHash()
	if cache.ContainsHashes(&firstTxID) {
		t.Fatalf("oldest tx %v was not evicted", firstTxID)
	}
	for _, tx := range txns[1:] {
		txid := tx.TxHash()
		if !cache.ContainsHashes(&txid) {
			t.Fatalf("newer tx %v was unexpectedly evicted", txid)
		}
	}

	cache.RLock()
	numEntries := len(cache.sigHashes)
	cache.RUnlock()
	if numEntries != cacheSize {
		t.Fatalf("cache size = %d, want %d", numEntries, cacheSize)
	}
}

// TestHashCacheGetOrAddEviction ensures atomic acquisition returns usable
// sighashes even after a later insertion evicts them from the cache.
func TestHashCacheGetOrAddEviction(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(1)
	prevOuts := NewMultiPrevOutFetcher(nil)
	txns := make([]*wire.MsgTx, 2)
	for i := range txns {
		var txPrevOuts *MultiPrevOutFetcher
		var err error
		txns[i], txPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}
		prevOuts.Merge(txPrevOuts)
	}

	wantFirst := NewTxSigHashes(txns[0], prevOuts)
	gotFirst := cache.GetOrAddSigHashes(txns[0], prevOuts)
	if gotFirst == nil || *gotFirst != *wantFirst {
		t.Fatalf("first sighashes mismatch: want %v, got %v",
			spew.Sdump(wantFirst), spew.Sdump(gotFirst))
	}
	if gotAgain := cache.GetOrAddSigHashes(txns[0], prevOuts); gotAgain != gotFirst {
		t.Fatal("cache hit did not return the cached sighashes")
	}

	gotSecond := cache.GetOrAddSigHashes(txns[1], prevOuts)
	if gotSecond == nil {
		t.Fatal("second atomic acquisition returned nil")
	}
	firstTxID := txns[0].TxHash()
	if cache.ContainsHashes(&firstTxID) {
		t.Fatalf("evicted tx %v remains in cache", firstTxID)
	}
	if *gotFirst != *wantFirst {
		t.Fatal("eviction changed previously acquired sighashes")
	}
}

type gatedPrevOutputFetcher struct {
	PrevOutputFetcher
	once    sync.Once
	entered chan<- struct{}
	release <-chan struct{}
}

func (f *gatedPrevOutputFetcher) FetchPrevOutput(
	outpoint wire.OutPoint) *wire.TxOut {

	f.once.Do(func() {
		f.entered <- struct{}{}
		<-f.release
	})
	return f.PrevOutputFetcher.FetchPrevOutput(outpoint)
}

// TestHashCacheConcurrentSameTx ensures concurrent misses compute outside the
// global cache lock and converge on the retained value during insertion.
func TestHashCacheConcurrentSameTx(t *testing.T) {
	t.Parallel()

	const numCallers = 16
	cache := NewHashCache(1)
	tx, prevOuts, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate test tx: %v", err)
	}
	want := NewTxSigHashes(tx, prevOuts)

	start := make(chan struct{})
	entered := make(chan struct{}, numCallers)
	release := make(chan struct{})
	results := make([]*TxSigHashes, numCallers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			fetcher := &gatedPrevOutputFetcher{
				PrevOutputFetcher: prevOuts,
				entered:           entered,
				release:           release,
			}
			results[i] = cache.GetOrAddSigHashes(tx, fetcher)
		}(i)
	}
	close(start)

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for i := 0; i < numCallers; i++ {
		select {
		case <-entered:
		case <-timer.C:
			close(release)
			wg.Wait()
			t.Fatalf("only %d of %d callers computed outside the cache lock",
				i, numCallers)
		}
	}
	close(release)
	wg.Wait()

	txid := tx.TxHash()
	retained, ok := cache.GetSigHashes(&txid)
	if !ok || retained == nil {
		t.Fatal("concurrent insertion did not retain sighashes")
	}
	if *retained != *want {
		t.Fatal("concurrent insertion retained invalid sighashes")
	}
	for i, result := range results {
		if result != retained {
			t.Fatalf("caller %d did not receive the retained value", i)
		}
	}
}

// TestHashCacheZeroCapacity ensures a zero-sized cache disables storage while
// atomic acquisition still returns the computed sighashes.
func TestHashCacheZeroCapacity(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(0)
	tx, prevOuts, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate test tx: %v", err)
	}
	cache.AddSigHashes(tx, prevOuts)
	want := NewTxSigHashes(tx, prevOuts)
	got := cache.GetOrAddSigHashes(tx, prevOuts)
	if got == nil || *got != *want {
		t.Fatalf("zero-capacity acquisition mismatch: want %v, got %v",
			spew.Sdump(want), spew.Sdump(got))
	}

	txid := tx.TxHash()
	if cache.ContainsHashes(&txid) {
		t.Fatalf("zero-capacity cache retained tx %v", txid)
	}
	if _, ok := cache.GetSigHashes(&txid); ok {
		t.Fatalf("zero-capacity cache returned tx %v", txid)
	}
}

// TestHashCacheConcurrentBound exercises concurrent adds, lookups, and purges
// while asserting the cache and eviction-list invariants remain bounded.
func TestHashCacheConcurrentBound(t *testing.T) {
	t.Parallel()

	const (
		cacheSize  = 7
		numTxns    = 32
		iterations = 25
	)
	cache := NewHashCache(cacheSize)
	prevOuts := NewMultiPrevOutFetcher(nil)
	txns := make([]*wire.MsgTx, numTxns)
	for i := range txns {
		var txPrevOuts *MultiPrevOutFetcher
		var err error
		txns[i], txPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}
		prevOuts.Merge(txPrevOuts)
	}
	wantHashes := make([]TxSigHashes, numTxns)
	for i, tx := range txns {
		wantHashes[i] = *NewTxSigHashes(tx, prevOuts)
	}

	start := make(chan struct{})
	badResult := make(chan int, numTxns)
	var wg sync.WaitGroup
	for i, tx := range txns {
		wg.Add(1)
		go func(i int, tx *wire.MsgTx) {
			defer wg.Done()
			<-start
			txid := tx.TxHash()
			for j := 0; j < iterations; j++ {
				sigHashes := cache.GetOrAddSigHashes(tx, prevOuts)
				if sigHashes == nil || *sigHashes != wantHashes[i] {
					badResult <- i
					return
				}
				cache.ContainsHashes(&txid)
				cache.GetSigHashes(&txid)
				if (i+j)%11 == 0 {
					cache.PurgeSigHashes(&txid)
				}
			}
		}(i, tx)
	}
	close(start)
	wg.Wait()
	select {
	case i := <-badResult:
		t.Fatalf("atomic acquisition returned invalid sighashes for tx %d", i)
	default:
	}

	cache.RLock()
	defer cache.RUnlock()
	if len(cache.sigHashes) > cacheSize {
		t.Fatalf("cache size = %d, exceeds maximum %d",
			len(cache.sigHashes), cacheSize)
	}

	seen := make(map[*hashCacheEntry]struct{}, len(cache.sigHashes))
	var previous *hashCacheEntry
	numEntries := 0
	for entry := cache.oldest; entry != nil; entry = entry.next {
		if entry.prev != previous {
			t.Fatalf("entry %v has inconsistent previous link", entry.txid)
		}
		if _, ok := seen[entry]; ok {
			t.Fatalf("entry %v appears more than once in eviction list",
				entry.txid)
		}
		seen[entry] = struct{}{}
		if cachedEntry := cache.sigHashes[entry.txid]; cachedEntry != entry {
			t.Fatalf("entry %v does not match cache map", entry.txid)
		}
		previous = entry
		numEntries++
	}
	if previous != cache.newest {
		t.Fatal("newest entry does not terminate eviction list")
	}
	if numEntries != len(cache.sigHashes) {
		t.Fatalf("eviction list size = %d, map size = %d", numEntries,
			len(cache.sigHashes))
	}
}
