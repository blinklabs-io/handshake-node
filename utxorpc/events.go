// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"sync"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
)

// Event buffer depths. A subscriber that fails to drain within these
// bounds is terminated rather than silently skipping events, since a
// gap in a chain-following stream is indistinguishable to the client
// from a chain that stopped advancing.
const (
	blockEventBuffer   = 256
	mempoolEventBuffer = 1024
)

// chainAction distinguishes a block being added to the main chain from
// one being rolled back off it.
type chainAction int

const (
	chainApply chainAction = iota
	chainUndo
)

// blockEvent carries a block already reduced to immutable values.
// hnsutil.Block caches its serialization and transaction list lazily
// and without locking, so a single instance shared across subscriber
// goroutines would race; the publisher does that work once instead.
type blockEvent struct {
	action chainAction
	raw    []byte
	hash   chainhash.Hash
	prev   chainhash.Hash
	height int32
}

// mempoolEvent carries a transaction reduced to immutable values, for
// the same reason as blockEvent.
type mempoolEvent struct {
	stage submitpb.Stage
	ref   chainhash.Hash
	raw   []byte
}

// subscription delivers events of type T to one streaming RPC handler.
// lagged is closed instead of events being dropped when the handler
// falls behind the buffer.
type subscription[T any] struct {
	events chan T
	lagged chan struct{}

	once sync.Once
}

func newSubscription[T any](buffer int) *subscription[T] {
	return &subscription[T]{
		events: make(chan T, buffer),
		lagged: make(chan struct{}),
	}
}

// publish delivers ev, or marks the subscription lagged if its buffer
// is full. Returns false once the subscription has lagged.
func (s *subscription[T]) publish(ev T) bool {
	select {
	case <-s.lagged:
		return false
	default:
	}
	select {
	case s.events <- ev:
		return true
	default:
		s.once.Do(func() { close(s.lagged) })
		return false
	}
}

// broker fans node events out to the streaming RPC handlers. Its
// publish methods are called from the node's chain and mempool
// notification paths, so they must never block.
type broker struct {
	mtx         sync.Mutex
	blockSubs   map[*subscription[blockEvent]]struct{}
	mempoolSubs map[*subscription[mempoolEvent]]struct{}
}

func newBroker() *broker {
	return &broker{
		blockSubs:   make(map[*subscription[blockEvent]]struct{}),
		mempoolSubs: make(map[*subscription[mempoolEvent]]struct{}),
	}
}

func (b *broker) subscribeBlocks() *subscription[blockEvent] {
	sub := newSubscription[blockEvent](blockEventBuffer)
	b.mtx.Lock()
	b.blockSubs[sub] = struct{}{}
	b.mtx.Unlock()
	return sub
}

func (b *broker) unsubscribeBlocks(sub *subscription[blockEvent]) {
	b.mtx.Lock()
	delete(b.blockSubs, sub)
	b.mtx.Unlock()
}

func (b *broker) subscribeMempool() *subscription[mempoolEvent] {
	sub := newSubscription[mempoolEvent](mempoolEventBuffer)
	b.mtx.Lock()
	b.mempoolSubs[sub] = struct{}{}
	b.mtx.Unlock()
	return sub
}

func (b *broker) unsubscribeMempool(sub *subscription[mempoolEvent]) {
	b.mtx.Lock()
	delete(b.mempoolSubs, sub)
	b.mtx.Unlock()
}

func (b *broker) publishBlock(ev blockEvent) {
	b.mtx.Lock()
	subs := make([]*subscription[blockEvent], 0, len(b.blockSubs))
	for sub := range b.blockSubs {
		subs = append(subs, sub)
	}
	b.mtx.Unlock()

	for _, sub := range subs {
		sub.publish(ev)
	}
}

func (b *broker) publishMempoolTx(ev mempoolEvent) {
	b.mtx.Lock()
	subs := make([]*subscription[mempoolEvent], 0, len(b.mempoolSubs))
	for sub := range b.mempoolSubs {
		subs = append(subs, sub)
	}
	b.mtx.Unlock()

	for _, sub := range subs {
		sub.publish(ev)
	}
}

// blockSubscriberCount reports the number of active block subscribers.
func (b *broker) blockSubscriberCount() int {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return len(b.blockSubs)
}

// mempoolSubscriberCount reports the number of active mempool
// subscribers.
func (b *broker) mempoolSubscriberCount() int {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return len(b.mempoolSubs)
}
