// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	querypb "github.com/utxorpc/go-codegen/utxorpc/v1beta/query"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/query/queryconnect"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/submit/submitconnect"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/sync/syncconnect"
)

// Request limits. Every batch and page size a client can ask for is
// capped so a single request cannot pin an unbounded amount of memory.
const (
	// DefaultMaxBlockRefs caps the block references accepted by
	// FetchBlock.
	DefaultMaxBlockRefs = 100

	// DefaultMaxUtxoKeys caps the outputs accepted by ReadUtxos.
	DefaultMaxUtxoKeys = 1000

	// DefaultMaxHistoryItems caps a DumpHistory page, and is also the
	// page size used when a request omits max_items.
	DefaultMaxHistoryItems = 1000

	// compressMinBytes is the response size above which connect
	// compresses. Below it, framing overhead outweighs the saving.
	compressMinBytes = 1024
)

// Timeouts. Streaming procedures (FollowTip, WatchMempool, WaitForTx)
// hold a response open indefinitely, so there is deliberately no write
// timeout.
const (
	readHeaderTimeout = 60 * time.Second
	idleTimeout       = 120 * time.Second
	shutdownTimeout   = 30 * time.Second
)

// Config holds the dependencies and tuning for a Server. Chain,
// ChainParams, and Listeners are required.
type Config struct {
	// Listeners are the already-bound listeners the server accepts on.
	// The server closes them when it stops.
	Listeners []net.Listener

	// TLSConfig, when non-nil, wraps every listener in TLS. The server
	// adds the HTTP/2 ALPN protocol to a clone of it, which gRPC
	// clients require.
	TLSConfig *tls.Config

	Chain       Chain
	ChainParams *chaincfg.Params

	// TxMemPool and Submitter back the submit service. When either is
	// nil the submit service reports its procedures unimplemented.
	TxMemPool Mempool
	Submitter TxSubmitter

	// TxFetcher resolves confirmed transactions for ReadTx. It is nil
	// when the node runs without a transaction index.
	TxFetcher RawTxFetcher

	// MaxBlockRefs, MaxUtxoKeys, and MaxHistoryItems override the
	// corresponding Default limits. Zero or negative selects the
	// default.
	MaxBlockRefs    int
	MaxUtxoKeys     int
	MaxHistoryItems int
}

// Server serves the UTxO RPC services over the configured listeners.
type Server struct {
	cfg    Config
	broker *broker

	httpServer *http.Server
	wg         sync.WaitGroup
	started    atomic.Bool
	stopped    atomic.Bool
}

// New returns a Server ready to be started. It fails if a required
// dependency is missing or no listeners were supplied.
func New(config *Config) (*Server, error) {
	if config == nil {
		return nil, errors.New("utxorpc: config is required")
	}
	if len(config.Listeners) == 0 {
		return nil, errors.New("utxorpc: at least one listener is required")
	}
	if config.Chain == nil {
		return nil, errors.New("utxorpc: chain is required")
	}
	if config.ChainParams == nil {
		return nil, errors.New("utxorpc: chain params are required")
	}

	cfg := *config
	if cfg.MaxBlockRefs <= 0 {
		cfg.MaxBlockRefs = DefaultMaxBlockRefs
	}
	if cfg.MaxUtxoKeys <= 0 {
		cfg.MaxUtxoKeys = DefaultMaxUtxoKeys
	}
	if cfg.MaxHistoryItems <= 0 {
		cfg.MaxHistoryItems = DefaultMaxHistoryItems
	}

	return &Server{cfg: cfg, broker: newBroker()}, nil
}

// serviceNames are the services advertised through health checking and
// server reflection. watch.WatchService is absent on purpose; see the
// package documentation.
var serviceNames = []string{
	syncconnect.SyncServiceName,
	queryconnect.QueryServiceName,
	submitconnect.SubmitServiceName,
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	compress := connect.WithCompressMinBytes(compressMinBytes)

	syncPath, syncHandler := syncconnect.NewSyncServiceHandler(
		&syncService{server: s}, compress)
	mux.Handle(syncPath, syncHandler)

	queryPath, queryHandler := queryconnect.NewQueryServiceHandler(
		&queryService{server: s}, compress)
	mux.Handle(queryPath, queryHandler)

	submitPath, submitHandler := submitconnect.NewSubmitServiceHandler(
		&submitService{server: s}, compress)
	mux.Handle(submitPath, submitHandler)

	checker := grpchealth.NewStaticChecker(serviceNames...)
	mux.Handle(grpchealth.NewHandler(checker, compress))

	reflector := grpcreflect.NewStaticReflector(serviceNames...)
	mux.Handle(grpcreflect.NewHandlerV1(reflector, compress))
	mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector, compress))

	return mux
}

// Start begins serving on the configured listeners. It returns without
// error once every listener has been handed to the HTTP server.
func (s *Server) Start() {
	if !s.started.CompareAndSwap(false, true) {
		return
	}

	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	// gRPC clients speaking cleartext need prior-knowledge HTTP/2,
	// which the server only accepts when this is set.
	protocols.SetUnencryptedHTTP2(s.cfg.TLSConfig == nil)

	s.httpServer = &http.Server{
		Handler:           s.handler(),
		Protocols:         protocols,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}

	for _, listener := range s.cfg.Listeners {
		listener := listener
		if s.cfg.TLSConfig != nil {
			tlsConfig := s.cfg.TLSConfig.Clone()
			// Without h2 in the ALPN list, gRPC-over-TLS clients
			// negotiate HTTP/1.1 and every gRPC call fails.
			if !hasALPN(tlsConfig.NextProtos, "h2") {
				tlsConfig.NextProtos = append(
					[]string{"h2"}, tlsConfig.NextProtos...)
			}
			listener = tls.NewListener(listener, tlsConfig)
		}

		log.Infof("UTxO RPC server listening on %s", listener.Addr())
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			err := s.httpServer.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Errorf("UTxO RPC server error: %v", err)
			}
		}()
	}
}

func hasALPN(protos []string, want string) bool {
	for _, proto := range protos {
		if proto == want {
			return true
		}
	}
	return false
}

// Stop gracefully shuts the server down and waits for its listeners to
// close.
func (s *Server) Stop() {
	if !s.started.Load() || !s.stopped.CompareAndSwap(false, true) {
		return
	}

	log.Infof("UTxO RPC server shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Warnf("UTxO RPC server shutdown: %v", err)
		_ = s.httpServer.Close()
	}
	s.wg.Wait()
}

// NotifyBlockConnected reports a block added to the main chain to
// FollowTip subscribers, and marks its transactions confirmed for
// WaitForTx subscribers.
func (s *Server) NotifyBlockConnected(block *hnsutil.Block) {
	s.publishBlock(chainApply, block)

	for _, tx := range block.Transactions() {
		s.NotifyTxStage(tx, submitpb.Stage_STAGE_CONFIRMED)
	}
}

// NotifyBlockDisconnected reports a block rolled back off the main
// chain to FollowTip subscribers.
func (s *Server) NotifyBlockDisconnected(block *hnsutil.Block) {
	s.publishBlock(chainUndo, block)
}

// NotifyMempoolTx reports a transaction accepted into the mempool.
func (s *Server) NotifyMempoolTx(tx *hnsutil.Tx) {
	s.NotifyTxStage(tx, submitpb.Stage_STAGE_MEMPOOL)
}

// NotifyTxStage reports a transaction reaching a submission stage.
func (s *Server) NotifyTxStage(tx *hnsutil.Tx, stage submitpb.Stage) {
	if tx == nil {
		return
	}
	raw, err := serializeTx(tx.MsgTx())
	if err != nil {
		log.Errorf("Failed to serialize transaction %v: %v",
			tx.Hash(), err)
		return
	}
	s.broker.publishMempoolTx(mempoolEvent{
		stage: stage,
		ref:   *tx.Hash(),
		raw:   raw,
	})
}

// publishBlock reduces a block to the immutable values the subscriber
// goroutines need. Doing it here rather than per subscriber keeps the
// block's unsynchronized lazy caches confined to this goroutine.
func (s *Server) publishBlock(action chainAction, block *hnsutil.Block) {
	if block == nil {
		return
	}
	raw, err := block.Bytes()
	if err != nil {
		log.Errorf("Failed to serialize block %v: %v", block.Hash(), err)
		return
	}
	s.broker.publishBlock(blockEvent{
		action: action,
		raw:    raw,
		hash:   *block.Hash(),
		prev:   block.MsgBlock().Header.PrevBlock,
		height: block.Height(),
	})
}

// bestState returns the current chain tip, or an error when the chain
// has no tip yet.
func (s *Server) bestState() (*querypb.ChainPoint, error) {
	best := s.cfg.Chain.BestSnapshot()
	if best == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("chain tip is not available yet"))
	}
	return tipChainPoint(best), nil
}
