// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/wire"
)

type nodeMetrics struct {
	p2pMessages *p2pMessageCounters

	blockValidationCount  uint64
	blockValidationSumNS  uint64
	blockValidationLastNS uint64
	blockValidationMaxNS  uint64
}

func newNodeMetrics() *nodeMetrics {
	return &nodeMetrics{
		p2pMessages: newP2PMessageCounters(),
	}
}

func (m *nodeMetrics) observeP2PMessage(direction string,
	msg wire.HandshakeMessage) {

	if m == nil || msg == nil {
		return
	}
	m.observeP2PMessageType(direction, msg.Type())
}

func (m *nodeMetrics) observeP2PMessageType(direction string,
	msgType wire.HnsMsgType) {

	if m == nil {
		return
	}
	m.p2pMessages.add(direction, msgType.String())
}

func (m *nodeMetrics) observeBlockValidation(d time.Duration) {
	if m == nil {
		return
	}

	ns := uint64(d)
	atomic.AddUint64(&m.blockValidationCount, 1)
	atomic.AddUint64(&m.blockValidationSumNS, ns)
	atomic.StoreUint64(&m.blockValidationLastNS, ns)
	for {
		maxNS := atomic.LoadUint64(&m.blockValidationMaxNS)
		if ns <= maxNS || atomic.CompareAndSwapUint64(
			&m.blockValidationMaxNS, maxNS, ns) {

			return
		}
	}
}

type p2pMessageCounters struct {
	mtx    sync.RWMutex
	counts map[p2pMessageKey]uint64
}

type p2pMessageKey struct {
	direction string
	msgType   string
}

func newP2PMessageCounters() *p2pMessageCounters {
	return &p2pMessageCounters{
		counts: make(map[p2pMessageKey]uint64),
	}
}

func (c *p2pMessageCounters) add(direction, msgType string) {
	c.mtx.Lock()
	c.counts[p2pMessageKey{direction: direction, msgType: msgType}]++
	c.mtx.Unlock()
}

func (c *p2pMessageCounters) snapshot() map[p2pMessageKey]uint64 {
	c.mtx.RLock()
	defer c.mtx.RUnlock()

	result := make(map[p2pMessageKey]uint64, len(c.counts))
	for key, count := range c.counts {
		result[key] = count
	}
	return result
}

type metricsServer struct {
	httpServer *http.Server
	listeners  []net.Listener
	wg         sync.WaitGroup
}

func newMetricsServer(addrs []string, node *server) (*metricsServer, error) {
	netAddrs, err := parseListeners(addrs)
	if err != nil {
		return nil, err
	}

	listeners := make([]net.Listener, 0, len(netAddrs))
	for _, addr := range netAddrs {
		listener, err := net.Listen(addr.Network(), addr.String())
		if err != nil {
			for _, existing := range listeners {
				_ = existing.Close()
			}
			return nil, fmt.Errorf("listen on metrics address %s: %w",
				addr, err)
		}
		listeners = append(listeners, listener)
	}
	if len(listeners) == 0 {
		return nil, fmt.Errorf("no valid metrics listen address")
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(renderPrometheusMetrics(node)))
	}))

	return &metricsServer{
		httpServer: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		listeners: listeners,
	}, nil
}

func (m *metricsServer) Start() {
	if m == nil {
		return
	}
	for _, listener := range m.listeners {
		listener := listener
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			err := m.httpServer.Serve(listener)
			if err != nil && err != http.ErrServerClosed {
				srvrLog.Warnf("Metrics listener %s stopped: %v",
					listener.Addr(), err)
			}
		}()
		srvrLog.Infof("Prometheus metrics listening on %s", listener.Addr())
	}
}

func (m *metricsServer) Stop() {
	if m == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.httpServer.Shutdown(ctx); err != nil {
		srvrLog.Warnf("Graceful metrics shutdown failed: %v", err)
		_ = m.httpServer.Close()
	}
	for _, listener := range m.listeners {
		_ = listener.Close()
	}
	m.wg.Wait()
}

func renderPrometheusMetrics(s *server) string {
	var b strings.Builder
	writeMetricHeader(&b, "handshake_chain_height",
		"Current best chain height.", "gauge")
	writeMetricHeader(&b, "handshake_chain_current",
		"Whether the sync manager believes the chain is current.", "gauge")
	writeMetricHeader(&b, "handshake_sync_progress",
		"Best height divided by the highest announced peer height.", "gauge")
	writeMetricHeader(&b, "handshake_connected_peers",
		"Number of connected peers.", "gauge")
	writeMetricHeader(&b, "handshake_mempool_transactions",
		"Number of transactions in the mempool.", "gauge")
	writeMetricHeader(&b, "handshake_mempool_fee_rate_doo_per_kb",
		"Mempool fee rate summary in dollarydoos per kilobyte.", "gauge")
	writeMetricHeader(&b, "handshake_mining_hashes_per_second",
		"CPU miner hash rate.", "gauge")
	writeMetricHeader(&b, "handshake_p2p_bytes_total",
		"Total P2P bytes by direction.", "counter")
	writeMetricHeader(&b, "handshake_p2p_messages_total",
		"Total P2P messages by direction and message type.", "counter")
	writeMetricHeader(&b, "handshake_block_validation_seconds",
		"Block processing duration summary.", "summary")
	writeMetricHeader(&b, "handshake_block_validation_last_seconds",
		"Last block processing duration in seconds.", "gauge")
	writeMetricHeader(&b, "handshake_block_validation_max_seconds",
		"Maximum observed block processing duration in seconds.", "gauge")

	if s == nil {
		return b.String()
	}

	best := s.chain.BestSnapshot()
	peerStats := s.connectedPeerStats()
	connectedPeers := len(peerStats)
	current := s.syncManager != nil && s.syncManager.IsCurrent()
	progress := syncProgress(best.Height, peerStats, current)

	writeSample(&b, "handshake_chain_height", nil, float64(best.Height))
	writeBoolSample(&b, "handshake_chain_current", nil, current)
	writeSample(&b, "handshake_sync_progress", nil, progress)
	writeSample(&b, "handshake_connected_peers", nil, float64(connectedPeers))

	writeMempoolMetrics(&b, s)
	if s.cpuMiner != nil {
		writeSample(&b, "handshake_mining_hashes_per_second", nil,
			s.cpuMiner.HashesPerSecond())
	} else {
		writeSample(&b, "handshake_mining_hashes_per_second", nil, 0)
	}

	bytesRecv, bytesSent := s.NetTotals()
	writeSample(&b, "handshake_p2p_bytes_total",
		map[string]string{"direction": "inbound"}, float64(bytesRecv))
	writeSample(&b, "handshake_p2p_bytes_total",
		map[string]string{"direction": "outbound"}, float64(bytesSent))

	if s.metrics != nil {
		writeP2PMessageMetrics(&b, s.metrics.p2pMessages.snapshot())
		writeBlockValidationMetrics(&b, s.metrics)
	}

	return b.String()
}

func (s *server) connectedPeerStats() []*peer.StatsSnap {
	replyChan := make(chan []*serverPeer)
	s.query <- getPeersMsg{reply: replyChan}
	serverPeers := <-replyChan

	stats := make([]*peer.StatsSnap, 0, len(serverPeers))
	for _, sp := range serverPeers {
		stats = append(stats, sp.StatsSnapshot())
	}
	return stats
}

func syncProgress(bestHeight int32, peers []*peer.StatsSnap, current bool) float64 {
	if current {
		return 1
	}
	if len(peers) == 0 {
		return 0
	}

	target := bestHeight
	for _, stats := range peers {
		if stats.LastBlock > target {
			target = stats.LastBlock
		}
	}
	if target <= 0 {
		return 0
	}
	if bestHeight >= target {
		return 1
	}
	if bestHeight < 0 {
		bestHeight = 0
	}
	return float64(bestHeight) / float64(target)
}

func writeMempoolMetrics(b *strings.Builder, s *server) {
	if s.txMemPool == nil {
		writeSample(b, "handshake_mempool_transactions", nil, 0)
		for _, stat := range []string{"min", "avg", "max"} {
			writeSample(b, "handshake_mempool_fee_rate_doo_per_kb",
				map[string]string{"stat": stat}, 0)
		}
		return
	}

	descs := s.txMemPool.TxDescs()
	writeSample(b, "handshake_mempool_transactions", nil, float64(len(descs)))
	if len(descs) == 0 {
		for _, stat := range []string{"min", "avg", "max"} {
			writeSample(b, "handshake_mempool_fee_rate_doo_per_kb",
				map[string]string{"stat": stat}, 0)
		}
		return
	}

	minFee := int64(^uint64(0) >> 1)
	maxFee := int64(0)
	var sumFee int64
	for _, desc := range descs {
		feeRate := desc.FeePerKB
		if feeRate < minFee {
			minFee = feeRate
		}
		if feeRate > maxFee {
			maxFee = feeRate
		}
		sumFee += feeRate
	}
	writeSample(b, "handshake_mempool_fee_rate_doo_per_kb",
		map[string]string{"stat": "min"}, float64(minFee))
	writeSample(b, "handshake_mempool_fee_rate_doo_per_kb",
		map[string]string{"stat": "avg"}, float64(sumFee)/float64(len(descs)))
	writeSample(b, "handshake_mempool_fee_rate_doo_per_kb",
		map[string]string{"stat": "max"}, float64(maxFee))
}

func writeP2PMessageMetrics(b *strings.Builder,
	counts map[p2pMessageKey]uint64) {

	keys := make([]p2pMessageKey, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].direction != keys[j].direction {
			return keys[i].direction < keys[j].direction
		}
		return keys[i].msgType < keys[j].msgType
	})

	for _, key := range keys {
		writeSample(b, "handshake_p2p_messages_total", map[string]string{
			"direction": key.direction,
			"type":      key.msgType,
		}, float64(counts[key]))
	}
}

func writeBlockValidationMetrics(b *strings.Builder, m *nodeMetrics) {
	count := atomic.LoadUint64(&m.blockValidationCount)
	sumNS := atomic.LoadUint64(&m.blockValidationSumNS)
	lastNS := atomic.LoadUint64(&m.blockValidationLastNS)
	maxNS := atomic.LoadUint64(&m.blockValidationMaxNS)

	writeSample(b, "handshake_block_validation_seconds_count", nil,
		float64(count))
	writeSample(b, "handshake_block_validation_seconds_sum", nil,
		secondsFromNS(sumNS))
	writeSample(b, "handshake_block_validation_last_seconds", nil,
		secondsFromNS(lastNS))
	writeSample(b, "handshake_block_validation_max_seconds", nil,
		secondsFromNS(maxNS))
}

func secondsFromNS(ns uint64) float64 {
	return float64(ns) / float64(time.Second)
}

func writeMetricHeader(b *strings.Builder, name, help, metricType string) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(metricType)
	b.WriteByte('\n')
}

func writeBoolSample(b *strings.Builder, name string, labels map[string]string,
	value bool) {

	if value {
		writeSample(b, name, labels, 1)
		return
	}
	writeSample(b, name, labels, 0)
}

func writeSample(b *strings.Builder, name string, labels map[string]string,
	value float64) {

	b.WriteString(name)
	if len(labels) > 0 {
		writeLabels(b, labels)
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	b.WriteByte('\n')
}

func writeLabels(b *strings.Builder, labels map[string]string) {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	b.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(key)
		b.WriteString("=\"")
		b.WriteString(escapePromLabel(labels[key]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
}

func escapePromLabel(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}
