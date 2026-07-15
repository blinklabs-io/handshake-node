// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"
	"time"
)

const proofRequestWindowDuration = time.Second

// proofRequestWindow counts requests in the current and previous time buckets.
// Weighting the previous bucket by its overlap with the trailing one-second
// window avoids allowing two full bursts across a bucket boundary.
type proofRequestWindow struct {
	mu       sync.Mutex
	limit    uint64
	start    time.Time
	current  uint64
	previous uint64
}

func newProofRequestWindow(limit uint32) *proofRequestWindow {
	if limit == 0 {
		limit = defaultMaxProofRPS
	}
	return &proofRequestWindow{limit: uint64(limit)}
}

// allow records a request and reports whether its weighted request count is
// below the configured limit. This intentionally rejects the request that
// reaches the limit to match hsd's max-proof-rps behavior.
func (w *proofRequestWindow) allow(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.start.IsZero() || now.Before(w.start) {
		w.start = now
		w.current = 0
		w.previous = 0
	}

	elapsed := now.Sub(w.start)
	if elapsed >= proofRequestWindowDuration {
		windows := elapsed / proofRequestWindowDuration
		if windows == 1 {
			w.previous = w.current
		} else {
			w.previous = 0
		}
		w.current = 0
		w.start = w.start.Add(windows * proofRequestWindowDuration)
		elapsed = now.Sub(w.start)
	}

	if w.current != ^uint64(0) {
		w.current++
	}

	remaining := proofRequestWindowDuration - elapsed
	score := float64(w.previous)*float64(remaining)/
		float64(proofRequestWindowDuration) + float64(w.current)
	return score < float64(w.limit)
}
