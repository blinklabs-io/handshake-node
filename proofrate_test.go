// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProofRequestWindowLimit(t *testing.T) {
	window := newProofRequestWindow(4)
	now := time.Unix(1, 0)

	for i := 0; i < 3; i++ {
		if !window.allow(now) {
			t.Fatalf("request %d was rejected below the limit", i+1)
		}
	}
	if window.allow(now) {
		t.Fatal("request reaching the limit was allowed")
	}
}

func TestProofRequestWindowDefaultLimit(t *testing.T) {
	window := newProofRequestWindow(0)
	now := time.Unix(1, 0)

	for i := 1; i < defaultMaxProofRPS; i++ {
		if !window.allow(now) {
			t.Fatalf("request %d was rejected below the default limit", i)
		}
	}
	if window.allow(now) {
		t.Fatal("request reaching the default limit was allowed")
	}
}

func TestProofRequestWindowWeightsPreviousBucket(t *testing.T) {
	window := newProofRequestWindow(5)
	start := time.Unix(1, 0)

	for i := 0; i < 4; i++ {
		if !window.allow(start) {
			t.Fatalf("initial request %d was rejected", i+1)
		}
	}
	if window.allow(start.Add(time.Second)) {
		t.Fatal("boundary burst was allowed")
	}
	if !window.allow(start.Add(1500 * time.Millisecond)) {
		t.Fatal("request was not allowed after the previous bucket decayed")
	}
}

func TestProofRequestWindowResetsAfterIdlePeriod(t *testing.T) {
	window := newProofRequestWindow(3)
	start := time.Unix(1, 0)

	for i := 0; i < 2; i++ {
		if !window.allow(start) {
			t.Fatalf("request %d was rejected below the limit", i+1)
		}
	}
	if !window.allow(start.Add(2 * time.Second)) {
		t.Fatal("request was rejected after an idle period")
	}
}

func TestProofRequestWindowConcurrentLimit(t *testing.T) {
	const limit = 50
	window := newProofRequestWindow(limit)
	now := time.Unix(1, 0)

	var allowed atomic.Uint32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if window.allow(now) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got, want := allowed.Load(), uint32(limit-1); got != want {
		t.Fatalf("allowed requests = %d, want %d", got, want)
	}
}
