package main

import (
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/peer"
)

func TestValidateLocalListeners(t *testing.T) {
	local := []string{"127.0.0.1:12039", "[::1]:12039", "localhost:12039"}
	if err := validateLocalListeners(local, "metricslisten",
		"metricsallowpublic"); err != nil {

		t.Fatalf("validateLocalListeners local: %v", err)
	}

	public := []string{"0.0.0.0:12039"}
	if err := validateLocalListeners(public, "metricslisten",
		"metricsallowpublic"); err == nil {

		t.Fatalf("validateLocalListeners accepted public bind")
	}
}

func TestSyncProgress(t *testing.T) {
	peers := []*peer.StatsSnap{
		{LastBlock: 100},
		{LastBlock: 80},
	}
	if got := syncProgress(25, peers, false); got != 0.25 {
		t.Fatalf("syncProgress = %v, want 0.25", got)
	}
	if got := syncProgress(25, peers, true); got != 1 {
		t.Fatalf("syncProgress current = %v, want 1", got)
	}
	if got := syncProgress(25, nil, false); got != 0 {
		t.Fatalf("syncProgress no peers = %v, want 0", got)
	}
}

func TestPrometheusLabelEscaping(t *testing.T) {
	var b strings.Builder
	writeSample(&b, "handshake_p2p_messages_total", map[string]string{
		"type": "bad\"type\\x",
	}, 1)
	got := b.String()
	want := `type="bad\"type\\x"`
	if !strings.Contains(got, want) {
		t.Fatalf("writeSample = %q, want substring %q", got, want)
	}
}

func TestBlockValidationMetricsUseSummaryAndGauges(t *testing.T) {
	metrics := newNodeMetrics()
	metrics.observeBlockValidation(2 * time.Second)
	metrics.observeBlockValidation(3 * time.Second)

	var b strings.Builder
	writeBlockValidationMetrics(&b, metrics)
	got := b.String()

	for _, want := range []string{
		"handshake_block_validation_seconds_count 2",
		"handshake_block_validation_seconds_sum 5",
		"handshake_block_validation_last_seconds 3",
		"handshake_block_validation_max_seconds 3",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "handshake_block_validation_seconds{") {
		t.Fatalf("summary metric includes non-quantile labels:\n%s", got)
	}
}
