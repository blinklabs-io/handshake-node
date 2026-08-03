// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"errors"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

type statisticsChecker struct {
	period    uint32
	threshold uint32
	votes     map[int32]bool
}

func (c statisticsChecker) HasStarted(*blockNode) bool {
	return true
}

func (c statisticsChecker) HasEnded(*blockNode) bool {
	return false
}

func (c statisticsChecker) RuleChangeActivationThreshold() uint32 {
	return c.threshold
}

func (c statisticsChecker) MinerConfirmationWindow() uint32 {
	return c.period
}

func (c statisticsChecker) EligibleToActivate(*blockNode) bool {
	return true
}

func (c statisticsChecker) IsSpeedy() bool {
	return false
}

func (c statisticsChecker) Condition(node *blockNode) (bool, error) {
	return c.votes[node.height], nil
}

func (c statisticsChecker) ForceActive(*blockNode) bool {
	return false
}

func statisticsTestTip(height int32) *blockNode {
	var tip *blockNode
	for i := int32(0); i <= height; i++ {
		tip = &blockNode{
			parent: tip,
			height: i,
		}
	}
	return tip
}

func TestThresholdStatistics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tipHeight int32
		checker   statisticsChecker
		want      ThresholdStatistics
	}{
		{
			name:      "window boundary resets",
			tipHeight: 9,
			checker: statisticsChecker{
				period:    10,
				threshold: 8,
				votes:     map[int32]bool{9: true},
			},
			want: ThresholdStatistics{
				Period:    10,
				Threshold: 8,
				Possible:  true,
			},
		},
		{
			name:      "counts elapsed blocks ending at tip",
			tipHeight: 12,
			checker: statisticsChecker{
				period:    10,
				threshold: 8,
				votes: map[int32]bool{
					10: true,
					12: true,
					9:  true,
				},
			},
			want: ThresholdStatistics{
				Period:    10,
				Threshold: 8,
				Elapsed:   3,
				Count:     2,
				Possible:  true,
			},
		},
		{
			name:      "no longer possible",
			tipHeight: 15,
			checker: statisticsChecker{
				period:    10,
				threshold: 8,
				votes: map[int32]bool{
					10: true,
					12: true,
				},
			},
			want: ThresholdStatistics{
				Period:    10,
				Threshold: 8,
				Elapsed:   6,
				Count:     2,
				Possible:  false,
			},
		},
		{
			name:      "custom threshold",
			tipHeight: 15,
			checker: statisticsChecker{
				period:    10,
				threshold: 6,
				votes: map[int32]bool{
					10: true,
					12: true,
				},
			},
			want: ThresholdStatistics{
				Period:    10,
				Threshold: 6,
				Elapsed:   6,
				Count:     2,
				Possible:  true,
			},
		},
		{
			name:      "zero period",
			tipHeight: 3,
			checker: statisticsChecker{
				threshold: 1,
			},
			want: ThresholdStatistics{
				Threshold: 1,
				Possible:  false,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stats, err := thresholdStatistics(
				statisticsTestTip(test.tipHeight), test.checker,
			)
			if err != nil {
				t.Fatalf("thresholdStatistics: %v", err)
			}
			if *stats != test.want {
				t.Fatalf("thresholdStatistics = %+v, want %+v",
					*stats, test.want)
			}
		})
	}
}

func TestBestSnapshotAndThresholdStatesInvalidDeployment(t *testing.T) {
	chain := newFakeChain(&chaincfg.MainNetParams)
	deploymentID := uint32(len(chain.chainParams.Deployments))
	snapshot, results, err := chain.BestSnapshotAndThresholdStates(
		[]uint32{deploymentID},
	)

	if snapshot != nil {
		t.Fatalf("snapshot = %+v, want nil", snapshot)
	}
	if results != nil {
		t.Fatalf("results = %+v, want nil", results)
	}
	var deploymentErr DeploymentError
	if !errors.As(err, &deploymentErr) {
		t.Fatalf("error = %v, want DeploymentError", err)
	}
	if deploymentErr != DeploymentError(deploymentID) {
		t.Fatalf("DeploymentError = %v, want %v", deploymentErr,
			DeploymentError(deploymentID))
	}
}

func TestBestSnapshotAndThresholdStates(t *testing.T) {
	chain := newFakeChain(&chaincfg.MainNetParams)
	snapshot, results, err := chain.BestSnapshotAndThresholdStates(
		[]uint32{
			chaincfg.DeploymentHardening,
			chaincfg.DeploymentTestDummy,
		},
	)
	if err != nil {
		t.Fatalf("BestSnapshotAndThresholdStates: %v", err)
	}
	if snapshot != chain.BestSnapshot() {
		t.Fatal("snapshot does not match the best-chain snapshot")
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want 2", len(results))
	}
	for deploymentID, result := range results {
		if result.State != ThresholdDefined {
			t.Fatalf("deployment %d state = %v, want %v", deploymentID,
				result.State, ThresholdDefined)
		}
		if result.Statistics != nil {
			t.Fatalf("deployment %d statistics = %+v, want nil",
				deploymentID, result.Statistics)
		}
	}
}
