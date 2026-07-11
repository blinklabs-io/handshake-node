// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import "github.com/blinklabs-io/handshake-node/chaincfg"

type handshakeDeploymentFlags struct {
	icannLockupActive bool
	airstopActive     bool
}

func (b *BlockChain) handshakeDeploymentFlags(prevNode *blockNode) (
	handshakeDeploymentFlags, error) {

	active := func(deploymentID uint32) (bool, error) {
		state, err := b.deploymentState(prevNode, deploymentID)
		if err != nil {
			return false, err
		}
		return state == ThresholdActive, nil
	}

	icannLockupActive, err := active(chaincfg.DeploymentICANNLockup)
	if err != nil {
		return handshakeDeploymentFlags{}, err
	}
	airstopActive, err := active(chaincfg.DeploymentAirstop)
	if err != nil {
		return handshakeDeploymentFlags{}, err
	}

	return handshakeDeploymentFlags{
		icannLockupActive: icannLockupActive,
		airstopActive:     airstopActive,
	}, nil
}

func (b *BlockChain) currentHandshakeDeploymentFlags() (
	handshakeDeploymentFlags, error) {

	b.chainLock.Lock()
	flags, err := b.handshakeDeploymentFlags(b.bestChain.Tip())
	b.chainLock.Unlock()

	return flags, err
}
