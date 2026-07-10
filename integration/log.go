// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build rpctest
// +build rpctest

package integration

import (
	"os"

	"github.com/blinklabs-io/handshake-node/rpcclient"
	"github.com/btcsuite/btclog"
)

type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	os.Stdout.Write(p)
	return len(p), nil
}

func init() {
	backendLog := btclog.NewBackend(logWriter{})
	testLog := backendLog.Logger("ITEST")
	testLog.SetLevel(btclog.LevelDebug)

	rpcclient.UseLogger(testLog)
}
