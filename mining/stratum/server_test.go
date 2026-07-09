// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package stratum

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/wire"
)

type fakeGenerator struct {
	best *blockchain.BestState
	bits uint32
}

func (g *fakeGenerator) NewBlockTemplate(hnsutil.Address) (*mining.BlockTemplate, error) {
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{
			PrevBlock: g.best.Hash,
			Timestamp: time.Unix(1000, 0),
			Bits:      g.bits,
		},
	}
	return &mining.BlockTemplate{
		Block:  block,
		Height: g.best.Height + 1,
	}, nil
}

func (g *fakeGenerator) BestSnapshot() *blockchain.BestState {
	return g.best
}

func newTestServer(t *testing.T, difficulty float64,
	processBlock func(*hnsutil.Block, blockchain.BehaviorFlags) (bool, error)) *Server {

	t.Helper()

	params := &chaincfg.RegressionNetParams
	addr, err := hnsutil.NewAddressPubKeyHash(make([]byte, 20), params)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}

	s, err := New(&Config{
		ChainParams: params,
		BlockTemplateGenerator: &fakeGenerator{
			best: &blockchain.BestState{
				Height: 10,
			},
			bits: chaincfg.MainNetParams.PowLimitBits,
		},
		MiningAddrs:        []hnsutil.Address{addr},
		Difficulty:         difficulty,
		ProcessBlock:       processBlock,
		JobRefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSubmitAcceptsShareBelowPoolTarget(t *testing.T) {
	var processed bool
	s := newTestServer(t, 1, func(*hnsutil.Block, blockchain.BehaviorFlags) (bool, error) {
		processed = true
		return false, nil
	})
	job, err := s.currentJob()
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}

	extraNonce1 := []byte("12345678")
	extraNonce2 := make([]byte, ExtraNonce2Size)
	ntime := "00000000000003e8"
	nonce := solveShareNonce(t, job, s.shareTarget, extraNonce1,
		extraNonce2, ntime)

	result, err := s.Submit(job.ID, extraNonce1, hex.EncodeToString(extraNonce2),
		ntime, nonce)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("Submit accepted=false")
	}
	if result.BlockAccepted {
		t.Fatalf("Submit accepted share as block")
	}
	if processed {
		t.Fatalf("Submit processed non-block share")
	}
}

func TestSubmitRejectsLowDifficultyShare(t *testing.T) {
	s := newTestServer(t, 1e30, nil)
	job, err := s.currentJob()
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}

	_, err = s.Submit(job.ID, []byte("12345678"),
		"00000000000000000000000000000000",
		"00000000000003e8", "00000000")
	if err == nil {
		t.Fatalf("Submit accepted low difficulty share")
	}
}

func TestSubmitRejectsDuplicateShare(t *testing.T) {
	s := newTestServer(t, 1, nil)
	job, err := s.currentJob()
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}

	extraNonce1 := []byte("12345678")
	extraNonce2 := make([]byte, ExtraNonce2Size)
	ntime := "00000000000003e8"
	nonce := solveShareNonce(t, job, s.shareTarget, extraNonce1,
		extraNonce2, ntime)

	if _, err := s.Submit(job.ID, extraNonce1,
		hex.EncodeToString(extraNonce2), ntime, nonce); err != nil {

		t.Fatalf("first Submit: %v", err)
	}
	if _, err := s.Submit(job.ID, extraNonce1,
		hex.EncodeToString(extraNonce2), ntime, nonce); !errors.Is(err,
		errDuplicateShare) {

		t.Fatalf("second Submit error = %v, want %v", err, errDuplicateShare)
	}
}

func TestSubmitRejectsNTimeBeforeTemplate(t *testing.T) {
	s := newTestServer(t, 1, nil)
	job, err := s.currentJob()
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}

	_, err = s.Submit(job.ID, []byte("12345678"),
		"00000000000000000000000000000000",
		"00000000000003e7", "00000000")
	if err == nil || !strings.Contains(err.Error(), "before template") {
		t.Fatalf("Submit error = %v, want before-template rejection", err)
	}
}

func TestCreateJobPrunesSameTipJobs(t *testing.T) {
	s := newTestServer(t, 1, nil)

	var latest *Job
	for i := 0; i < maxJobsPerPrevBlock+2; i++ {
		job, err := s.createJob()
		if err != nil {
			t.Fatalf("createJob: %v", err)
		}
		latest = job
	}

	s.jobsMtx.RLock()
	if got := len(s.jobs); got != maxJobsPerPrevBlock {
		t.Fatalf("jobs len = %d, want %d", got, maxJobsPerPrevBlock)
	}
	if s.jobs[latest.ID] == nil {
		t.Fatalf("latest job %s was pruned", latest.ID)
	}
	s.jobsMtx.RUnlock()

	current, err := s.currentJob()
	if err != nil {
		t.Fatalf("currentJob: %v", err)
	}
	if current.ID != latest.ID {
		t.Fatalf("currentJob ID = %s, want latest %s", current.ID,
			latest.ID)
	}
}

func TestSubscribeAuthorizeProtocol(t *testing.T) {
	s := newTestServer(t, 1, nil)
	s.cfg.Authorize = func(user, pass string) bool {
		return user == "worker" && pass == "secret"
	}

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go s.ServeConn(serverConn)

	reader := bufio.NewReader(clientConn)
	fmt.Fprintln(clientConn, `{"id":1,"method":"mining.subscribe","params":[]}`)

	subscribe := readJSONLine(t, reader)
	if subscribe["id"].(float64) != 1 {
		t.Fatalf("subscribe id = %v", subscribe["id"])
	}
	result := subscribe["result"].([]interface{})
	if result[2].(float64) != ExtraNonce2Size {
		t.Fatalf("extranonce2 size = %v", result[2])
	}

	setDifficulty := readJSONLine(t, reader)
	if setDifficulty["method"] != "mining.set_difficulty" {
		t.Fatalf("method = %v", setDifficulty["method"])
	}

	fmt.Fprintln(clientConn, `{"id":2,"method":"mining.authorize","params":["worker","secret"]}`)
	authorize := readJSONLine(t, reader)
	if authorize["result"] != true {
		t.Fatalf("authorize result = %v", authorize["result"])
	}
	notify := readJSONLine(t, reader)
	if notify["method"] != "mining.notify" {
		t.Fatalf("method = %v", notify["method"])
	}
}

func TestNoAuthSubmitAfterSubscribe(t *testing.T) {
	s := newTestServer(t, 1, nil)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go s.ServeConn(serverConn)

	reader := bufio.NewReader(clientConn)
	fmt.Fprintln(clientConn, `{"id":1,"method":"mining.subscribe","params":[]}`)

	subscribe := readJSONLine(t, reader)
	result := subscribe["result"].([]interface{})
	extraNonce1, err := hex.DecodeString(result[1].(string))
	if err != nil {
		t.Fatalf("DecodeString extranonce1: %v", err)
	}
	readJSONLine(t, reader) // mining.set_difficulty
	notify := readJSONLine(t, reader)
	params := notify["params"].([]interface{})
	jobID := params[0].(string)

	s.jobsMtx.RLock()
	job := s.jobs[jobID]
	s.jobsMtx.RUnlock()
	if job == nil {
		t.Fatalf("unknown notified job %s", jobID)
	}

	extraNonce2 := make([]byte, ExtraNonce2Size)
	ntime := "00000000000003e8"
	nonce := solveShareNonce(t, job, s.shareTarget, extraNonce1,
		extraNonce2, ntime)
	fmt.Fprintf(clientConn,
		`{"id":2,"method":"mining.submit","params":["worker","%s","%s","%s","%s"]}`+"\n",
		jobID, hex.EncodeToString(extraNonce2), ntime, nonce)

	submit := readJSONLine(t, reader)
	if submit["result"] != true {
		t.Fatalf("submit response = %#v", submit)
	}
}

func solveShareNonce(t *testing.T, job *Job, target *big.Int,
	extraNonce1, extraNonce2 []byte, ntimeHex string) string {

	t.Helper()

	ntime, err := parseNTime(ntimeHex)
	if err != nil {
		t.Fatalf("parseNTime: %v", err)
	}
	for nonce := uint32(0); ; nonce++ {
		block := job.Block.Copy()
		copy(block.Header.ExtraNonce[:ExtraNonce1Size], extraNonce1)
		copy(block.Header.ExtraNonce[ExtraNonce1Size:], extraNonce2)
		block.Header.Timestamp = time.Unix(int64(ntime), 0)
		block.Header.Nonce = nonce
		hash := block.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return fmt.Sprintf("%08x", nonce)
		}
		if nonce == ^uint32(0) {
			t.Fatalf("unable to find share nonce for target %064x",
				target)
		}
	}
}

func readJSONLine(t *testing.T, r *bufio.Reader) map[string]interface{} {
	t.Helper()

	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(line, &msg); err != nil {
		t.Fatalf("Unmarshal %q: %v", line, err)
	}
	return msg
}
