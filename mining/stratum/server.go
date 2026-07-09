// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package stratum implements a minimal Handshake-specific Stratum v1 server.
//
// The protocol uses standard Stratum JSON line framing and method names
// (mining.subscribe, mining.authorize, mining.submit).  Work notifications
// intentionally carry a serialized Handshake header template instead of
// Bitcoin coinbase-splitting fields because Handshake's mining search space is
// in the 236-byte header, including the 24-byte ExtraNonce field.
package stratum

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	// ExtraNonce1Size is the server-assigned prefix of the Handshake
	// header ExtraNonce field.
	ExtraNonce1Size = 8

	// ExtraNonce2Size is the miner-supplied suffix of the Handshake header
	// ExtraNonce field.
	ExtraNonce2Size = 16

	defaultDifficulty         = 1.0
	defaultJobRefreshInterval = 30 * time.Second
	tipPollInterval           = time.Second
	clientReadTimeout         = 2 * time.Minute
	maxJobsPerPrevBlock       = 8
	maxRequestLineBytes       = 1 << 20
)

var (
	errUnauthorized   = errors.New("worker is not authorized")
	errUnknownJob     = errors.New("unknown job")
	errStaleJob       = errors.New("stale job")
	errDuplicateShare = errors.New("duplicate share")
	errLowDifficulty  = errors.New(
		"share hash does not meet the configured target")
)

// BlockTemplateGenerator is the subset of the mining template generator used by
// the Stratum server.
type BlockTemplateGenerator interface {
	NewBlockTemplate(hnsutil.Address) (*mining.BlockTemplate, error)
	BestSnapshot() *blockchain.BestState
}

// Config describes a Stratum server instance.
type Config struct {
	ChainParams            *chaincfg.Params
	BlockTemplateGenerator BlockTemplateGenerator
	MiningAddrs            []hnsutil.Address
	Listeners              []net.Listener
	ProcessBlock           func(*hnsutil.Block, blockchain.BehaviorFlags) (bool, error)
	Authorize              func(user, pass string) bool
	Difficulty             float64
	JobRefreshInterval     time.Duration
}

// Server provides a minimal Stratum v1 server for Handshake mining.
type Server struct {
	cfg Config

	started int32
	quit    chan struct{}
	wg      sync.WaitGroup

	shareTarget *big.Int

	jobsMtx sync.RWMutex
	jobs    map[string]*Job
	jobSeq  uint64

	clientsMtx sync.Mutex
	clients    map[*client]struct{}
}

// Job is a mining job derived from a Handshake block template.
type Job struct {
	ID        string
	Seq       uint64
	Block     *wire.MsgBlock
	Height    int32
	PrevBlock chainhash.Hash
	Created   time.Time
	Submitted map[string]struct{}
}

// SubmitResult describes the result of a submitted share.
type SubmitResult struct {
	Accepted      bool
	BlockAccepted bool
	BlockHash     chainhash.Hash
}

// New returns a Stratum server configured with the provided settings.
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("nil stratum config")
	}
	if cfg.ChainParams == nil {
		return nil, errors.New("missing chain params")
	}
	if cfg.BlockTemplateGenerator == nil {
		return nil, errors.New("missing block template generator")
	}
	if len(cfg.MiningAddrs) == 0 {
		return nil, errors.New("missing mining address")
	}
	if cfg.Difficulty <= 0 {
		cfg.Difficulty = defaultDifficulty
	}
	if cfg.JobRefreshInterval <= 0 {
		cfg.JobRefreshInterval = defaultJobRefreshInterval
	}

	shareTarget, err := shareTarget(cfg.ChainParams.PowLimit,
		cfg.Difficulty)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:         *cfg,
		quit:        make(chan struct{}),
		shareTarget: shareTarget,
		jobs:        make(map[string]*Job),
		clients:     make(map[*client]struct{}),
	}, nil
}

// Start begins accepting Stratum clients.
func (s *Server) Start() {
	if s == nil || !atomic.CompareAndSwapInt32(&s.started, 0, 1) {
		return
	}

	for _, listener := range s.cfg.Listeners {
		listener := listener
		s.wg.Add(1)
		go s.acceptLoop(listener)
		log.Infof("Stratum listening on %s", listener.Addr())
	}

	s.wg.Add(1)
	go s.jobLoop()
}

// Stop gracefully stops the Stratum server.
func (s *Server) Stop() {
	if s == nil {
		return
	}

	started := atomic.CompareAndSwapInt32(&s.started, 1, 0)
	if started {
		close(s.quit)
	}
	for _, listener := range s.cfg.Listeners {
		_ = listener.Close()
	}

	s.clientsMtx.Lock()
	for c := range s.clients {
		c.close()
	}
	s.clientsMtx.Unlock()

	if started {
		s.wg.Wait()
	}
}

func (s *Server) acceptLoop(listener net.Listener) {
	defer s.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Warnf("Stratum accept failed on %s: %v",
					listener.Addr(), err)
				continue
			}
		}

		c := newClient(s, conn)
		s.clientsMtx.Lock()
		s.clients[c] = struct{}{}
		s.clientsMtx.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			c.serve()
			s.clientsMtx.Lock()
			delete(s.clients, c)
			s.clientsMtx.Unlock()
		}()
	}
}

func (s *Server) jobLoop() {
	defer s.wg.Done()

	refreshTicker := time.NewTicker(s.cfg.JobRefreshInterval)
	defer refreshTicker.Stop()
	tipTicker := time.NewTicker(tipPollInterval)
	defer tipTicker.Stop()

	var lastBest chainhash.Hash
	if best := s.cfg.BlockTemplateGenerator.BestSnapshot(); best != nil {
		lastBest = best.Hash
	}

	for {
		select {
		case <-refreshTicker.C:
			job, err := s.createJob()
			if err != nil {
				log.Debugf("Unable to refresh Stratum job: %v", err)
				continue
			}
			s.broadcastJob(job)

		case <-tipTicker.C:
			best := s.cfg.BlockTemplateGenerator.BestSnapshot()
			if best == nil || best.Hash == lastBest {
				continue
			}
			lastBest = best.Hash
			job, err := s.createJob()
			if err != nil {
				log.Debugf("Unable to refresh Stratum job for new tip: %v",
					err)
				continue
			}
			s.broadcastJob(job)

		case <-s.quit:
			return
		}
	}
}

func (s *Server) broadcastJob(job *Job) {
	s.clientsMtx.Lock()
	clients := make([]*client, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.clientsMtx.Unlock()

	for _, c := range clients {
		c.notifyJob(job)
	}
}

func (s *Server) currentJob() (*Job, error) {
	best := s.cfg.BlockTemplateGenerator.BestSnapshot()
	if best == nil {
		return nil, errors.New("missing best chain snapshot")
	}

	s.jobsMtx.RLock()
	var latest *Job
	for _, job := range s.jobs {
		if job.PrevBlock == best.Hash {
			if latest == nil || job.Seq > latest.Seq {
				latest = job
			}
		}
	}
	s.jobsMtx.RUnlock()
	if latest != nil {
		return latest, nil
	}

	return s.createJob()
}

func (s *Server) createJob() (*Job, error) {
	template, err := s.cfg.BlockTemplateGenerator.NewBlockTemplate(
		s.cfg.MiningAddrs[0])
	if err != nil {
		return nil, err
	}
	seq := atomic.AddUint64(&s.jobSeq, 1)
	job := &Job{
		ID:        strconv.FormatUint(seq, 16),
		Seq:       seq,
		Block:     template.Block.Copy(),
		Height:    template.Height,
		PrevBlock: template.Block.Header.PrevBlock,
		Created:   time.Now(),
		Submitted: make(map[string]struct{}),
	}

	s.jobsMtx.Lock()
	s.jobs[job.ID] = job
	s.pruneJobsLocked(job.PrevBlock)
	s.jobsMtx.Unlock()

	return job, nil
}

func (s *Server) pruneJobsLocked(bestHash chainhash.Hash) {
	sameTipJobs := make([]*Job, 0, maxJobsPerPrevBlock+1)
	for id, existing := range s.jobs {
		if existing.PrevBlock != bestHash {
			delete(s.jobs, id)
			continue
		}
		sameTipJobs = append(sameTipJobs, existing)
	}
	if len(sameTipJobs) <= maxJobsPerPrevBlock {
		return
	}

	sort.Slice(sameTipJobs, func(i, j int) bool {
		return sameTipJobs[i].Seq > sameTipJobs[j].Seq
	})
	for _, job := range sameTipJobs[maxJobsPerPrevBlock:] {
		delete(s.jobs, job.ID)
	}
}

// Submit validates and possibly submits a share for the provided job.  It only
// calls ProcessBlock when the reconstructed Handshake block hash meets the
// network target encoded by the block header.
func (s *Server) Submit(jobID string, extraNonce1 []byte,
	extraNonce2Hex, ntimeHex, nonceHex string) (*SubmitResult, error) {

	if len(extraNonce1) != ExtraNonce1Size {
		return nil, fmt.Errorf("extranonce1 must be %d bytes",
			ExtraNonce1Size)
	}

	s.jobsMtx.RLock()
	job := s.jobs[jobID]
	s.jobsMtx.RUnlock()
	if job == nil {
		return nil, errUnknownJob
	}

	best := s.cfg.BlockTemplateGenerator.BestSnapshot()
	if best == nil {
		return nil, errors.New("missing best chain snapshot")
	}
	if job.PrevBlock != best.Hash {
		return nil, errStaleJob
	}

	extraNonce2, err := parseFixedHex(extraNonce2Hex, ExtraNonce2Size,
		"extranonce2")
	if err != nil {
		return nil, err
	}
	ntime, err := parseNTime(ntimeHex)
	if err != nil {
		return nil, err
	}
	if err := validateNTime(job, ntime); err != nil {
		return nil, err
	}
	nonce, err := parseUint32Hex(nonceHex, "nonce")
	if err != nil {
		return nil, err
	}

	msgBlock := job.Block.Copy()
	copy(msgBlock.Header.ExtraNonce[:ExtraNonce1Size], extraNonce1)
	copy(msgBlock.Header.ExtraNonce[ExtraNonce1Size:], extraNonce2)
	msgBlock.Header.Timestamp = time.Unix(int64(ntime), 0)
	msgBlock.Header.Nonce = nonce

	blockHash := msgBlock.Header.BlockHash()
	hashNum := blockchain.HashToBig(&blockHash)
	networkTarget := blockchain.CompactToBig(msgBlock.Header.Bits)
	isBlock := hashNum.Cmp(networkTarget) <= 0
	if !isBlock && hashNum.Cmp(s.shareTarget) > 0 {
		return nil, errLowDifficulty
	}
	shareKey := formatShareKey(extraNonce1, extraNonce2, ntime, nonce)
	if err := s.recordShare(jobID, job.PrevBlock, shareKey); err != nil {
		return nil, err
	}

	result := &SubmitResult{
		Accepted:  true,
		BlockHash: blockHash,
	}
	if !isBlock {
		return result, nil
	}

	if s.cfg.ProcessBlock == nil {
		return nil, errors.New("no block processor configured")
	}
	isOrphan, err := s.cfg.ProcessBlock(hnsutil.NewBlock(msgBlock),
		blockchain.BFNone)
	if err != nil {
		return nil, err
	}
	if isOrphan {
		return nil, errors.New("submitted block is orphan")
	}

	result.BlockAccepted = true
	log.Infof("Stratum submitted block accepted: %s", blockHash)
	return result, nil
}

func validateNTime(job *Job, ntime uint64) error {
	if ntime > math.MaxInt64 {
		return errors.New("ntime is out of range")
	}

	timestamp := time.Unix(int64(ntime), 0)
	if timestamp.Before(job.Block.Header.Timestamp) {
		return fmt.Errorf("ntime %s is before template timestamp %s",
			timestamp, job.Block.Header.Timestamp)
	}

	maxTimestamp := time.Now().Add(time.Second *
		blockchain.MaxTimeOffsetSeconds)
	if timestamp.After(maxTimestamp) {
		return fmt.Errorf("ntime %s is too far in the future", timestamp)
	}
	return nil
}

func formatShareKey(extraNonce1, extraNonce2 []byte, ntime uint64,
	nonce uint32) string {

	return fmt.Sprintf("%x:%x:%016x:%08x", extraNonce1, extraNonce2,
		ntime, nonce)
}

func (s *Server) recordShare(jobID string, prevBlock chainhash.Hash,
	shareKey string) error {

	best := s.cfg.BlockTemplateGenerator.BestSnapshot()
	if best == nil {
		return errors.New("missing best chain snapshot")
	}
	if prevBlock != best.Hash {
		return errStaleJob
	}

	s.jobsMtx.Lock()
	defer s.jobsMtx.Unlock()

	job := s.jobs[jobID]
	if job == nil {
		return errUnknownJob
	}
	if job.PrevBlock != prevBlock {
		return errStaleJob
	}
	if _, exists := job.Submitted[shareKey]; exists {
		return errDuplicateShare
	}
	job.Submitted[shareKey] = struct{}{}
	return nil
}

func shareTarget(powLimit *big.Int, difficulty float64) (*big.Int, error) {
	if powLimit == nil || powLimit.Sign() <= 0 {
		return nil, errors.New("invalid pow limit")
	}

	diffRat := new(big.Rat).SetFloat64(difficulty)
	if diffRat == nil || diffRat.Sign() <= 0 {
		return nil, fmt.Errorf("invalid difficulty %v", difficulty)
	}

	targetRat := new(big.Rat).SetInt(powLimit)
	targetRat.Quo(targetRat, diffRat)
	target := new(big.Int).Quo(targetRat.Num(), targetRat.Denom())
	if target.Sign() <= 0 {
		target.SetInt64(1)
	}
	if target.Cmp(powLimit) > 0 {
		target.Set(powLimit)
	}
	return target, nil
}

type client struct {
	server *Server
	conn   net.Conn

	writeMtx sync.Mutex

	stateMtx    sync.RWMutex
	extraNonce1 [ExtraNonce1Size]byte
	subscribed  bool
	authorized  bool
	closed      int32
}

func newClient(server *Server, conn net.Conn) *client {
	c := &client{
		server: server,
		conn:   conn,
	}
	if _, err := rand.Read(c.extraNonce1[:]); err != nil {
		// A zero extranonce1 is safe, but unique prefixes reduce accidental
		// share collisions across clients.
		log.Warnf("Unable to generate Stratum extranonce1: %v", err)
	}
	return c
}

func (c *client) serve() {
	defer c.close()

	scanner := bufio.NewScanner(c.conn)
	scanner.Buffer(make([]byte, 0, 4096), maxRequestLineBytes)
	_ = c.conn.SetReadDeadline(time.Now().Add(clientReadTimeout))
	for scanner.Scan() {
		_ = c.conn.SetReadDeadline(time.Now().Add(clientReadTimeout))
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			c.writeError(rawID(nil), 20, "invalid JSON request")
			continue
		}
		c.handleRequest(&req)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return
		}
		log.Debugf("Stratum client read failed: %v", err)
	}
}

func (c *client) close() {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		_ = c.conn.Close()
	}
}

func (c *client) handleRequest(req *request) {
	switch req.Method {
	case "mining.subscribe":
		c.handleSubscribe(req)
	case "mining.authorize":
		c.handleAuthorize(req)
	case "mining.submit":
		c.handleSubmit(req)
	default:
		c.writeError(req.id(), 20, "unknown method")
	}
}

func (c *client) handleSubscribe(req *request) {
	c.setSubscribed(true)
	subscriptions := [][]string{
		{"mining.set_difficulty", "handshake-node"},
		{"mining.notify", "handshake-node"},
	}
	result := []interface{}{
		subscriptions,
		hex.EncodeToString(c.extraNonce1[:]),
		ExtraNonce2Size,
	}
	c.writeResult(req.id(), result)
	c.notifyDifficulty()
	if c.canReceiveWork() {
		job, err := c.server.currentJob()
		if err != nil {
			return
		}
		c.notifyJob(job)
	}
}

func (c *client) handleAuthorize(req *request) {
	user, pass, err := parseTwoStringParams(req.Params,
		"username", "password")
	if err != nil {
		c.writeError(req.id(), 20, err.Error())
		return
	}

	authorized := true
	if c.server.cfg.Authorize != nil {
		authorized = c.server.cfg.Authorize(user, pass)
	}
	c.setAuthorized(authorized)
	c.writeResult(req.id(), authorized)
	if c.canReceiveWork() {
		if job, err := c.server.currentJob(); err == nil {
			c.notifyJob(job)
		}
	}
}

func (c *client) handleSubmit(req *request) {
	if !c.canReceiveWork() {
		c.writeError(req.id(), 24, errUnauthorized.Error())
		return
	}

	_, jobID, extraNonce2, ntime, nonce, err := parseSubmitParams(req.Params)
	if err != nil {
		c.writeError(req.id(), 20, err.Error())
		return
	}

	_, err = c.server.Submit(jobID, c.extraNonce1[:], extraNonce2,
		ntime, nonce)
	if err != nil {
		c.writeError(req.id(), 23, err.Error())
		return
	}
	c.writeResult(req.id(), true)
}

func (c *client) notifyDifficulty() {
	c.writeNotification("mining.set_difficulty",
		[]interface{}{c.server.cfg.Difficulty})
}

func (c *client) notifyJob(job *Job) {
	if !c.canReceiveWork() {
		return
	}

	headerHex, err := job.headerHex(c.extraNonce1[:])
	if err != nil {
		log.Debugf("Unable to serialize Stratum job %s header: %v",
			job.ID, err)
		return
	}

	c.writeNotification("mining.notify", []interface{}{
		job.ID,
		headerHex,
		targetHex(c.server.shareTarget),
		job.Height,
		true,
	})
}

func (c *client) canReceiveWork() bool {
	c.stateMtx.RLock()
	defer c.stateMtx.RUnlock()

	return c.subscribed && (c.authorized || c.server.cfg.Authorize == nil)
}

func (c *client) setSubscribed(subscribed bool) {
	c.stateMtx.Lock()
	c.subscribed = subscribed
	c.stateMtx.Unlock()
}

func (c *client) setAuthorized(authorized bool) {
	c.stateMtx.Lock()
	c.authorized = authorized
	c.stateMtx.Unlock()
}

func (j *Job) headerHex(extraNonce1 []byte) (string, error) {
	header := j.Block.Header
	copy(header.ExtraNonce[:ExtraNonce1Size], extraNonce1)
	for i := ExtraNonce1Size; i < len(header.ExtraNonce); i++ {
		header.ExtraNonce[i] = 0
	}
	header.Nonce = 0

	var buf bytes.Buffer
	if err := header.Serialize(&buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf.Bytes()), nil
}

func (c *client) writeResult(id json.RawMessage, result interface{}) {
	c.write(response{
		ID:     id,
		Result: result,
		Error:  nil,
	})
}

func (c *client) writeError(id json.RawMessage, code int, message string) {
	c.write(response{
		ID:     id,
		Result: nil,
		Error:  []interface{}{code, message, nil},
	})
}

func (c *client) writeNotification(method string, params interface{}) {
	c.write(notification{
		ID:     json.RawMessage("null"),
		Method: method,
		Params: params,
	})
}

func (c *client) write(v interface{}) {
	c.writeMtx.Lock()
	defer c.writeMtx.Unlock()

	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err := json.NewEncoder(c.conn).Encode(v)
	_ = c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		c.close()
	}
}

type request struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

func (r *request) id() json.RawMessage {
	return rawID(r.ID)
}

type response struct {
	ID     json.RawMessage `json:"id"`
	Result interface{}     `json:"result"`
	Error  interface{}     `json:"error"`
}

type notification struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params interface{}     `json:"params"`
}

func rawID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func parseTwoStringParams(params []json.RawMessage, firstName,
	secondName string) (string, string, error) {

	if len(params) < 2 {
		return "", "", fmt.Errorf("missing %s or %s", firstName,
			secondName)
	}
	first, err := parseStringParam(params[0], firstName)
	if err != nil {
		return "", "", err
	}
	second, err := parseStringParam(params[1], secondName)
	if err != nil {
		return "", "", err
	}
	return first, second, nil
}

func parseSubmitParams(params []json.RawMessage) (
	worker, jobID, extraNonce2, ntime, nonce string, err error) {

	if len(params) < 5 {
		err = errors.New("mining.submit requires worker, job_id, extranonce2, ntime, and nonce")
		return
	}
	if worker, err = parseStringParam(params[0], "worker"); err != nil {
		return
	}
	if jobID, err = parseStringParam(params[1], "job_id"); err != nil {
		return
	}
	if extraNonce2, err = parseStringParam(params[2], "extranonce2"); err != nil {
		return
	}
	if ntime, err = parseStringParam(params[3], "ntime"); err != nil {
		return
	}
	nonce, err = parseStringParam(params[4], "nonce")
	return
}

func parseStringParam(raw json.RawMessage, name string) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return value, nil
}

func parseFixedHex(value string, size int, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("%s must be %d bytes", name, size)
	}
	return decoded, nil
}

func parseNTime(value string) (uint64, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0, fmt.Errorf("ntime must be hex: %w", err)
	}
	switch len(decoded) {
	case 4:
		return uint64(binary.BigEndian.Uint32(decoded)), nil
	case 8:
		return binary.BigEndian.Uint64(decoded), nil
	default:
		return 0, errors.New("ntime must be 4 or 8 bytes")
	}
}

func parseUint32Hex(value, name string) (uint32, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be hex: %w", name, err)
	}
	if len(decoded) != 4 {
		return 0, fmt.Errorf("%s must be 4 bytes", name)
	}
	return binary.BigEndian.Uint32(decoded), nil
}

func targetHex(target *big.Int) string {
	if target == nil {
		return ""
	}
	out := target.Bytes()
	if len(out) > chainhash.HashSize {
		out = out[len(out)-chainhash.HashSize:]
	}
	if len(out) < chainhash.HashSize {
		padded := make([]byte, chainhash.HashSize)
		copy(padded[chainhash.HashSize-len(out):], out)
		out = padded
	}
	return hex.EncodeToString(out)
}

// ServeConn runs a single Stratum client connection. It is primarily useful for
// focused protocol tests.
func (s *Server) ServeConn(conn net.Conn) {
	c := newClient(s, conn)
	c.serve()
}
