// Copyright (c) 2013-2018 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/lru"
)

const (
	// MaxProtocolVersion is the max protocol version the peer supports.
	MaxProtocolVersion = wire.HnsProtocolVersion

	// DefaultTrickleInterval is the min time between attempts to send an
	// inv message to a peer.
	DefaultTrickleInterval = 10 * time.Second

	// MinAcceptableProtocolVersion is the lowest protocol version that a
	// connected peer may support.
	MinAcceptableProtocolVersion = wire.HnsMinProtocolVersion

	// outputBufferSize is the number of elements the output channels use.
	outputBufferSize = 50

	// invTrickleSize is the maximum amount of inventory to send in a single
	// message when trickling inventory to remote peers.
	maxInvTrickleSize = 1000

	// maxKnownInventory is the maximum number of items to keep in the known
	// inventory cache.
	maxKnownInventory = 1000

	// pingInterval is the interval of time to wait in between sending ping
	// messages.
	pingInterval = 2 * time.Minute

	// negotiateTimeout is the duration of inactivity before we timeout a
	// peer that hasn't completed the initial version negotiation.
	negotiateTimeout = 30 * time.Second

	// idleTimeout is the duration of inactivity before we time out a peer.
	idleTimeout = 5 * time.Minute

	// maxQueuedOutboundMessages and maxQueuedOutboundBytes bound all messages
	// accepted by a peer's asynchronous output queue, including the message
	// currently being written.
	maxQueuedOutboundMessages = 100000
	maxQueuedOutboundBytes    = 32 * 1024 * 1024
	maxQueuedControlMessages  = 16
	maxQueuedControlBytes     = 256 * 1024
	maxQueuedInventory        = maxInvTrickleSize
	outboundMessageOverhead   = 128
	outboundInventoryOverhead = 64
	defaultControlReserve     = 2 * 1024 * 1024
	brontideFrameOverhead     = 64
	brontideTransientCopies   = 3

	// outboundSerializationMemoryFactor accounts for the peak payload and
	// immutable envelope allocations made by EncodeHnsMessage.  Once encoding
	// completes, only the exact envelope and fixed queue/list metadata remain.
	outboundSerializationMemoryFactor = 2

	// A decoded transaction can encode an empty witness element in one byte
	// while retaining a 24-byte slice header.  A factor of 32 covers that
	// worst per-element amplification plus containing slices and structs for
	// legacy concrete OnWrite callbacks.  The full node uses OnWriteType and
	// avoids this decoded allocation entirely.
	outboundDecodedCallbackMemoryFactor = 32
	legacyOnWriteWorkspaceBytes         = 256 * 1024 * 1024

	// stallTickInterval is the interval of time between each check for
	// stalled peers.
	stallTickInterval = 15 * time.Second

	// stallResponseTimeout is the base maximum amount of time messages that
	// expect a response will wait before disconnecting the peer for
	// stalling.  The deadlines are adjusted for callback running times and
	// only checked on each stall tick interval.
	stallResponseTimeout = 30 * time.Second
)

// DefaultWriteTimeout bounds one P2P message write while allowing a maximum
// block to cross slow or proxied links without an aggressive disconnect.
const DefaultWriteTimeout = 2 * time.Minute

// MinimumOutboundQueueBudget is the minimum aggregate budget that can prepare
// and retain any single valid plaintext Handshake message while preserving the
// small control-message reserve.
const MinimumOutboundQueueBudget = outboundSerializationMemoryFactor*(wire.HnsMessageHeaderSize+wire.HnsMaxMessagePayload) +
	outboundMessageOverhead + defaultControlReserve

// MinimumBrontideOutboundQueueBudget is the corresponding minimum when the
// retained plaintext message may also need the bounded Brontide encryption
// copies charged while it is written.
const MinimumBrontideOutboundQueueBudget = (1+brontideTransientCopies)*(wire.HnsMessageHeaderSize+wire.HnsMaxMessagePayload) +
	outboundMessageOverhead + brontideFrameOverhead + defaultControlReserve

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	zeroHash chainhash.Hash

	// sentNonces houses the unique nonces that are generated when pushing
	// version messages that are used to detect self connections.
	sentNonces = lru.NewCache(50)

	// legacyOnWriteWorkspaceBudget bounds concrete message reconstruction for
	// legacy OnWrite observers across all peers without making the serialized
	// message itself consume a type-maximum per-peer queue charge.
	legacyOnWriteWorkspaceBudget = &OutboundQueueBudget{
		maxBytes: legacyOnWriteWorkspaceBytes,
	}
)

var (
	// ErrPeerDisconnected indicates an outbound message was not accepted
	// because the peer is already stopping.
	ErrPeerDisconnected = errors.New("peer is disconnected")

	// ErrOutboundQueueLimit indicates the peer exceeded its own bounded
	// outbound queue and was disconnected as a slow consumer.
	ErrOutboundQueueLimit = errors.New("peer outbound queue limit exceeded")

	// ErrOutboundQueueBudget indicates the aggregate queue budget was full.
	// The message is shed, but the peer remains connected so slow peers cannot
	// force unrelated healthy peers to disconnect.
	ErrOutboundQueueBudget = errors.New("aggregate outbound queue budget exhausted")
)

// MessageListeners defines callback function pointers to invoke with native
// Handshake message listeners for a peer. Any listener which is not set to a
// concrete callback during peer initialization is ignored. Execution of multiple message
// listeners occurs serially, so one callback blocks the execution of the next.
//
// NOTE: Unless otherwise documented, these listeners must NOT directly call any
// blocking calls (such as WaitForShutdown) on the peer instance since the input
// handler goroutine blocks until the callback has completed.  Doing so will
// result in a deadlock.
type MessageListeners struct {
	// OnGetAddr is invoked when a peer receives a getaddr message.
	OnGetAddr func(p *Peer, msg *wire.HnsMsgGetAddr)

	// OnAddr is invoked when a peer receives an addr message.
	OnAddr func(p *Peer, msg *wire.HnsMsgAddr)

	// OnPing is invoked when a peer receives a ping message.
	OnPing func(p *Peer, msg *wire.HnsMsgPing)

	// OnPong is invoked when a peer receives a pong message.
	OnPong func(p *Peer, msg *wire.HnsMsgPong)

	// OnMemPool is invoked when a peer receives a mempool message.
	OnMemPool func(p *Peer, msg *wire.HnsMsgMemPool)

	// OnTx is invoked when a peer receives a tx message.
	OnTx func(p *Peer, msg *wire.HnsMsgTx)

	// OnBlock is invoked when a peer receives a block message.
	OnBlock func(p *Peer, msg *wire.HnsMsgBlock, buf []byte)

	// OnInv is invoked when a peer receives an inv message.
	OnInv func(p *Peer, msg *wire.HnsMsgInv)

	// OnHeaders is invoked when a peer receives a headers message.
	OnHeaders func(p *Peer, msg *wire.HnsMsgHeaders)

	// OnNotFound is invoked when a peer receives a notfound message.
	OnNotFound func(p *Peer, msg *wire.HnsMsgNotFound)

	// OnGetData is invoked when a peer receives a getdata message.
	OnGetData func(p *Peer, msg *wire.HnsMsgGetData)

	// OnGetBlocks is invoked when a peer receives a getblocks message.
	OnGetBlocks func(p *Peer, msg *wire.HnsMsgGetBlocks)

	// OnGetHeaders is invoked when a peer receives a getheaders message.
	OnGetHeaders func(p *Peer, msg *wire.HnsMsgGetHeaders)

	// OnFeeFilter is invoked when a peer receives a feefilter message.
	OnFeeFilter func(p *Peer, msg *wire.HnsMsgFeeFilter)

	// OnFilterAdd is invoked when a peer receives a filteradd message.
	OnFilterAdd func(p *Peer, msg *wire.HnsMsgFilterAdd)

	// OnFilterClear is invoked when a peer receives a filterclear message.
	OnFilterClear func(p *Peer, msg *wire.HnsMsgFilterClear)

	// OnFilterLoad is invoked when a peer receives a filterload message.
	OnFilterLoad func(p *Peer, msg *wire.HnsMsgFilterLoad)

	// OnMerkleBlock is invoked when a peer receives a merkleblock message.
	OnMerkleBlock func(p *Peer, msg *wire.HnsMsgMerkleBlock)

	// OnVersion is invoked when a peer receives a version message. The caller
	// may return a reject message in which case the message will be sent to the
	// peer and the peer will be disconnected.
	OnVersion func(p *Peer, msg *wire.HnsMsgVersion) *wire.HnsMsgReject

	// OnVerAck is invoked when a peer receives a verack message.
	OnVerAck func(p *Peer, msg *wire.HnsMsgVerack)

	// OnReject is invoked when a peer receives a reject message.
	OnReject func(p *Peer, msg *wire.HnsMsgReject)

	// OnSendHeaders is invoked when a peer receives a sendheaders message.
	OnSendHeaders func(p *Peer, msg *wire.HnsMsgSendHeaders)

	// OnSendCmpct is invoked when a peer receives a sendcmpct message.
	OnSendCmpct func(p *Peer, msg *wire.HnsMsgSendCmpct)

	// OnCmpctBlock is invoked when a peer receives a cmpctblock message.
	OnCmpctBlock func(p *Peer, msg *wire.HnsMsgCmpctBlock)

	// OnGetBlockTxn is invoked when a peer receives a getblocktxn message.
	OnGetBlockTxn func(p *Peer, msg *wire.HnsMsgGetBlockTxn)

	// OnBlockTxn is invoked when a peer receives a blocktxn message.
	OnBlockTxn func(p *Peer, msg *wire.HnsMsgBlockTxn)

	// OnGetProof is invoked when a peer receives a getproof message.
	OnGetProof func(p *Peer, msg *wire.HnsMsgGetProof)

	// OnProof is invoked when a peer receives a proof message.
	OnProof func(p *Peer, msg *wire.HnsMsgProof)

	// OnClaim is invoked when a peer receives a claim message.
	OnClaim func(p *Peer, msg *wire.HnsMsgClaim)

	// OnAirDrop is invoked when a peer receives an airdrop message.
	OnAirDrop func(p *Peer, msg *wire.HnsMsgAirDrop)

	// OnUnknown is invoked when a peer receives a type-30 unknown message.
	OnUnknown func(p *Peer, msg *wire.HnsMsgUnknown)

	// OnRead is invoked when a peer receives a Handshake message.
	OnRead func(p *Peer, bytesRead int, msg wire.HandshakeMessage, err error)

	// OnWrite is invoked when we write a Handshake message to a peer.  The
	// callback receives the concrete message value.
	OnWrite func(p *Peer, bytesWritten int, msg wire.HandshakeMessage, err error)

	// OnWriteType is the allocation-free alternative for observers that only
	// need the message class.  It is invoked for direct and queued writes.
	OnWriteType func(p *Peer, bytesWritten int, msgType wire.HnsMsgType, err error)
}

// Config is the struct to hold configuration options useful to Peer.
type Config struct {
	// NewestBlock specifies a callback which provides the newest block
	// details to the peer as needed.  This can be nil in which case the
	// peer will report a block height of 0, however it is good practice for
	// peers to specify this so their currently best known is accurately
	// reported.
	NewestBlock HashFunc

	// HostToNetAddress returns the netaddress for the given host. This can be
	// nil in  which case the host will be parsed as an IP address.
	HostToNetAddress HostToNetAddrFunc

	// Proxy indicates a proxy is being used for connections.  The only
	// effect this has is to prevent leaking the tor proxy address, so it
	// only needs to specified if using a tor proxy.
	Proxy string

	// UserAgentName specifies the user agent name to advertise.  It is
	// highly recommended to specify this value.
	UserAgentName string

	// UserAgentVersion specifies the user agent version to advertise.  It
	// is highly recommended to specify this value and that it follows the
	// form "major.minor.revision" e.g. "2.6.41".
	UserAgentVersion string

	// UserAgentComments specify the user agent comments to advertise.  These
	// values must not contain the illegal characters specified in BIP 14:
	// '/', ':', '(', ')'.
	UserAgentComments []string

	// ChainParams identifies which chain parameters the peer is associated
	// with.  It is highly recommended to specify this field, however it can
	// be omitted in which case the regression test network will be used.
	ChainParams *chaincfg.Params

	// Services specifies which services to advertise as supported by the
	// local peer.  This field can be omitted in which case it will be 0
	// and therefore advertise no supported services.
	Services wire.ServiceFlag

	// ProtocolVersion specifies the maximum protocol version to use and
	// advertise.  This field can be omitted in which case
	// peer.MaxProtocolVersion will be used.
	ProtocolVersion uint32

	// DisableRelayTx specifies if the remote peer should be informed to
	// not send inv messages for transactions.
	DisableRelayTx bool

	// Listeners houses callback functions to be invoked on receiving peer
	// messages.
	Listeners MessageListeners

	// TrickleInterval is the duration of the ticker which trickles down the
	// inventory to a peer.
	TrickleInterval time.Duration

	// AllowSelfConns is only used to allow the tests to bypass the self
	// connection detecting and disconnect logic since they intentionally
	// do so for testing purposes.
	AllowSelfConns bool

	// DisableStallHandler if true, then the stall handler that attempts to
	// disconnect from peers that appear to be taking too long to respond
	// to requests won't be activated. This can be useful in certain regtest
	// scenarios where the stall behavior isn't important to the system
	// under test.
	DisableStallHandler bool

	// WriteTimeout bounds each write to the remote peer.  A non-positive value
	// selects DefaultWriteTimeout.
	WriteTimeout time.Duration

	// OutboundQueueBudget optionally shares an aggregate byte budget across
	// multiple peers.  The server supplies one budget to all of its peers.
	OutboundQueueBudget *OutboundQueueBudget

	// MaxOutboundQueueMessages and MaxOutboundQueueBytes optionally override
	// the per-peer queue bounds.  Non-positive values select safe defaults.
	MaxOutboundQueueMessages int
	MaxOutboundQueueBytes    uint64

	// MaxOutboundInventory optionally overrides the number of inventory
	// announcements retained for trickled delivery.  A non-positive value
	// selects the default.
	MaxOutboundInventory int

	// UsingV2Conn is defined if and only if we accept and attempt to make
	// v2 connections.
	UsingV2Conn bool
}

// OutboundQueueBudget bounds response generation, serialization, retained
// queue data, and transport-copy workspace across a group of peers.  It is not
// a bound on all process memory used by P2P handling.
type OutboundQueueBudget struct {
	prepareMu           sync.Mutex
	mu                  sync.Mutex
	maxBytes            uint64
	controlReserveBytes uint64
	usedBytes           uint64
}

// NewOutboundQueueBudget constructs a shared outbound queue budget.  A zero
// maximum disables the aggregate limit.
func NewOutboundQueueBudget(maxBytes uint64) *OutboundQueueBudget {
	controlReserve := uint64(defaultControlReserve)
	if fraction := maxBytes / 8; controlReserve > fraction {
		controlReserve = fraction
	}
	return &OutboundQueueBudget{
		maxBytes:            maxBytes,
		controlReserveBytes: controlReserve,
	}
}

func (b *OutboundQueueBudget) reserve(bytes uint64, control bool) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.maxBytes
	if !control && limit > b.controlReserveBytes {
		limit -= b.controlReserveBytes
	}
	if b.maxBytes > 0 && (bytes > limit || b.usedBytes > limit-bytes) {

		return false
	}
	b.usedBytes += bytes
	return true
}

func (b *OutboundQueueBudget) release(bytes uint64) {
	if b == nil || bytes == 0 {
		return
	}
	b.mu.Lock()
	b.usedBytes -= bytes
	b.mu.Unlock()
}

// OutboundQueueWorkspace reserves bounded transient memory used to construct
// an outbound response before it has an immutable serialized representation.
type OutboundQueueWorkspace struct {
	budget *OutboundQueueBudget
	bytes  uint64
	once   sync.Once
}

// AcquireWorkspace reserves response-generation memory from the aggregate
// output budget.  The returned workspace must be released.
func (b *OutboundQueueBudget) AcquireWorkspace(
	bytes uint64) (*OutboundQueueWorkspace, bool) {

	if !b.reserve(bytes, false) {
		return nil, false
	}
	return &OutboundQueueWorkspace{budget: b, bytes: bytes}, true
}

// Release returns a response-generation workspace reservation.
func (w *OutboundQueueWorkspace) Release() {
	if w == nil {
		return
	}
	w.once.Do(func() { w.budget.release(w.bytes) })
}

// FormatUserAgent returns the local user-agent string advertised to peers.
func FormatUserAgent(name, version string, comments []string) string {
	agent := wire.DefaultUserAgent
	if name != "" || version != "" {
		comment := ""
		if len(comments) > 0 {
			comment = "(" + strings.Join(comments, "; ") + ")"
		}
		agent += fmt.Sprintf("%s:%s%s/", name, version, comment)
	}
	return agent
}

// minUint32 is a helper function to return the minimum of two uint32s.
// This avoids a math import and the need to cast to floats.
func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// newNetAddress attempts to extract the IP address and port from the passed
// net.Addr interface and create a bitcoin NetAddress structure using that
// information.
func newNetAddress(addr net.Addr, services wire.ServiceFlag) (*wire.NetAddress, error) {
	// addr will be a net.TCPAddr when not using a proxy.
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		ip := tcpAddr.IP
		port := uint16(tcpAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// addr will be a socks.ProxiedAddr when using a proxy.
	if proxiedAddr, ok := addr.(*socks.ProxiedAddr); ok {
		ip := net.ParseIP(proxiedAddr.Host)
		if ip == nil {
			ip = net.ParseIP("0.0.0.0")
		}
		port := uint16(proxiedAddr.Port)
		na := wire.NewNetAddressIPPort(ip, port, services)
		return na, nil
	}

	// For the most part, addr should be one of the two above cases, but
	// to be safe, fall back to trying to parse the information from the
	// address string as a last resort.
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	na := wire.NewNetAddressIPPort(ip, uint16(port), services)
	return na, nil
}

// outMsg is used to house a message to be sent along with a channel to signal
// when the message has been sent (or won't be sent due to things such as
// shutdown)
type outMsg struct {
	message           wire.HandshakeMessage
	messageType       wire.HnsMsgType
	encoded           []byte
	doneChan          chan<- struct{}
	callbackWorkspace *OutboundQueueWorkspace
	queueBytes        uint64
	budgetReserved    bool
	control           bool
	reserved          bool
}

type outInv struct {
	invVect    wire.InvVect
	queueBytes uint64
	reserved   bool
}

// serializedHandshakeMessage is the allocation-free message type view used by
// the stall handler for queued messages.
type serializedHandshakeMessage struct {
	messageType wire.HnsMsgType
}

func (m *serializedHandshakeMessage) Type() wire.HnsMsgType {
	return m.messageType
}

func (m *serializedHandshakeMessage) Encode() []byte {
	return nil
}

func (*serializedHandshakeMessage) Decode([]byte) error {
	return nil
}

type outboundQueueResult uint8

const (
	outboundQueueAccepted outboundQueueResult = iota
	outboundQueueStopped
	outboundQueuePeerLimit
	outboundQueueGlobalLimit
	outboundQueueDuplicate
)

// stallControlCmd represents the command of a stall control message.
type stallControlCmd uint8

// Constants for the command of a stall control message.
const (
	// sccSendMessage indicates a message is being sent to the remote peer.
	sccSendMessage stallControlCmd = iota

	// sccReceiveMessage indicates a message has been received from the
	// remote peer.
	sccReceiveMessage

	// sccHandlerStart indicates a callback handler is about to be invoked.
	sccHandlerStart

	// sccHandlerStart indicates a callback handler has completed.
	sccHandlerDone
)

// stallControlMsg is used to signal the stall handler about specific events
// so it can properly detect and handle stalled remote peers.
type stallControlMsg struct {
	command stallControlCmd
	message wire.HandshakeMessage
}

// StatsSnap is a snapshot of peer stats at a point in time.
type StatsSnap struct {
	ID             int32
	Addr           string
	Services       wire.ServiceFlag
	LastSend       time.Time
	LastRecv       time.Time
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       time.Time
	TimeOffset     int64
	Version        uint32
	UserAgent      string
	Inbound        bool
	StartingHeight int32
	LastBlock      int32
	LastPingNonce  uint64
	LastPingTime   time.Time
	LastPingMicros int64
	V2Connection   bool
}

// HashFunc is a function which returns a block hash, height and error
// It is used as a callback to get newest block details.
type HashFunc func() (hash *chainhash.Hash, height int32, err error)

// AddrFunc is a func which takes an address and returns a related address.
type AddrFunc func(remoteAddr *wire.NetAddress) *wire.NetAddress

// HostToNetAddrFunc is a func which takes a host, port, services and returns
// the netaddress.
type HostToNetAddrFunc func(host string, port uint16,
	services wire.ServiceFlag) (*wire.NetAddressV2, error)

// NOTE: The overall data flow of a peer is split into 3 goroutines.  Inbound
// messages are read via the inHandler goroutine and generally dispatched to
// their own handler.  For inbound data-related messages such as blocks,
// transactions, and inventory, the data is handled by the corresponding
// message handlers.  The data flow for outbound messages is split into 2
// goroutines, queueHandler and outHandler.  The first, queueHandler, is used
// as a way for external entities to queue messages, by way of the QueueMessage
// function, quickly regardless of whether the peer is currently sending or not.
// It acts as the traffic cop between the external world and the actual
// goroutine which writes to the network socket.

// Peer provides a basic concurrent safe bitcoin peer for handling bitcoin
// communications via the peer-to-peer protocol.  It provides full duplex
// reading and writing, automatic handling of the initial handshake process,
// querying of usage statistics and other information about the remote peer such
// as its address, user agent, and protocol version, output message queuing,
// inventory trickling, and the ability to dynamically register and unregister
// callbacks for handling bitcoin protocol messages.
//
// Outbound messages are typically queued via QueueMessage or QueueInventory.
// QueueMessage is intended for all messages, including responses to data such
// as blocks and transactions.  QueueInventory, on the other hand, is only
// intended for relaying inventory as it employs a trickling mechanism to batch
// the inventory together.  However, some helper functions for pushing messages
// of specific types that typically require common special handling are
// provided as a convenience.
type Peer struct {
	// The following variables must only be used atomically.
	bytesReceived uint64
	bytesSent     uint64
	lastRecv      int64
	lastSend      int64
	connected     int32
	disconnect    int32

	conn         net.Conn
	lifecycleMtx sync.Mutex
	lifecycleWg  sync.WaitGroup

	// These fields are set at creation time and never modified, so they are
	// safe to read from concurrently without a mutex.
	addr    string
	cfg     Config
	inbound bool

	flagsMtx             sync.Mutex // protects the peer flags below
	na                   *wire.NetAddressV2
	id                   int32
	userAgent            string
	services             wire.ServiceFlag
	versionKnown         bool
	advertisedProtoVer   uint32 // protocol version advertised by remote
	protocolVersion      uint32 // negotiated protocol version
	sendHeadersPreferred bool   // peer sent a sendheaders message
	verAckReceived       bool
	witnessEnabled       bool

	wireEncoding wire.MessageEncoding

	knownInventory     lru.Cache
	prepareMtx         sync.Mutex
	queueMtx           sync.Mutex
	queueEnqueueWg     sync.WaitGroup
	queueStopped       bool
	queuedMessages     int
	queuedInventory    int
	queuedBytes        uint64
	queuedControlMsgs  int
	queuedControlBytes uint64
	queuedInventorySet map[wire.InvVect]struct{}
	maxQueuedMessages  int
	maxQueuedInventory int
	maxQueuedBytes     uint64
	queueBudget        *OutboundQueueBudget
	prevGetBlocksMtx   sync.Mutex
	prevGetBlocksBegin *chainhash.Hash
	prevGetBlocksStop  *chainhash.Hash
	prevGetHdrsMtx     sync.Mutex
	prevGetHdrsBegin   *chainhash.Hash
	prevGetHdrsStop    *chainhash.Hash

	// These fields keep track of statistics for the peer and are protected
	// by the statsMtx mutex.
	statsMtx           sync.RWMutex
	timeOffset         int64
	timeConnected      time.Time
	startingHeight     int32
	lastBlock          int32
	lastAnnouncedBlock *chainhash.Hash
	lastPingNonce      uint64    // Set to nonce if we have a pending ping.
	lastPingTime       time.Time // Time we sent last ping.
	lastPingMicros     int64     // Time for last ping to return.

	stallControl  chan stallControlMsg
	outputQueue   chan outMsg
	sendQueue     chan outMsg
	sendDoneQueue chan struct{}
	outputInvChan chan outInv
	inQuit        chan struct{}
	queueQuit     chan struct{}
	outQuit       chan struct{}
	quit          chan struct{}
}

// String returns the peer's address and directionality as a human-readable
// string.
//
// This function is safe for concurrent access.
func (p *Peer) String() string {
	return fmt.Sprintf("%s (%s)", p.addr, directionString(p.inbound))
}

// UpdateLastBlockHeight updates the last known block for the peer.
//
// This function is safe for concurrent access.
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	if newHeight <= p.lastBlock {
		p.statsMtx.Unlock()
		return
	}
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.addr, p.lastBlock, newHeight)
	p.lastBlock = newHeight
	p.statsMtx.Unlock()
}

// UpdateLastAnnouncedBlock updates meta-data about the last block hash this
// peer is known to have announced.
//
// This function is safe for concurrent access.
func (p *Peer) UpdateLastAnnouncedBlock(blkHash *chainhash.Hash) {
	log.Tracef("Updating last blk for peer %v, %v", p.addr, blkHash)

	p.statsMtx.Lock()
	p.lastAnnouncedBlock = blkHash
	p.statsMtx.Unlock()
}

// AddKnownInventory adds the passed inventory to the cache of known inventory
// for the peer.
//
// This function is safe for concurrent access.
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	if invVect != nil {
		p.knownInventory.Add(*invVect)
	}
}

// StatsSnapshot returns a snapshot of the current peer flags and statistics.
//
// This function is safe for concurrent access.
func (p *Peer) StatsSnapshot() *StatsSnap {
	p.statsMtx.RLock()

	p.flagsMtx.Lock()
	id := p.id
	addr := p.addr
	userAgent := p.userAgent
	services := p.services
	protocolVersion := p.advertisedProtoVer
	p.flagsMtx.Unlock()

	// Get a copy of all relevant flags and stats.
	statsSnap := &StatsSnap{
		ID:             id,
		Addr:           addr,
		UserAgent:      userAgent,
		Services:       services,
		LastSend:       p.LastSend(),
		LastRecv:       p.LastRecv(),
		BytesSent:      p.BytesSent(),
		BytesRecv:      p.BytesReceived(),
		ConnTime:       p.timeConnected,
		TimeOffset:     p.timeOffset,
		Version:        protocolVersion,
		Inbound:        p.inbound,
		StartingHeight: p.startingHeight,
		LastBlock:      p.lastBlock,
		LastPingNonce:  p.lastPingNonce,
		LastPingMicros: p.lastPingMicros,
		LastPingTime:   p.lastPingTime,
		V2Connection:   p.cfg.UsingV2Conn,
	}

	p.statsMtx.RUnlock()
	return statsSnap
}

// ID returns the peer id.
//
// This function is safe for concurrent access.
func (p *Peer) ID() int32 {
	p.flagsMtx.Lock()
	id := p.id
	p.flagsMtx.Unlock()

	return id
}

// NA returns the peer network address.
//
// This function is safe for concurrent access.
func (p *Peer) NA() *wire.NetAddressV2 {
	p.flagsMtx.Lock()
	na := p.na
	p.flagsMtx.Unlock()

	return na
}

// Addr returns the peer address.
//
// This function is safe for concurrent access.
func (p *Peer) Addr() string {
	// The address doesn't change after initialization, therefore it is not
	// protected by a mutex.
	return p.addr
}

// Inbound returns whether the peer is inbound.
//
// This function is safe for concurrent access.
func (p *Peer) Inbound() bool {
	return p.inbound
}

// Services returns the services flag of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) Services() wire.ServiceFlag {
	p.flagsMtx.Lock()
	services := p.services
	p.flagsMtx.Unlock()

	return services
}

// UserAgent returns the user agent of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) UserAgent() string {
	p.flagsMtx.Lock()
	userAgent := p.userAgent
	p.flagsMtx.Unlock()

	return userAgent
}

// LastAnnouncedBlock returns the last announced block of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastAnnouncedBlock() *chainhash.Hash {
	p.statsMtx.RLock()
	lastAnnouncedBlock := p.lastAnnouncedBlock
	p.statsMtx.RUnlock()

	return lastAnnouncedBlock
}

// LastPingNonce returns the last ping nonce of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingNonce() uint64 {
	p.statsMtx.RLock()
	lastPingNonce := p.lastPingNonce
	p.statsMtx.RUnlock()

	return lastPingNonce
}

// LastPingTime returns the last ping time of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingTime() time.Time {
	p.statsMtx.RLock()
	lastPingTime := p.lastPingTime
	p.statsMtx.RUnlock()

	return lastPingTime
}

// LastPingMicros returns the last ping micros of the remote peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastPingMicros() int64 {
	p.statsMtx.RLock()
	lastPingMicros := p.lastPingMicros
	p.statsMtx.RUnlock()

	return lastPingMicros
}

// VersionKnown returns the whether or not the version of a peer is known
// locally.
//
// This function is safe for concurrent access.
func (p *Peer) VersionKnown() bool {
	p.flagsMtx.Lock()
	versionKnown := p.versionKnown
	p.flagsMtx.Unlock()

	return versionKnown
}

// VerAckReceived returns whether or not a verack message was received by the
// peer.
//
// This function is safe for concurrent access.
func (p *Peer) VerAckReceived() bool {
	p.flagsMtx.Lock()
	verAckReceived := p.verAckReceived
	p.flagsMtx.Unlock()

	return verAckReceived
}

// ProtocolVersion returns the negotiated peer protocol version.
//
// This function is safe for concurrent access.
func (p *Peer) ProtocolVersion() uint32 {
	p.flagsMtx.Lock()
	protocolVersion := p.protocolVersion
	p.flagsMtx.Unlock()

	return protocolVersion
}

// LastBlock returns the last block of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastBlock() int32 {
	p.statsMtx.RLock()
	lastBlock := p.lastBlock
	p.statsMtx.RUnlock()

	return lastBlock
}

// LastSend returns the last send time of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastSend() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastSend), 0)
}

// LastRecv returns the last recv time of the peer.
//
// This function is safe for concurrent access.
func (p *Peer) LastRecv() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastRecv), 0)
}

// LocalAddr returns the local address of the connection.
//
// This function is safe for concurrent access.
func (p *Peer) LocalAddr() net.Addr {
	var localAddr net.Addr
	if atomic.LoadInt32(&p.connected) != 0 {
		localAddr = p.conn.LocalAddr()
	}
	return localAddr
}

// BytesSent returns the total number of bytes sent by the peer.
//
// This function is safe for concurrent access.
func (p *Peer) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

// BytesReceived returns the total number of bytes received by the peer.
//
// This function is safe for concurrent access.
func (p *Peer) BytesReceived() uint64 {
	return atomic.LoadUint64(&p.bytesReceived)
}

// TimeConnected returns the time at which the peer connected.
//
// This function is safe for concurrent access.
func (p *Peer) TimeConnected() time.Time {
	p.statsMtx.RLock()
	timeConnected := p.timeConnected
	p.statsMtx.RUnlock()

	return timeConnected
}

// TimeOffset returns the number of seconds the local time was offset from the
// time the peer reported during the initial negotiation phase.  Negative values
// indicate the remote peer's time is before the local time.
//
// This function is safe for concurrent access.
func (p *Peer) TimeOffset() int64 {
	p.statsMtx.RLock()
	timeOffset := p.timeOffset
	p.statsMtx.RUnlock()

	return timeOffset
}

// StartingHeight returns the last known height the peer reported during the
// initial negotiation phase.
//
// This function is safe for concurrent access.
func (p *Peer) StartingHeight() int32 {
	p.statsMtx.RLock()
	startingHeight := p.startingHeight
	p.statsMtx.RUnlock()

	return startingHeight
}

// WantsHeaders returns if the peer wants header messages instead of
// inventory vectors for blocks.
//
// This function is safe for concurrent access.
func (p *Peer) WantsHeaders() bool {
	p.flagsMtx.Lock()
	sendHeadersPreferred := p.sendHeadersPreferred
	p.flagsMtx.Unlock()

	return sendHeadersPreferred
}

// IsWitnessEnabled returns true if the peer has signalled that it supports
// segregated witness.
//
// This function is safe for concurrent access.
func (p *Peer) IsWitnessEnabled() bool {
	p.flagsMtx.Lock()
	witnessEnabled := p.witnessEnabled
	p.flagsMtx.Unlock()

	return witnessEnabled
}

// PushAddrMsg sends an addr message to the connected peer using the provided
// addresses.  This function is useful over manually sending the message via
// QueueMessage since it automatically limits the addresses to the maximum
// number allowed by the message and randomizes the chosen addresses when there
// are too many.  It returns the addresses that were actually sent and no
// message will be sent if there are no entries in the provided addresses slice.
//
// This function is safe for concurrent access.
func (p *Peer) PushAddrMsg(addresses []*wire.NetAddress) ([]*wire.NetAddress, error) {
	addressCount := len(addresses)

	// Nothing to send.
	if addressCount == 0 {
		return nil, nil
	}

	addrList := make([]*wire.NetAddress, addressCount)
	copy(addrList, addresses)

	// Randomize the addresses sent if there are more than the maximum allowed.
	if addressCount > wire.MaxAddrPerMsg {
		// Shuffle the address list.
		for i := 0; i < wire.MaxAddrPerMsg; i++ {
			j := i + rand.Intn(addressCount-i)
			addrList[i], addrList[j] = addrList[j], addrList[i]
		}

		// Truncate it to the maximum size.
		addrList = addrList[:wire.MaxAddrPerMsg]
	}

	msg := &wire.HnsMsgAddr{Peers: make([]wire.HnsNetAddress, len(addrList))}
	for i := range addrList {
		msg.Peers[i] = wire.NewHnsNetAddress(addrList[i])
	}
	if err := p.TryQueueMessage(msg, nil); err != nil {
		return nil, err
	}
	return addrList, nil
}

// PushGetBlocksMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
func (p *Peer) PushGetBlocksMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getblocks requests.
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getblocks requests.
	p.prevGetBlocksMtx.Lock()
	isDuplicate := p.prevGetBlocksStop != nil && p.prevGetBlocksBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetBlocksStop) &&
		beginHash.IsEqual(p.prevGetBlocksBegin)
	p.prevGetBlocksMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getblocks] with begin "+
			"hash %v, stop hash %v", beginHash, stopHash)
		return nil
	}

	// Construct the getblocks request and queue it to be sent.
	msg := &wire.HnsMsgGetBlocks{}
	copy(msg.StopHash[:], stopHash[:])
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	if err := p.TryQueueMessage(msg, nil); err != nil {
		return err
	}

	// Update the previous getblocks request information for filtering
	// duplicates.
	p.prevGetBlocksMtx.Lock()
	p.prevGetBlocksBegin = beginHash
	p.prevGetBlocksStop = stopHash
	p.prevGetBlocksMtx.Unlock()
	return nil
}

// PushGetHeadersMsg sends a getblocks message for the provided block locator
// and stop hash.  It will ignore back-to-back duplicate requests.
//
// This function is safe for concurrent access.
func (p *Peer) PushGetHeadersMsg(locator blockchain.BlockLocator, stopHash *chainhash.Hash) error {
	// Extract the begin hash from the block locator, if one was specified,
	// to use for filtering duplicate getheaders requests.
	var beginHash *chainhash.Hash
	if len(locator) > 0 {
		beginHash = locator[0]
	}

	// Filter duplicate getheaders requests.
	p.prevGetHdrsMtx.Lock()
	isDuplicate := p.prevGetHdrsStop != nil && p.prevGetHdrsBegin != nil &&
		beginHash != nil && stopHash.IsEqual(p.prevGetHdrsStop) &&
		beginHash.IsEqual(p.prevGetHdrsBegin)
	p.prevGetHdrsMtx.Unlock()

	if isDuplicate {
		log.Tracef("Filtering duplicate [getheaders] with begin hash %v",
			beginHash)
		return nil
	}

	// Construct the getheaders request and queue it to be sent.
	msg := &wire.HnsMsgGetHeaders{}
	copy(msg.StopHash[:], stopHash[:])
	for _, hash := range locator {
		err := msg.AddBlockLocatorHash(hash)
		if err != nil {
			return err
		}
	}
	if err := p.TryQueueMessage(msg, nil); err != nil {
		return err
	}

	// Update the previous getheaders request information for filtering
	// duplicates.
	p.prevGetHdrsMtx.Lock()
	p.prevGetHdrsBegin = beginHash
	p.prevGetHdrsStop = stopHash
	p.prevGetHdrsMtx.Unlock()
	return nil
}

// PushRejectMsg sends a reject message for the provided Handshake message type,
// reject code, reject reason, and hash. The hash will only be used when the
// message type requires one and should be nil in other cases. The wait
// parameter will cause the function to block until the reject message has
// actually been sent.
//
// This function is safe for concurrent access.
func (p *Peer) PushRejectMsg(msgType wire.HnsMsgType, code wire.RejectCode,
	reason string, hash *chainhash.Hash, wait bool) {

	// Don't bother sending the reject message if the Handshake protocol
	// version is too low.
	if p.VersionKnown() && p.ProtocolVersion() < wire.HnsMinProtocolVersion {
		return
	}

	msg := &wire.HnsMsgReject{
		Message: msgType,
		Code:    code,
		Reason:  reason,
	}
	if hnsRejectMessageRequiresHash(msgType) {
		if hash == nil {
			log.Warnf("Sending a reject message for command "+
				"type %v which should have specified a hash "+
				"but does not", msgType)
			hash = &zeroHash
		}
		copy(msg.Hash[:], hash[:])
	}

	// Send the message without waiting if the caller has not requested it.
	if !wait {
		p.QueueHnsMessage(msg, nil)
		return
	}

	// Send the message and block until it has been sent before returning.
	doneChan := make(chan struct{}, 1)
	p.QueueHnsMessage(msg, doneChan)
	<-doneChan
}

func hnsRejectMessageRequiresHash(msgType wire.HnsMsgType) bool {
	switch msgType {
	case wire.HnsMsgTypeBlock, wire.HnsMsgTypeTx, wire.HnsMsgTypeClaim,
		wire.HnsMsgTypeAirDrop:
		return true
	default:
		return false
	}
}

func hnsTimeToTime(sec uint64) time.Time {
	const maxInt64Unix = uint64(1<<63 - 1)
	if sec > maxInt64Unix {
		sec = maxInt64Unix
	}
	return time.Unix(int64(sec), 0)
}

// handlePingMsg is invoked when a peer receives a ping message.
func (p *Peer) handlePingMsg(msg *wire.HnsMsgPing) {
	// Include nonce from ping so pong can be identified.
	if err := p.TryQueueHnsMessage(
		&wire.HnsMsgPong{Nonce: msg.Nonce}, nil,
	); err != nil {
		log.Debugf("Unable to queue mandatory pong to %s: %v", p, err)
		p.Disconnect()
	}
}

// handlePongMsg is invoked when a peer receives a pong message. It updates the
// ping statistics as required for recent clients.
func (p *Peer) handlePongMsg(msg *wire.HnsMsgPong) {
	// Arguably we could use a buffered channel here sending data
	// in a fifo manner whenever we send a ping, or a list keeping track of
	// the times of each ping. For now we just make a best effort and
	// only record stats if it was for the last ping sent. Any preceding
	// and overlapping pings will be ignored. It is unlikely to occur
	// without large usage of the ping rpc call since we ping infrequently
	// enough that if they overlap we would have timed out the peer.
	p.statsMtx.Lock()
	nonce := binary.LittleEndian.Uint64(msg.Nonce[:])
	if p.lastPingNonce != 0 && nonce == p.lastPingNonce {
		p.lastPingMicros = time.Since(p.lastPingTime).Nanoseconds()
		p.lastPingMicros /= 1000 // convert to usec.
		p.lastPingNonce = 0
	}
	p.statsMtx.Unlock()
}

// readMessage reads the next Handshake message from the peer with logging. The
// partial bool is retained for the old transport-downgrade path; Handshake
// uses Brontide/plaintext transports instead.
func (p *Peer) readMessage(encoding wire.MessageEncoding, partial bool) (
	wire.HandshakeMessage, []byte, error) {

	var (
		n   int
		msg wire.HandshakeMessage
		buf []byte
		err error
	)

	n, msg, buf, err = wire.ReadHandshakeMessageN(p.conn, p.cfg.ChainParams.Net)

	atomic.AddUint64(&p.bytesReceived, uint64(n))
	if p.cfg.Listeners.OnRead != nil {
		p.cfg.Listeners.OnRead(p, n, msg, err)
	}
	if err != nil {
		return nil, nil, err
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		summary := messageSummary(msg)
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Received %v%s from %s",
			msg.Type(), summary, p)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(msg)
	}))
	log.Tracef("%v", newLogClosure(func() string {
		return spew.Sdump(buf)
	}))

	return msg, buf, nil
}

// writeMessage sends a Handshake message to the peer with logging.
func (p *Peer) writeMessage(msg wire.HandshakeMessage) error {
	encoded, err := wire.EncodeHnsMessage(msg,
		uint32(p.cfg.ChainParams.Net))
	if err != nil {
		return err
	}
	return p.writeEncodedMessage(msg, msg.Type(), encoded)
}

func (p *Peer) writeEncodedMessage(msg wire.HandshakeMessage,
	msgType wire.HnsMsgType, encoded []byte) error {

	// Don't do anything if we're disconnecting.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return nil
	}

	written := 0
	err := p.conn.SetWriteDeadline(time.Now().Add(p.cfg.WriteTimeout))
	if err == nil {
		for written < len(encoded) {
			var n int
			n, err = p.conn.Write(encoded[written:])
			written += n
			if err != nil {
				break
			}
			if n == 0 {
				err = io.ErrShortWrite
				break
			}
		}
		if clearErr := p.conn.SetWriteDeadline(time.Time{}); err == nil {
			err = clearErr
		}
	}

	// Use closures to log expensive operations so they are only run when
	// the logging level requires it.
	log.Debugf("%v", newLogClosure(func() string {
		// Debug summary of message.
		var summary string
		if msg != nil {
			summary = messageSummary(msg)
		}
		if len(summary) > 0 {
			summary = " (" + summary + ")"
		}
		return fmt.Sprintf("Sending %v%s to %s", msgType,
			summary, p)
	}))
	if msg != nil {
		log.Tracef("%v", newLogClosure(func() string {
			return spew.Sdump(msg)
		}))
	}
	atomic.AddUint64(&p.bytesSent, uint64(written))
	if p.cfg.Listeners.OnWrite != nil {
		p.cfg.Listeners.OnWrite(p, written, msg, err)
	}
	if p.cfg.Listeners.OnWriteType != nil {
		p.cfg.Listeners.OnWriteType(p, written, msgType, err)
	}
	return err
}

func (p *Peer) prepareOutboundMessage(msg *outMsg) error {
	if msg.encoded != nil {
		return nil
	}
	if msg.message == nil {
		msg.queueBytes = outboundMessageOverhead
		return nil
	}
	msg.messageType = msg.message.Type()
	msg.control = isOutboundControlMessage(msg.messageType)
	encoded, err := wire.EncodeHnsMessage(msg.message,
		uint32(p.cfg.ChainParams.Net))
	if err != nil {
		return err
	}
	msg.encoded = encoded
	// The legacy OnWrite callback promises the original concrete message.
	// Retain it only when that callback is configured.  OnWriteType users,
	// including the full node, keep the allocation-free serialized path.
	if p.cfg.Listeners.OnWrite == nil {
		msg.message = nil
	}
	msg.queueBytes = uint64(len(encoded)) + outboundMessageOverhead
	if p.cfg.UsingV2Conn {
		msg.queueBytes += uint64(len(encoded))*brontideTransientCopies +
			brontideFrameOverhead
	}
	return nil
}

func (p *Peer) reserveLegacyOnWriteWorkspace(msg *outMsg) bool {
	if p.cfg.Listeners.OnWrite == nil || msg.message == nil ||
		msg.callbackWorkspace != nil {

		return true
	}

	workspaceBytes := uint64(len(msg.encoded)) *
		outboundDecodedCallbackMemoryFactor
	workspace, ok := legacyOnWriteWorkspaceBudget.AcquireWorkspace(workspaceBytes)
	if !ok {
		return false
	}
	msg.callbackWorkspace = workspace
	return true
}

func releaseLegacyOnWriteWorkspace(msg *outMsg) {
	if msg.callbackWorkspace == nil {
		return
	}
	msg.callbackWorkspace.Release()
	msg.callbackWorkspace = nil
}

func (p *Peer) releasePreparedOutboundMessage(msg *outMsg) {
	if msg.budgetReserved {
		p.queueBudget.release(msg.queueBytes)
		msg.budgetReserved = false
	}
	releaseLegacyOnWriteWorkspace(msg)
}

func isOutboundControlMessage(msgType wire.HnsMsgType) bool {
	switch msgType {
	case wire.HnsMsgTypeVersion,
		wire.HnsMsgTypeVerack,
		wire.HnsMsgTypePing,
		wire.HnsMsgTypePong,
		wire.HnsMsgTypeGetAddr,
		wire.HnsMsgTypeSendHeaders,
		wire.HnsMsgTypeReject,
		wire.HnsMsgTypeMempool,
		wire.HnsMsgTypeFilterLoad,
		wire.HnsMsgTypeFilterAdd,
		wire.HnsMsgTypeFilterClear,
		wire.HnsMsgTypeFeeFilter,
		wire.HnsMsgTypeSendCmpct,
		wire.HnsMsgTypeGetProof:

		return true
	default:
		return false
	}
}

func outboundDataByteLimit(limit uint64) uint64 {
	controlReserve := uint64(maxQueuedControlBytes)
	if halfLimit := limit / 2; controlReserve > halfLimit {
		controlReserve = halfLimit
	}
	return limit - controlReserve
}

func outboundDataMessageLimit(limit int) int {
	controlReserve := maxQueuedControlMessages
	if halfLimit := limit / 2; controlReserve > halfLimit {
		controlReserve = halfLimit
	}
	return limit - controlReserve
}

func (p *Peer) prepareOutboundMessageBudgeted(
	msg *outMsg) (outboundQueueResult, error) {

	if msg.encoded != nil || msg.message == nil || p.queueBudget == nil {
		return outboundQueueAccepted, p.prepareOutboundMessage(msg)
	}
	msg.messageType = msg.message.Type()
	msg.control = isOutboundControlMessage(msg.messageType)

	// Reserve the type-specific worst-case serialization footprint before
	// EncodeHnsMessage allocates its payload and immutable envelope.  The
	// preparation mutex ensures this conservative reservation can be reduced
	// to the exact retained charge before another message starts encoding.
	maxEncoded := uint64(wire.HnsMessageHeaderSize) +
		uint64(wire.MaxHnsPayloadLength(msg.message.Type()))
	preparationBytes := maxEncoded*outboundSerializationMemoryFactor +
		outboundMessageOverhead
	if !p.queueBudget.reserve(preparationBytes, msg.control) {
		return outboundQueueGlobalLimit, nil
	}
	msg.budgetReserved = true

	if err := p.prepareOutboundMessage(msg); err != nil {
		p.queueBudget.release(preparationBytes)
		msg.budgetReserved = false
		return outboundQueueStopped, err
	}
	if preparationBytes > msg.queueBytes {
		p.queueBudget.release(preparationBytes - msg.queueBytes)
	} else if preparationBytes < msg.queueBytes {
		// The wire package's type maximums must always make this impossible.
		// Keep the check defensive in case a new message type is added without
		// a corresponding maximum.
		if !p.queueBudget.reserve(
			msg.queueBytes-preparationBytes, msg.control,
		) {
			p.queueBudget.release(preparationBytes)
			msg.budgetReserved = false
			return outboundQueueGlobalLimit, nil
		}
	}
	return outboundQueueAccepted, nil
}

func (p *Peer) lockOutboundPreparation() func() {
	if p.queueBudget != nil {
		p.queueBudget.prepareMu.Lock()
		return p.queueBudget.prepareMu.Unlock
	}
	p.prepareMtx.Lock()
	return p.prepareMtx.Unlock
}

func (p *Peer) reserveOutboundMessageLocked(
	msg *outMsg) outboundQueueResult {

	if msg.reserved {
		return outboundQueueAccepted
	}
	if p.queueStopped {
		if msg.budgetReserved {
			p.queueBudget.release(msg.queueBytes)
			msg.budgetReserved = false
		}
		return outboundQueueStopped
	}
	peerByteLimit := p.maxQueuedBytes
	if !msg.control {
		peerByteLimit = outboundDataByteLimit(peerByteLimit)
	}
	peerMessageLimit := p.maxQueuedMessages
	if !msg.control {
		peerMessageLimit = outboundDataMessageLimit(peerMessageLimit)
	}
	if p.queuedMessages >= peerMessageLimit ||
		msg.queueBytes > peerByteLimit ||
		p.queuedBytes > peerByteLimit-msg.queueBytes {

		if msg.budgetReserved {
			p.queueBudget.release(msg.queueBytes)
			msg.budgetReserved = false
		}
		return outboundQueuePeerLimit
	}
	if msg.control && (p.queuedControlMsgs >= maxQueuedControlMessages ||
		msg.queueBytes > maxQueuedControlBytes ||
		p.queuedControlBytes > maxQueuedControlBytes-msg.queueBytes) {

		if msg.budgetReserved {
			p.queueBudget.release(msg.queueBytes)
			msg.budgetReserved = false
		}
		return outboundQueuePeerLimit
	}
	if !msg.budgetReserved &&
		!p.queueBudget.reserve(msg.queueBytes, msg.control) {

		return outboundQueueGlobalLimit
	}
	p.queuedMessages++
	p.queuedBytes += msg.queueBytes
	if msg.control {
		p.queuedControlMsgs++
		p.queuedControlBytes += msg.queueBytes
	}
	msg.reserved = true
	msg.budgetReserved = true
	return outboundQueueAccepted
}

func (p *Peer) reserveOutboundMessage(msg *outMsg) outboundQueueResult {
	p.queueMtx.Lock()
	result := p.reserveOutboundMessageLocked(msg)
	p.queueMtx.Unlock()
	return result
}

func (p *Peer) prepareAndReserveOutboundMessage(
	msg *outMsg) (outboundQueueResult, error) {

	unlock := p.lockOutboundPreparation()
	defer unlock()
	result, err := p.prepareOutboundMessageBudgeted(msg)
	if err != nil || result != outboundQueueAccepted {
		return result, err
	}
	if !p.reserveLegacyOnWriteWorkspace(msg) {
		p.releasePreparedOutboundMessage(msg)
		return outboundQueueGlobalLimit, nil
	}
	result = p.reserveOutboundMessage(msg)
	if result != outboundQueueAccepted {
		p.releasePreparedOutboundMessage(msg)
	}
	return result, nil
}

func (p *Peer) beginOutboundMessageEnqueue(
	msg *outMsg) outboundQueueResult {

	p.queueMtx.Lock()
	result := p.reserveOutboundMessageLocked(msg)
	if result == outboundQueueAccepted {
		p.queueEnqueueWg.Add(1)
	}
	p.queueMtx.Unlock()
	return result
}

func (p *Peer) finishOutboundMessageEnqueue(
	msg *outMsg) outboundQueueResult {

	select {
	case p.outputQueue <- *msg:
		p.queueEnqueueWg.Done()
		return outboundQueueAccepted
	case <-p.quit:
		p.releaseOutboundMessage(*msg)
		p.queueEnqueueWg.Done()
		return outboundQueueStopped
	}
}

func (p *Peer) prepareAndEnqueueOutboundMessage(
	msg *outMsg) (outboundQueueResult, error) {

	unlock := p.lockOutboundPreparation()
	result, err := p.prepareOutboundMessageBudgeted(msg)
	if err != nil || result != outboundQueueAccepted {
		unlock()
		return result, err
	}
	if !p.reserveLegacyOnWriteWorkspace(msg) {
		p.releasePreparedOutboundMessage(msg)
		unlock()
		return outboundQueueGlobalLimit, nil
	}
	result = p.beginOutboundMessageEnqueue(msg)
	unlock()
	if result != outboundQueueAccepted {
		p.releasePreparedOutboundMessage(msg)
		return result, nil
	}
	return p.finishOutboundMessageEnqueue(msg), nil
}

func (p *Peer) releaseOutboundMessage(msg outMsg) {
	if !msg.reserved {
		releaseLegacyOnWriteWorkspace(&msg)
		return
	}

	p.queueMtx.Lock()
	p.queuedMessages--
	p.queuedBytes -= msg.queueBytes
	if msg.control {
		p.queuedControlMsgs--
		p.queuedControlBytes -= msg.queueBytes
	}
	p.queueBudget.release(msg.queueBytes)
	p.queueMtx.Unlock()
	releaseLegacyOnWriteWorkspace(&msg)
}

func (p *Peer) enqueueOutboundInventory(inv *outInv) outboundQueueResult {
	p.queueMtx.Lock()
	if p.queueStopped {
		p.queueMtx.Unlock()
		return outboundQueueStopped
	}
	if _, ok := p.queuedInventorySet[inv.invVect]; ok {
		p.queueMtx.Unlock()
		return outboundQueueDuplicate
	}
	peerByteLimit := outboundDataByteLimit(p.maxQueuedBytes)
	if p.queuedInventory >= p.maxQueuedInventory ||
		inv.queueBytes > peerByteLimit ||
		p.queuedBytes > peerByteLimit-inv.queueBytes {

		p.queueMtx.Unlock()
		return outboundQueuePeerLimit
	}
	if !p.queueBudget.reserve(inv.queueBytes, false) {
		p.queueMtx.Unlock()
		return outboundQueueGlobalLimit
	}
	p.queuedInventory++
	p.queuedBytes += inv.queueBytes
	p.queuedInventorySet[inv.invVect] = struct{}{}
	inv.reserved = true
	p.queueEnqueueWg.Add(1)
	p.queueMtx.Unlock()

	select {
	case p.outputInvChan <- *inv:
		p.queueEnqueueWg.Done()
		return outboundQueueAccepted
	case <-p.quit:
		p.releaseOutboundInventory(*inv)
		p.queueEnqueueWg.Done()
		return outboundQueueStopped
	}
}

func (p *Peer) releaseOutboundInventory(inv outInv) {
	if !inv.reserved {
		return
	}
	p.queueMtx.Lock()
	p.queuedInventory--
	p.queuedBytes -= inv.queueBytes
	delete(p.queuedInventorySet, inv.invVect)
	p.queueBudget.release(inv.queueBytes)
	p.queueMtx.Unlock()
}

func signalMessageDone(doneChan chan<- struct{}) {
	if doneChan != nil {
		doneChan <- struct{}{}
	}
}

// isAllowedReadError returns whether or not the passed error is allowed without
// disconnecting the peer.  In particular, regression tests need to be allowed
// to send malformed messages without the peer being disconnected.
func (p *Peer) isAllowedReadError(err error) bool {
	// Only allow read errors in regression test mode.
	if p.cfg.ChainParams.Net != wire.TestNet {
		return false
	}

	// Don't allow the error if it's not specifically a malformed message error.
	if _, ok := err.(*wire.MessageError); !ok {
		return false
	}

	// Don't allow the error if it's not coming from localhost or the
	// hostname can't be determined for some reason.
	host, _, err := net.SplitHostPort(p.addr)
	if err != nil {
		return false
	}

	if host != "127.0.0.1" && host != "localhost" {
		return false
	}

	// Allowed if all checks passed.
	return true
}

// shouldHandleReadError returns whether or not the passed error, which is
// expected to have come from reading from the remote peer in the inHandler,
// should be logged and responded to with a reject message.
func (p *Peer) shouldHandleReadError(err error) bool {
	// No logging or reject message when the peer is being forcibly
	// disconnected.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging or reject message when the remote peer has been
	// disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// maybeAddDeadline potentially adds a deadline for the appropriate expected
// response for the passed wire protocol command to the pending responses map.
func (p *Peer) maybeAddDeadline(pendingResponses map[wire.HnsMsgType]time.Time,
	msgType wire.HnsMsgType) {

	// Setup a deadline for each message being sent that expects a response.
	//
	// NOTE: Pings are intentionally ignored here since they are typically
	// sent asynchronously and as a result of a long backlock of messages,
	// such as is typical in the case of initial block download, the
	// response won't be received in time.
	deadline := time.Now().Add(stallResponseTimeout)
	switch msgType {
	case wire.HnsMsgTypeVersion:
		// Expects a verack message.
		pendingResponses[wire.HnsMsgTypeVerack] = deadline

	case wire.HnsMsgTypeMempool:
		// Expects an inv message.
		pendingResponses[wire.HnsMsgTypeInv] = deadline

	case wire.HnsMsgTypeGetBlocks:
		// Expects an inv message.
		pendingResponses[wire.HnsMsgTypeInv] = deadline

	case wire.HnsMsgTypeGetData:
		// Expects a block, merkleblock, tx, or notfound message.
		pendingResponses[wire.HnsMsgTypeBlock] = deadline
		pendingResponses[wire.HnsMsgTypeMerkleBlock] = deadline
		pendingResponses[wire.HnsMsgTypeTx] = deadline
		pendingResponses[wire.HnsMsgTypeNotFound] = deadline

	case wire.HnsMsgTypeGetHeaders:
		// Expects a headers message.  Use a longer deadline since it
		// can take a while for the remote peer to load all of the
		// headers.
		deadline = time.Now().Add(stallResponseTimeout * 3)
		pendingResponses[wire.HnsMsgTypeHeaders] = deadline
	}
}

// stallHandler handles stall detection for the peer.  This entails keeping
// track of expected responses and assigning them deadlines while accounting for
// the time spent in callbacks.  It must be run as a goroutine.
func (p *Peer) stallHandler() {
	// These variables are used to adjust the deadline times forward by the
	// time it takes callbacks to execute.  This is done because new
	// messages aren't read until the previous one is finished processing
	// (which includes callbacks), so the deadline for receiving a response
	// for a given message must account for the processing time as well.
	var handlerActive bool
	var handlersStartTime time.Time
	var deadlineOffset time.Duration

	// pendingResponses tracks the expected response deadline times.
	pendingResponses := make(map[wire.HnsMsgType]time.Time)

	// stallTicker is used to periodically check pending responses that have
	// exceeded the expected deadline and disconnect the peer due to
	// stalling.
	stallTicker := time.NewTicker(stallTickInterval)
	defer stallTicker.Stop()

	// ioStopped is used to detect when both the input and output handler
	// goroutines are done.
	var ioStopped bool
out:
	for {
		select {
		case msg := <-p.stallControl:
			if p.cfg.DisableStallHandler {
				continue
			}

			switch msg.command {
			case sccSendMessage:
				// Add a deadline for the expected response
				// message if needed.
				p.maybeAddDeadline(pendingResponses,
					msg.message.Type())

			case sccReceiveMessage:
				// Remove received messages from the expected
				// response map.  Since certain commands expect
				// one of a group of responses, remove
				// everything in the expected group accordingly.
				switch msgType := msg.message.Type(); msgType {
				case wire.HnsMsgTypeBlock:
					fallthrough
				case wire.HnsMsgTypeMerkleBlock:
					fallthrough
				case wire.HnsMsgTypeTx:
					fallthrough
				case wire.HnsMsgTypeNotFound:
					delete(pendingResponses, wire.HnsMsgTypeBlock)
					delete(pendingResponses, wire.HnsMsgTypeMerkleBlock)
					delete(pendingResponses, wire.HnsMsgTypeTx)
					delete(pendingResponses, wire.HnsMsgTypeNotFound)

				default:
					delete(pendingResponses, msgType)
				}

			case sccHandlerStart:
				// Warn on unbalanced callback signalling.
				if handlerActive {
					log.Warn("Received handler start " +
						"control command while a " +
						"handler is already active")
					continue
				}

				handlerActive = true
				handlersStartTime = time.Now()

			case sccHandlerDone:
				// Warn on unbalanced callback signalling.
				if !handlerActive {
					log.Warn("Received handler done " +
						"control command when a " +
						"handler is not already active")
					continue
				}

				// Extend active deadlines by the time it took
				// to execute the callback.
				duration := time.Since(handlersStartTime)
				deadlineOffset += duration
				handlerActive = false

			default:
				log.Warnf("Unsupported message command %v",
					msg.command)
			}

		case <-stallTicker.C:
			if p.cfg.DisableStallHandler {
				continue
			}

			// Calculate the offset to apply to the deadline based
			// on how long the handlers have taken to execute since
			// the last tick.
			now := time.Now()
			offset := deadlineOffset
			if handlerActive {
				offset += now.Sub(handlersStartTime)
			}

			// Disconnect the peer if any of the pending responses
			// don't arrive by their adjusted deadline.
			for command, deadline := range pendingResponses {
				if now.Before(deadline.Add(offset)) {
					continue
				}

				log.Debugf("Peer %s appears to be stalled or "+
					"misbehaving, %s timeout -- "+
					"disconnecting", p, command)
				p.Disconnect()
				break
			}

			// Reset the deadline offset for the next tick.
			deadlineOffset = 0

		case <-p.inQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			if ioStopped {
				break out
			}
			ioStopped = true

		case <-p.outQuit:
			// The stall handler can exit once both the input and
			// output handler goroutines are done.
			if ioStopped {
				break out
			}
			ioStopped = true
		}
	}

	// Drain any wait channels before going away so there is nothing left
	// waiting on this goroutine.
cleanup:
	for {
		select {
		case <-p.stallControl:
		default:
			break cleanup
		}
	}
	log.Tracef("Peer stall handler done for %s", p)
}

// inHandler handles all incoming messages for the peer.  It must be run as a
// goroutine.
func (p *Peer) inHandler() {
	// Must be first defer (runs last) to catch panics from
	// everything, including other defers.
	defer p.recoverFromPanic()
	defer close(p.inQuit)
	defer p.Disconnect()
	defer log.Tracef("Peer input handler done for %s", p)

	// The timer is stopped when a new message is received and reset after it
	// is processed.
	idleTimerDone := make(chan struct{})
	idleTimer := time.AfterFunc(idleTimeout, func() {
		defer close(idleTimerDone)
		log.Warnf("Peer %s no answer for %s -- disconnecting", p, idleTimeout)
		p.Disconnect()
	})
	idleTimerArmed := true
	defer func() {
		if idleTimerArmed && !idleTimer.Stop() {
			<-idleTimerDone
		}
	}()

out:
	for atomic.LoadInt32(&p.disconnect) == 0 {
		// Read a message and stop the idle timer as soon as the read
		// is done.  The timer is reset below for the next iteration if
		// needed.
		rmsg, buf, err := p.readMessage(p.wireEncoding, false)
		if !idleTimer.Stop() {
			<-idleTimerDone
			idleTimerArmed = false
			break out
		}
		idleTimerArmed = false
		if err != nil {
			// In order to allow regression tests with malformed messages, don't
			// disconnect the peer when we're in regression test mode and the
			// error is one of the allowed errors.
			if p.isAllowedReadError(err) {
				log.Errorf("Allowed test error from %s: %v", p, err)
				idleTimer.Reset(idleTimeout)
				idleTimerArmed = true
				continue
			}

			// Since the protocol version is 70016 but we don't
			// implement compact blocks, we have to ignore unknown
			// messages after the version-verack handshake. This
			// matches bitcoind's behavior and is necessary since
			// compact blocks negotiation occurs after the
			// handshake.
			if errors.Is(err, wire.ErrUnknownMessage) {
				log.Debugf("Received unknown message from %s:"+
					" %v", p, err)
				idleTimer.Reset(idleTimeout)
				idleTimerArmed = true
				continue
			}

			// Only log the error and send reject message if the
			// local peer is not forcibly disconnecting and the
			// remote peer has not disconnected.
			if p.shouldHandleReadError(err) {
				errMsg := fmt.Sprintf("Can't read message from %s: %v", p, err)
				if err != io.ErrUnexpectedEOF {
					log.Errorf("%s", errMsg)
				}

				// Push a reject message for the malformed message and wait for
				// the message to be sent before disconnecting.
				//
				// NOTE: Ideally this would include the command in the header if
				// at least that much of the message was valid, but that is not
				// currently exposed by wire, so just used malformed for the
				// command.
				p.PushRejectMsg(
					wire.HnsMsgTypeUnknown, wire.RejectMalformed,
					errMsg, nil, true,
				)
			}
			break out
		}
		atomic.StoreInt64(&p.lastRecv, time.Now().Unix())
		p.stallControl <- stallControlMsg{sccReceiveMessage, rmsg}

		// Handle each supported message type.
		p.stallControl <- stallControlMsg{sccHandlerStart, rmsg}
		switch msg := rmsg.(type) {
		case *wire.HnsMsgVersion:
			// Limit to one version message per peer.
			p.PushRejectMsg(wire.HnsMsgTypeVersion, wire.RejectDuplicate,
				"duplicate version message", nil, true)
			break out

		case *wire.HnsMsgVerack:
			// Limit to one verack message per peer.
			p.PushRejectMsg(
				wire.HnsMsgTypeVerack, wire.RejectDuplicate,
				"duplicate verack message", nil, true,
			)
			break out

		case *wire.HnsMsgGetAddr:
			if p.cfg.Listeners.OnGetAddr != nil {
				p.cfg.Listeners.OnGetAddr(p, msg)
			}

		case *wire.HnsMsgAddr:
			if p.cfg.Listeners.OnAddr != nil {
				p.cfg.Listeners.OnAddr(p, msg)
			}

		case *wire.HnsMsgPing:
			p.handlePingMsg(msg)
			if p.cfg.Listeners.OnPing != nil {
				p.cfg.Listeners.OnPing(p, msg)
			}

		case *wire.HnsMsgPong:
			p.handlePongMsg(msg)
			if p.cfg.Listeners.OnPong != nil {
				p.cfg.Listeners.OnPong(p, msg)
			}

		case *wire.HnsMsgMemPool:
			if p.cfg.Listeners.OnMemPool != nil {
				p.cfg.Listeners.OnMemPool(p, msg)
			}

		case *wire.HnsMsgTx:
			if p.cfg.Listeners.OnTx != nil {
				p.cfg.Listeners.OnTx(p, msg)
			}

		case *wire.HnsMsgBlock:
			if p.cfg.Listeners.OnBlock != nil {
				p.cfg.Listeners.OnBlock(p, msg, buf)
			}

		case *wire.HnsMsgInv:
			if p.cfg.Listeners.OnInv != nil {
				p.cfg.Listeners.OnInv(p, msg)
			}

		case *wire.HnsMsgHeaders:
			if p.cfg.Listeners.OnHeaders != nil {
				p.cfg.Listeners.OnHeaders(p, msg)
			}

		case *wire.HnsMsgNotFound:
			if p.cfg.Listeners.OnNotFound != nil {
				p.cfg.Listeners.OnNotFound(p, msg)
			}

		case *wire.HnsMsgGetData:
			if p.cfg.Listeners.OnGetData != nil {
				p.cfg.Listeners.OnGetData(p, msg)
			}

		case *wire.HnsMsgGetBlocks:
			if p.cfg.Listeners.OnGetBlocks != nil {
				p.cfg.Listeners.OnGetBlocks(p, msg)
			}

		case *wire.HnsMsgGetHeaders:
			if p.cfg.Listeners.OnGetHeaders != nil {
				p.cfg.Listeners.OnGetHeaders(p, msg)
			}

		case *wire.HnsMsgFeeFilter:
			if p.cfg.Listeners.OnFeeFilter != nil {
				p.cfg.Listeners.OnFeeFilter(p, msg)
			}

		case *wire.HnsMsgFilterAdd:
			if p.cfg.Listeners.OnFilterAdd != nil {
				p.cfg.Listeners.OnFilterAdd(p, msg)
			}

		case *wire.HnsMsgFilterClear:
			if p.cfg.Listeners.OnFilterClear != nil {
				p.cfg.Listeners.OnFilterClear(p, msg)
			}

		case *wire.HnsMsgFilterLoad:
			if p.cfg.Listeners.OnFilterLoad != nil {
				p.cfg.Listeners.OnFilterLoad(p, msg)
			}

		case *wire.HnsMsgMerkleBlock:
			if p.cfg.Listeners.OnMerkleBlock != nil {
				p.cfg.Listeners.OnMerkleBlock(p, msg)
			}

		case *wire.HnsMsgReject:
			if p.cfg.Listeners.OnReject != nil {
				p.cfg.Listeners.OnReject(p, msg)
			}

		case *wire.HnsMsgSendHeaders:
			p.flagsMtx.Lock()
			p.sendHeadersPreferred = true
			p.flagsMtx.Unlock()

			if p.cfg.Listeners.OnSendHeaders != nil {
				p.cfg.Listeners.OnSendHeaders(p, msg)
			}

		case *wire.HnsMsgSendCmpct:
			if p.cfg.Listeners.OnSendCmpct != nil {
				p.cfg.Listeners.OnSendCmpct(p, msg)
			}

		case *wire.HnsMsgCmpctBlock:
			if p.cfg.Listeners.OnCmpctBlock != nil {
				p.cfg.Listeners.OnCmpctBlock(p, msg)
			}

		case *wire.HnsMsgGetBlockTxn:
			if p.cfg.Listeners.OnGetBlockTxn != nil {
				p.cfg.Listeners.OnGetBlockTxn(p, msg)
			}

		case *wire.HnsMsgBlockTxn:
			if p.cfg.Listeners.OnBlockTxn != nil {
				p.cfg.Listeners.OnBlockTxn(p, msg)
			}

		case *wire.HnsMsgGetProof:
			if p.cfg.Listeners.OnGetProof != nil {
				p.cfg.Listeners.OnGetProof(p, msg)
			}

		case *wire.HnsMsgProof:
			if p.cfg.Listeners.OnProof != nil {
				p.cfg.Listeners.OnProof(p, msg)
			}

		case *wire.HnsMsgClaim:
			if p.cfg.Listeners.OnClaim != nil {
				p.cfg.Listeners.OnClaim(p, msg)
			}

		case *wire.HnsMsgAirDrop:
			if p.cfg.Listeners.OnAirDrop != nil {
				p.cfg.Listeners.OnAirDrop(p, msg)
			}

		case *wire.HnsMsgUnknown:
			if p.cfg.Listeners.OnUnknown != nil {
				p.cfg.Listeners.OnUnknown(p, msg)
			}

		default:
			log.Debugf("Received unhandled message of type %v "+
				"from %v", rmsg.Type(), p)
		}
		p.stallControl <- stallControlMsg{sccHandlerDone, rmsg}

		// A message was received so reset the idle timer.
		idleTimer.Reset(idleTimeout)
		idleTimerArmed = true
	}
}

// queueHandler handles the queuing of outgoing data for the peer. This runs as
// a muxer for various sources of input so we can ensure that server and peer
// handlers will not block on us sending a message.  That data is then passed on
// to outHandler to be actually written.
func (p *Peer) queueHandler() {
	pendingMsgs := list.New()
	invSendQueue := list.New()
	trickleTicker := time.NewTicker(p.cfg.TrickleInterval)
	defer trickleTicker.Stop()

	// We keep the waiting flag so that we know if we have a message queued
	// to the outHandler or not.  We could use the presence of a head of
	// the list for this but then we have rather racy concerns about whether
	// it has gotten it at cleanup time - and thus who sends on the
	// message's done channel.  To avoid such confusion we keep a different
	// flag and pendingMsgs only contains messages that we have not yet
	// passed to outHandler.
	waiting := false

	// To avoid duplication below.
	queuePacket := func(msg outMsg, list *list.List,
		waiting bool) (bool, bool) {

		result, err := p.prepareAndReserveOutboundMessage(&msg)
		if err != nil {
			log.Warnf("Cannot serialize outbound message for peer %s: %v", p, err)
			signalMessageDone(msg.doneChan)
			p.Disconnect()
			return waiting, false
		}
		switch result {
		case outboundQueueAccepted:
		case outboundQueueGlobalLimit:
			log.Debugf("Dropping outbound message for peer %s because the "+
				"aggregate queue budget is exhausted", p)
			signalMessageDone(msg.doneChan)
			return waiting, false
		case outboundQueuePeerLimit:
			log.Warnf("Peer %s exceeded outbound queue limits -- disconnecting", p)
			signalMessageDone(msg.doneChan)
			p.Disconnect()
			return waiting, false
		default:
			signalMessageDone(msg.doneChan)
			return waiting, false
		}
		if !waiting {
			p.sendQueue <- msg
		} else {
			list.PushBack(msg)
		}
		// we are always waiting now.
		return true, true
	}
out:
	for {
		select {
		case msg := <-p.outputQueue:
			waiting, _ = queuePacket(msg, pendingMsgs, waiting)

		// This channel is notified when a message has been sent across
		// the network socket.
		case <-p.sendDoneQueue:
			// No longer waiting if there are no more messages
			// in the pending messages queue.
			next := pendingMsgs.Front()
			if next == nil {
				waiting = false
				continue
			}

			// Notify the outHandler about the next item to
			// asynchronously send.
			val := pendingMsgs.Remove(next)
			p.sendQueue <- val.(outMsg)

		case queuedInv := <-p.outputInvChan:
			// No handshake?  They'll find out soon enough.
			if p.VersionKnown() {
				iv := &queuedInv.invVect
				// If this is a new block, then we'll blast it
				// out immediately, sipping the inv trickle
				// queue.
				if iv.Type == wire.InvTypeBlock ||
					iv.Type == wire.InvTypeWitnessBlock {

					invMsg := wire.NewHnsMsgInvSizeHint(1)
					_ = invMsg.AddInvVect(iv)
					p.releaseOutboundInventory(queuedInv)
					var accepted bool
					waiting, accepted = queuePacket(outMsg{message: invMsg},
						pendingMsgs, waiting)
					if accepted {
						p.AddKnownInventory(iv)
					}
				} else {
					invSendQueue.PushBack(queuedInv)
				}
			} else {
				p.releaseOutboundInventory(queuedInv)
			}

		case <-trickleTicker.C:
			// Don't send anything if we're disconnecting or there
			// is no queued inventory.
			// version is known if send queue has any entries.
			if atomic.LoadInt32(&p.disconnect) != 0 ||
				invSendQueue.Len() == 0 {
				continue
			}

			// Create and send as many inv messages as needed to
			// drain the inventory send queue.
			invMsg := wire.NewHnsMsgInvSizeHint(uint(invSendQueue.Len()))
			for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
				queuedInv := invSendQueue.Remove(e).(outInv)
				iv := &queuedInv.invVect

				// Don't send inventory that became known after
				// the initial check.
				if p.knownInventory.Contains(*iv) {
					p.releaseOutboundInventory(queuedInv)
					continue
				}

				_ = invMsg.AddInvVect(iv)
				p.releaseOutboundInventory(queuedInv)
				if len(invMsg.Inventory) >= maxInvTrickleSize {
					var accepted bool
					waiting, accepted = queuePacket(
						outMsg{message: invMsg},
						pendingMsgs, waiting)
					if accepted {
						for _, sentIV := range invMsg.InvVects() {
							p.AddKnownInventory(sentIV)
						}
					}
					invMsg = wire.NewHnsMsgInvSizeHint(uint(invSendQueue.Len()))
				}
			}
			if len(invMsg.Inventory) > 0 {
				var accepted bool
				waiting, accepted = queuePacket(outMsg{message: invMsg},
					pendingMsgs, waiting)
				if accepted {
					for _, sentIV := range invMsg.InvVects() {
						p.AddKnownInventory(sentIV)
					}
				}
			}

		case <-p.quit:
			break out
		}
	}
	p.queueMtx.Lock()
	p.queueStopped = true
	p.queueMtx.Unlock()
	p.queueEnqueueWg.Wait()

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us.
	for e := pendingMsgs.Front(); e != nil; e = pendingMsgs.Front() {
		val := pendingMsgs.Remove(e)
		msg := val.(outMsg)
		p.releaseOutboundMessage(msg)
		signalMessageDone(msg.doneChan)
	}
	for e := invSendQueue.Front(); e != nil; e = invSendQueue.Front() {
		queuedInv := invSendQueue.Remove(e).(outInv)
		p.releaseOutboundInventory(queuedInv)
	}
cleanup:
	for {
		select {
		case msg := <-p.outputQueue:
			p.releaseOutboundMessage(msg)
			signalMessageDone(msg.doneChan)
		case queuedInv := <-p.outputInvChan:
			p.releaseOutboundInventory(queuedInv)
		// sendDoneQueue is buffered so doesn't need draining.
		default:
			break cleanup
		}
	}
	close(p.queueQuit)
	log.Tracef("Peer queue handler done for %s", p)
}

// shouldLogWriteError returns whether or not the passed error, which is
// expected to have come from writing to the remote peer in the outHandler,
// should be logged.
func (p *Peer) shouldLogWriteError(err error) bool {
	// No logging when the peer is being forcibly disconnected.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		return false
	}

	// No logging when the remote peer has been disconnected.
	if err == io.EOF {
		return false
	}
	if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() {
		return false
	}

	return true
}

// outHandler handles all outgoing messages for the peer.  It must be run as a
// goroutine.  It uses a buffered channel to serialize output messages while
// allowing the sender to continue running asynchronously.
func (p *Peer) outHandler() {
out:
	for {
		select {
		case msg := <-p.sendQueue:
			if len(msg.encoded) < wire.HnsMessageHeaderSize {
				p.releaseOutboundMessage(msg)
				p.Disconnect()
				signalMessageDone(msg.doneChan)
				continue
			}

			if msg.messageType == wire.HnsMsgTypePing &&
				len(msg.encoded) >= wire.HnsMessageHeaderSize+8 {

				p.statsMtx.Lock()
				p.lastPingNonce = binary.LittleEndian.Uint64(
					msg.encoded[wire.HnsMessageHeaderSize:],
				)
				p.lastPingTime = time.Now()
				p.statsMtx.Unlock()
			}

			messageView := &serializedHandshakeMessage{
				messageType: msg.messageType,
			}
			p.stallControl <- stallControlMsg{sccSendMessage, messageView}

			err := p.writeEncodedMessage(
				msg.message, msg.messageType, msg.encoded,
			)
			p.releaseOutboundMessage(msg)
			if err != nil {
				p.Disconnect()
				if p.shouldLogWriteError(err) {
					log.Errorf("Failed to send message to "+
						"%s: %v", p, err)
				}
				signalMessageDone(msg.doneChan)
				continue
			}

			// At this point, the message was successfully sent, so
			// update the last send time, signal the sender of the
			// message that it has been sent (if requested), and
			// signal the send queue to the deliver the next queued
			// message.
			atomic.StoreInt64(&p.lastSend, time.Now().Unix())
			signalMessageDone(msg.doneChan)
			p.sendDoneQueue <- struct{}{}

		case <-p.quit:
			break out
		}
	}

	<-p.queueQuit

	// Drain any wait channels before we go away so we don't leave something
	// waiting for us. We have waited on queueQuit and thus we can be sure
	// that we will not miss anything sent on sendQueue.
cleanup:
	for {
		select {
		case msg := <-p.sendQueue:
			p.releaseOutboundMessage(msg)
			signalMessageDone(msg.doneChan)
			// no need to send on sendDoneQueue since queueHandler
			// has been waited on and already exited.
		default:
			break cleanup
		}
	}
	close(p.outQuit)
	log.Tracef("Peer output handler done for %s", p)
}

// pingHandler periodically pings the peer.  It must be run as a goroutine.
func (p *Peer) pingHandler() {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

out:
	for {
		select {
		case <-pingTicker.C:
			nonce, err := wire.RandomUint64()
			if err != nil {
				log.Errorf("Not sending ping to %s: %v", p, err)
				continue
			}
			p.QueueMessage(wire.NewHnsMsgPing(nonce), nil)

		case <-p.quit:
			break out
		}
	}
}

// QueueHnsMessage adds the passed native Handshake message to the peer send
// queue.
//
// This function is safe for concurrent access.
func (p *Peer) QueueHnsMessage(msg wire.HandshakeMessage,
	doneChan chan<- struct{}) {

	_ = p.TryQueueMessage(msg, doneChan)
}

// TryQueueHnsMessage adds the passed native Handshake message to the peer send
// queue and reports whether it was accepted.
func (p *Peer) TryQueueHnsMessage(msg wire.HandshakeMessage,
	doneChan chan<- struct{}) error {

	return p.TryQueueMessage(msg, doneChan)
}

// QueueMessage adds the passed Handshake message to the peer send queue.
// Call TryQueueMessage when the caller needs explicit admission status.
//
// This function is safe for concurrent access.
func (p *Peer) QueueMessage(msg wire.HandshakeMessage, doneChan chan<- struct{}) {
	_ = p.TryQueueMessage(msg, doneChan)
}

// TryQueueMessage adds the passed Handshake message to the peer send queue and
// returns an error when the message was not accepted.  In particular,
// ErrOutboundQueueBudget means the item was shed without disconnecting the
// peer.  When doneChan is non-nil it is signaled exactly once whether the
// message is sent or rejected, so callers waiting on a response batch cannot
// hang during backpressure or shutdown.
//
// This function is safe for concurrent access.
func (p *Peer) TryQueueMessage(msg wire.HandshakeMessage,
	doneChan chan<- struct{}) error {

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	if !p.Connected() {
		if doneChan != nil {
			go signalMessageDone(doneChan)
		}
		return ErrPeerDisconnected
	}
	queued := outMsg{message: msg, doneChan: doneChan}
	result, err := p.prepareAndEnqueueOutboundMessage(&queued)
	if err != nil {
		log.Warnf("Cannot serialize outbound message for peer %s: %v", p, err)
		p.Disconnect()
		if doneChan != nil {
			go signalMessageDone(doneChan)
		}
		return err
	}
	switch result {
	case outboundQueueAccepted:
		return nil
	case outboundQueueGlobalLimit:
		log.Debugf("Dropping outbound message for peer %s because the "+
			"aggregate queue budget is exhausted", p)
	case outboundQueuePeerLimit:
		log.Warnf("Peer %s exceeded outbound queue limits -- disconnecting", p)
		p.Disconnect()
	default:
		// The peer is already stopping.
	}
	if doneChan != nil {
		go signalMessageDone(doneChan)
	}
	if result == outboundQueueGlobalLimit {
		return ErrOutboundQueueBudget
	}
	if result == outboundQueuePeerLimit {
		return ErrOutboundQueueLimit
	}
	return ErrPeerDisconnected
}

// QueueInventory adds the passed inventory to the inventory send queue which
// might not be sent right away, rather it is trickled to the peer in batches.
// Inventory that the peer is already known to have is ignored.
//
// This function is safe for concurrent access.
func (p *Peer) QueueInventory(invVect *wire.InvVect) {
	if invVect == nil {
		return
	}
	// Don't add the inventory to the send queue if the peer is already
	// known to have it.
	if p.knownInventory.Contains(*invVect) {
		return
	}

	// Avoid risk of deadlock if goroutine already exited.  The goroutine
	// we will be sending to hangs around until it knows for a fact that
	// it is marked as disconnected and *then* it drains the channels.
	if !p.Connected() {
		return
	}

	queued := outInv{
		invVect:    *invVect,
		queueBytes: wire.HnsInvItemSize + outboundInventoryOverhead,
	}
	switch result := p.enqueueOutboundInventory(&queued); result {
	case outboundQueueAccepted, outboundQueueDuplicate, outboundQueueStopped:
		return
	case outboundQueuePeerLimit:
		log.Debugf("Dropping inventory announcement for peer %s because its "+
			"bounded inventory queue is full", p)
	case outboundQueueGlobalLimit:
		log.Debugf("Dropping inventory announcement for peer %s because the "+
			"aggregate queue budget is exhausted", p)
	}
}

// Connected returns whether or not the peer is currently connected.
//
// This function is safe for concurrent access.
func (p *Peer) Connected() bool {
	return atomic.LoadInt32(&p.connected) != 0 &&
		atomic.LoadInt32(&p.disconnect) == 0
}

// SetBrontideConnection records whether the underlying transport was upgraded
// to Handshake Brontide. It is set by the server after transport negotiation.
func (p *Peer) SetBrontideConnection(encrypted bool) {
	p.cfg.UsingV2Conn = encrypted
}

// recoverFromPanic catches any panic that occurs in a peer goroutine,
// logs the error with a stack trace, and disconnects the peer. This
// prevents a single malformed message from crashing the entire node.
func (p *Peer) recoverFromPanic() {
	if r := recover(); r != nil {
		log.Errorf("Recovered panic in peer %s: %v\n%s",
			p, r, debug.Stack())
		p.Disconnect()
	}
}

// Disconnect disconnects the peer by closing the connection.  Calling this
// function when the peer is already disconnected or in the process of
// disconnecting will have no effect.
func (p *Peer) Disconnect() {
	if atomic.AddInt32(&p.disconnect, 1) != 1 {
		return
	}

	p.lifecycleMtx.Lock()
	defer p.lifecycleMtx.Unlock()

	log.Tracef("Disconnecting %s", p)
	if atomic.LoadInt32(&p.connected) != 0 {
		p.conn.Close()
	}
	close(p.quit)
}

// launchGoroutine starts a peer-owned goroutine and tracks it for
// WaitForDisconnect.
func (p *Peer) launchGoroutine(f func()) {
	p.lifecycleWg.Add(1)
	go func() {
		defer p.lifecycleWg.Done()
		f()
	}()
}

// readRemoteVersionMsg waits for the next message to arrive from the remote
// peer.  If the next message is not a version message or the version is not
// acceptable then return an error.  The readPartial bool denotes whether we
// need to read the rest of a partially-received version message.  This only
// happens with implicitly downgraded v2->v1 connections.
func (p *Peer) readRemoteVersionMsg(readPartial bool) error {
	var (
		remoteMsg wire.HandshakeMessage
		err       error
	)

	remoteMsg, _, err = p.readMessage(wire.LatestEncoding, readPartial)
	if err != nil {
		return err
	}

	// Notify and disconnect clients if the first message is not a version
	// message.
	msg, ok := remoteMsg.(*wire.HnsMsgVersion)
	if !ok {
		reason := "a version message must precede all others"
		rejectMsg := &wire.HnsMsgReject{
			Message: remoteMsg.Type(),
			Code:    wire.RejectMalformed,
			Reason:  reason,
		}
		_ = p.writeMessage(rejectMsg)
		return errors.New(reason)
	}

	return p.processRemoteVersionMsg(msg)
}

// processRemoteVersionMsg validates the remote version message and updates the
// negotiated peer state.
func (p *Peer) processRemoteVersionMsg(msg *wire.HnsMsgVersion) error {
	// Detect self connections.
	nonce := binary.LittleEndian.Uint64(msg.Nonce[:])
	if !p.cfg.AllowSelfConns && sentNonces.Contains(nonce) {
		return errors.New("disconnecting peer connected to self")
	}

	// Negotiate the protocol version and set the services to what the remote
	// peer advertised.
	p.flagsMtx.Lock()
	p.advertisedProtoVer = msg.Version
	p.protocolVersion = minUint32(p.protocolVersion, p.advertisedProtoVer)
	p.versionKnown = true
	p.services = wire.ServiceFlag(msg.Services)
	p.flagsMtx.Unlock()
	log.Debugf("Negotiated protocol version %d for peer %s",
		p.protocolVersion, p)

	// Updating a bunch of stats including block based stats, and the
	// peer's time offset.
	p.statsMtx.Lock()
	p.lastBlock = int32(msg.Height)
	p.startingHeight = int32(msg.Height)
	p.timeOffset = hnsTimeToTime(msg.Time).Unix() - time.Now().Unix()
	p.statsMtx.Unlock()

	// Set the peer's ID, user agent, and potentially the flag which
	// specifies the witness support is enabled.
	p.flagsMtx.Lock()
	p.id = atomic.AddInt32(&nodeCount, 1)
	p.userAgent = msg.Agent

	// Determine if the peer would like to receive witness data with
	// transactions, or not.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.witnessEnabled = true
	}
	p.flagsMtx.Unlock()

	// Once the version message has been exchanged, we're able to determine
	// if this peer knows how to encode witness data over the wire
	// protocol. If so, then we'll switch to a decoding mode which is
	// prepared for the new transaction format introduced as part of
	// BIP0144.
	if p.services&wire.SFNodeWitness == wire.SFNodeWitness {
		p.wireEncoding = wire.WitnessEncoding
	}

	// Invoke the callback if specified.
	if p.cfg.Listeners.OnVersion != nil {
		rejectMsg := p.cfg.Listeners.OnVersion(p, msg)
		if rejectMsg != nil {
			_ = p.writeMessage(rejectMsg)
			return errors.New(rejectMsg.Reason)
		}
	}

	// Notify and disconnect clients that have a protocol version that is
	// too old.
	//
	if msg.Version < MinAcceptableProtocolVersion {
		// Send a reject message indicating the protocol version is
		// obsolete and wait for the message to be sent before
		// disconnecting.
		reason := fmt.Sprintf("protocol version must be %d or greater",
			MinAcceptableProtocolVersion)
		rejectMsg := &wire.HnsMsgReject{
			Message: wire.HnsMsgTypeVersion,
			Code:    wire.RejectObsolete,
			Reason:  reason,
		}
		_ = p.writeMessage(rejectMsg)
		return errors.New(reason)
	}

	return nil
}

func (p *Peer) recordRemoteVerAckMsg() {
	p.flagsMtx.Lock()
	p.verAckReceived = true
	p.flagsMtx.Unlock()
}

func (p *Peer) notifyRemoteVerAckMsg(msg *wire.HnsMsgVerack) {
	if p.cfg.Listeners.OnVerAck != nil {
		p.cfg.Listeners.OnVerAck(p, msg)
	}
}

// processRemoteVerAckMsg takes the verack from the remote peer and handles it.
func (p *Peer) processRemoteVerAckMsg(msg *wire.HnsMsgVerack) {
	p.recordRemoteVerAckMsg()
	p.notifyRemoteVerAckMsg(msg)
}

// localVersionMsg creates a version message that can be used to send to the
// remote peer.
func (p *Peer) localVersionMsg() (*wire.HnsMsgVersion, error) {
	var blockNum int32
	if p.cfg.NewestBlock != nil {
		var err error
		_, blockNum, err = p.cfg.NewestBlock()
		if err != nil {
			return nil, err
		}
	}

	theirNA := p.na.ToLegacy()

	// If p.na is a torv3 hidden service address, we'll need to send over
	// an empty NetAddress for their address.
	if p.na.IsTorV3() {
		theirNA = wire.NewNetAddressIPPort(
			net.IP([]byte{0, 0, 0, 0}), p.na.Port, p.na.Services,
		)
	}

	// If we are behind a proxy and the connection comes from the proxy then
	// we return an unroutable address as their address. This is to prevent
	// leaking the tor proxy address.
	if p.cfg.Proxy != "" {
		proxyaddress, _, err := net.SplitHostPort(p.cfg.Proxy)
		// invalid proxy means poorly configured, be on the safe side.
		if err != nil || p.na.Addr.String() == proxyaddress {
			theirNA = wire.NewNetAddressIPPort(net.IP([]byte{0, 0, 0, 0}), 0,
				theirNA.Services)
		}
	}

	// Generate a unique nonce for this peer so self connections can be
	// detected.  This is accomplished by adding it to a size-limited map of
	// recently seen nonces.
	nonce := uint64(rand.Int63())
	sentNonces.Add(nonce)

	msg := &wire.HnsMsgVersion{
		Version:  p.cfg.ProtocolVersion,
		Services: uint64(p.cfg.Services),
		Time:     uint64(time.Now().Unix()), //nolint:gosec
		Remote:   wire.NewHnsNetAddress(theirNA),
		Agent: FormatUserAgent(p.cfg.UserAgentName,
			p.cfg.UserAgentVersion, p.cfg.UserAgentComments),
		Height:  uint32(blockNum), //nolint:gosec
		NoRelay: p.cfg.DisableRelayTx,
	}
	msg.SetNonce(nonce)
	return msg, nil
}

// writeLocalVersionMsg writes our version message to the remote peer.
func (p *Peer) writeLocalVersionMsg() error {
	localVerMsg, err := p.localVersionMsg()
	if err != nil {
		return err
	}

	return p.writeMessage(localVerMsg)
}

// writeSendAddrV2Msg is retained as a negotiation hook while the peer package
// still has btcd-era method names. Handshake has no sendaddrv2 packet; peers
// use the type-5 addr message with 88-byte Handshake NetAddress entries.
func (p *Peer) writeSendAddrV2Msg(_ uint32) error {
	return nil
}

// waitToFinishNegotiation waits until verack is received. Unknown messages are
// skipped so peers can advertise packet types this migration has not wired to
// the btcd-era listener API yet.
func (p *Peer) waitToFinishNegotiation(_ uint32) error {
	if p.VerAckReceived() {
		return nil
	}

	for {
		remoteMsg, _, err := p.readMessage(wire.LatestEncoding, false)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			return err
		}

		switch m := remoteMsg.(type) {
		case *wire.HnsMsgVerack:
			// Receiving a verack means we are done with the
			// handshake.
			p.processRemoteVerAckMsg(m)
			return nil
		default:
			// This is triggered if the peer sends, for example, a
			// GETDATA message during this negotiation.
			return wire.ErrInvalidHandshake
		}
	}
}

// readRemoteVersionAllowingEarlyVerAck reads messages until the remote peer's
// version is received. hsd sends verack immediately after accepting our version
// on inbound connections, so outbound negotiation must allow verack to arrive
// before the remote version packet.
func (p *Peer) readRemoteVersionAllowingEarlyVerAck() error {
	var earlyVerAck *wire.HnsMsgVerack

	for {
		remoteMsg, _, err := p.readMessage(wire.LatestEncoding, false)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			return err
		}

		switch msg := remoteMsg.(type) {
		case *wire.HnsMsgVersion:
			if err := p.processRemoteVersionMsg(msg); err != nil {
				return err
			}
			if earlyVerAck != nil {
				p.notifyRemoteVerAckMsg(earlyVerAck)
			}
			return nil
		case *wire.HnsMsgVerack:
			if p.VerAckReceived() {
				return wire.ErrInvalidHandshake
			}
			p.recordRemoteVerAckMsg()
			earlyVerAck = msg
		default:
			return wire.ErrInvalidHandshake
		}
	}
}

// negotiateInboundProtocol performs the negotiation protocol for an inbound
// peer. The events should occur in the following order, otherwise an error is
// returned:
//
//  1. Remote peer sends their version.
//  2. We send our version.
//  3. We skip Bitcoin sendaddrv2 negotiation; Handshake has no sendaddrv2.
//  4. We send our verack.
//  5. Wait until verack is received, skipping unknown Handshake packet types.
func (p *Peer) negotiateInboundProtocol() error {
	if err := p.readRemoteVersionMsg(false); err != nil {
		return err
	}

	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}

	var protoVersion uint32
	p.flagsMtx.Lock()
	protoVersion = p.protocolVersion
	p.flagsMtx.Unlock()

	if err := p.writeSendAddrV2Msg(protoVersion); err != nil {
		return err
	}

	err := p.writeMessage(&wire.HnsMsgVerack{})
	if err != nil {
		return err
	}

	// Finish the negotiation by waiting for negotiable messages or verack.
	return p.waitToFinishNegotiation(protoVersion)
}

// negotiateOutboundProtocol performs the negotiation protocol for an outbound
// peer. The events should occur in the following order, otherwise an error is
// returned:
//
//  1. We send our version.
//  2. Remote peer may send verack before their version.
//  3. Remote peer sends their version.
//  4. We skip Bitcoin sendaddrv2 negotiation; Handshake has no sendaddrv2.
//  5. We send our verack.
//  6. We wait to receive verack if it was not already received, skipping
//     unknown Handshake packet types.
func (p *Peer) negotiateOutboundProtocol() error {
	if err := p.writeLocalVersionMsg(); err != nil {
		return err
	}

	if err := p.readRemoteVersionAllowingEarlyVerAck(); err != nil {
		return err
	}

	var protoVersion uint32
	p.flagsMtx.Lock()
	protoVersion = p.protocolVersion
	p.flagsMtx.Unlock()

	if err := p.writeSendAddrV2Msg(protoVersion); err != nil {
		return err
	}

	err := p.writeMessage(&wire.HnsMsgVerack{})
	if err != nil {
		return err
	}

	// Finish the negotiation by waiting for negotiable messages or verack.
	return p.waitToFinishNegotiation(protoVersion)
}

// start begins processing input and output messages.
func (p *Peer) start() error {
	log.Tracef("Starting peer %s", p)

	negotiateErr := make(chan error, 1)
	p.launchGoroutine(func() {
		defer p.recoverFromPanic()

		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	})

	// Negotiate the protocol within the specified negotiateTimeout.
	select {
	case err := <-negotiateErr:
		if err != nil {
			p.Disconnect()
			return err
		}
	case <-time.After(negotiateTimeout):
		p.Disconnect()
		return errors.New("protocol negotiation timeout")
	case <-p.quit:
		return errors.New("peer disconnected during negotiation")
	}
	log.Debugf("Connected to %s", p.Addr())

	// The protocol has been negotiated successfully so start processing input
	// and output messages.
	p.launchGoroutine(p.stallHandler)
	p.launchGoroutine(p.inHandler)
	p.launchGoroutine(p.queueHandler)
	p.launchGoroutine(p.outHandler)
	p.launchGoroutine(p.pingHandler)

	return nil
}

// AssociateConnection associates the given conn to the peer.   Calling this
// function when the peer is already connected will have no effect.
func (p *Peer) AssociateConnection(conn net.Conn) {
	p.lifecycleMtx.Lock()

	// A connection associated after shutdown cannot be serviced.  Close it so
	// the caller does not leak the transport.
	if atomic.LoadInt32(&p.disconnect) != 0 {
		p.lifecycleMtx.Unlock()
		_ = conn.Close()
		return
	}

	// Already connected?
	if !atomic.CompareAndSwapInt32(&p.connected, 0, 1) {
		p.lifecycleMtx.Unlock()
		return
	}

	p.conn = conn
	p.timeConnected = time.Now()

	if p.inbound {
		p.addr = p.conn.RemoteAddr().String()

		// Set up a NetAddress for the peer to be used with AddrManager.  We
		// only do this inbound because outbound set this up at connection time
		// and no point recomputing.
		na, err := newNetAddress(p.conn.RemoteAddr(), p.services)
		if err != nil {
			log.Errorf("Cannot create remote net address: %v", err)
			p.lifecycleMtx.Unlock()
			p.Disconnect()
			return
		}

		// Convert the NetAddress created above into NetAddressV2.
		currentNa := wire.NetAddressV2FromBytes(
			na.Timestamp, na.Services, na.IP, na.Port,
		)
		p.na = currentNa
	}

	p.launchGoroutine(func() {
		if err := p.start(); err != nil {
			log.Debugf("Cannot start peer %v: %v", p, err)
			p.Disconnect()
		}
	})
	p.lifecycleMtx.Unlock()
}

// WaitForDisconnect waits until the peer has disconnected and its connection
// and protocol handler goroutines have exited.  This will happen if either the
// local or remote side has disconnected or the peer is forcibly disconnected
// via Disconnect.
//
// This method must not be called synchronously from a message listener because
// listeners execute in the input handler that this method waits for.
func (p *Peer) WaitForDisconnect() {
	<-p.quit

	// Synchronize with AssociateConnection so the initial lifecycle goroutine
	// is registered before waiting.  That goroutine remains registered while
	// start adds the negotiation and handler goroutines.
	p.lifecycleMtx.Lock()
	p.lifecycleWg.Wait()
	p.lifecycleMtx.Unlock()
}

// ShouldDowngradeToV1 is retained for the old transport downgrade hook.
// Handshake Brontide/plaintext fallback is handled before peer negotiation.
//
// This function is safe for concurrent access.
func (p *Peer) ShouldDowngradeToV1() bool {
	// Brontide fallback is handled before the peer protocol starts.
	return false
}

// newPeerBase returns a new base bitcoin peer based on the inbound flag.  This
// is used by the NewInboundPeer and NewOutboundPeer functions to perform base
// setup needed by both types of peers.
func newPeerBase(origCfg *Config, inbound bool) *Peer {
	// Default to the max supported protocol version if not specified by the
	// caller.
	cfg := *origCfg // Copy to avoid mutating caller.
	if cfg.ProtocolVersion == 0 {
		cfg.ProtocolVersion = MaxProtocolVersion
	}

	// Set the chain parameters to regtest if the caller did not specify any.
	if cfg.ChainParams == nil {
		cfg.ChainParams = &chaincfg.RegressionNetParams
	}

	// Set the trickle interval if a non-positive value is specified.
	if cfg.TrickleInterval <= 0 {
		cfg.TrickleInterval = DefaultTrickleInterval
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultWriteTimeout
	}
	if cfg.MaxOutboundQueueMessages <= 0 {
		cfg.MaxOutboundQueueMessages = maxQueuedOutboundMessages
	}
	if cfg.MaxOutboundQueueBytes == 0 {
		cfg.MaxOutboundQueueBytes = maxQueuedOutboundBytes
	}
	if cfg.MaxOutboundInventory <= 0 {
		cfg.MaxOutboundInventory = maxQueuedInventory
	}

	p := Peer{
		inbound:            inbound,
		wireEncoding:       wire.BaseEncoding,
		knownInventory:     lru.NewCache(maxKnownInventory),
		queuedInventorySet: make(map[wire.InvVect]struct{}),
		maxQueuedMessages:  cfg.MaxOutboundQueueMessages,
		maxQueuedInventory: cfg.MaxOutboundInventory,
		maxQueuedBytes:     cfg.MaxOutboundQueueBytes,
		queueBudget:        cfg.OutboundQueueBudget,
		stallControl:       make(chan stallControlMsg, 1), // nonblocking sync
		outputQueue:        make(chan outMsg, outputBufferSize),
		sendQueue:          make(chan outMsg, 1),   // nonblocking sync
		sendDoneQueue:      make(chan struct{}, 1), // nonblocking sync
		outputInvChan:      make(chan outInv, outputBufferSize),
		inQuit:             make(chan struct{}),
		queueQuit:          make(chan struct{}),
		outQuit:            make(chan struct{}),
		quit:               make(chan struct{}),
		cfg:                cfg, // Copy so caller can't mutate.
		services:           cfg.Services,
		protocolVersion:    cfg.ProtocolVersion,
	}

	// Transport encryption is set by the server after Brontide/plaintext
	// connection setup.
	p.cfg.UsingV2Conn = false

	return &p
}

// NewInboundPeer returns a new inbound bitcoin peer. Use Start to begin
// processing incoming and outgoing messages.
func NewInboundPeer(cfg *Config) *Peer {
	return newPeerBase(cfg, true)
}

// NewOutboundPeer returns a new outbound bitcoin peer. If the Config argument
// does not set HostToNetAddress, connecting to anything other than an ipv4 or
// ipv6 address will fail and may cause a nil-pointer-dereference. This
// includes hostnames and onion services.
func NewOutboundPeer(cfg *Config, addr string) (*Peer, error) {
	p := newPeerBase(cfg, false)
	p.addr = addr

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}

	if cfg.HostToNetAddress != nil {
		na, err := cfg.HostToNetAddress(host, uint16(port), 0)
		if err != nil {
			return nil, err
		}
		p.na = na
	} else {
		// If host is an onion hidden service or a hostname, it is
		// likely that a nil-pointer-dereference will occur. The caller
		// should set HostToNetAddress if connecting to these.
		p.na = wire.NetAddressV2FromBytes(
			time.Now(), 0, net.ParseIP(host), uint16(port),
		)
	}

	return p, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
