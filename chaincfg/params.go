// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Handshake block can
	// have for the main network.  This is the value represented by compact
	// bits 0x1c00ffff: 0x0000000000ffff00...
	mainPowLimit, _ = new(big.Int).SetString("0000000000ffff00000000000000000000000000000000000000000000000000", 16)

	// regressionPowLimit is the highest proof of work value a Handshake
	// block can have for the regression test network.  This is the value
	// represented by compact bits 0x207fffff: 0x7fffff00...
	regressionPowLimit, _ = new(big.Int).SetString("7fffff0000000000000000000000000000000000000000000000000000000000", 16)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// EffectiveAlwaysActiveHeight returns the effective activation height for the
// deployment. If AlwaysActiveHeight is unset (i.e. zero), it returns
// the maximum uint32 value to indicate that it does not force activation.
func (d *ConsensusDeployment) EffectiveAlwaysActiveHeight() uint32 {
	if d.AlwaysActiveHeight == 0 {
		return math.MaxUint32
	}
	return d.AlwaysActiveHeight
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// ConsensusDeployment defines details related to a specific consensus rule
// change that is voted in.  This is part of BIP0009.
type ConsensusDeployment struct {
	// BitNumber defines the specific bit number within the block version
	// this particular soft-fork deployment refers to.
	BitNumber uint8

	// MinActivationHeight is an optional field that when set (default
	// value being zero), modifies the traditional BIP 9 state machine by
	// only transitioning from LockedIn to Active once the block height is
	// greater than (or equal to) thus specified height.
	MinActivationHeight uint32

	// CustomActivationThreshold if set (non-zero), will _override_ the
	// existing RuleChangeActivationThreshold value set at the
	// network/chain level.
	CustomActivationThreshold uint32

	// AlwaysActiveHeight defines an optional block threshold at which the
	// deployment is forced to be active. If unset (0), it defaults to
	// math.MaxUint32, meaning the deployment does not force activation.
	AlwaysActiveHeight uint32

	// DeploymentStarter is used to determine if the given
	// ConsensusDeployment has started or not.
	DeploymentStarter ConsensusDeploymentStarter

	// DeploymentEnder is used to determine if the given
	// ConsensusDeployment has ended or not.
	DeploymentEnder ConsensusDeploymentEnder
}

// Constants that define the deployment offset in the deployments field of the
// parameters for each deployment.
const (
	// DeploymentTestDummy defines the rule change deployment ID for testing
	// purposes.
	DeploymentTestDummy = iota

	// DeploymentTestDummyMinActivation defines the rule change deployment
	// ID for testing purposes with min activation height.
	DeploymentTestDummyMinActivation

	// DeploymentCSV defines the rule change deployment ID for the CSV
	// soft-fork package. The CSV package includes the deployment of BIPS
	// 68, 112, and 113.
	DeploymentCSV

	// DeploymentSegwit defines the rule change deployment ID for the
	// Segregated Witness (segwit) soft-fork package.
	DeploymentSegwit

	// DeploymentTaproot is kept for array sizing compatibility but is
	// unused in Handshake (no Taproot).
	DeploymentTaproot

	// DeploymentTestDummyAlwaysActive is a dummy deployment that is meant
	// to always be active.
	DeploymentTestDummyAlwaysActive

	// DeploymentHardening defines the Handshake RSA-1024 hardening rule.
	DeploymentHardening

	// DeploymentICANNLockup defines the Handshake ICANN lockup rule.
	DeploymentICANNLockup

	// DeploymentAirstop defines the Handshake airdrop disablement rule.
	DeploymentAirstop

	// NOTE: DefinedDeployments must always come last since it is used to
	// determine how many defined deployments there currently are.

	// DefinedDeployments is the number of currently defined deployments.
	DefinedDeployments
)

// Params defines a network by its parameters.  These parameters may be
// used by applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// PoWNoRetargeting defines whether the network has difficulty
	// retargeting enabled or not. This should only be set to true for
	// regtest like networks.
	PoWNoRetargeting bool

	// EnforceBIP94 is kept for struct compatibility but unused in
	// Handshake.
	EnforceBIP94 bool

	// These fields define the block heights at which the specified softfork
	// BIP became active.  Handshake has these active from genesis (height 0).
	BIP0034Height int32
	BIP0065Height int32
	BIP0066Height int32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced (halving interval).
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.  Handshake retargets every block using a 144-block
	// window.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// These fields are related to voting on consensus rule changes as
	// defined by BIP0009.
	//
	// RuleChangeActivationThreshold is the number of blocks in a threshold
	// state retarget window for which a positive vote for a rule change
	// must be cast in order to lock in a rule change.
	//
	// MinerConfirmationWindow is the number of blocks in each threshold
	// state retarget window.
	//
	// Deployments define the specific consensus rule changes to be voted
	// on.
	RuleChangeActivationThreshold uint32
	MinerConfirmationWindow       uint32
	Deployments                   [DefinedDeployments]ConsensusDeployment

	// Mempool parameters
	RelayNonStdTxs bool

	// Human-readable part for Bech32 encoded addresses, as defined
	// in BIP 173.
	Bech32HRPSegwit string

	// Address encoding magics
	PubKeyHashAddrID        byte // First byte of a P2PKH address
	ScriptHashAddrID        byte // First byte of a P2SH address
	PrivateKeyID            byte // First byte of a WIF private key
	WitnessPubKeyHashAddrID byte // First byte of a P2WPKH address
	WitnessScriptHashAddrID byte // First byte of a P2WSH address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32

	// Handshake name-auction consensus parameters.  These values match hsd's
	// network constants and are expressed in blocks.
	NameAuctionStart    uint32
	NameRolloutInterval uint32
	NameLockupPeriod    uint32
	NameRenewalWindow   uint32
	NameRenewalPeriod   uint32
	NameRenewalMaturity uint32
	NameClaimPeriod     uint32
	NameAlexaLockup     uint32
	NameClaimFrequency  uint32
	NameBiddingPeriod   uint32
	NameRevealPeriod    uint32
	NameTreeInterval    uint32
	NameTransferLockup  uint32
	NameAuctionMaturity uint32
	NameDeflationHeight uint32
	NameClaimPrefix     string
	NameNoRollout       bool
	NameNoReserved      bool
	AirdropGooSigStop   uint32
}

// MainNetParams defines the network parameters for the Handshake mainnet.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "12038",
	DNSSeeds: []DNSSeed{
		{"hs-mainnet.bcoin.ninja", true},
		{"seed.htools.work", true},
	},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1c00ffff,
	BIP0034Height:            0, // Active from genesis
	BIP0065Height:            0,
	BIP0066Height:            0,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 170000,
	TargetTimespan:           time.Minute * 10 * 144, // 144 blocks (1 day)
	TargetTimePerBlock:       time.Minute * 10,       // 10 minutes
	RetargetAdjustmentFactor: 4,                      // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments. Handshake uses versionbits for
	// several historical consensus changes while retaining the surrounding
	// btcd deployment machinery.
	RuleChangeActivationThreshold: 1916, // 95% of MinerConfirmationWindow
	MinerConfirmationWindow:       2016,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentHardening: {
			BitNumber: 0,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1581638400, 0), // February 14, 2020
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1707868800, 0), // February 14, 2024
			),
		},
		DeploymentICANNLockup: {
			BitNumber: 1,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1691625600, 0), // August 10, 2023
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1703980800, 0), // December 31, 2023
			),
		},
		DeploymentAirstop: {
			BitNumber: 2,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1751328000, 0), // July 1, 2025
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1759881600, 0), // October 8, 2025
			),
		},
		DeploymentTestDummy: {
			BitNumber: 28,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1199145601, 0), // January 1, 2008
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1230767999, 0), // December 31, 2008
			),
		},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded addresses.
	Bech32HRPSegwit: "hs",

	// Address encoding magics
	PubKeyHashAddrID: 0x00,
	ScriptHashAddrID: 0x05,
	PrivateKeyID:     0x80,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 5353,

	// Handshake name auction parameters.
	NameAuctionStart:    2016,
	NameRolloutInterval: 1008,
	NameLockupPeriod:    4320,
	NameRenewalWindow:   105120,
	NameRenewalPeriod:   26208,
	NameRenewalMaturity: 4320,
	NameClaimPeriod:     210240,
	NameAlexaLockup:     420480,
	NameClaimFrequency:  288,
	NameBiddingPeriod:   720,
	NameRevealPeriod:    1440,
	NameTreeInterval:    36,
	NameTransferLockup:  288,
	NameAuctionMaturity: 4176,
	NameDeflationHeight: 61043,
	NameClaimPrefix:     "hns-claim:",
	NameNoRollout:       false,
	NameNoReserved:      false,
	AirdropGooSigStop:   56880,
}

// RegressionNetParams defines the network parameters for the Handshake
// regression test network.
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "14038",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	PoWNoRetargeting:         true,
	CoinbaseMaturity:         2,
	BIP0034Height:            0,
	BIP0065Height:            0,
	BIP0066Height:            0,
	SubsidyReductionInterval: 2500,
	TargetTimespan:           time.Minute * 10 * 144, // 144 blocks
	TargetTimePerBlock:       time.Minute * 10,       // 10 minutes
	RetargetAdjustmentFactor: 4,
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Consensus rule change deployments.
	RuleChangeActivationThreshold: 108, // 75% of MinerConfirmationWindow
	MinerConfirmationWindow:       144,
	Deployments: [DefinedDeployments]ConsensusDeployment{
		DeploymentTestDummy: {
			BitNumber: 28,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Time{}, // Always available for vote
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Time{}, // Never expires
			),
		},
		DeploymentTestDummyMinActivation: {
			BitNumber:                 22,
			CustomActivationThreshold: 72,  // Only needs 50% hash rate.
			MinActivationHeight:       600, // Can only activate after height 600.
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Time{}, // Always available for vote
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Time{}, // Never expires
			),
		},
		DeploymentTestDummyAlwaysActive: {
			BitNumber: 30,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Time{}, // Always available for vote
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Time{}, // Never expires
			),
			AlwaysActiveHeight: 1,
		},
		DeploymentHardening: {
			BitNumber: 3,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1581638400, 0), // February 14, 2020
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1707868800, 0), // February 14, 2024
			),
		},
		DeploymentICANNLockup: {
			BitNumber: 4,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1691625600, 0), // August 10, 2023
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1703980800, 0), // December 31, 2023
			),
		},
		DeploymentAirstop: {
			BitNumber: 2,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Unix(1751328000, 0), // July 1, 2025
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Unix(1759881600, 0), // October 8, 2025
			),
		},
		DeploymentCSV: {
			BitNumber: 0,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Time{}, // Always available for vote
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Time{}, // Never expires
			),
		},
		DeploymentSegwit: {
			BitNumber: 1,
			DeploymentStarter: NewMedianTimeDeploymentStarter(
				time.Time{}, // Always available for vote
			),
			DeploymentEnder: NewMedianTimeDeploymentEnder(
				time.Time{}, // Never expires.
			),
		},
	},

	// Mempool parameters
	RelayNonStdTxs: true,

	// Human-readable part for Bech32 encoded addresses.
	Bech32HRPSegwit: "rs",

	// Address encoding magics
	PubKeyHashAddrID: 0x6f,
	ScriptHashAddrID: 0xc4,
	PrivateKeyID:     0x5a,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0xea, 0xb4, 0x04, 0xc7}, // rprv
	HDPublicKeyID:  [4]byte{0xea, 0xb4, 0xfa, 0x05}, // rpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 5355,

	// Handshake name auction parameters.
	NameAuctionStart:    0,
	NameRolloutInterval: 2,
	NameLockupPeriod:    2,
	NameRenewalWindow:   5000,
	NameRenewalPeriod:   2500,
	NameRenewalMaturity: 50,
	NameClaimPeriod:     250000,
	NameAlexaLockup:     500000,
	NameClaimFrequency:  0,
	NameBiddingPeriod:   5,
	NameRevealPeriod:    10,
	NameTreeInterval:    5,
	NameTransferLockup:  10,
	NameAuctionMaturity: 65,
	NameDeflationHeight: 200,
	NameClaimPrefix:     "hns-regtest:",
	NameNoRollout:       false,
	NameNoReserved:      false,
	AirdropGooSigStop:   math.MaxUint32,
}

var (
	// ErrDuplicateNet describes an error where the parameters for a
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")

	// ErrInvalidHDKeyID describes an error where the provided hierarchical
	// deterministic version bytes, or hd key id, is malformed.
	ErrInvalidHDKeyID = errors.New("invalid hd extended key version bytes")
)

var (
	registeredNets       = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs    = make(map[byte]struct{})
	scriptHashAddrIDs    = make(map[byte]struct{})
	bech32SegwitPrefixes = make(map[string]struct{})
	hdPrivToPubKeyIDs    = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}

	err := RegisterHDKeyID(params.HDPublicKeyID[:], params.HDPrivateKeyID[:])
	if err != nil {
		return err
	}

	// A valid Bech32 encoded address always has as prefix the
	// human-readable part for the given net followed by '1'.
	bech32SegwitPrefixes[params.Bech32HRPSegwit+"1"] = struct{}{}
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsBech32SegwitPrefix returns whether the prefix is a known prefix for
// addresses on any default or registered network.
func IsBech32SegwitPrefix(prefix string) bool {
	prefix = strings.ToLower(prefix)
	_, ok := bech32SegwitPrefixes[prefix]
	return ok
}

// RegisterHDKeyID registers a public and private hierarchical deterministic
// extended key ID pair.
//
// Non-standard HD version bytes, such as the ones documented in SLIP-0132,
// should be registered using this method for library packages to lookup key
// IDs (aka HD version bytes). When the provided key IDs are invalid, the
// ErrInvalidHDKeyID error will be returned.
func RegisterHDKeyID(hdPublicKeyID []byte, hdPrivateKeyID []byte) error {
	if len(hdPublicKeyID) != 4 || len(hdPrivateKeyID) != 4 {
		return ErrInvalidHDKeyID
	}

	var keyID [4]byte
	copy(keyID[:], hdPrivateKeyID)
	hdPrivToPubKeyIDs[keyID] = hdPublicKeyID

	return nil
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed native-order hex string into a
// chainhash.Hash. It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&RegressionNetParams)
}
