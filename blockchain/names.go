// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	maxNameSize     = 63
	maxResourceSize = 512

	maxBlockNameOpens    = 300
	maxBlockNameUpdates  = 600
	maxBlockNameRenewals = 600
)

type nameStateKind uint8

const (
	nameStateOpening nameStateKind = iota
	nameStateLocked
	nameStateBidding
	nameStateReveal
	nameStateClosed
	nameStateRevoked
)

var nameBlacklist = map[string]struct{}{
	"example":   {},
	"invalid":   {},
	"local":     {},
	"localhost": {},
	"test":      {},
}

type nameState struct {
	nameHash   chainhash.Hash
	name       []byte
	height     uint32
	renewal    uint32
	owner      wire.OutPoint
	value      int64
	highest    int64
	data       []byte
	transfer   uint32
	revoked    uint32
	claimed    uint32
	renewals   uint32
	registered bool
	expired    bool
	weak       bool
}

// NameState is an immutable snapshot of the persisted state for a Handshake
// name.
type NameState struct {
	nameHash   chainhash.Hash
	name       []byte
	height     uint32
	renewal    uint32
	owner      wire.OutPoint
	value      int64
	highest    int64
	data       []byte
	transfer   uint32
	revoked    uint32
	claimed    uint32
	renewals   uint32
	registered bool
	expired    bool
	weak       bool
}

func newNameState(nameHash chainhash.Hash) *nameState {
	return &nameState{
		nameHash: nameHash,
		owner:    nullNameOwner(),
	}
}

func newNameStateView(ns *nameState) *NameState {
	if ns == nil {
		return nil
	}

	return &NameState{
		nameHash:   ns.nameHash,
		name:       append([]byte(nil), ns.name...),
		height:     ns.height,
		renewal:    ns.renewal,
		owner:      ns.owner,
		value:      ns.value,
		highest:    ns.highest,
		data:       append([]byte(nil), ns.data...),
		transfer:   ns.transfer,
		revoked:    ns.revoked,
		claimed:    ns.claimed,
		renewals:   ns.renewals,
		registered: ns.registered,
		expired:    ns.expired,
		weak:       ns.weak,
	}
}

// NameHash returns the consensus name hash.
func (ns *NameState) NameHash() chainhash.Hash {
	return ns.nameHash
}

// NameBytes returns a copy of the raw name bytes.
func (ns *NameState) NameBytes() []byte {
	return append([]byte(nil), ns.name...)
}

// Name returns the raw name as a string.
func (ns *NameState) Name() string {
	return string(ns.name)
}

// Height returns the height at which the current name lifecycle began.
func (ns *NameState) Height() uint32 {
	return ns.height
}

// Renewal returns the height of the most recent renewal.
func (ns *NameState) Renewal() uint32 {
	return ns.renewal
}

// Owner returns the current name owner outpoint.
func (ns *NameState) Owner() wire.OutPoint {
	return ns.owner
}

// Value returns the current name value.
func (ns *NameState) Value() int64 {
	return ns.value
}

// Highest returns the highest bid value tracked for the name.
func (ns *NameState) Highest() int64 {
	return ns.highest
}

// Data returns a copy of the current resource data.
func (ns *NameState) Data() []byte {
	return append([]byte(nil), ns.data...)
}

// Transfer returns the transfer height, or zero when no transfer is pending.
func (ns *NameState) Transfer() uint32 {
	return ns.transfer
}

// Revoked returns the revoke height, or zero when the name is not revoked.
func (ns *NameState) Revoked() uint32 {
	return ns.revoked
}

// Claimed returns the claim height, or zero when the name was not claimed.
func (ns *NameState) Claimed() uint32 {
	return ns.claimed
}

// Renewals returns the number of renewals tracked for the name.
func (ns *NameState) Renewals() uint32 {
	return ns.renewals
}

// Registered returns whether the name has been registered.
func (ns *NameState) Registered() bool {
	return ns.registered
}

// Expired returns whether the name is marked expired.
func (ns *NameState) Expired() bool {
	return ns.expired
}

// Weak returns whether the name was claimed with the weak flag.
func (ns *NameState) Weak() bool {
	return ns.weak
}

func nullNameOwner() wire.OutPoint {
	return wire.OutPoint{
		Hash:  zeroHash,
		Index: math.MaxUint32,
	}
}

func isNullNameOwner(owner wire.OutPoint) bool {
	return owner.Hash == zeroHash && owner.Index == math.MaxUint32
}

func (ns *nameState) clone() *nameState {
	if ns == nil {
		return nil
	}

	clone := *ns
	clone.name = append([]byte(nil), ns.name...)
	clone.data = append([]byte(nil), ns.data...)
	return &clone
}

func (ns *nameState) isNull() bool {
	return ns.height == 0 &&
		ns.renewal == 0 &&
		isNullNameOwner(ns.owner) &&
		ns.value == 0 &&
		ns.highest == 0 &&
		len(ns.data) == 0 &&
		ns.transfer == 0 &&
		ns.revoked == 0 &&
		ns.claimed == 0 &&
		ns.renewals == 0 &&
		!ns.registered &&
		!ns.expired &&
		!ns.weak
}

func (ns *nameState) reset(height uint32) {
	ns.height = height
	ns.renewal = height
	ns.owner = nullNameOwner()
	ns.value = 0
	ns.highest = 0
	ns.data = nil
	ns.transfer = 0
	ns.revoked = 0
	ns.claimed = 0
	ns.renewals = 0
	ns.registered = false
	ns.expired = false
	ns.weak = false
}

func (ns *nameState) set(name []byte, height uint32) {
	ns.name = append(ns.name[:0], name...)
	ns.reset(height)
}

func (ns *nameState) state(height uint32, params *chaincfg.Params) nameStateKind {
	openPeriod := params.NameTreeInterval + 1

	if ns.revoked != 0 {
		return nameStateRevoked
	}

	if ns.claimed != 0 {
		if height < ns.height+params.NameLockupPeriod {
			return nameStateLocked
		}
		return nameStateClosed
	}

	if height < ns.height+openPeriod {
		return nameStateOpening
	}

	if height < ns.height+openPeriod+params.NameBiddingPeriod {
		return nameStateBidding
	}

	if height < ns.height+openPeriod+params.NameBiddingPeriod+
		params.NameRevealPeriod {

		return nameStateReveal
	}

	return nameStateClosed
}

func (ns *nameState) isClosed(height uint32, params *chaincfg.Params) bool {
	return ns.state(height, params) == nameStateClosed
}

func (ns *nameState) isClaimable(height uint32, params *chaincfg.Params) bool {
	return ns.claimed != 0 && !params.NameNoReserved &&
		height < params.NameClaimPeriod
}

func (ns *nameState) isExpired(height uint32, params *chaincfg.Params) bool {
	if ns.revoked != 0 {
		return height >= ns.revoked+params.NameAuctionMaturity
	}

	if !ns.isClosed(height, params) {
		return false
	}

	if ns.isClaimable(height, params) {
		return false
	}

	if height >= ns.renewal+params.NameRenewalWindow {
		return true
	}

	return isNullNameOwner(ns.owner)
}

func (ns *nameState) maybeExpire(height uint32, params *chaincfg.Params) {
	if !ns.isExpired(height, params) {
		return
	}

	data := append([]byte(nil), ns.data...)
	ns.reset(height)
	ns.expired = true
	ns.data = data
}

func (ns *nameState) encode() ([]byte, error) {
	if len(ns.name) > maxNameSize {
		return nil, fmt.Errorf("name length %d exceeds max %d",
			len(ns.name), maxNameSize)
	}
	if len(ns.data) > maxResourceSize {
		return nil, fmt.Errorf("name resource length %d exceeds max %d",
			len(ns.data), maxResourceSize)
	}
	if ns.value < 0 || ns.highest < 0 {
		return nil, fmt.Errorf("name values must be non-negative")
	}

	var field uint16
	if !isNullNameOwner(ns.owner) {
		field |= 1 << 0
	}
	if ns.value != 0 {
		field |= 1 << 1
	}
	if ns.highest != 0 {
		field |= 1 << 2
	}
	if ns.transfer != 0 {
		field |= 1 << 3
	}
	if ns.revoked != 0 {
		field |= 1 << 4
	}
	if ns.claimed != 0 {
		field |= 1 << 5
	}
	if ns.renewals != 0 {
		field |= 1 << 6
	}
	if ns.registered {
		field |= 1 << 7
	}
	if ns.expired {
		field |= 1 << 8
	}
	if ns.weak {
		field |= 1 << 9
	}

	var buf bytes.Buffer
	buf.WriteByte(byte(len(ns.name)))
	buf.Write(ns.name)

	var scratch [8]byte
	binary.LittleEndian.PutUint16(scratch[:2], uint16(len(ns.data)))
	buf.Write(scratch[:2])
	buf.Write(ns.data)

	binary.LittleEndian.PutUint32(scratch[:4], ns.height)
	buf.Write(scratch[:4])
	binary.LittleEndian.PutUint32(scratch[:4], ns.renewal)
	buf.Write(scratch[:4])
	binary.LittleEndian.PutUint16(scratch[:2], field)
	buf.Write(scratch[:2])

	if field&(1<<0) != 0 {
		buf.Write(ns.owner.Hash[:])
		if err := wire.WriteVarInt(&buf, 0, uint64(ns.owner.Index)); err != nil {
			return nil, err
		}
	}
	if field&(1<<1) != 0 {
		if err := wire.WriteVarInt(&buf, 0, uint64(ns.value)); err != nil {
			return nil, err
		}
	}
	if field&(1<<2) != 0 {
		if err := wire.WriteVarInt(&buf, 0, uint64(ns.highest)); err != nil {
			return nil, err
		}
	}
	if field&(1<<3) != 0 {
		binary.LittleEndian.PutUint32(scratch[:4], ns.transfer)
		buf.Write(scratch[:4])
	}
	if field&(1<<4) != 0 {
		binary.LittleEndian.PutUint32(scratch[:4], ns.revoked)
		buf.Write(scratch[:4])
	}
	if field&(1<<5) != 0 {
		binary.LittleEndian.PutUint32(scratch[:4], ns.claimed)
		buf.Write(scratch[:4])
	}
	if field&(1<<6) != 0 {
		if err := wire.WriteVarInt(&buf, 0, uint64(ns.renewals)); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func decodeNameState(nameHash chainhash.Hash, serialized []byte) (*nameState, error) {
	ns := newNameState(nameHash)
	if len(serialized) < 1 {
		return nil, errDeserialize("missing name length")
	}

	offset := 0
	nameLen := int(serialized[offset])
	offset++
	if nameLen > maxNameSize || len(serialized[offset:]) < nameLen+2 {
		return nil, errDeserialize("corrupt name state name")
	}
	ns.name = append([]byte(nil), serialized[offset:offset+nameLen]...)
	offset += nameLen

	dataLen := int(binary.LittleEndian.Uint16(serialized[offset:]))
	offset += 2
	if dataLen > maxResourceSize || len(serialized[offset:]) < dataLen+10 {
		return nil, errDeserialize("corrupt name state data")
	}
	ns.data = append([]byte(nil), serialized[offset:offset+dataLen]...)
	offset += dataLen

	ns.height = binary.LittleEndian.Uint32(serialized[offset:])
	offset += 4
	ns.renewal = binary.LittleEndian.Uint32(serialized[offset:])
	offset += 4
	field := binary.LittleEndian.Uint16(serialized[offset:])
	offset += 2

	need := func(n int) error {
		if len(serialized[offset:]) < n {
			return errDeserialize("truncated name state")
		}
		return nil
	}

	if field&(1<<0) != 0 {
		if err := need(chainhash.HashSize); err != nil {
			return nil, err
		}
		copy(ns.owner.Hash[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		index, err := readNameVarInt(serialized, &offset)
		if err != nil {
			return nil, err
		}
		if index > math.MaxUint32 {
			return nil, errDeserialize("name owner index overflows uint32")
		}
		ns.owner.Index = uint32(index)
	}
	if field&(1<<1) != 0 {
		value, err := readNameVarInt(serialized, &offset)
		if err != nil {
			return nil, err
		}
		if value > math.MaxInt64 {
			return nil, errDeserialize("name value overflows int64")
		}
		ns.value = int64(value)
	}
	if field&(1<<2) != 0 {
		highest, err := readNameVarInt(serialized, &offset)
		if err != nil {
			return nil, err
		}
		if highest > math.MaxInt64 {
			return nil, errDeserialize("name highest overflows int64")
		}
		ns.highest = int64(highest)
	}
	if field&(1<<3) != 0 {
		if err := need(4); err != nil {
			return nil, err
		}
		ns.transfer = binary.LittleEndian.Uint32(serialized[offset:])
		offset += 4
	}
	if field&(1<<4) != 0 {
		if err := need(4); err != nil {
			return nil, err
		}
		ns.revoked = binary.LittleEndian.Uint32(serialized[offset:])
		offset += 4
	}
	if field&(1<<5) != 0 {
		if err := need(4); err != nil {
			return nil, err
		}
		ns.claimed = binary.LittleEndian.Uint32(serialized[offset:])
		offset += 4
	}
	if field&(1<<6) != 0 {
		renewals, err := readNameVarInt(serialized, &offset)
		if err != nil {
			return nil, err
		}
		if renewals > math.MaxUint32 {
			return nil, errDeserialize("name renewals overflow uint32")
		}
		ns.renewals = uint32(renewals)
	}

	ns.registered = field&(1<<7) != 0
	ns.expired = field&(1<<8) != 0
	ns.weak = field&(1<<9) != 0

	if offset != len(serialized) {
		return nil, errDeserialize("trailing bytes in name state")
	}

	return ns, nil
}

func readNameVarInt(serialized []byte, offset *int) (uint64, error) {
	r := bytes.NewReader(serialized[*offset:])
	value, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return 0, err
	}
	*offset = len(serialized) - r.Len()
	return value, nil
}

func isNameCovenant(covenantType uint8) bool {
	return covenantType >= wire.CovenantClaim &&
		covenantType <= wire.CovenantRevoke
}

func isMutableNameCovenant(covenantType uint8) bool {
	switch covenantType {
	case wire.CovenantClaim, wire.CovenantOpen, wire.CovenantUpdate,
		wire.CovenantTransfer, wire.CovenantRevoke:
		return true
	case wire.CovenantRegister, wire.CovenantRenew,
		wire.CovenantFinalize:
		return true
	default:
		return false
	}
}

func isNameUpdateCovenant(covenantType uint8) bool {
	switch covenantType {
	case wire.CovenantClaim, wire.CovenantOpen, wire.CovenantUpdate,
		wire.CovenantTransfer, wire.CovenantRevoke:
		return true
	default:
		return false
	}
}

func isRenewalNameCovenant(covenantType uint8) bool {
	switch covenantType {
	case wire.CovenantRegister, wire.CovenantRenew, wire.CovenantFinalize:
		return true
	default:
		return false
	}
}

func covenantItem(covenant wire.Covenant, index int) []byte {
	if index < 0 {
		index += len(covenant.Items)
	}
	if index < 0 || index >= len(covenant.Items) {
		return nil
	}
	return covenant.Items[index]
}

func covenantHash(covenant wire.Covenant, index int) (chainhash.Hash, bool) {
	item := covenantItem(covenant, index)
	if len(item) != chainhash.HashSize {
		return chainhash.Hash{}, false
	}

	var hash chainhash.Hash
	copy(hash[:], item)
	return hash, true
}

func covenantU32(covenant wire.Covenant, index int) (uint32, bool) {
	item := covenantItem(covenant, index)
	if len(item) != 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(item), true
}

func covenantU8(covenant wire.Covenant, index int) (uint8, bool) {
	item := covenantItem(covenant, index)
	if len(item) != 1 {
		return 0, false
	}
	return item[0], true
}

// HashName returns the Handshake consensus hash for the provided raw name.
func HashName(name []byte) chainhash.Hash {
	return hashName(name)
}

func hashName(name []byte) chainhash.Hash {
	return chainhash.Hash(sha3.Sum256(name))
}

func verifyName(name []byte) bool {
	if len(name) == 0 || len(name) > maxNameSize {
		return false
	}

	for i, ch := range name {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'z':
		case ch == '-' || ch == '_':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}

	_, blacklisted := nameBlacklist[string(name)]
	return !blacklisted
}

func checkCovenantSanity(tx *hnsutil.Tx) error {
	msgTx := tx.MsgTx()

	if err := checkTransactionNameLimits(tx); err != nil {
		return err
	}

	if IsCoinBase(tx) {
		for i := 1; i < len(msgTx.TxIn); i++ {
			if i >= len(msgTx.TxOut) {
				return badCovenant(
					"coinbase proof input is unlinked")
			}
		}

		for i, txOut := range msgTx.TxOut {
			covenant := txOut.Covenant
			switch covenant.Type {
			case wire.CovenantNone:
				if len(covenant.Items) != 0 {
					return badCovenant("NONE covenant has items")
				}
				if i > 0 && i < len(msgTx.TxIn) {
					if err := checkCoinbaseAirdropProofSanity(tx,
						i); err != nil {

						return err
					}
				}
			case wire.CovenantClaim:
				if i == 0 || i >= len(msgTx.TxIn) {
					return badCovenant("coinbase CLAIM is not linked")
				}
				if err := checkClaimCovenant(covenant); err != nil {
					return err
				}
				if err := checkCoinbaseClaimProofSanity(tx, i,
					covenant); err != nil {

					return err
				}
			default:
				return badCovenant("coinbase creates non-claim covenant")
			}
		}
		return nil
	}

	for i, txOut := range msgTx.TxOut {
		covenant := txOut.Covenant
		switch covenant.Type {
		case wire.CovenantNone:
			if len(covenant.Items) != 0 {
				return badCovenant("NONE covenant has items")
			}
		case wire.CovenantClaim:
			return badCovenant("non-coinbase CLAIM covenant")
		case wire.CovenantOpen:
			if err := checkNamedCovenant(covenant, 3, true); err != nil {
				return err
			}
			start, _ := covenantU32(covenant, 1)
			if start != 0 {
				return badCovenant("OPEN covenant has non-zero height")
			}
		case wire.CovenantBid:
			if err := checkNamedCovenant(covenant, 4, true); err != nil {
				return err
			}
			if _, ok := covenantHash(covenant, 3); !ok {
				return badCovenant("BID covenant blind is not a hash")
			}
		case wire.CovenantReveal:
			if i >= len(msgTx.TxIn) {
				return badCovenant("REVEAL covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 3); err != nil {
				return err
			}
			if _, ok := covenantHash(covenant, 2); !ok {
				return badCovenant("REVEAL covenant nonce is not a hash")
			}
		case wire.CovenantRedeem:
			if i >= len(msgTx.TxIn) {
				return badCovenant("REDEEM covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 2); err != nil {
				return err
			}
		case wire.CovenantRegister:
			if i >= len(msgTx.TxIn) {
				return badCovenant("REGISTER covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 4); err != nil {
				return err
			}
			if len(covenantItem(covenant, 2)) > maxResourceSize {
				return badCovenant("REGISTER resource is too large")
			}
			if _, ok := covenantHash(covenant, 3); !ok {
				return badCovenant("REGISTER renewal is not a hash")
			}
		case wire.CovenantUpdate:
			if i >= len(msgTx.TxIn) {
				return badCovenant("UPDATE covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 3); err != nil {
				return err
			}
			if len(covenantItem(covenant, 2)) > maxResourceSize {
				return badCovenant("UPDATE resource is too large")
			}
		case wire.CovenantRenew:
			if i >= len(msgTx.TxIn) {
				return badCovenant("RENEW covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 3); err != nil {
				return err
			}
			if _, ok := covenantHash(covenant, 2); !ok {
				return badCovenant("RENEW renewal is not a hash")
			}
		case wire.CovenantTransfer:
			if i >= len(msgTx.TxIn) {
				return badCovenant("TRANSFER covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 4); err != nil {
				return err
			}
			version, ok := covenantU8(covenant, 2)
			if !ok || version > 31 {
				return badCovenant("TRANSFER address version is invalid")
			}
			hash := covenantItem(covenant, 3)
			if len(hash) < 2 || len(hash) > 40 {
				return badCovenant("TRANSFER address hash is invalid")
			}
		case wire.CovenantFinalize:
			if i >= len(msgTx.TxIn) {
				return badCovenant("FINALIZE covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 7); err != nil {
				return err
			}
			name := covenantItem(covenant, 2)
			if !verifyName(name) || hashName(name) != covenantHashMust(covenant, 0) {
				return badCovenant("FINALIZE name is invalid")
			}
			if _, ok := covenantU8(covenant, 3); !ok {
				return badCovenant("FINALIZE flags are invalid")
			}
			if _, ok := covenantU32(covenant, 4); !ok {
				return badCovenant("FINALIZE claim height is invalid")
			}
			if _, ok := covenantU32(covenant, 5); !ok {
				return badCovenant("FINALIZE renewal count is invalid")
			}
			if _, ok := covenantHash(covenant, 6); !ok {
				return badCovenant("FINALIZE renewal is not a hash")
			}
		case wire.CovenantRevoke:
			if i >= len(msgTx.TxIn) {
				return badCovenant("REVOKE covenant is not linked")
			}
			if err := checkNameHashHeight(covenant, 2); err != nil {
				return err
			}
		default:
			return badCovenant("unknown covenant type")
		}
	}

	return nil
}

func checkTransactionNameLimits(tx *hnsutil.Tx) error {
	var opens, updates, renewals int

	for _, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		switch covenant.Type {
		case wire.CovenantOpen:
			opens++
		}
		if isNameUpdateCovenant(covenant.Type) {
			updates++
		}
		if isRenewalNameCovenant(covenant.Type) {
			renewals++
		}
	}

	if opens > maxBlockNameOpens {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"transaction contains too many name opens - got %d, max %d",
			opens, maxBlockNameOpens))
	}
	if updates > maxBlockNameUpdates {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"transaction contains too many name updates - got %d, max %d",
			updates, maxBlockNameUpdates))
	}
	if renewals > maxBlockNameRenewals {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"transaction contains too many name renewals - got %d, max %d",
			renewals, maxBlockNameRenewals))
	}

	return nil
}

func checkClaimCovenant(covenant wire.Covenant) error {
	if err := checkNamedCovenant(covenant, 6, true); err != nil {
		return err
	}
	if _, ok := covenantU8(covenant, 3); !ok {
		return badCovenant("CLAIM flags are invalid")
	}
	if _, ok := covenantHash(covenant, 4); !ok {
		return badCovenant("CLAIM commit hash is invalid")
	}
	if _, ok := covenantU32(covenant, 5); !ok {
		return badCovenant("CLAIM commit height is invalid")
	}
	nameHash, _ := covenantHash(covenant, 0)
	if !reservedNameDB.has(nameHash) {
		return badCovenant("CLAIM name is not reserved")
	}
	return nil
}

func checkNamedCovenant(covenant wire.Covenant, count int, hasName bool) error {
	if err := checkNameHashHeight(covenant, count); err != nil {
		return err
	}
	if hasName {
		name := covenantItem(covenant, 2)
		nameHash, _ := covenantHash(covenant, 0)
		if !verifyName(name) || hashName(name) != nameHash {
			return badCovenant("covenant name does not match hash")
		}
	}
	return nil
}

func checkNameHashHeight(covenant wire.Covenant, count int) error {
	if len(covenant.Items) != count {
		return badCovenant(fmt.Sprintf("covenant has %d items, want %d",
			len(covenant.Items), count))
	}
	if _, ok := covenantHash(covenant, 0); !ok {
		return badCovenant("covenant name hash is invalid")
	}
	if _, ok := covenantU32(covenant, 1); !ok {
		return badCovenant("covenant height is invalid")
	}
	return nil
}

func covenantHashMust(covenant wire.Covenant, index int) chainhash.Hash {
	hash, _ := covenantHash(covenant, index)
	return hash
}

func badCovenant(reason string) error {
	return ruleError(ErrInvalidCovenant, reason)
}

func checkBlockNameLimits(block *hnsutil.Block) error {
	var opens, updates, renewals int
	seen := make(map[chainhash.Hash]struct{})

	for _, tx := range block.Transactions() {
		if hasSeenMutableName(tx, seen) {
			return ruleError(ErrInvalidCovenant,
				"block contains duplicate covenant name action")
		}

		for _, txOut := range tx.MsgTx().TxOut {
			covenant := txOut.Covenant
			switch covenant.Type {
			case wire.CovenantOpen:
				opens++
			}
			if isNameUpdateCovenant(covenant.Type) {
				updates++
			}
			if isRenewalNameCovenant(covenant.Type) {
				renewals++
			}
		}

		addMutableNames(tx, seen)
	}

	if opens > maxBlockNameOpens {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"block contains too many name opens - got %d, max %d",
			opens, maxBlockNameOpens))
	}
	if updates > maxBlockNameUpdates {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"block contains too many name updates - got %d, max %d",
			updates, maxBlockNameUpdates))
	}
	if renewals > maxBlockNameRenewals {
		return ruleError(ErrInvalidCovenant, fmt.Sprintf(
			"block contains too many name renewals - got %d, max %d",
			renewals, maxBlockNameRenewals))
	}

	return nil
}

func hasSeenMutableName(tx *hnsutil.Tx, seen map[chainhash.Hash]struct{}) bool {
	txSeen := make(map[chainhash.Hash]struct{})
	for _, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isMutableNameCovenant(covenant.Type) {
			continue
		}
		nameHash, ok := covenantHash(covenant, 0)
		if !ok {
			continue
		}
		if _, exists := seen[nameHash]; exists {
			return true
		}
		if _, exists := txSeen[nameHash]; exists {
			return true
		}
		txSeen[nameHash] = struct{}{}
	}
	return false
}

func addMutableNames(tx *hnsutil.Tx, seen map[chainhash.Hash]struct{}) {
	for _, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isMutableNameCovenant(covenant.Type) {
			continue
		}
		nameHash, ok := covenantHash(covenant, 0)
		if !ok {
			continue
		}
		seen[nameHash] = struct{}{}
	}
}
