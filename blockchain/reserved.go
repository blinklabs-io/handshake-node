// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	_ "embed"
	"encoding/binary"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

//go:embed names.db
var reservedNameDBBytes []byte

//go:embed lockup.db
var lockedNameDBBytes []byte

var (
	reservedNameDB = mustLoadReservedNameDB(reservedNameDBBytes)
	lockedNameDB   = mustLoadLockedNameDB(lockedNameDBBytes)
)

type reservedNameEntry struct {
	name   string
	target string
	value  uint64
	root   bool
	top100 bool
	custom bool
	zero   bool
}

type lockedNameEntry struct {
	name   string
	target string
	root   bool
	custom bool
}

type reservedNamesDB struct {
	data       []byte
	size       uint32
	tableStart int
	nameValue  uint64
	rootValue  uint64
	topValue   uint64
}

type lockedNamesDB struct {
	data       []byte
	size       uint32
	tableStart int
}

func mustLoadReservedNameDB(data []byte) *reservedNamesDB {
	if len(data) < 28 {
		panic("reserved name database is corrupt")
	}

	db := &reservedNamesDB{
		data:       data,
		size:       binary.LittleEndian.Uint32(data[0:4]),
		tableStart: 28,
		nameValue:  binary.LittleEndian.Uint64(data[4:12]),
		rootValue:  binary.LittleEndian.Uint64(data[12:20]),
		topValue:   binary.LittleEndian.Uint64(data[20:28]),
	}
	if len(data) < db.tableStart+int(db.size)*36 {
		panic("reserved name database is truncated")
	}
	return db
}

func mustLoadLockedNameDB(data []byte) *lockedNamesDB {
	if len(data) < 4 {
		panic("locked name database is corrupt")
	}

	db := &lockedNamesDB{
		data:       data,
		size:       binary.LittleEndian.Uint32(data[0:4]),
		tableStart: 4,
	}
	if len(data) < db.tableStart+int(db.size)*36 {
		panic("locked name database is truncated")
	}
	return db
}

func (db *reservedNamesDB) has(nameHash chainhash.Hash) bool {
	return db.find(nameHash) >= 0
}

func (db *reservedNamesDB) get(nameHash chainhash.Hash) (reservedNameEntry, bool) {
	pos := db.find(nameHash)
	if pos < 0 {
		return reservedNameEntry{}, false
	}

	target, flags, index, customValue := readReservedRecord(db.data, pos)
	if index > len(target) {
		return reservedNameEntry{}, false
	}
	entry := reservedNameEntry{
		name:   target[:index],
		target: target,
		value:  db.nameValue,
		root:   flags&1 != 0,
		top100: flags&2 != 0,
		custom: flags&4 != 0,
		zero:   flags&8 != 0,
	}
	if entry.root {
		entry.value += db.rootValue
	}
	if entry.top100 {
		entry.value += db.topValue
	}
	if entry.custom {
		entry.value += customValue
	}
	if entry.zero {
		entry.value = 0
	}
	return entry, true
}

func (db *reservedNamesDB) find(nameHash chainhash.Hash) int {
	start := 0
	end := int(db.size) - 1

	for start <= end {
		index := (start + end) >> 1
		pos := db.tableStart + index*36
		cmp := bytes.Compare(db.data[pos:pos+chainhash.HashSize],
			nameHash[:])
		switch {
		case cmp == 0:
			return int(binary.LittleEndian.Uint32(
				db.data[pos+chainhash.HashSize : pos+36]))
		case cmp < 0:
			start = index + 1
		default:
			end = index - 1
		}
	}

	return -1
}

func (db *lockedNamesDB) has(nameHash chainhash.Hash) bool {
	return db.find(nameHash) >= 0
}

func (db *lockedNamesDB) get(nameHash chainhash.Hash) (lockedNameEntry, bool) {
	pos := db.find(nameHash)
	if pos < 0 {
		return lockedNameEntry{}, false
	}

	target, flags, index, _ := readReservedRecord(db.data, pos)
	if index > len(target) {
		return lockedNameEntry{}, false
	}
	return lockedNameEntry{
		name:   target[:index],
		target: target,
		root:   flags&1 != 0,
		custom: flags&2 != 0,
	}, true
}

func (db *lockedNamesDB) find(nameHash chainhash.Hash) int {
	start := 0
	end := int(db.size) - 1

	for start <= end {
		index := (start + end) >> 1
		pos := db.tableStart + index*36
		cmp := bytes.Compare(db.data[pos:pos+chainhash.HashSize],
			nameHash[:])
		switch {
		case cmp == 0:
			return int(binary.LittleEndian.Uint32(
				db.data[pos+chainhash.HashSize : pos+36]))
		case cmp < 0:
			start = index + 1
		default:
			end = index - 1
		}
	}

	return -1
}

func readReservedRecord(data []byte, pos int) (string, byte, int, uint64) {
	nameLen := int(data[pos])
	targetStart := pos + 1
	targetEnd := targetStart + nameLen
	target := string(data[targetStart:targetEnd])
	flags := data[targetEnd]
	index := int(data[targetEnd+1])

	var customValue uint64
	customValueOffset := targetEnd + 2
	if len(data[customValueOffset:]) >= 8 {
		customValue = binary.LittleEndian.Uint64(
			data[customValueOffset : customValueOffset+8])
	}

	return target, flags, index, customValue
}

func isReservedNameHash(nameHash chainhash.Hash, height uint32,
	params *chaincfg.Params) bool {

	if params.NameNoReserved {
		return false
	}
	if height >= params.NameClaimPeriod {
		return false
	}
	return reservedNameDB.has(nameHash)
}

func reservedNameValue(nameHash chainhash.Hash) (uint64, bool) {
	entry, ok := reservedNameDB.get(nameHash)
	if !ok {
		return 0, false
	}
	return entry.value, true
}

func isLockedUpNameHash(nameHash chainhash.Hash, height uint32,
	params *chaincfg.Params) bool {

	if params.NameNoReserved {
		return false
	}
	if height < params.NameClaimPeriod {
		return false
	}

	entry, ok := lockedNameDB.get(nameHash)
	if !ok {
		return false
	}
	if entry.root {
		return true
	}
	return height < params.NameAlexaLockup
}
