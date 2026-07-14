// Copyright (c) 2024-2025 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

const (
	// CovenantNone represents a transaction with no name covenant action.
	CovenantNone uint8 = 0

	// CovenantClaim represents an ICANN/Alexa reserved name claim.
	CovenantClaim uint8 = 1

	// CovenantOpen represents the opening of a name auction.
	CovenantOpen uint8 = 2

	// CovenantBid represents a bid in a name auction.
	CovenantBid uint8 = 3

	// CovenantReveal represents revealing a bid's true value.
	CovenantReveal uint8 = 4

	// CovenantRedeem represents reclaiming a losing bid's coins.
	CovenantRedeem uint8 = 5

	// CovenantRegister represents registering a won name with DNS data.
	CovenantRegister uint8 = 6

	// CovenantUpdate represents updating a name's DNS data.
	CovenantUpdate uint8 = 7

	// CovenantRenew represents renewing a name to prevent expiry.
	CovenantRenew uint8 = 8

	// CovenantTransfer represents initiating a name transfer.
	CovenantTransfer uint8 = 9

	// CovenantFinalize represents finalizing a name transfer.
	CovenantFinalize uint8 = 10

	// CovenantRevoke represents revoking a name.
	CovenantRevoke uint8 = 11

	// maxCovenantType is the highest known covenant type value.
	maxCovenantType = CovenantRevoke

	// MaxCovenantItems is the maximum number of items a covenant can have.
	// This matches hsd's consensus MAX_SCRIPT_STACK bound.
	MaxCovenantItems = 1000

	maxCovenantItems = MaxCovenantItems

	// maxCovenantItemSize is the maximum size of a single covenant item.
	// It is large enough to admit every hsd-sane unknown covenant while still
	// bounding memory during deserialization.
	maxCovenantItemSize = 585
)

// covenantTypeNames maps covenant types to their human-readable names.
var covenantTypeNames = [maxCovenantType + 1]string{
	CovenantNone:     "NONE",
	CovenantClaim:    "CLAIM",
	CovenantOpen:     "OPEN",
	CovenantBid:      "BID",
	CovenantReveal:   "REVEAL",
	CovenantRedeem:   "REDEEM",
	CovenantRegister: "REGISTER",
	CovenantUpdate:   "UPDATE",
	CovenantRenew:    "RENEW",
	CovenantTransfer: "TRANSFER",
	CovenantFinalize: "FINALIZE",
	CovenantRevoke:   "REVOKE",
}

// Covenant represents a Handshake name covenant attached to a transaction
// output.  Covenants encode the state transitions of the Handshake name
// auction system.
//
// Wire format:
//
//	type(1 byte) + varint(itemCount) + for each item: varint(itemLen) + itemBytes
type Covenant struct {
	Type  uint8
	Items [][]byte
}

func validateCovenantFields(covenantType uint8, itemCount int, items [][]byte,
	op string) error {

	if itemCount > maxCovenantItems {
		str := fmt.Sprintf("covenant item count is too large "+
			"[count %d, max %d]", itemCount, maxCovenantItems)
		return messageError(op, str)
	}

	for i, item := range items {
		if len(item) > maxCovenantItemSize {
			str := fmt.Sprintf("covenant item %d is too large "+
				"[size %d, max %d]", i, len(item),
				maxCovenantItemSize)
			return messageError(op, str)
		}
	}

	return nil
}

// Encode serializes the covenant to w.
//
// Wire format: type(1) + varint(itemCount) + for each item: varint(len) + bytes
func (c *Covenant) Encode(w io.Writer) error {
	itemCount := len(c.Items)
	if err := validateCovenantFields(c.Type, itemCount, c.Items,
		"Covenant.Encode"); err != nil {
		return err
	}

	err := binarySerializer.PutUint8(w, c.Type)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, 0, uint64(itemCount))
	if err != nil {
		return err
	}

	for _, item := range c.Items {
		err = WriteVarBytes(w, 0, item)
		if err != nil {
			return err
		}
	}

	return nil
}

// Decode deserializes a covenant from r.
func (c *Covenant) Decode(r io.Reader) error {
	typ, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}
	c.Type = typ

	itemCount, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if itemCount > maxCovenantItems {
		str := fmt.Sprintf("covenant item count is too large "+
			"[count %d, max %d]", itemCount, maxCovenantItems)
		return messageError("Covenant.Decode", str)
	}

	if itemCount == 0 {
		c.Items = nil
		return nil
	}

	c.Items = make([][]byte, itemCount)
	for i := uint64(0); i < itemCount; i++ {
		item, err := ReadVarBytes(r, 0, maxCovenantItemSize,
			"covenant item")
		if err != nil {
			return err
		}
		c.Items[i] = item
	}

	return nil
}

// SerializeSize returns the number of bytes needed to serialize the covenant.
func (c *Covenant) SerializeSize() int {
	// Type (1 byte) + varint(itemCount)
	n := 1 + VarIntSerializeSize(uint64(len(c.Items)))

	for _, item := range c.Items {
		// varint(itemLen) + item bytes
		n += VarIntSerializeSize(uint64(len(item))) + len(item)
	}

	return n
}

// String returns a human-readable covenant type name.
func (c *Covenant) String() string {
	if c.Type <= maxCovenantType {
		return covenantTypeNames[c.Type]
	}
	return fmt.Sprintf("UNKNOWN(%d)", c.Type)
}

// IsKnown returns whether the covenant type is one of the currently defined
// Handshake covenant types.
func (c *Covenant) IsKnown() bool {
	return c.Type <= maxCovenantType
}

// IsUnknown returns whether the covenant type is reserved for a future
// Handshake covenant extension.
func (c *Covenant) IsUnknown() bool {
	return !c.IsKnown()
}

// NewCovenant returns a new Covenant with the given type and items.
func NewCovenant(covenantType uint8, items [][]byte) *Covenant {
	return &Covenant{
		Type:  covenantType,
		Items: items,
	}
}
