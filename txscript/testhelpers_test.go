// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parseHex parses a hexadecimal literal used in short-form test scripts.
func parseHex(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, "0x") {
		return nil, errors.New("not a hex number")
	}
	return hex.DecodeString(tok[2:])
}

// shortFormOps holds a map of opcode names to values for use in short-form
// parsing.
var shortFormOps map[string]byte

// mustParseShortForm parses a short-form test script and panics on error.
func mustParseShortForm(script string) []byte {
	s, err := parseShortForm(script)
	if err != nil {
		panic("invalid short form script in test: " + err.Error())
	}
	return s
}

// scriptClassTest describes a pkScript in short form and the ScriptClass it is
// expected to map to. Handshake does not support generating or spending the
// legacy P2SH form below; it remains solely to cover retained classification.
type scriptClassTest struct {
	name   string
	script string
	class  ScriptClass
}

var scriptClassTests = []scriptClassTest{
	{
		name: "P2SH",
		script: "HASH160 DATA_20 " +
			"0x63bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb EQUAL",
		class: ScriptHashTy,
	},
	{
		name: "P2WPKH",
		script: "OP_0 DATA_20 " +
			"0x0102030405060708090a0b0c0d0e0f1011121314",
		class: WitnessV0PubKeyHashTy,
	},
	{
		name: "P2WSH",
		script: "OP_0 DATA_32 " +
			"0x000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f",
		class: WitnessV0ScriptHashTy,
	},
	{
		name:   "nulldata",
		script: "RETURN 'data'",
		class:  NullDataTy,
	},
	{
		name:   "nonstandard",
		script: "NOP",
		class:  NonStandardTy,
	},
}

// parseShortForm parses the compact script notation used throughout the
// txscript unit tests.
//
// Opcodes use OP_NAME or NAME, decimal values become integer pushes,
// 0x-prefixed values are inserted as raw bytes, and single-quoted strings are
// pushed as data.
func parseShortForm(script string) ([]byte, error) {
	if shortFormOps == nil {
		ops := make(map[string]byte)
		for opcodeName, opcodeValue := range OpcodeByName {
			if strings.Contains(opcodeName, "OP_UNKNOWN") {
				continue
			}
			ops[opcodeName] = opcodeValue

			if (opcodeName == "OP_FALSE" || opcodeName == "OP_TRUE") ||
				(opcodeValue != OP_0 && (opcodeValue < OP_1 ||
					opcodeValue > OP_16)) {

				ops[strings.TrimPrefix(opcodeName, "OP_")] = opcodeValue
			}
		}
		shortFormOps = ops
	}

	script = strings.ReplaceAll(script, "\n", " ")
	script = strings.ReplaceAll(script, "\t", " ")
	tokens := strings.Split(script, " ")
	builder := NewScriptBuilder()

	for _, tok := range tokens {
		if len(tok) == 0 {
			continue
		}

		if num, err := strconv.ParseInt(tok, 10, 64); err == nil {
			builder.AddInt64(num)
			continue
		} else if bts, err := parseHex(tok); err == nil {
			// Some active tests intentionally construct scripts that exceed
			// builder policy limits, so append raw literals directly.
			if builder.err == nil {
				builder.script = append(builder.script, bts...)
			}
		} else if len(tok) >= 2 &&
			tok[0] == '\'' && tok[len(tok)-1] == '\'' {

			builder.AddFullData([]byte(tok[1 : len(tok)-1]))
		} else if opcode, ok := shortFormOps[tok]; ok {
			builder.AddOp(opcode)
		} else {
			return nil, fmt.Errorf("bad token %q", tok)
		}
	}
	return builder.Script()
}
