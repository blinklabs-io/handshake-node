// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMainNetCheckpointsMatchHsdV8(t *testing.T) {
	t.Parallel()

	want := []struct {
		height int32
		hash   string
	}{
		{1008, "0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"},
		{2016, "0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40"},
		{10000, "00000000000001a86811a6f520bf67cefa03207dc84fd315f58153b28694ec51"},
		{20000, "0000000000000162c7ac70a582256f59c189b5c90d8e9861b3f374ed714c58de"},
		{30000, "0000000000000004f790862846b23c3a81585aea0fa79a7d851b409e027bcaa7"},
		{40000, "0000000000000002966206a40b10a575cb46531253b08dae8e1b356cfa277248"},
		{50000, "00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e"},
		{56880, "0000000000000001d4ef9ea6908bb4eb970d556bd07cbd7d06a634e1cd5bbf4e"},
		{61043, "00000000000000015b84385e0307370f8323420eaa27ef6e407f2d3162f1fd05"},
		{100000, "000000000000000136d7d3efa688072f40d9fdd71bd47bb961694c0f38950246"},
		{130000, "0000000000000005ee5106df9e48bcd232a1917684ac344b35ddd9b9e4101096"},
		{160000, "00000000000000021e723ce5aedc021ab4f85d46a6914e40148f01986baa46c9"},
		{200000, "000000000000000181ebc18d6c34442ffef3eedca90c57ca8ecc29016a1cfe16"},
		{225000, "00000000000000021f0be013ebad018a9ef97c8501766632f017a778781320d5"},
		{258026, "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95"},
	}

	if len(MainNetParams.Checkpoints) != len(want) {
		t.Fatalf("mainnet checkpoints: got %d, want %d",
			len(MainNetParams.Checkpoints), len(want))
	}

	for i, checkpoint := range MainNetParams.Checkpoints {
		if checkpoint.Height != want[i].height {
			t.Fatalf("checkpoint %d height: got %d, want %d", i,
				checkpoint.Height, want[i].height)
		}
		if checkpoint.Hash == nil {
			t.Fatalf("checkpoint %d hash is nil", i)
		}

		wantBytes, err := hex.DecodeString(want[i].hash)
		if err != nil {
			t.Fatalf("checkpoint %d test hash: %v", i, err)
		}
		if !bytes.Equal(checkpoint.Hash[:], wantBytes) {
			t.Fatalf("checkpoint %d native hash bytes: got %x, want %x", i,
				checkpoint.Hash[:], wantBytes)
		}
		if got := checkpoint.Hash.String(); got != want[i].hash {
			t.Fatalf("checkpoint %d hash text: got %s, want %s", i,
				got, want[i].hash)
		}
	}

	if len(RegressionNetParams.Checkpoints) != 0 {
		t.Fatalf("regtest checkpoints: got %d, want 0",
			len(RegressionNetParams.Checkpoints))
	}
}

// TestInvalidHashStr ensures newHashFromStr only accepts full, valid hashes.
func TestInvalidHashStr(t *testing.T) {
	tests := []string{
		"banana",
		"01",
	}

	for _, test := range tests {
		t.Run(test, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic for invalid hash, got nil")
				}
			}()
			newHashFromStr(test)
		})
	}
}

// TestMustRegisterPanic ensures the mustRegister function panics when used to
// register an invalid network.
func TestMustRegisterPanic(t *testing.T) {
	t.Parallel()

	// Setup a defer to catch the expected panic to ensure it actually
	// paniced.
	defer func() {
		if err := recover(); err == nil {
			t.Error("mustRegister did not panic as expected")
		}
	}()

	// Intentionally try to register duplicate params to force a panic.
	mustRegister(&MainNetParams)
}

func TestRegisterHDKeyID(t *testing.T) {
	t.Parallel()

	// Ref: https://github.com/satoshilabs/slips/blob/master/slip-0132.md
	hdKeyIDZprv := []byte{0x02, 0xaa, 0x7a, 0x99}
	hdKeyIDZpub := []byte{0x02, 0xaa, 0x7e, 0xd3}

	if err := RegisterHDKeyID(hdKeyIDZpub, hdKeyIDZprv); err != nil {
		t.Fatalf("RegisterHDKeyID: expected no error, got %v", err)
	}

	got, err := HDPrivateKeyToPublicKeyID(hdKeyIDZprv)
	if err != nil {
		t.Fatalf("HDPrivateKeyToPublicKeyID: expected no error, got %v", err)
	}

	if !bytes.Equal(got, hdKeyIDZpub) {
		t.Fatalf("HDPrivateKeyToPublicKeyID: expected result %v, got %v",
			hdKeyIDZpub, got)
	}
}

func TestInvalidHDKeyID(t *testing.T) {
	t.Parallel()

	prvValid := []byte{0x02, 0xaa, 0x7a, 0x99}
	pubValid := []byte{0x02, 0xaa, 0x7e, 0xd3}
	prvInvalid := []byte{0x00}
	pubInvalid := []byte{0x00}

	if err := RegisterHDKeyID(pubInvalid, prvValid); err != ErrInvalidHDKeyID {
		t.Fatalf("RegisterHDKeyID: want err ErrInvalidHDKeyID, got %v", err)
	}

	if err := RegisterHDKeyID(pubValid, prvInvalid); err != ErrInvalidHDKeyID {
		t.Fatalf("RegisterHDKeyID: want err ErrInvalidHDKeyID, got %v", err)
	}

	if err := RegisterHDKeyID(pubInvalid, prvInvalid); err != ErrInvalidHDKeyID {
		t.Fatalf("RegisterHDKeyID: want err ErrInvalidHDKeyID, got %v", err)
	}

	// FIXME: The error type should be changed to ErrInvalidHDKeyID.
	if _, err := HDPrivateKeyToPublicKeyID(prvInvalid); err != ErrUnknownHDKeyID {
		t.Fatalf("HDPrivateKeyToPublicKeyID: want err ErrUnknownHDKeyID, got %v", err)
	}
}
