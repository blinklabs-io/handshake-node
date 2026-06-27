// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package brontide

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

// hsd's Noise_XK three-act message pattern:
//
//	Act One   (initiator -> responder): e, es
//	Act Two   (responder -> initiator): e, ee
//	Act Three (initiator -> responder): s, se
//
// Unlike LND's Brontide, hsd's acts carry no version byte: the ephemeral keys
// in acts one and two are sent as 64-byte Elligator Squared encodings, keeping
// the entire handshake indistinguishable from random bytes.
const (
	// ActOneSize is hsd's ACT_ONE_SIZE: a 64-byte uniform ephemeral key
	// encoding plus a 16-byte authentication tag.
	ActOneSize = UniformPublicKeySize + tagSize

	// ActTwoSize is hsd's ACT_TWO_SIZE: a 64-byte uniform ephemeral key
	// encoding plus a 16-byte authentication tag.
	ActTwoSize = UniformPublicKeySize + tagSize

	// ActThreeSize is hsd's ACT_THREE_SIZE: a 33-byte encrypted static key
	// plus two 16-byte authentication tags.
	ActThreeSize = PublicKeySize + tagSize + tagSize

	// HandshakeTimeout bounds a complete act exchange, matching hsd's
	// Peer.CONNECT_TIMEOUT, which covers the Brontide handshake before the
	// stream emits its connect event.
	HandshakeTimeout = 5 * time.Second
)

var (
	// ErrActSize is returned when a handshake act has the wrong length,
	// matching hsd's 'Act N: bad size.' errors.
	ErrActSize = errors.New("brontide: bad act size")

	// ErrActTag is returned when a handshake act fails authentication,
	// matching hsd's 'Act N: bad tag.' errors.
	ErrActTag = errors.New("brontide: bad act tag")

	// ErrHandshakeState is returned when handshake state is missing for the
	// requested act, such as an initiator without a remote static key.
	ErrHandshakeState = errors.New("brontide: invalid handshake state")
)

// HandshakeState is hsd's Brontide handshake state: a Noise symmetric state
// plus the key material accumulated across the three Noise_XK acts.
type HandshakeState struct {
	SymmetricState

	initiator       bool
	localStatic     *btcec.PrivateKey
	localEphemeral  *btcec.PrivateKey
	remoteStatic    *btcec.PublicKey
	remoteEphemeral *btcec.PublicKey

	sendCipher *CipherState
	recvCipher *CipherState

	// generateKey produces ephemeral keys and is overridable for
	// deterministic tests, like hsd's Brontide.generateKey.
	generateKey func() (*btcec.PrivateKey, error)

	// rng supplies randomness for the Elligator Squared encoding of
	// ephemeral keys. A nil reader selects crypto/rand.
	rng io.Reader
}

// NewHandshakeState initializes Brontide handshake state for one side of a
// connection, mirroring hsd's HandshakeState.initState. Initiators must
// supply the responder's static public key; responders pass nil.
func NewHandshakeState(initiator bool, localPriv *btcec.PrivateKey,
	remotePub *btcec.PublicKey) (*HandshakeState, error) {

	if localPriv == nil {
		return nil, fmt.Errorf("%w: nil local private key", ErrInvalidKey)
	}
	if initiator && remotePub == nil {
		return nil, fmt.Errorf("%w: initiator requires remote static key",
			ErrHandshakeState)
	}

	hs := &HandshakeState{
		initiator:    initiator,
		localStatic:  localPriv,
		remoteStatic: remotePub,
		generateKey:  GenerateKey,
	}

	hs.InitSymmetric(ProtocolName)
	hs.MixHash([]byte(Prologue))
	if initiator {
		hs.MixHash(remotePub.SerializeCompressed())
	} else {
		hs.MixHash(localPriv.PubKey().SerializeCompressed())
	}

	return hs, nil
}

// GenActOne generates act one for the initiator: a uniform-encoded ephemeral
// key and a tag binding the es ECDH result.
func (hs *HandshakeState) GenActOne() ([ActOneSize]byte, error) {
	var actOne [ActOneSize]byte

	// e
	ephemeral, err := hs.generateKey()
	if err != nil {
		return actOne, err
	}
	hs.localEphemeral = ephemeral

	ephemeralPub := ephemeral.PubKey()
	uniform, err := PublicKeyToHash(ephemeralPub, hs.rng)
	if err != nil {
		return actOne, err
	}
	hs.MixHash(ephemeralPub.SerializeCompressed())

	// es
	secret, err := ECDH(hs.remoteStatic, ephemeral)
	if err != nil {
		return actOne, err
	}
	hs.MixKey(secret[:])

	_, tag, err := hs.EncryptHash(nil)
	if err != nil {
		return actOne, err
	}

	copy(actOne[:UniformPublicKeySize], uniform)
	copy(actOne[UniformPublicKeySize:], tag)
	return actOne, nil
}

// RecvActOne processes act one on the responder.
func (hs *HandshakeState) RecvActOne(actOne []byte) error {
	if len(actOne) != ActOneSize {
		return fmt.Errorf("%w: act one is %d bytes, want %d",
			ErrActSize, len(actOne), ActOneSize)
	}

	uniform := actOne[:UniformPublicKeySize]
	tag := actOne[UniformPublicKeySize:]

	// e
	ephemeral, err := PublicKeyFromHash(uniform)
	if err != nil {
		return err
	}
	hs.remoteEphemeral = ephemeral
	hs.MixHash(ephemeral.SerializeCompressed())

	// es
	secret, err := ECDH(ephemeral, hs.localStatic)
	if err != nil {
		return err
	}
	hs.MixKey(secret[:])

	if _, err := hs.DecryptHash(nil, tag); err != nil {
		return fmt.Errorf("%w: act one", ErrActTag)
	}
	return nil
}

// GenActTwo generates act two for the responder: a uniform-encoded ephemeral
// key and a tag binding the ee ECDH result.
func (hs *HandshakeState) GenActTwo() ([ActTwoSize]byte, error) {
	var actTwo [ActTwoSize]byte

	// e
	ephemeral, err := hs.generateKey()
	if err != nil {
		return actTwo, err
	}
	hs.localEphemeral = ephemeral

	ephemeralPub := ephemeral.PubKey()
	uniform, err := PublicKeyToHash(ephemeralPub, hs.rng)
	if err != nil {
		return actTwo, err
	}
	hs.MixHash(ephemeralPub.SerializeCompressed())

	// ee
	secret, err := ECDH(hs.remoteEphemeral, ephemeral)
	if err != nil {
		return actTwo, err
	}
	hs.MixKey(secret[:])

	_, tag, err := hs.EncryptHash(nil)
	if err != nil {
		return actTwo, err
	}

	copy(actTwo[:UniformPublicKeySize], uniform)
	copy(actTwo[UniformPublicKeySize:], tag)
	return actTwo, nil
}

// RecvActTwo processes act two on the initiator.
func (hs *HandshakeState) RecvActTwo(actTwo []byte) error {
	if len(actTwo) != ActTwoSize {
		return fmt.Errorf("%w: act two is %d bytes, want %d",
			ErrActSize, len(actTwo), ActTwoSize)
	}

	uniform := actTwo[:UniformPublicKeySize]
	tag := actTwo[UniformPublicKeySize:]

	// e
	ephemeral, err := PublicKeyFromHash(uniform)
	if err != nil {
		return err
	}
	hs.remoteEphemeral = ephemeral
	hs.MixHash(ephemeral.SerializeCompressed())

	// ee
	secret, err := ECDH(ephemeral, hs.localEphemeral)
	if err != nil {
		return err
	}
	hs.MixKey(secret[:])

	if _, err := hs.DecryptHash(nil, tag); err != nil {
		return fmt.Errorf("%w: act two", ErrActTag)
	}
	return nil
}

// GenActThree generates act three for the initiator: the encrypted local
// static key and a tag binding the se ECDH result. It derives the final
// transport ciphers.
func (hs *HandshakeState) GenActThree() ([ActThreeSize]byte, error) {
	var actThree [ActThreeSize]byte

	// s
	localPub := hs.localStatic.PubKey().SerializeCompressed()
	ciphertext, tag1, err := hs.EncryptHash(localPub)
	if err != nil {
		return actThree, err
	}

	// se
	secret, err := ECDH(hs.remoteEphemeral, hs.localStatic)
	if err != nil {
		return actThree, err
	}
	hs.MixKey(secret[:])

	_, tag2, err := hs.EncryptHash(nil)
	if err != nil {
		return actThree, err
	}

	copy(actThree[:PublicKeySize], ciphertext)
	copy(actThree[PublicKeySize:PublicKeySize+tagSize], tag1)
	copy(actThree[PublicKeySize+tagSize:], tag2)

	if err := hs.split(); err != nil {
		return actThree, err
	}
	return actThree, nil
}

// RecvActThree processes act three on the responder, authenticating the
// initiator's static key and deriving the final transport ciphers.
func (hs *HandshakeState) RecvActThree(actThree []byte) error {
	if len(actThree) != ActThreeSize {
		return fmt.Errorf("%w: act three is %d bytes, want %d",
			ErrActSize, len(actThree), ActThreeSize)
	}

	ciphertext := actThree[:PublicKeySize]
	tag1 := actThree[PublicKeySize : PublicKeySize+tagSize]
	tag2 := actThree[PublicKeySize+tagSize:]

	// s
	plaintext, err := hs.DecryptHash(ciphertext, tag1)
	if err != nil {
		return fmt.Errorf("%w: act three", ErrActTag)
	}
	remoteStatic, err := ParsePublicKey(plaintext)
	if err != nil {
		return err
	}
	hs.remoteStatic = remoteStatic

	// se
	secret, err := ECDH(remoteStatic, hs.localEphemeral)
	if err != nil {
		return err
	}
	hs.MixKey(secret[:])

	if _, err := hs.DecryptHash(nil, tag2); err != nil {
		return fmt.Errorf("%w: act three", ErrActTag)
	}

	return hs.split()
}

// RemoteStatic returns the remote static public key: the key supplied at
// initialization for initiators, or the key learned in act three for
// responders.
func (hs *HandshakeState) RemoteStatic() *btcec.PublicKey {
	return hs.remoteStatic
}

// split derives the final send and receive transport ciphers from the
// handshake chaining key.
func (hs *HandshakeState) split() error {
	send, recv, err := hs.Split(hs.initiator)
	if err != nil {
		return err
	}
	hs.sendCipher = send
	hs.recvCipher = recv
	return nil
}

// ClientHandshake runs the initiator side of the Brontide handshake over conn
// and returns the encrypted connection. remotePub is the responder's
// compressed static public key. The exchange is bounded by HandshakeTimeout.
func ClientHandshake(conn net.Conn, localPriv *btcec.PrivateKey,
	remotePub []byte) (*Conn, error) {

	return ClientHandshakeTimeout(conn, localPriv, remotePub, HandshakeTimeout)
}

// ClientHandshakeTimeout is ClientHandshake with a caller-selected timeout
// covering the complete act exchange.
func ClientHandshakeTimeout(conn net.Conn, localPriv *btcec.PrivateKey,
	remotePub []byte, timeout time.Duration) (*Conn, error) {

	if conn == nil {
		return nil, fmt.Errorf("%w: nil connection", ErrInvalidConn)
	}

	parsedPub, err := ParsePublicKey(remotePub)
	if err != nil {
		return nil, err
	}
	hs, err := NewHandshakeState(true, localPriv, parsedPub)
	if err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	deadlineSet := true
	defer func() {
		if deadlineSet {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	actOne, err := hs.GenActOne()
	if err != nil {
		return nil, err
	}
	if err := writeFull(conn, actOne[:]); err != nil {
		return nil, err
	}

	var actTwo [ActTwoSize]byte
	if _, err := io.ReadFull(conn, actTwo[:]); err != nil {
		return nil, err
	}
	if err := hs.RecvActTwo(actTwo[:]); err != nil {
		return nil, err
	}

	actThree, err := hs.GenActThree()
	if err != nil {
		return nil, err
	}
	if err := writeFull(conn, actThree[:]); err != nil {
		return nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	deadlineSet = false
	return NewConn(conn, hs.sendCipher, hs.recvCipher)
}

// ServerHandshake runs the responder side of the Brontide handshake over conn
// and returns the encrypted connection along with the initiator's
// authenticated static public key. The exchange is bounded by
// HandshakeTimeout.
func ServerHandshake(conn net.Conn,
	localPriv *btcec.PrivateKey) (*Conn, *btcec.PublicKey, error) {

	return ServerHandshakeTimeout(conn, localPriv, HandshakeTimeout)
}

// ServerHandshakeTimeout is ServerHandshake with a caller-selected timeout
// covering the complete act exchange.
func ServerHandshakeTimeout(conn net.Conn, localPriv *btcec.PrivateKey,
	timeout time.Duration) (*Conn, *btcec.PublicKey, error) {

	if conn == nil {
		return nil, nil, fmt.Errorf("%w: nil connection", ErrInvalidConn)
	}

	hs, err := NewHandshakeState(false, localPriv, nil)
	if err != nil {
		return nil, nil, err
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	deadlineSet := true
	defer func() {
		if deadlineSet {
			_ = conn.SetDeadline(time.Time{})
		}
	}()

	var actOne [ActOneSize]byte
	if _, err := io.ReadFull(conn, actOne[:]); err != nil {
		return nil, nil, err
	}
	if err := hs.RecvActOne(actOne[:]); err != nil {
		return nil, nil, err
	}

	actTwo, err := hs.GenActTwo()
	if err != nil {
		return nil, nil, err
	}
	if err := writeFull(conn, actTwo[:]); err != nil {
		return nil, nil, err
	}

	var actThree [ActThreeSize]byte
	if _, err := io.ReadFull(conn, actThree[:]); err != nil {
		return nil, nil, err
	}
	if err := hs.RecvActThree(actThree[:]); err != nil {
		return nil, nil, err
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	deadlineSet = false
	econn, err := NewConn(conn, hs.sendCipher, hs.recvCipher)
	if err != nil {
		return nil, nil, err
	}
	return econn, hs.remoteStatic, nil
}
