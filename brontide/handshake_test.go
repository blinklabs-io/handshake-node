// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func mustPrivKey(t *testing.T, s string) *btcec.PrivateKey {
	t.Helper()

	priv, _ := btcec.PrivKeyFromBytes(mustHex(t, s))
	if priv == nil {
		t.Fatalf("invalid private key %q", s)
	}
	return priv
}

func fixedKeyGen(t *testing.T, s string) func() (*btcec.PrivateKey, error) {
	priv := mustPrivKey(t, s)
	return func() (*btcec.PrivateKey, error) {
		return priv, nil
	}
}

type deadlineTrackingConn struct {
	readErr       error
	writeErr      error
	lastDeadline  time.Time
	deadlineCalls int
}

func (c *deadlineTrackingConn) Read(_ []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, io.EOF
}

func (c *deadlineTrackingConn) Write(_ []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return 0, io.ErrShortWrite
}

func (*deadlineTrackingConn) Close() error                     { return nil }
func (*deadlineTrackingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (*deadlineTrackingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (*deadlineTrackingConn) SetReadDeadline(time.Time) error  { return nil }
func (*deadlineTrackingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *deadlineTrackingConn) SetDeadline(deadline time.Time) error {
	c.lastDeadline = deadline
	c.deadlineCalls++
	return nil
}

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func assertDeadlineCleared(t *testing.T, conn *deadlineTrackingConn) {
	t.Helper()

	if conn.deadlineCalls < 2 {
		t.Fatalf("SetDeadline calls: got %d, want at least 2",
			conn.deadlineCalls)
	}
	if !conn.lastDeadline.IsZero() {
		t.Fatalf("deadline not cleared: %v", conn.lastDeadline)
	}
}

// hsdPacketWrite frames data like hsd's Brontide.write: a 2-byte big-endian
// encrypted length, its tag, the encrypted payload, and its tag. hsd's test
// vectors use this framing rather than the 4-byte stream framing.
func hsdPacketWrite(t *testing.T, send *CipherState, data []byte) []byte {
	t.Helper()

	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(data)))

	encLength, tag1, err := send.Encrypt(length[:], nil)
	if err != nil {
		t.Fatalf("encrypt length: %v", err)
	}
	encData, tag2, err := send.Encrypt(data, nil)
	if err != nil {
		t.Fatalf("encrypt data: %v", err)
	}

	packet := make([]byte, 0, 2+tagSize+len(data)+tagSize)
	packet = append(packet, encLength...)
	packet = append(packet, tag1...)
	packet = append(packet, encData...)
	packet = append(packet, tag2...)
	return packet
}

// hsdPacketRead is the inverse of hsdPacketWrite, like hsd's Brontide.read.
func hsdPacketRead(t *testing.T, recv *CipherState, packet []byte) []byte {
	t.Helper()

	length, err := recv.Decrypt(packet[:2], packet[2:2+tagSize], nil)
	if err != nil {
		t.Fatalf("decrypt length: %v", err)
	}
	size := int(binary.BigEndian.Uint16(length))
	if len(packet) != 2+tagSize+size+tagSize {
		t.Fatalf("packet size: got %d, want %d", len(packet),
			2+tagSize+size+tagSize)
	}

	data, err := recv.Decrypt(packet[2+tagSize:2+tagSize+size],
		packet[2+tagSize+size:], nil)
	if err != nil {
		t.Fatalf("decrypt data: %v", err)
	}
	return data
}

func newTestHandshakePair(t *testing.T) (*HandshakeState, *HandshakeState) {
	t.Helper()

	initiatorPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	responderPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	initiator, err := NewHandshakeState(true, initiatorPriv,
		responderPriv.PubKey())
	if err != nil {
		t.Fatalf("NewHandshakeState(initiator): %v", err)
	}
	responder, err := NewHandshakeState(false, responderPriv, nil)
	if err != nil {
		t.Fatalf("NewHandshakeState(responder): %v", err)
	}
	return initiator, responder
}

// TestHandshakeActSizes pins the act sizes to hsd's constants.
func TestHandshakeActSizes(t *testing.T) {
	if ActOneSize != 80 {
		t.Fatalf("ActOneSize: got %d, want 80", ActOneSize)
	}
	if ActTwoSize != 80 {
		t.Fatalf("ActTwoSize: got %d, want 80", ActTwoSize)
	}
	if ActThreeSize != 65 {
		t.Fatalf("ActThreeSize: got %d, want 65", ActThreeSize)
	}
}

func TestHandshakeTimeoutClearsDeadlineOnClientError(t *testing.T) {
	localPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey local: %v", err)
	}
	remotePriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey remote: %v", err)
	}

	conn := &deadlineTrackingConn{writeErr: io.ErrClosedPipe}
	_, err = ClientHandshakeTimeout(
		conn, localPriv, remotePriv.PubKey().SerializeCompressed(),
		time.Second,
	)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("ClientHandshakeTimeout error: got %v, want %v",
			err, io.ErrClosedPipe)
	}
	assertDeadlineCleared(t, conn)
}

func TestHandshakeTimeoutClearsDeadlineOnServerError(t *testing.T) {
	localPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	conn := &deadlineTrackingConn{readErr: io.ErrUnexpectedEOF}
	_, _, err = ServerHandshakeTimeout(conn, localPriv, time.Second)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ServerHandshakeTimeout error: got %v, want %v",
			err, io.ErrUnexpectedEOF)
	}
	assertDeadlineCleared(t, conn)
}

// TestHandshakeHsdVectors ports the 'should test brontide exchange' case from
// hsd's test/brontide-test.js, including the deterministic packets exchanged
// across two key rotations.
func TestHandshakeHsdVectors(t *testing.T) {
	initiatorStatic := mustPrivKey(t,
		"1111111111111111111111111111111111111111111111111111111111111111")
	responderStatic := mustPrivKey(t,
		"2121212121212121212121212121212121212121212121212121212121212121")
	responderPub := mustHex(t,
		"028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")
	if !bytes.Equal(responderStatic.PubKey().SerializeCompressed(), responderPub) {
		t.Fatalf("responder static pubkey mismatch")
	}

	remotePub, err := ParsePublicKey(responderPub)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	initiator, err := NewHandshakeState(true, initiatorStatic, remotePub)
	if err != nil {
		t.Fatalf("NewHandshakeState(initiator): %v", err)
	}
	responder, err := NewHandshakeState(false, responderStatic, nil)
	if err != nil {
		t.Fatalf("NewHandshakeState(responder): %v", err)
	}

	initiator.generateKey = fixedKeyGen(t,
		"1212121212121212121212121212121212121212121212121212121212121212")
	responder.generateKey = fixedKeyGen(t,
		"2222222222222222222222222222222222222222222222222222222222222222")

	actOne, err := initiator.GenActOne()
	if err != nil {
		t.Fatalf("GenActOne: %v", err)
	}
	if err := responder.RecvActOne(actOne[:]); err != nil {
		t.Fatalf("RecvActOne: %v", err)
	}

	actTwo, err := responder.GenActTwo()
	if err != nil {
		t.Fatalf("GenActTwo: %v", err)
	}
	if err := initiator.RecvActTwo(actTwo[:]); err != nil {
		t.Fatalf("RecvActTwo: %v", err)
	}

	actThree, err := initiator.GenActThree()
	if err != nil {
		t.Fatalf("GenActThree: %v", err)
	}
	if err := responder.RecvActThree(actThree[:]); err != nil {
		t.Fatalf("RecvActThree: %v", err)
	}

	wantSendKey := mustHex(t,
		"1f33627bc124e43ab1024fded2f5c0d6730430f3f4cb85172b10e77c055b3b65")
	wantRecvKey := mustHex(t,
		"5b943fc7215b1d55f7b440d43ad0057d6ef1cfde0e12ab69b1db6b4578e84469")

	if !bytes.Equal(initiator.sendCipher.key[:], wantSendKey) {
		t.Fatalf("initiator send key: got %x, want %x",
			initiator.sendCipher.key, wantSendKey)
	}
	if !bytes.Equal(initiator.recvCipher.key[:], wantRecvKey) {
		t.Fatalf("initiator recv key: got %x, want %x",
			initiator.recvCipher.key, wantRecvKey)
	}
	if !bytes.Equal(responder.recvCipher.key[:], wantSendKey) {
		t.Fatalf("responder recv key: got %x, want %x",
			responder.recvCipher.key, wantSendKey)
	}
	if !bytes.Equal(responder.sendCipher.key[:], wantRecvKey) {
		t.Fatalf("responder send key: got %x, want %x",
			responder.sendCipher.key, wantRecvKey)
	}

	if !bytes.Equal(responder.RemoteStatic().SerializeCompressed(),
		initiatorStatic.PubKey().SerializeCompressed()) {
		t.Fatal("responder learned wrong initiator static key")
	}

	wantPackets := map[int]string{
		0: "186a811dd5ebcd7c79b728cc8b72178ef5f8a44" +
			"7efac0f9b5477046ce72596296844e1702fe463",
		1: "e338507655712eaa0ddc2f8d408599e80a0e266" +
			"2afc110add447e6a0ed512c46a9bdacd4cb946e",
		500: "46aee83987990b46271f678d1303d3e94ba4c45" +
			"bb20d23ec21ca2b5f6de5cdfdad83183569bea5",
		501: "2a05bf99a1815b4781c1ac27547755c8a3ba86e" +
			"de8c309880e6ab866cfa233036924769652601e",
		1000: "bd2be824ec969430f9c4a4bd34eef8bbee4811d" +
			"c287f98bbb718abbd5c8b78a59dc1eaf0d74375",
		1001: "b837d23ea6d5de0fe380c91abe9110ce519791d" +
			"533ed151ddab4d9172c5561457dda713bfb7ce0",
	}

	hello := []byte("hello")
	for i := 0; i <= 1001; i++ {
		packet := hsdPacketWrite(t, initiator.sendCipher, hello)
		if want, ok := wantPackets[i]; ok {
			if got := hex.EncodeToString(packet); got != want {
				t.Fatalf("packet #%d: got %s, want %s", i, got, want)
			}
		}

		msg := hsdPacketRead(t, responder.recvCipher, packet)
		if !bytes.Equal(msg, hello) {
			t.Fatalf("message #%d: got %x, want %x", i, msg, hello)
		}
	}
}

// TestHandshakeOverPipe runs ClientHandshake and ServerHandshake over an
// in-memory connection and exchanges data both ways, including past the
// 1000-message key-rotation boundary.
func TestHandshakeOverPipe(t *testing.T) {
	clientPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serverPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	clientSide, serverSide := net.Pipe()

	type serverResult struct {
		conn   *Conn
		remote *btcec.PublicKey
		err    error
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		conn, remote, err := ServerHandshake(serverSide, serverPriv)
		serverCh <- serverResult{conn: conn, remote: remote, err: err}
	}()

	clientConn, err := ClientHandshake(clientSide, clientPriv,
		serverPriv.PubKey().SerializeCompressed())
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	server := <-serverCh
	if server.err != nil {
		t.Fatalf("ServerHandshake: %v", server.err)
	}
	defer clientConn.Close()
	defer server.conn.Close()

	if !bytes.Equal(server.remote.SerializeCompressed(),
		clientPriv.PubKey().SerializeCompressed()) {
		t.Fatal("server learned wrong client static key")
	}

	// Echo every message back so each direction crosses the rotation
	// boundary. Each frame consumes two cipher nonces, so 1100 frames per
	// direction rotate the keys twice.
	const messages = 1100
	go func() {
		buf := make([]byte, 64)
		for i := 0; i < messages; i++ {
			n, err := server.conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := server.conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	echo := make([]byte, 64)
	for i := 0; i < messages; i++ {
		msg := []byte(fmt.Sprintf("brontide message %04d", i))
		if _, err := clientConn.Write(msg); err != nil {
			t.Fatalf("client write #%d: %v", i, err)
		}
		n, err := clientConn.Read(echo)
		if err != nil {
			t.Fatalf("client read #%d: %v", i, err)
		}
		if !bytes.Equal(echo[:n], msg) {
			t.Fatalf("echo #%d: got %q, want %q", i, echo[:n], msg)
		}
	}
}

// TestHandshakeRejectsTamperedActs verifies every act fails cleanly when its
// tag, key material, or ciphertext is corrupted.
func TestHandshakeRejectsTamperedActs(t *testing.T) {
	t.Run("act one tag", func(t *testing.T) {
		initiator, responder := newTestHandshakePair(t)

		actOne, err := initiator.GenActOne()
		if err != nil {
			t.Fatalf("GenActOne: %v", err)
		}
		actOne[ActOneSize-1] ^= 0x01

		if err := responder.RecvActOne(actOne[:]); !errors.Is(err, ErrActTag) {
			t.Fatalf("RecvActOne error: got %v, want %v", err, ErrActTag)
		}
	})

	t.Run("act one uniform key", func(t *testing.T) {
		initiator, responder := newTestHandshakePair(t)

		actOne, err := initiator.GenActOne()
		if err != nil {
			t.Fatalf("GenActOne: %v", err)
		}
		// A flipped bit in the uniform encoding decodes to a different
		// ephemeral point, so the act must fail authentication.
		actOne[0] ^= 0x01

		if err := responder.RecvActOne(actOne[:]); !errors.Is(err, ErrActTag) {
			t.Fatalf("RecvActOne error: got %v, want %v", err, ErrActTag)
		}
	})

	t.Run("act two tag", func(t *testing.T) {
		initiator, responder := newTestHandshakePair(t)

		actOne, err := initiator.GenActOne()
		if err != nil {
			t.Fatalf("GenActOne: %v", err)
		}
		if err := responder.RecvActOne(actOne[:]); err != nil {
			t.Fatalf("RecvActOne: %v", err)
		}

		actTwo, err := responder.GenActTwo()
		if err != nil {
			t.Fatalf("GenActTwo: %v", err)
		}
		actTwo[ActTwoSize-1] ^= 0x01

		if err := initiator.RecvActTwo(actTwo[:]); !errors.Is(err, ErrActTag) {
			t.Fatalf("RecvActTwo error: got %v, want %v", err, ErrActTag)
		}
	})

	t.Run("act three static key ciphertext", func(t *testing.T) {
		initiator, responder := runActsOneAndTwo(t)

		actThree, err := initiator.GenActThree()
		if err != nil {
			t.Fatalf("GenActThree: %v", err)
		}
		actThree[0] ^= 0x01

		err = responder.RecvActThree(actThree[:])
		if !errors.Is(err, ErrActTag) {
			t.Fatalf("RecvActThree error: got %v, want %v", err, ErrActTag)
		}
	})

	t.Run("act three trailing tag", func(t *testing.T) {
		initiator, responder := runActsOneAndTwo(t)

		actThree, err := initiator.GenActThree()
		if err != nil {
			t.Fatalf("GenActThree: %v", err)
		}
		actThree[ActThreeSize-1] ^= 0x01

		err = responder.RecvActThree(actThree[:])
		if !errors.Is(err, ErrActTag) {
			t.Fatalf("RecvActThree error: got %v, want %v", err, ErrActTag)
		}
	})
}

func runActsOneAndTwo(t *testing.T) (*HandshakeState, *HandshakeState) {
	t.Helper()

	initiator, responder := newTestHandshakePair(t)

	actOne, err := initiator.GenActOne()
	if err != nil {
		t.Fatalf("GenActOne: %v", err)
	}
	if err := responder.RecvActOne(actOne[:]); err != nil {
		t.Fatalf("RecvActOne: %v", err)
	}

	actTwo, err := responder.GenActTwo()
	if err != nil {
		t.Fatalf("GenActTwo: %v", err)
	}
	if err := initiator.RecvActTwo(actTwo[:]); err != nil {
		t.Fatalf("RecvActTwo: %v", err)
	}
	return initiator, responder
}

// TestHandshakeRejectsWrongResponderStatic verifies act one fails when the
// initiator targets the wrong responder identity key.
func TestHandshakeRejectsWrongResponderStatic(t *testing.T) {
	initiatorPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	responderPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrongPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	initiator, err := NewHandshakeState(true, initiatorPriv, wrongPriv.PubKey())
	if err != nil {
		t.Fatalf("NewHandshakeState(initiator): %v", err)
	}
	responder, err := NewHandshakeState(false, responderPriv, nil)
	if err != nil {
		t.Fatalf("NewHandshakeState(responder): %v", err)
	}

	actOne, err := initiator.GenActOne()
	if err != nil {
		t.Fatalf("GenActOne: %v", err)
	}
	if err := responder.RecvActOne(actOne[:]); !errors.Is(err, ErrActTag) {
		t.Fatalf("RecvActOne error: got %v, want %v", err, ErrActTag)
	}
}

// TestHandshakeRejectsBadActSizes verifies truncated and padded acts are
// rejected before any cryptographic processing. hsd's acts carry no version
// byte, so an LND-style act one (a 0x00 version byte plus a compressed key)
// is rejected purely by size.
func TestHandshakeRejectsBadActSizes(t *testing.T) {
	initiator, responder := newTestHandshakePair(t)

	if err := responder.RecvActOne(make([]byte, ActOneSize-1)); !errors.Is(err, ErrActSize) {
		t.Fatalf("short act one error: got %v, want %v", err, ErrActSize)
	}
	if err := responder.RecvActOne(make([]byte, 50)); !errors.Is(err, ErrActSize) {
		t.Fatalf("lnd-style act one error: got %v, want %v", err, ErrActSize)
	}
	if err := responder.RecvActOne(make([]byte, ActOneSize+1)); !errors.Is(err, ErrActSize) {
		t.Fatalf("long act one error: got %v, want %v", err, ErrActSize)
	}
	if err := initiator.RecvActTwo(make([]byte, ActTwoSize-1)); !errors.Is(err, ErrActSize) {
		t.Fatalf("short act two error: got %v, want %v", err, ErrActSize)
	}
	if err := responder.RecvActThree(make([]byte, ActThreeSize-1)); !errors.Is(err, ErrActSize) {
		t.Fatalf("short act three error: got %v, want %v", err, ErrActSize)
	}
}

// TestHandshakeRejectsTruncatedActOverConn verifies a peer that sends a
// partial act and disconnects produces a clean error.
func TestHandshakeRejectsTruncatedActOverConn(t *testing.T) {
	serverPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	clientSide, serverSide := net.Pipe()
	go func() {
		_, _ = clientSide.Write(make([]byte, ActOneSize/2))
		_ = clientSide.Close()
	}()

	_, _, err = ServerHandshake(serverSide, serverPriv)
	if err == nil {
		t.Fatal("ServerHandshake succeeded with truncated act one")
	}
}

// TestHandshakeTimeout verifies a silent peer trips the handshake deadline.
func TestHandshakeTimeout(t *testing.T) {
	clientPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serverPriv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	t.Run("client", func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		defer serverSide.Close()

		// Drain act one without ever answering with act two.
		go func() {
			buf := make([]byte, ActOneSize)
			_, _ = serverSide.Read(buf)
		}()

		_, err := ClientHandshakeTimeout(clientSide, clientPriv,
			serverPriv.PubKey().SerializeCompressed(), 50*time.Millisecond)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ClientHandshakeTimeout error: got %v, want %v",
				err, os.ErrDeadlineExceeded)
		}
	})

	t.Run("server", func(t *testing.T) {
		clientSide, serverSide := net.Pipe()
		defer clientSide.Close()

		_, _, err := ServerHandshakeTimeout(serverSide, serverPriv,
			50*time.Millisecond)
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ServerHandshakeTimeout error: got %v, want %v",
				err, os.ErrDeadlineExceeded)
		}
	})
}

// TestHandshakeStateValidation verifies constructor and entry-point input
// checks.
func TestHandshakeStateValidation(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err := NewHandshakeState(true, nil, priv.PubKey()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil private key error: got %v, want %v", err, ErrInvalidKey)
	}
	if _, err := NewHandshakeState(true, priv, nil); !errors.Is(err, ErrHandshakeState) {
		t.Fatalf("missing remote static error: got %v, want %v",
			err, ErrHandshakeState)
	}
	if _, err := NewHandshakeState(false, nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil responder key error: got %v, want %v", err, ErrInvalidKey)
	}

	if _, err := ClientHandshake(nil, priv, priv.PubKey().SerializeCompressed()); !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("nil client conn error: got %v, want %v", err, ErrInvalidConn)
	}
	if _, _, err := ServerHandshake(nil, priv); !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("nil server conn error: got %v, want %v", err, ErrInvalidConn)
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	if _, err := ClientHandshake(clientSide, priv, []byte{0x02, 0x03}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad remote pub error: got %v, want %v", err, ErrInvalidKey)
	}
}
