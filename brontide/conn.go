// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	// ErrInvalidConn is returned when a Brontide connection wrapper receives
	// a nil connection.
	ErrInvalidConn = errors.New("brontide: invalid connection")
)

// Conn wraps a net.Conn with hsd-compatible Brontide frame encryption. It
// expects the Noise handshake to have already derived send and receive ciphers.
type Conn struct {
	conn net.Conn
	send *CipherState
	recv *CipherState

	readMtx  sync.Mutex
	writeMtx sync.Mutex
	failMtx  sync.Mutex
	failed   error
	readBuf  []byte
}

// NewConn returns a Brontide-encrypted connection using established ciphers.
func NewConn(conn net.Conn, send, recv *CipherState) (*Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil connection", ErrInvalidConn)
	}
	if send == nil {
		return nil, fmt.Errorf("%w: nil send cipher", ErrInvalidKey)
	}
	if recv == nil {
		return nil, fmt.Errorf("%w: nil receive cipher", ErrInvalidKey)
	}
	return &Conn{
		conn: conn,
		send: send,
		recv: recv,
	}, nil
}

// Read decrypts bytes from the Brontide stream. Frame boundaries are hidden
// from callers; unread bytes from a decrypted frame are buffered.
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.failure(); err != nil {
		return 0, err
	}

	c.readMtx.Lock()
	defer c.readMtx.Unlock()
	if err := c.failure(); err != nil {
		return 0, err
	}

	for len(c.readBuf) == 0 {
		payload, err := c.readFrame()
		if err != nil {
			return 0, c.fail(err)
		}
		c.readBuf = payload
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write encrypts p into a single Brontide frame and writes it to the
// underlying connection.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.failure(); err != nil {
		return 0, err
	}

	c.writeMtx.Lock()
	defer c.writeMtx.Unlock()
	if err := c.failure(); err != nil {
		return 0, err
	}

	frame, err := WriteFrame(c.send, p)
	if err != nil {
		return 0, err
	}
	if err := writeFull(c.conn, frame); err != nil {
		return 0, c.fail(err)
	}
	return len(p), nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets both read and write deadlines on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) readFrame() ([]byte, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	length, err := c.recv.Decrypt(header[:4], header[4:], nil)
	if err != nil {
		return nil, err
	}
	if len(length) != 4 {
		return nil, fmt.Errorf("%w: decrypted length is %d bytes",
			ErrFrameSizeMismatch, len(length))
	}

	size := binary.LittleEndian.Uint32(length)
	if size > MaxMessageSize {
		return nil, fmt.Errorf("%w: got %d bytes, max %d",
			ErrFrameTooLarge, size, MaxMessageSize)
	}

	body := make([]byte, int(size)+tagSize)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, err
	}

	return c.recv.Decrypt(body[:size], body[size:], nil)
}

func (c *Conn) failure() error {
	c.failMtx.Lock()
	defer c.failMtx.Unlock()
	return c.failed
}

func (c *Conn) fail(err error) error {
	if err == nil {
		err = net.ErrClosed
	}

	c.failMtx.Lock()
	if c.failed == nil {
		c.failed = err
		_ = c.conn.Close()
	}
	c.failMtx.Unlock()
	return err
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
