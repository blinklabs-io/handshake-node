// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/websocket"
	"github.com/stretchr/testify/require"
)

type rpcTestAddr string

func (a rpcTestAddr) Network() string { return "tcp" }
func (a rpcTestAddr) String() string  { return string(a) }

type rpcTestListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

func newRPCTestListener(closeErr error) *rpcTestListener {
	return &rpcTestListener{
		connections: make(chan net.Conn, 1),
		closed:      make(chan struct{}),
		closeErr:    closeErr,
	}
}

func (l *rpcTestListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *rpcTestListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return l.closeErr
}

func (l *rpcTestListener) Addr() net.Addr {
	return rpcTestAddr("127.0.0.1:0")
}

type rpcReadTrackingConn struct {
	net.Conn
	readStarted chan struct{}
}

func (c *rpcReadTrackingConn) Read(p []byte) (int, error) {
	select {
	case c.readStarted <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func TestChainMutationRPCAuthorization(t *testing.T) {
	const (
		adminUser   = "admin"
		adminPass   = "admin-pass"
		limitedUser = "limited"
		limitedPass = "limited-pass"
	)
	methods := []string{"invalidateblock", "reconsiderblock"}

	// Replace the chain-mutating handlers with side-effect-free sentinels.  An
	// admin request must reach these handlers, while a limited request must be
	// rejected before dispatch.
	originalHandlers := make(map[string]commandHandler, len(methods))
	for _, method := range methods {
		method := method
		originalHandlers[method] = rpcHandlers[method]
		rpcHandlers[method] = func(*rpcServer, interface{}, <-chan struct{}) (
			interface{}, error) {

			return "authorized:" + method, nil
		}
	}
	defer func() {
		for method, handler := range originalHandlers {
			rpcHandlers[method] = handler
		}
	}()

	originalCfg := cfg
	cfg = &config{
		RPCMaxClients:        defaultMaxRPCClients,
		RPCMaxWebsockets:     defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs: defaultMaxRPCConcurrentReqs,
	}
	defer func() {
		cfg = originalCfg
	}()
	// The RPC log backend normally requires the daemon's log rotator.  Disable
	// its output while request handlers log expected authorization failures, and
	// restore the original level without replacing the package-global logger.
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)
	defer rpcsLog.SetLevel(originalRPCLogLevel)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &rpcServer{
		cfg: rpcserverConfig{
			Listeners: []net.Listener{listener},
		},
		statusLines:            make(map[int]string),
		requestProcessShutdown: make(chan struct{}),
		quit:                   make(chan int),
	}
	server.authsha = testRPCAuthHash(adminUser, adminPass)
	server.limitauthsha = testRPCAuthHash(limitedUser, limitedPass)
	server.ntfnMgr = newWsNotificationManager(server)
	server.Start()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("stop RPC server: %v", err)
		}
	}()

	httpURL := "http://" + listener.Addr().String() + "/"
	wsURL := "ws://" + listener.Addr().String() + "/ws"

	transports := []struct {
		name string
		call func(*testing.T, string, string, string) hnsjson.Response
	}{
		{
			name: "http",
			call: func(t *testing.T, method, user, pass string) hnsjson.Response {
				return callHTTPRPCForAuthTest(t, httpURL, method, user, pass)
			},
		},
		{
			name: "websocket",
			call: func(t *testing.T, method, user, pass string) hnsjson.Response {
				return callWebsocketRPCForAuthTest(t, wsURL, method, user, pass)
			},
		},
	}

	for _, transport := range transports {
		for _, method := range methods {
			t.Run(transport.name+"/limited/"+method, func(t *testing.T) {
				response := transport.call(t, method, limitedUser, limitedPass)
				if response.Error == nil || !strings.Contains(
					response.Error.Message,
					"limited user not authorized for this method",
				) {

					t.Fatalf("limited %s response error = %v, want authorization error",
						method, response.Error)
				}
			})

			t.Run(transport.name+"/admin/"+method, func(t *testing.T) {
				response := transport.call(t, method, adminUser, adminPass)
				if response.Error != nil {
					t.Fatalf("admin %s response error = %v", method,
						response.Error)
				}
				var result string
				if err := json.Unmarshal(response.Result, &result); err != nil {
					t.Fatalf("decode admin %s result: %v", method, err)
				}
				want := "authorized:" + method
				if result != want {
					t.Fatalf("admin %s result = %q, want %q", method,
						result, want)
				}
			})
		}
	}

	for _, role := range []struct {
		name    string
		user    string
		pass    string
		limited bool
	}{
		{name: "limited", user: limitedUser, pass: limitedPass, limited: true},
		{name: "admin", user: adminUser, pass: adminPass},
	} {
		t.Run("websocket-batch/"+role.name, func(t *testing.T) {
			responses := callWebsocketRPCBatchForAuthTest(t, wsURL, methods,
				role.user, role.pass)
			if len(responses) != len(methods) {
				t.Fatalf("response count = %d, want %d", len(responses),
					len(methods))
			}

			for i, method := range methods {
				response := responses[i]
				if role.limited {
					if response.Error == nil || !strings.Contains(
						response.Error.Message,
						"limited user not authorized for this method",
					) {

						t.Fatalf("limited %s response error = %v, want authorization error",
							method, response.Error)
					}
					continue
				}

				if response.Error != nil {
					t.Fatalf("admin %s response error = %v", method,
						response.Error)
				}
				var result string
				if err := json.Unmarshal(response.Result, &result); err != nil {
					t.Fatalf("decode admin %s result: %v", method, err)
				}
				want := "authorized:" + method
				if result != want {
					t.Fatalf("admin %s result = %q, want %q", method,
						result, want)
				}
			}
		})
	}
}

func TestRPCHandlerStateShutdown(t *testing.T) {
	var handlers rpcHandlerState
	if !handlers.begin() {
		t.Fatal("initial handler admission rejected")
	}

	drained := handlers.stop()
	if handlers.begin() {
		t.Fatal("handler admitted after shutdown started")
	}
	select {
	case <-drained:
		t.Fatal("handlers reported drained while a handler was active")
	default:
	}

	handlers.done()
	<-drained
}

func TestRPCServerStopClosesActiveHTTPConnection(t *testing.T) {
	const (
		adminUser = "admin"
		adminPass = "admin-pass"
	)

	originalCfg := cfg
	cfg = &config{
		RPCMaxClients:        defaultMaxRPCClients,
		RPCMaxWebsockets:     defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs: defaultMaxRPCConcurrentReqs,
	}
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)
	t.Cleanup(func() {
		rpcsLog.SetLevel(originalRPCLogLevel)
		cfg = originalCfg
	})

	listener := newRPCTestListener(nil)
	serverConn, clientConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
	}()
	readStarted := make(chan struct{}, 2)
	listener.connections <- &rpcReadTrackingConn{
		Conn:        serverConn,
		readStarted: readStarted,
	}

	server := &rpcServer{
		cfg: rpcserverConfig{
			Listeners: []net.Listener{listener},
		},
		statusLines:            make(map[int]string),
		requestProcessShutdown: make(chan struct{}),
		quit:                   make(chan int),
	}
	server.authsha = testRPCAuthHash(adminUser, adminPass)
	server.ntfnMgr = newWsNotificationManager(server)
	server.Start()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			if err := server.Stop(); err != nil {
				t.Errorf("stop RPC server: %v", err)
			}
		}
	})

	server.lifecycleMu.Lock()
	httpServer := server.httpServer
	server.lifecycleMu.Unlock()
	if httpServer == nil {
		t.Fatal("shared HTTP server was not stored")
	}

	// Wait for net/http's initial request read, then provide headers for a
	// body which is intentionally left incomplete.  The second read proves
	// the admitted handler is blocked reading that body before Stop begins.
	<-readStarted
	auth := base64.StdEncoding.EncodeToString(
		[]byte(adminUser + ":" + adminPass))
	request := "POST / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Authorization: Basic " + auth + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 1\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write incomplete HTTP request: %v", err)
	}
	<-readStarted

	if err := server.Stop(); err != nil {
		t.Fatalf("stop RPC server: %v", err)
	}
	stopped = true

	server.handlers.mu.Lock()
	active := server.handlers.active
	server.handlers.mu.Unlock()
	if active != 0 {
		t.Fatalf("active handler count after Stop = %d, want 0", active)
	}
}

func TestRPCServerStopClosesHijackedHTTPConnection(t *testing.T) {
	const (
		adminUser = "admin"
		adminPass = "admin-pass"
	)

	originalHandler := rpcHandlers["help"]
	handlerStarted := make(chan struct{})
	rpcHandlers["help"] = func(_ *rpcServer, _ interface{},
		closeChan <-chan struct{}) (interface{}, error) {

		close(handlerStarted)
		<-closeChan
		return nil, ErrClientQuit
	}
	t.Cleanup(func() {
		rpcHandlers["help"] = originalHandler
	})

	originalCfg := cfg
	cfg = &config{
		RPCMaxClients:        defaultMaxRPCClients,
		RPCMaxWebsockets:     defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs: defaultMaxRPCConcurrentReqs,
	}
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)
	t.Cleanup(func() {
		rpcsLog.SetLevel(originalRPCLogLevel)
		cfg = originalCfg
	})

	listener := newRPCTestListener(nil)
	serverConn, clientConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
	}()
	listener.connections <- serverConn

	server := &rpcServer{
		cfg: rpcserverConfig{
			Listeners: []net.Listener{listener},
		},
		statusLines:            make(map[int]string),
		requestProcessShutdown: make(chan struct{}),
		quit:                   make(chan int),
	}
	server.authsha = testRPCAuthHash(adminUser, adminPass)
	server.ntfnMgr = newWsNotificationManager(server)
	server.Start()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			if err := server.Stop(); err != nil {
				t.Errorf("stop RPC server: %v", err)
			}
		}
	})

	rpcRequest, err := hnsjson.NewRequest(hnsjson.RpcVersion1, 1, "help",
		[]interface{}{})
	if err != nil {
		t.Fatalf("create help request: %v", err)
	}
	body, err := json.Marshal(rpcRequest)
	if err != nil {
		t.Fatalf("marshal help request: %v", err)
	}
	auth := base64.StdEncoding.EncodeToString(
		[]byte(adminUser + ":" + adminPass))
	request := fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: localhost\r\n"+
		"Authorization: Basic %s\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s", auth, len(body), body)
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}
	<-handlerStarted

	// The disconnect watcher must continue after reading unexpected client
	// data so closing the tracked connection still cancels the RPC handler.
	if _, err := clientConn.Write([]byte{'x'}); err != nil {
		t.Fatalf("write post-request byte: %v", err)
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("stop RPC server: %v", err)
	}
	stopped = true

	server.lifecycleMu.Lock()
	hijackedConnCount := len(server.hijackedConns)
	server.lifecycleMu.Unlock()
	if hijackedConnCount != 0 {
		t.Fatalf("hijacked connection count after Stop = %d, want 0",
			hijackedConnCount)
	}
}

func TestRPCServerStopWaitersReceiveCloseError(t *testing.T) {
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)
	t.Cleanup(func() {
		rpcsLog.SetLevel(originalRPCLogLevel)
	})

	synctest.Test(t, func(t *testing.T) {
		closeErr := errors.New("listener close failed")
		listener := newRPCTestListener(closeErr)
		server := &rpcServer{
			cfg: rpcserverConfig{
				Listeners: []net.Listener{listener},
			},
			requestProcessShutdown: make(chan struct{}),
			quit:                   make(chan int),
		}
		server.ntfnMgr = newWsNotificationManager(server)
		if !server.handlers.begin() {
			t.Fatal("initial handler admission rejected")
		}

		firstResult := make(chan error, 1)
		go func() {
			firstResult <- server.Stop()
		}()
		<-listener.closed
		synctest.Wait()
		select {
		case err := <-firstResult:
			t.Fatalf("Stop returned before its active handler drained: %v", err)
		default:
		}

		secondResult := make(chan error, 1)
		go func() {
			secondResult <- server.Stop()
		}()
		synctest.Wait()
		select {
		case err := <-secondResult:
			t.Fatalf("concurrent Stop returned before shutdown completed: %v", err)
		default:
		}

		server.handlers.done()
		synctest.Wait()

		if err := <-firstResult; !errors.Is(err, closeErr) {
			t.Fatalf("first Stop error = %v, want %v", err, closeErr)
		}
		if err := <-secondResult; !errors.Is(err, closeErr) {
			t.Fatalf("concurrent Stop error = %v, want %v", err, closeErr)
		}
		if err := server.Stop(); !errors.Is(err, closeErr) {
			t.Fatalf("repeated Stop error = %v, want %v", err, closeErr)
		}
	})
}

func TestRPCServerStopBeforeStart(t *testing.T) {
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)
	t.Cleanup(func() {
		rpcsLog.SetLevel(originalRPCLogLevel)
	})

	listener := newRPCTestListener(net.ErrClosed)
	server := &rpcServer{
		cfg: rpcserverConfig{
			Listeners: []net.Listener{listener},
		},
		requestProcessShutdown: make(chan struct{}),
		quit:                   make(chan int),
	}
	server.ntfnMgr = newWsNotificationManager(server)

	if err := server.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	server.Start()

	server.lifecycleMu.Lock()
	httpServer := server.httpServer
	server.lifecycleMu.Unlock()
	if httpServer != nil {
		t.Fatal("HTTP server was created after Stop completed")
	}
	if atomic.LoadInt32(&server.started) != 0 {
		t.Fatal("Start launched after Stop completed")
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("repeated Stop before Start: %v", err)
	}
}

func TestRPCServerStopDrainsWebsocketHandlers(t *testing.T) {
	const (
		adminUser = "admin"
		adminPass = "admin-pass"
	)

	originalCfg := cfg
	cfg = &config{
		RPCMaxClients:        defaultMaxRPCClients,
		RPCMaxWebsockets:     defaultMaxRPCWebsockets,
		RPCMaxConcurrentReqs: defaultMaxRPCConcurrentReqs,
	}
	originalRPCLogLevel := rpcsLog.Level()
	rpcsLog.SetLevel(btclog.LevelOff)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		rpcsLog.SetLevel(originalRPCLogLevel)
		cfg = originalCfg
		t.Fatalf("listen: %v", err)
	}
	server := &rpcServer{
		cfg: rpcserverConfig{
			Listeners: []net.Listener{listener},
		},
		statusLines:            make(map[int]string),
		requestProcessShutdown: make(chan struct{}),
		quit:                   make(chan int),
	}
	server.authsha = testRPCAuthHash(adminUser, adminPass)
	server.ntfnMgr = newWsNotificationManager(server)
	server.Start()
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			if err := server.Stop(); err != nil {
				t.Errorf("stop RPC server: %v", err)
			}
		}
		rpcsLog.SetLevel(originalRPCLogLevel)
		cfg = originalCfg
	})

	header := make(http.Header)
	login := adminUser + ":" + adminPass
	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(login)))
	conn, _, err := (&websocket.Dialer{}).Dial(
		"ws://"+listener.Addr().String()+"/ws", header,
	)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	request, err := hnsjson.NewRequest(hnsjson.RpcVersion1, 1, "session",
		[]interface{}{})
	if err != nil {
		t.Fatalf("create session request: %v", err)
	}
	if err := conn.WriteJSON(request); err != nil {
		t.Fatalf("write session request: %v", err)
	}
	var response hnsjson.Response
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("read session response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("session response error: %v", response.Error)
	}

	if err := server.Stop(); err != nil {
		t.Fatalf("stop RPC server: %v", err)
	}
	stopped = true

	server.handlers.mu.Lock()
	active := server.handlers.active
	stopping := server.handlers.stopping
	server.handlers.mu.Unlock()
	if active != 0 {
		t.Fatalf("active handler count after Stop = %d, want 0", active)
	}
	if !stopping {
		t.Fatal("handler admission remained open after Stop")
	}
	if server.handlers.begin() {
		t.Fatal("handler admitted after Stop returned")
	}
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("websocket remained connected after Stop returned")
	}
}

func testRPCAuthHash(user, pass string) [sha256.Size]byte {
	login := user + ":" + pass
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
	return sha256.Sum256([]byte(auth))
}

func chainMutationAuthTestRequest(t *testing.T, method string) *hnsjson.Request {
	t.Helper()
	request, err := hnsjson.NewRequest(hnsjson.RpcVersion1, 1, method,
		[]interface{}{strings.Repeat("0", chainhash.MaxHashStringSize)})
	if err != nil {
		t.Fatalf("create %s request: %v", method, err)
	}
	return request
}

func callHTTPRPCForAuthTest(t *testing.T, url, method, user,
	pass string) hnsjson.Response {

	t.Helper()
	payload, err := json.Marshal(chainMutationAuthTestRequest(t, method))
	if err != nil {
		t.Fatalf("marshal %s request: %v", method, err)
	}
	request, err := http.NewRequest(http.MethodPost, url,
		bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create HTTP %s request: %v", method, err)
	}
	request.SetBasicAuth(user, pass)
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTP %s request: %v", method, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("close HTTP %s response body: %v", method, err)
		}
	}()

	var rpcResponse hnsjson.Response
	if err := json.NewDecoder(response.Body).Decode(&rpcResponse); err != nil {
		t.Fatalf("decode HTTP %s response: %v", method, err)
	}
	return rpcResponse
}

func callWebsocketRPCForAuthTest(t *testing.T, url, method, user,
	pass string) hnsjson.Response {

	t.Helper()
	header := make(http.Header)
	login := user + ":" + pass
	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(login)))
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(url, header)
	if err != nil {
		t.Fatalf("dial websocket for %s: %v", method, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close websocket for %s: %v", method, err)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set websocket read deadline for %s: %v", method, err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set websocket write deadline for %s: %v", method, err)
	}
	if err := conn.WriteJSON(chainMutationAuthTestRequest(t, method)); err != nil {
		t.Fatalf("write websocket %s request: %v", method, err)
	}

	var rpcResponse hnsjson.Response
	if err := conn.ReadJSON(&rpcResponse); err != nil {
		t.Fatalf("read websocket %s response: %v", method, err)
	}
	return rpcResponse
}

func callWebsocketRPCBatchForAuthTest(t *testing.T, url string,
	methods []string, user, pass string) []hnsjson.Response {

	t.Helper()
	header := make(http.Header)
	login := user + ":" + pass
	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(login)))
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(url, header)
	if err != nil {
		t.Fatalf("dial websocket batch: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close websocket batch: %v", err)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set websocket batch read deadline: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("set websocket batch write deadline: %v", err)
	}
	requests := make([]*hnsjson.Request, 0, len(methods))
	for i, method := range methods {
		request := chainMutationAuthTestRequest(t, method)
		request.ID = i + 1
		requests = append(requests, request)
	}
	if err := conn.WriteJSON(requests); err != nil {
		t.Fatalf("write websocket batch: %v", err)
	}

	var rpcResponses []hnsjson.Response
	if err := conn.ReadJSON(&rpcResponses); err != nil {
		t.Fatalf("read websocket batch response: %v", err)
	}
	return rpcResponses
}

func TestReadLimitedRPCRequestBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		limit   int64
		want    string
		wantErr bool
	}{
		{
			name:  "at limit",
			body:  "1234",
			limit: 4,
			want:  "1234",
		},
		{
			name:    "chunked over limit",
			body:    "12345",
			limit:   4,
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/",
				strings.NewReader(test.body))
			if test.wantErr {
				req.ContentLength = -1
			}
			got, err := readLimitedRPCRequestBody(httptest.NewRecorder(),
				req, test.limit)
			if test.wantErr {
				var maxBytesErr *http.MaxBytesError
				if !errors.As(err, &maxBytesErr) {
					t.Fatalf("error = %v, want *http.MaxBytesError", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("readLimitedRPCRequestBody: %v", err)
			}
			if string(got) != test.want {
				t.Fatalf("body = %q, want %q", got, test.want)
			}
		})
	}
}

func TestJSONRPCReadRejectsDeclaredOversizeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.ContentLength = maxRPCRequestSize + 1
	recorder := httptest.NewRecorder()

	server := &rpcServer{}
	server.jsonRPCRead(recorder, req, true)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		body, _ := io.ReadAll(recorder.Result().Body)
		t.Fatalf("status = %d, want %d (body %q)", recorder.Code,
			http.StatusRequestEntityTooLarge, body)
	}
}

func TestHandshakeDeploymentNames(t *testing.T) {
	tests := []struct {
		id   int
		name string
	}{
		{chaincfg.DeploymentHardening, "hardening"},
		{chaincfg.DeploymentICANNLockup, "icann-lockup"},
		{chaincfg.DeploymentAirstop, "airstop"},
	}

	for _, test := range tests {
		got, ok := deploymentName(test.id)
		if !ok || got != test.name {
			t.Errorf("deploymentName(%d) = %q, %v; want %q, true",
				test.id, got, ok, test.name)
		}
	}
}

func TestHandshakeDeploymentStatuses(t *testing.T) {
	tests := []struct {
		state blockchain.ThresholdState
		want  string
	}{
		{blockchain.ThresholdDefined, "defined"},
		{blockchain.ThresholdStarted, "started"},
		{blockchain.ThresholdLockedIn, "lockedin"},
		{blockchain.ThresholdActive, "active"},
		{blockchain.ThresholdFailed, "failed"},
	}
	for _, test := range tests {
		got, err := softForkStatus(test.state)
		if err != nil || got != test.want {
			t.Errorf("softForkStatus(%v) = %q, %v; want %q, nil",
				test.state, got, err, test.want)
		}
	}
}

func TestConfiguredDeploymentNamesByNetwork(t *testing.T) {
	tests := []struct {
		name   string
		params *chaincfg.Params
		want   map[string]bool
	}{
		{
			name:   "mainnet",
			params: &chaincfg.MainNetParams,
			want: map[string]bool{
				"dummy": true, "hardening": true,
				"icann-lockup": true, "airstop": true,
			},
		},
		{
			name:   "regtest",
			params: &chaincfg.RegressionNetParams,
			want: map[string]bool{
				"dummy": true, "dummy-min-activation": true,
				"dummy-always-active": true, "csv": true,
				"segwit": true, "hardening": true,
				"icann-lockup": true, "airstop": true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := make(map[string]bool)
			for id, deployment := range test.params.Deployments {
				if !deploymentConfigured(&deployment) {
					continue
				}
				name, ok := deploymentName(id)
				if !ok {
					t.Fatalf("configured deployment %d has no RPC name", id)
				}
				got[name] = true
			}
			require.Equal(t, test.want, got, "configured deployment names mismatch")
		})
	}
}

func TestHnsutilAddressToWireRejectsTaprootShapedAddress(t *testing.T) {
	addr, err := hnsutil.NewAddress(1, make([]byte, 32),
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}

	if _, err := hnsutilAddressToWire(addr); err == nil {
		t.Fatal("hnsutilAddressToWire accepted taproot-shaped address")
	}
}

func TestRPCClientAllowed(t *testing.T) {
	nets, err := parseIPNets([]string{"127.0.0.1", "10.0.0.0/8"},
		"rpcallowip")
	if err != nil {
		t.Fatalf("parseIPNets: %v", err)
	}

	server := &rpcServer{cfg: rpcserverConfig{RPCAllowNets: nets}}
	tests := []struct {
		addr string
		want bool
	}{
		{addr: "127.0.0.1:12037", want: true},
		{addr: "10.1.2.3:12037", want: true},
		{addr: "192.0.2.1:12037", want: false},
		{addr: "not-an-address", want: false},
	}
	for _, test := range tests {
		if got := server.rpcClientAllowed(test.addr); got != test.want {
			t.Errorf("rpcClientAllowed(%q): got %v, want %v",
				test.addr, got, test.want)
		}
	}

	allowAll := &rpcServer{}
	if !allowAll.rpcClientAllowed("192.0.2.1:12037") {
		t.Fatalf("empty allowlist rejected RPC client")
	}
}

func TestHnsToDooZeroAmount(t *testing.T) {
	if value, rpcErr := hnsToDoo(0, true); rpcErr != nil || value != 0 {
		t.Fatalf("hnsToDoo zero allowed: got value %d err %v, want 0 nil",
			value, rpcErr)
	}

	if _, rpcErr := hnsToDoo(0, false); rpcErr == nil {
		t.Fatalf("hnsToDoo zero disallowed succeeded")
	}

	if _, rpcErr := hnsToDoo(-1, true); rpcErr == nil {
		t.Fatalf("hnsToDoo negative amount succeeded")
	}
}

func TestHandshakeRawHashRPCEncoding(t *testing.T) {
	var hash chainhash.Hash
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	wantRaw := hex.EncodeToString(hash[:])
	if got := rawHashString(hash); got != wantRaw {
		t.Fatalf("rawHashString = %q, want %q", got, wantRaw)
	}
	if got := hash.String(); got != wantRaw {
		t.Fatalf("Hash.String = %q, want native-order %q", got, wantRaw)
	}

	parsed, rpcErr := parseRPCRawHash(wantRaw, "name hash")
	if rpcErr != nil {
		t.Fatalf("parseRPCRawHash: %v", rpcErr)
	}
	if parsed != hash {
		t.Fatalf("parseRPCRawHash = %x, want %x", parsed, hash)
	}

	item, rpcErr := parseRawHashCovenantItem(wantRaw, "name hash")
	if rpcErr != nil {
		t.Fatalf("parseRawHashCovenantItem: %v", rpcErr)
	}
	if !bytes.Equal(item, hash[:]) {
		t.Fatalf("covenant item = %x, want %x", item, hash[:])
	}

	if _, rpcErr := parseRPCRawHash(wantRaw[:len(wantRaw)-2],
		"name hash"); rpcErr == nil {
		t.Fatal("parseRPCRawHash accepted short hash")
	}
}

func TestSendRawProofRPCRejectsInvalidBase64(t *testing.T) {
	s := &rpcServer{}

	if _, err := handleSendRawClaim(s, hnsjson.NewSendRawClaimCmd("%%%"),
		nil); err == nil {

		t.Fatal("handleSendRawClaim accepted invalid base64")
	}

	if _, err := handleSendRawAirdrop(s,
		hnsjson.NewSendRawAirdropCmd("%%%"), nil); err == nil {

		t.Fatal("handleSendRawAirdrop accepted invalid base64")
	}
}

func TestNameAuctionInfoUsesRawNameHash(t *testing.T) {
	const name = "rawhash"
	nameHash := blockchain.HashName([]byte(name))

	got := nameAuctionInfoToJSON(name, 0, &chaincfg.RegressionNetParams,
		nil, false)
	want := rawHashString(nameHash)
	if got.NameHash != want {
		t.Fatalf("NameHash = %q, want %q", got.NameHash, want)
	}
	if got.NameHash != nameHash.String() {
		t.Fatal("NameHash did not use native chainhash string encoding")
	}
}

func testRPCHashString(tag byte) string {
	var hash chainhash.Hash
	hash[0] = tag
	return hash.String()
}

func TestMempoolEntryGraphRPCResults(t *testing.T) {
	parent := testRPCHashString(0x01)
	child := testRPCHashString(0x02)
	grandchild := testRPCHashString(0x03)
	entries := map[string]*hnsjson.GetRawMempoolVerboseResult{
		parent: {
			Size:   100,
			Vsize:  100,
			Weight: 400,
			Fee:    1,
			Time:   10,
			Height: 1,
		},
		child: {
			Size:    200,
			Vsize:   200,
			Weight:  800,
			Fee:     2,
			Time:    20,
			Height:  2,
			Depends: []string{parent},
		},
		grandchild: {
			Size:    300,
			Vsize:   300,
			Weight:  1200,
			Fee:     3,
			Time:    30,
			Height:  3,
			Depends: []string{child},
		},
	}

	mm := &mempool.MockTxMempool{}
	mm.On("RawMempoolVerbose").Return(entries).Times(3)
	s := &rpcServer{cfg: rpcserverConfig{TxMemPool: mm}}

	entryResult, err := handleGetMempoolEntry(s,
		hnsjson.NewGetMempoolEntryCmd(child), nil)
	require.NoError(t, err)
	entry := entryResult.(*hnsjson.GetMempoolEntryResult)
	require.Equal(t, int64(2), entry.AncestorCount)
	require.Equal(t, int64(300), entry.AncestorSize)
	require.Equal(t, float64(3), entry.AncestorFees)
	require.Equal(t, int64(2), entry.DescendantCount)
	require.Equal(t, int64(500), entry.DescendantSize)
	require.Equal(t, float64(5), entry.DescendantFees)
	require.Equal(t, []string{parent}, entry.Depends)

	ancestorResult, err := handleGetMempoolAncestors(s,
		hnsjson.NewGetMempoolAncestorsCmd(grandchild, nil), nil)
	require.NoError(t, err)
	require.Equal(t, []string{parent, child}, ancestorResult)

	descendantResult, err := handleGetMempoolDescendants(s,
		hnsjson.NewGetMempoolDescendantsCmd(parent, hnsjson.Bool(true)),
		nil)
	require.NoError(t, err)
	descendants := descendantResult.([]*hnsjson.GetMempoolEntryResult)
	require.Len(t, descendants, 2)
	require.Equal(t, child, descendants[0].WTxId)
	require.Equal(t, grandchild, descendants[1].WTxId)
	mm.AssertExpectations(t)
}

type testRPCConnManager struct {
	services       wire.ServiceFlag
	localAddresses []rpcserverLocalAddress
	connectedCount int32
}

func (m *testRPCConnManager) Connect(addr string, permanent bool) error  { return nil }
func (m *testRPCConnManager) RemoveByID(id int32) error                  { return nil }
func (m *testRPCConnManager) RemoveByAddr(addr string) error             { return nil }
func (m *testRPCConnManager) DisconnectByID(id int32) error              { return nil }
func (m *testRPCConnManager) DisconnectByAddr(addr string) error         { return nil }
func (m *testRPCConnManager) ConnectedCount() int32                      { return m.connectedCount }
func (m *testRPCConnManager) Services() wire.ServiceFlag                 { return m.services }
func (m *testRPCConnManager) NetTotals() (uint64, uint64)                { return 0, 0 }
func (m *testRPCConnManager) ConnectedPeers() []rpcserverPeer            { return nil }
func (m *testRPCConnManager) PersistentPeers() []rpcserverPeer           { return nil }
func (m *testRPCConnManager) BroadcastMessage(msg wire.HandshakeMessage) {}
func (m *testRPCConnManager) AddRebroadcastInventory(iv *wire.InvVect, data interface{}) {
}
func (m *testRPCConnManager) RelayInventory(iv *wire.InvVect, data interface{}) {}
func (m *testRPCConnManager) RelayTransactions(txns []*mempool.TxDesc)          {}
func (m *testRPCConnManager) NodeAddresses() []*wire.NetAddressV2               { return nil }
func (m *testRPCConnManager) LocalAddresses() []rpcserverLocalAddress {
	return m.localAddresses
}

func TestHandleGetTxOutUsesAtomicMempoolFetch(t *testing.T) {
	server, _ := newGBTTestRPCServer(t, &gbtTestTxSource{})

	msgTx := wire.NewMsgTx(1)
	msgTx.AddTxOut(wire.NewTxOut(
		hnsutil.DooPerHNS,
		wire.Address{Version: 0, Hash: make([]byte, 20)},
		wire.Covenant{},
	))
	tx := hnsutil.NewTx(msgTx)
	txHash := tx.Hash()
	cmd := hnsjson.NewGetTxOutCmd(txHash.String(), 0, hnsjson.Bool(true))

	t.Run("mempool hit", func(t *testing.T) {
		mockPool := &mempool.MockTxMempool{}
		mockPool.On("FetchTransaction", txHash).Return(tx, nil).Once()
		server.cfg.TxMemPool = mockPool

		result, err := handleGetTxOut(server, cmd, nil)
		require.NoError(t, err)
		reply, ok := result.(*hnsjson.GetTxOutResult)
		require.True(t, ok)
		require.Equal(t, int64(0), reply.Confirmations)
		require.Equal(t, float64(1), reply.Value)
		mockPool.AssertExpectations(t)
	})

	t.Run("concurrent removal falls back to chain", func(t *testing.T) {
		mockPool := &mempool.MockTxMempool{}
		mockPool.On("FetchTransaction", txHash).
			Return(nil, errors.New("transaction is not in the pool")).Once()
		server.cfg.TxMemPool = mockPool

		result, err := handleGetTxOut(server, cmd, nil)
		require.NoError(t, err)
		require.Nil(t, result)
		mockPool.AssertExpectations(t)
	})
}

func TestGetNetworkInfo(t *testing.T) {
	oldCfg := cfg
	cfg = &config{
		UserAgentComments: []string{"test"},
		minRelayTxFee:     hnsutil.Amount(1000),
	}
	t.Cleanup(func() {
		cfg = oldCfg
	})

	localAddr := wire.NetAddressV2FromBytes(time.Now(),
		wire.SFNodeNetwork|wire.SFNodeBloom, net.ParseIP("204.124.1.1"),
		12038)
	connMgr := &testRPCConnManager{
		services:       wire.SFNodeNetwork | wire.SFNodeBloom,
		localAddresses: []rpcserverLocalAddress{{NetAddress: localAddr, Score: 3}},
		connectedCount: 0,
	}
	s := &rpcServer{cfg: rpcserverConfig{
		ConnMgr:    connMgr,
		TimeSource: blockchain.NewMedianTime(),
	}}

	result, err := handleGetNetworkInfo(s, hnsjson.NewGetNetworkInfoCmd(),
		nil)
	require.NoError(t, err)
	info := result.(*hnsjson.GetNetworkInfoResult)
	require.Equal(t, int32(wire.HnsProtocolVersion), info.ProtocolVersion)
	require.Equal(t, "00000003", info.LocalServices)
	require.Equal(t, []string{"NETWORK", "BLOOM"}, info.LocalServiceNames)
	require.True(t, info.LocalRelay)
	require.Equal(t, float64(0.001), info.RelayFee)
	require.Len(t, info.LocalAddresses, 1)
	require.Equal(t, "204.124.1.1", info.LocalAddresses[0].Address)
	require.Equal(t, uint16(12038), info.LocalAddresses[0].Port)
	require.Equal(t, int32(3), info.LocalAddresses[0].Score)
}

type gbtTestTxSource struct {
	updated time.Time
}

func (s *gbtTestTxSource) LastUpdated() time.Time { return s.updated }
func (*gbtTestTxSource) MiningDescs() []*mining.TxDesc {
	return nil
}
func (*gbtTestTxSource) HaveTransaction(*chainhash.Hash) bool {
	return false
}

func newGBTTestRPCServer(t *testing.T, txSource *gbtTestTxSource) (
	*rpcServer, *blockchain.BlockChain) {

	t.Helper()

	blockchain.DisableLog()
	database.UseLogger(btclog.Disabled)

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	timeSource := blockchain.NewMedianTime()
	sigCache := txscript.NewSigCache(1000)
	hashCache := txscript.NewHashCache(1000)
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: &params,
		TimeSource:  timeSource,
		SigCache:    sigCache,
	})
	if err != nil {
		t.Fatalf("blockchain.New: %v", err)
	}

	policy := mining.Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := mining.NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)
	server := &rpcServer{
		cfg: rpcserverConfig{
			TimeSource:  timeSource,
			Chain:       chain,
			ChainParams: &params,
			Generator:   generator,
		},
		gbtWorkState: newGbtWorkState(timeSource),
	}

	return server, chain
}

func newGBTTestResult(t *testing.T, server *rpcServer,
	useCoinbaseValue bool) (*hnsjson.GetBlockTemplateResult, *mining.BlockTemplate) {

	t.Helper()

	var payAddr hnsutil.Address
	if !useCoinbaseValue {
		var err error
		payAddr, err = hnsutil.NewAddressPubKeyHash(make([]byte, 20),
			server.cfg.ChainParams)
		if err != nil {
			t.Fatalf("NewAddressPubKeyHash: %v", err)
		}
	}

	template, err := server.cfg.Generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	state := server.gbtWorkState
	state.Lock()
	defer state.Unlock()

	best := server.cfg.Chain.BestSnapshot()
	prevHash := best.Hash
	state.template = template
	state.prevHash = &prevHash
	state.lastGenerated = time.Now()
	state.lastTxUpdate = server.cfg.Generator.TxSource().LastUpdated()
	if state.lastTxUpdate.IsZero() {
		state.lastTxUpdate = time.Now()
	}
	state.minTimestamp = mining.MinimumMedianTime(best)

	result, err := state.blockTemplateResult(useCoinbaseValue, nil)
	if err != nil {
		t.Fatalf("blockTemplateResult: %v", err)
	}

	return result, template
}

func solveGBTTestBlock(t *testing.T, msgBlock *wire.MsgBlock) {
	t.Helper()

	targetDifficulty := blockchain.CompactToBig(msgBlock.Header.Bits)
	for nonce := uint32(0); ; nonce++ {
		msgBlock.Header.Nonce = nonce
		hash := msgBlock.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			return
		}
		if nonce == ^uint32(0) {
			break
		}
	}

	t.Fatalf("unable to solve block at difficulty %08x",
		msgBlock.Header.Bits)
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireMutableField(t *testing.T, fields []string, want string) {
	t.Helper()
	if !hasString(fields, want) {
		t.Fatalf("mutable fields %v missing %q", fields, want)
	}
}

func requireNoMutableField(t *testing.T, fields []string, unwanted string) {
	t.Helper()
	if hasString(fields, unwanted) {
		t.Fatalf("mutable fields %v unexpectedly include %q", fields,
			unwanted)
	}
}

func requireGBTHandshakeHeaderFields(t *testing.T,
	result *hnsjson.GetBlockTemplateResult, template *mining.BlockTemplate) {

	t.Helper()

	header := &template.Block.Header
	if got, want := result.TreeRoot, rawHashString(header.NameRoot); got != want {
		t.Fatalf("treeroot = %q, want %q", got, want)
	}
	if got, want := result.ReservedRoot, header.ReservedRoot.String(); got != want {
		t.Fatalf("reservedroot = %q, want %q", got, want)
	}
	if got, want := result.Mask, header.Mask.String(); got != want {
		t.Fatalf("mask = %q, want %q", got, want)
	}
}

func gbtTestAirdropWitness(t *testing.T, index uint32, version uint8,
	address []byte, value, fee uint64) []byte {

	t.Helper()

	var buf bytes.Buffer
	var scratch [8]byte
	binary.LittleEndian.PutUint32(scratch[:4], index)
	buf.Write(scratch[:4])
	buf.WriteByte(0) // proof path count
	buf.WriteByte(0) // subindex
	buf.WriteByte(0) // subproof path count

	var key bytes.Buffer
	key.WriteByte(gbtAirdropKeyAddress)
	key.WriteByte(version)
	key.WriteByte(byte(len(address)))
	key.Write(address)
	binary.LittleEndian.PutUint64(scratch[:], value)
	key.Write(scratch[:])
	key.WriteByte(0)
	if err := wire.WriteVarBytes(&buf, 0, key.Bytes()); err != nil {
		t.Fatalf("WriteVarBytes key: %v", err)
	}

	buf.WriteByte(version)
	buf.WriteByte(byte(len(address)))
	buf.Write(address)
	if err := wire.WriteVarInt(&buf, 0, fee); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	if err := wire.WriteVarBytes(&buf, 0, nil); err != nil {
		t.Fatalf("WriteVarBytes signature: %v", err)
	}

	return buf.Bytes()
}

func TestBlockTemplateResultHandshakeFieldsForCoinbaseValue(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	result, template := newGBTTestResult(t, server, true)
	requireGBTHandshakeHeaderFields(t, result, template)

	if result.CoinbaseValue == nil {
		t.Fatal("coinbasevalue missing")
	}
	if result.CoinbaseTxn != nil {
		t.Fatal("coinbasetxn included for coinbasevalue template")
	}
	if result.MerkleRoot != "" {
		t.Fatalf("merkleroot = %q, want empty for external coinbase",
			result.MerkleRoot)
	}
	if result.WitnessRoot != "" {
		t.Fatalf("witnessroot = %q, want empty for external coinbase",
			result.WitnessRoot)
	}

	requireMutableField(t, result.Mutable, "time")
	requireMutableField(t, result.Mutable, "transactions")
	requireMutableField(t, result.Mutable, "prevblock")
	requireNoMutableField(t, result.Mutable, "transactions/add")
	requireNoMutableField(t, result.Mutable, "coinbase")
	requireNoMutableField(t, result.Mutable, "coinbase/append")
	requireNoMutableField(t, result.Mutable, "generation")
}

func TestBlockTemplateResultHandshakeFieldsForCoinbaseTxn(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	result, template := newGBTTestResult(t, server, false)
	requireGBTHandshakeHeaderFields(t, result, template)

	if result.CoinbaseTxn == nil {
		t.Fatal("coinbasetxn missing")
	}
	if result.CoinbaseValue != nil {
		t.Fatal("coinbasevalue included for coinbasetxn template")
	}

	header := &template.Block.Header
	if got, want := result.MerkleRoot, header.MerkleRoot.String(); got != want {
		t.Fatalf("merkleroot = %q, want %q", got, want)
	}
	if got, want := result.WitnessRoot, header.WitnessRoot.String(); got != want {
		t.Fatalf("witnessroot = %q, want %q", got, want)
	}

	requireMutableField(t, result.Mutable, "time")
	requireMutableField(t, result.Mutable, "transactions")
	requireMutableField(t, result.Mutable, "prevblock")
	requireMutableField(t, result.Mutable, "coinbase")
	requireMutableField(t, result.Mutable, "coinbase/append")
	requireMutableField(t, result.Mutable, "generation")
	requireNoMutableField(t, result.Mutable, "transactions/add")
}

func TestBlockTemplateResultIncludesCoinbaseProofMetadata(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	_, template := newGBTTestResult(t, server, true)

	nameHash := bytes.Repeat([]byte{0x11}, chainhash.HashSize)
	commitHash := bytes.Repeat([]byte{0x22}, chainhash.HashSize)
	claimHeight := make([]byte, 4)
	commitHeight := make([]byte, 4)
	binary.LittleEndian.PutUint32(claimHeight, uint32(template.Height))
	binary.LittleEndian.PutUint32(commitHeight, 2)
	claimAddrHash := bytes.Repeat([]byte{0x33}, 20)
	claimProof := mining.CoinbaseProof{
		Witness: []byte{0xaa, 0xbb, 0xcc},
		Output: wire.NewTxOut(4_900, wire.Address{
			Version: 0,
			Hash:    claimAddrHash,
		}, wire.Covenant{
			Type: wire.CovenantClaim,
			Items: [][]byte{
				nameHash,
				claimHeight,
				[]byte("com"),
				[]byte{0x01},
				commitHash,
				commitHeight,
			},
		}),
		Fee: 100,
	}

	airdropAddrHash := bytes.Repeat([]byte{0x44}, 20)
	airdropWitness := gbtTestAirdropWitness(t, 7, 0,
		airdropAddrHash, 7_000, 200)
	airdropProof := mining.CoinbaseProof{
		Witness: airdropWitness,
		Output: wire.NewTxOut(6_800, wire.Address{
			Version: 0,
			Hash:    airdropAddrHash,
		}, wire.Covenant{}),
		Fee: 200,
	}

	template.CoinbaseProofs = []mining.CoinbaseProof{
		claimProof,
		airdropProof,
	}
	template.NameDeflationHeight = uint32(template.Height)

	state := server.gbtWorkState
	state.Lock()
	result, err := state.blockTemplateResult(true, nil)
	state.Unlock()
	if err != nil {
		t.Fatalf("blockTemplateResult: %v", err)
	}

	if len(result.Claims) != 1 {
		t.Fatalf("claims count = %d, want 1", len(result.Claims))
	}
	claim := result.Claims[0]
	if claim.Data != hex.EncodeToString(claimProof.Witness) {
		t.Fatalf("claim data = %q, want %q", claim.Data,
			hex.EncodeToString(claimProof.Witness))
	}
	if claim.Name != "com" {
		t.Fatalf("claim name = %q, want com", claim.Name)
	}
	if claim.NameHash != hex.EncodeToString(nameHash) {
		t.Fatalf("claim namehash = %q, want %q", claim.NameHash,
			hex.EncodeToString(nameHash))
	}
	if claim.Hash != hex.EncodeToString(claimAddrHash) {
		t.Fatalf("claim hash = %q, want %q", claim.Hash,
			hex.EncodeToString(claimAddrHash))
	}
	if claim.Value != claimProof.Output.Value || claim.Fee != 0 {
		t.Fatalf("deflated claim value/fee = %d/%d, want %d/0",
			claim.Value, claim.Fee, claimProof.Output.Value)
	}
	if !claim.Weak {
		t.Fatal("claim weak = false, want true")
	}
	if claim.CommitHash != hex.EncodeToString(commitHash) {
		t.Fatalf("claim commitHash = %q, want %q", claim.CommitHash,
			hex.EncodeToString(commitHash))
	}
	if claim.CommitHeight != 2 {
		t.Fatalf("claim commitHeight = %d, want 2", claim.CommitHeight)
	}
	wantClaimWeight := int64(1 +
		wire.VarIntSerializeSize(uint64(len(claimProof.Witness))) +
		len(claimProof.Witness) +
		(1+8+claimProof.Output.Address.SerializeSize()+90+len("com"))*
			blockchain.WitnessScaleFactor)
	if claim.Weight != wantClaimWeight {
		t.Fatalf("claim weight = %d, want %d", claim.Weight,
			wantClaimWeight)
	}

	if len(result.Airdrops) != 1 {
		t.Fatalf("airdrops count = %d, want 1", len(result.Airdrops))
	}
	airdrop := result.Airdrops[0]
	if airdrop.Data != hex.EncodeToString(airdropWitness) {
		t.Fatalf("airdrop data = %q, want %q", airdrop.Data,
			hex.EncodeToString(airdropWitness))
	}
	if airdrop.Position != gbtAirdropLeaves+7 {
		t.Fatalf("airdrop position = %d, want %d", airdrop.Position,
			gbtAirdropLeaves+7)
	}
	if airdrop.Address != hex.EncodeToString(airdropAddrHash) {
		t.Fatalf("airdrop address = %q, want %q", airdrop.Address,
			hex.EncodeToString(airdropAddrHash))
	}
	if airdrop.Value != 7_000 || airdrop.Fee != 200 {
		t.Fatalf("airdrop value/fee = %d/%d, want 7000/200",
			airdrop.Value, airdrop.Fee)
	}
	wantRate := int64(200 * 1000 / ((len(airdropWitness) +
		blockchain.WitnessScaleFactor - 1) /
		blockchain.WitnessScaleFactor))
	if airdrop.Rate != wantRate {
		t.Fatalf("airdrop rate = %d, want %d", airdrop.Rate,
			wantRate)
	}
	if airdrop.Weak {
		t.Fatal("airdrop weak = true, want false")
	}
}

func connectGBTTestTemplate(t *testing.T, chain *blockchain.BlockChain,
	template *mining.BlockTemplate) {

	t.Helper()

	solveGBTTestBlock(t, template.Block)
	block := hnsutil.NewBlock(template.Block)
	block.SetHeight(template.Height)
	isMainChain, isOrphan, err := chain.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		t.Fatalf("ProcessBlock height %d: %v", template.Height, err)
	}
	if !isMainChain || isOrphan {
		t.Fatalf("ProcessBlock height %d main=%v orphan=%v, want main "+
			"chain non-orphan", template.Height, isMainChain,
			isOrphan)
	}
}

func TestGBTWorkStateRegeneratesTemplateAfterTipChange(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, chain := newGBTTestRPCServer(t, txSource)
	state := server.gbtWorkState

	state.Lock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate first: %v", err)
	}
	firstTemplate := state.template
	state.Unlock()

	connectGBTTestTemplate(t, chain, firstTemplate)
	connectedHash := firstTemplate.Block.BlockHash()

	state.Lock()
	defer state.Unlock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		t.Fatalf("updateBlockTemplate second: %v", err)
	}
	if state.template == firstTemplate {
		t.Fatal("template was reused after best chain tip changed")
	}
	if got, want := state.template.Height, firstTemplate.Height+1; got != want {
		t.Fatalf("template height = %d, want %d", got, want)
	}
	if got := state.template.Block.Header.PrevBlock; !got.IsEqual(&connectedHash) {
		t.Fatalf("template prev block = %v, want %v", got, connectedHash)
	}
}

func TestGBTWorkStateRegeneratesTemplateAfterMempoolUpdateWindow(t *testing.T) {
	firstUpdate := time.Now().Add(-2 * time.Minute)
	txSource := &gbtTestTxSource{updated: firstUpdate}
	server, _ := newGBTTestRPCServer(t, txSource)
	state := server.gbtWorkState

	state.Lock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate first: %v", err)
	}
	firstTemplate := state.template
	state.lastGenerated = time.Now().Add(-(gbtRegenerateSeconds + 1) *
		time.Second)
	txSource.updated = time.Now()

	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate second: %v", err)
	}
	defer state.Unlock()

	if state.template == firstTemplate {
		t.Fatal("template was reused after stale mempool update")
	}
	if !state.lastTxUpdate.Equal(txSource.updated) {
		t.Fatalf("last tx update = %v, want %v", state.lastTxUpdate,
			txSource.updated)
	}
	if got, want := state.template.Height, firstTemplate.Height; got != want {
		t.Fatalf("template height = %d, want %d", got, want)
	}
}

func TestGBTWorkStateUpdatesRootsAfterCachedCoinbaseAddress(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)
	state := server.gbtWorkState

	payAddr, err := hnsutil.NewAddressPubKeyHash(bytes.Repeat([]byte{0x44},
		20), server.cfg.ChainParams)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}
	oldCfg := cfg
	cfg = &config{miningAddrs: []hnsutil.Address{payAddr}}
	t.Cleanup(func() {
		cfg = oldCfg
	})

	state.Lock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate coinbasevalue: %v", err)
	}
	firstTemplate := state.template
	if firstTemplate.ValidPayAddress {
		state.Unlock()
		t.Fatal("coinbasevalue template unexpectedly had a payment address")
	}

	if err := state.updateBlockTemplate(server, false); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate coinbasetxn: %v", err)
	}
	if state.template != firstTemplate {
		state.Unlock()
		t.Fatal("template regenerated instead of updating cached coinbase")
	}
	result, err := state.blockTemplateResult(false, nil)
	state.Unlock()
	if err != nil {
		t.Fatalf("blockTemplateResult: %v", err)
	}
	if result.CoinbaseTxn == nil {
		t.Fatal("coinbasetxn missing")
	}

	rawCoinbase, err := hex.DecodeString(result.CoinbaseTxn.Data)
	if err != nil {
		t.Fatalf("DecodeString coinbase: %v", err)
	}
	var coinbase wire.MsgTx
	if err := coinbase.Deserialize(bytes.NewReader(rawCoinbase)); err != nil {
		t.Fatalf("Deserialize coinbase: %v", err)
	}
	txs := []*hnsutil.Tx{hnsutil.NewTx(&coinbase)}
	wantMerkleRoot := blockchain.CalcMerkleRoot(txs, false).String()
	wantWitnessRoot := blockchain.CalcMerkleRoot(txs, true).String()
	if result.MerkleRoot != wantMerkleRoot {
		t.Fatalf("merkleroot = %q, want %q", result.MerkleRoot,
			wantMerkleRoot)
	}
	if result.WitnessRoot != wantWitnessRoot {
		t.Fatalf("witnessroot = %q, want %q", result.WitnessRoot,
			wantWitnessRoot)
	}
}

// TestHandleTestMempoolAcceptFailDecode checks that when invalid hex string is
// used as the raw txns, the corresponding error is returned.
func TestHandleTestMempoolAcceptFailDecode(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a testing server.
	s := &rpcServer{}

	testCases := []struct {
		name            string
		txns            []string
		expectedErrCode hnsjson.RPCErrorCode
	}{
		{
			name:            "hex decode fail",
			txns:            []string{"invalid"},
			expectedErrCode: hnsjson.ErrRPCDecodeHexString,
		},
		{
			name:            "tx decode fail",
			txns:            []string{"696e76616c6964"},
			expectedErrCode: hnsjson.ErrRPCDeserialization,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a request that uses invalid raw txns.
			cmd := hnsjson.NewTestMempoolAcceptCmd(tc.txns, 0)

			// Call the method under test.
			closeChan := make(chan struct{})
			result, err := handleTestMempoolAccept(
				s, cmd, closeChan,
			)

			// Ensure the expected error is returned.
			require.Error(err)
			rpcErr, ok := err.(*hnsjson.RPCError)
			require.True(ok)
			require.Equal(tc.expectedErrCode, rpcErr.Code)

			// No result should be returned.
			require.Nil(result)
		})
	}
}

var (
	// Handshake-format test transactions: version(4) + input_count(1) +
	// prevhash(32) + previndex(4) + sequence(4) + output_count(1) +
	// value(8) + address(version+hashlen+hash) + covenant(type+items) +
	// locktime(4) + witness_count(1) + witness_items...
	//
	// txHex1: 1 input, 1 output (version-0, 20-byte zero hash), 1 witness item.
	txHex1 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010430440220"

	// txHex2: same structure, different witness bytes.
	txHex2 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010530440220ab"

	// txHex3: same structure, yet another witness variant.
	txHex3 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010630440220ff47"
)

// decodeTxHex decodes the given hex string into a transaction.
func decodeTxHex(t *testing.T, txHex string) *hnsutil.Tx {
	rawBytes, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	tx, err := hnsutil.NewTxFromBytes(rawBytes)
	require.NoError(t, err)

	return tx
}

// TestHandleTestMempoolAcceptMixedResults checks that when different txns get
// different responses from calling the mempool method `CheckMempoolAcceptance`
// their results are correctly returned.
func TestHandleTestMempoolAcceptMixedResults(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	// Decode the hex so we can assert the mock mempool is called with it.
	tx1 := decodeTxHex(t, txHex1)
	tx2 := decodeTxHex(t, txHex2)
	tx3 := decodeTxHex(t, txHex3)

	// Create a slice to hold the expected results. We will use three txns
	// so we expect threeresults.
	expectedResults := make([]*hnsjson.TestMempoolAcceptResult, 3)

	// We now mock the first call to `CheckMempoolAcceptance` to return an
	// error.
	dummyErr := errors.New("dummy error")
	mm.On("CheckMempoolAcceptance", tx1).Return(nil, dummyErr).Once()

	// Since the call failed, we expect the first result to give us the
	// error.
	expectedResults[0] = &hnsjson.TestMempoolAcceptResult{
		Txid:         tx1.Hash().String(),
		Wtxid:        tx1.WitnessHash().String(),
		Allowed:      false,
		RejectReason: dummyErr.Error(),
	}

	// We mock the second call to `CheckMempoolAcceptance` to return a
	// result saying the tx is missing inputs.
	mm.On("CheckMempoolAcceptance", tx2).Return(
		&mempool.MempoolAcceptResult{
			MissingParents: []*chainhash.Hash{},
		}, nil,
	).Once()

	// We expect the second result to give us the missing-inputs error.
	expectedResults[1] = &hnsjson.TestMempoolAcceptResult{
		Txid:         tx2.Hash().String(),
		Wtxid:        tx2.WitnessHash().String(),
		Allowed:      false,
		RejectReason: "missing-inputs",
	}

	// We mock the third call to `CheckMempoolAcceptance` to return a
	// result saying the tx allowed.
	const feeDoo = hnsutil.Amount(1000)
	mm.On("CheckMempoolAcceptance", tx3).Return(
		&mempool.MempoolAcceptResult{
			TxFee:  feeDoo,
			TxSize: 100,
		}, nil,
	).Once()

	// We expect the third result to give us the fee details.
	expectedResults[2] = &hnsjson.TestMempoolAcceptResult{
		Txid:    tx3.Hash().String(),
		Wtxid:   tx3.WitnessHash().String(),
		Allowed: true,
		Vsize:   100,
		Fees: &hnsjson.TestMempoolAcceptFees{
			Base:             feeDoo.ToHNS(),
			EffectiveFeeRate: feeDoo.ToHNS() * 1e3 / 100,
		},
	}

	// Create a mock request with default max fee rate of 0.1 HNS/KvB.
	cmd := hnsjson.NewTestMempoolAcceptCmd(
		[]string{txHex1, txHex2, txHex3}, 0.1,
	)

	// Call the method handler and assert the expected results are
	// returned.
	closeChan := make(chan struct{})
	results, err := handleTestMempoolAccept(s, cmd, closeChan)
	require.NoError(err)
	require.Equal(expectedResults, results)

	// Assert the mocked method is called as expected.
	mm.AssertExpectations(t)
}

// TestValidateFeeRate checks that `validateFeeRate` behaves as expected.
func TestValidateFeeRate(t *testing.T) {
	t.Parallel()

	const (
		// testFeeRate is in HNS/kvB.
		testFeeRate = 0.1

		// testTxSize is in vb.
		testTxSize = 100

		// testFeeDoo is in dollarydoos (1 HNS = 1e6 doo).
		// We have 0.1 HNS/kvB =
		//   0.1 * 1e6 doo/kvB =
		//   0.1 * 1e6 / 1e3 doo/vb = 0.1 * 1e3 doo/vb.
		testFeeDoo = hnsutil.Amount(testFeeRate * 1e3 * testTxSize)
	)

	testCases := []struct {
		name         string
		feeDoo       hnsutil.Amount
		txSize       int64
		maxFeeRate   float64
		expectedFees *hnsjson.TestMempoolAcceptFees
		allowed      bool
	}{
		{
			// When the fee rate(0.1) is above the max fee
			// rate(0.01), we expect a nil result and false.
			name:         "fee rate above max",
			feeDoo:       testFeeDoo,
			txSize:       testTxSize,
			maxFeeRate:   testFeeRate / 10,
			expectedFees: nil,
			allowed:      false,
		},
		{
			// When the fee rate(0.1) is no greater than the max
			// fee rate(0.1), we expect a result and true.
			name:       "fee rate below max",
			feeDoo:     testFeeDoo,
			txSize:     testTxSize,
			maxFeeRate: testFeeRate,
			expectedFees: &hnsjson.TestMempoolAcceptFees{
				Base:             testFeeDoo.ToHNS(),
				EffectiveFeeRate: testFeeRate,
			},
			allowed: true,
		},
		{
			// When the fee rate(1) is above the default max fee
			// rate(0.1), we expect a nil result and false.
			name:         "fee rate above default max",
			feeDoo:       testFeeDoo,
			txSize:       testTxSize / 10,
			expectedFees: nil,
			allowed:      false,
		},
		{
			// When the fee rate(0.1) is no greater than the
			// default max fee rate(0.1), we expect a result and
			// true.
			name:   "fee rate below default max",
			feeDoo: testFeeDoo,
			txSize: testTxSize,
			expectedFees: &hnsjson.TestMempoolAcceptFees{
				Base:             testFeeDoo.ToHNS(),
				EffectiveFeeRate: testFeeRate,
			},
			allowed: true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			result, allowed := validateFeeRate(
				tc.feeDoo, tc.txSize, tc.maxFeeRate,
			)

			require.Equal(tc.expectedFees, result)
			require.Equal(tc.allowed, allowed)
		})
	}
}

// TestHandleTestMempoolAcceptFees checks that the `Fees` field is correctly
// populated based on the max fee rate and the tx being checked.
func TestHandleTestMempoolAcceptFees(t *testing.T) {
	t.Parallel()

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	const (
		// Set transaction's fee rate to be 0.2 HNS/kvB.
		feeRate = defaultMaxFeeRate * 2

		// txSize is 100vb.
		txSize = 100

		// feeDoo is the fee expressed in dollarydoos
		// (feeRate [HNS/kvB] * 1e6 doo/HNS * txSize / 1e3 vb/kvB).
		feeDoo = feeRate * 1e6 * txSize / 1e3
	)

	testCases := []struct {
		name         string
		maxFeeRate   float64
		txHex        string
		rejectReason string
		allowed      bool
	}{
		{
			// When the fee rate(0.2) used by the tx is below the
			// max fee rate(2) specified, the result should allow
			// it.
			name:       "below max fee rate",
			maxFeeRate: feeRate * 10,
			txHex:      txHex1,
			allowed:    true,
		},
		{
			// When the fee rate(0.2) used by the tx is above the
			// max fee rate(0.02) specified, the result should
			// disallow it.
			name:         "above max fee rate",
			maxFeeRate:   feeRate / 10,
			txHex:        txHex1,
			allowed:      false,
			rejectReason: "max-fee-exceeded",
		},
		{
			// When the max fee rate is not set, the default
			// 0.1 HNS/kvB is used and the fee rate(0.2) used by the
			// tx is above it, the result should disallow it.
			name:         "above default max fee rate",
			txHex:        txHex1,
			allowed:      false,
			rejectReason: "max-fee-exceeded",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			// Decode the hex so we can assert the mock mempool is
			// called with it.
			tx := decodeTxHex(t, txHex1)

			// We mock the call to `CheckMempoolAcceptance` to
			// return the result.
			mm.On("CheckMempoolAcceptance", tx).Return(
				&mempool.MempoolAcceptResult{
					TxFee:  feeDoo,
					TxSize: txSize,
				}, nil,
			).Once()

			// We expect the third result to give us the fee
			// details.
			expected := &hnsjson.TestMempoolAcceptResult{
				Txid:    tx.Hash().String(),
				Wtxid:   tx.WitnessHash().String(),
				Allowed: tc.allowed,
			}

			if tc.allowed {
				expected.Vsize = txSize
				expected.Fees = &hnsjson.TestMempoolAcceptFees{
					Base:             feeDoo / 1e6,
					EffectiveFeeRate: feeRate,
				}
			} else {
				expected.RejectReason = tc.rejectReason
			}

			// Create a mock request with specified max fee rate.
			cmd := hnsjson.NewTestMempoolAcceptCmd(
				[]string{txHex1}, tc.maxFeeRate,
			)

			// Call the method handler and assert the expected
			// result is returned.
			closeChan := make(chan struct{})
			r, err := handleTestMempoolAccept(s, cmd, closeChan)
			require.NoError(err)

			// Check the interface type.
			results, ok := r.([]*hnsjson.TestMempoolAcceptResult)
			require.True(ok)

			// Expect exactly one result.
			require.Len(results, 1)

			// Check the result is returned as expected.
			require.Equal(expected, results[0])

			// Assert the mocked method is called as expected.
			mm.AssertExpectations(t)
		})
	}
}

// TestGetTxSpendingPrevOut checks that handleGetTxSpendingPrevOut handles the
// cmd as expected.
func TestGetTxSpendingPrevOut(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}
	defer mm.AssertExpectations(t)

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	// First, check the error case.
	//
	// Create a request that will cause an error.
	cmd := &hnsjson.GetTxSpendingPrevOutCmd{
		Outputs: []*hnsjson.GetTxSpendingPrevOutCmdOutput{
			{Txid: "invalid"},
		},
	}

	// Call the method handler and assert the error is returned.
	closeChan := make(chan struct{})
	results, err := handleGetTxSpendingPrevOut(s, cmd, closeChan)
	require.Error(err)
	require.Nil(results)

	// We now check the normal case. Two outputs will be tested - one found
	// in mempool and other not.
	//
	// Decode the hex so we can assert the mock mempool is called with it.
	tx := decodeTxHex(t, txHex1)

	// Create testing outpoints.
	opInMempool := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 1}
	opNotInMempool := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}

	// We only expect to see one output being found as spent in mempool.
	expectedResults := []*hnsjson.GetTxSpendingPrevOutResult{
		{
			Txid:         opInMempool.Hash.String(),
			Vout:         opInMempool.Index,
			SpendingTxid: tx.Hash().String(),
		},
		{
			Txid: opNotInMempool.Hash.String(),
			Vout: opNotInMempool.Index,
		},
	}

	// We mock the first call to `CheckSpend` to return a result saying the
	// output is found.
	mm.On("CheckSpend", opInMempool).Return(tx).Once()

	// We mock the second call to `CheckSpend` to return a result saying the
	// output is NOT found.
	mm.On("CheckSpend", opNotInMempool).Return(nil).Once()

	// Create a request with the above outputs.
	cmd = &hnsjson.GetTxSpendingPrevOutCmd{
		Outputs: []*hnsjson.GetTxSpendingPrevOutCmdOutput{
			{
				Txid: opInMempool.Hash.String(),
				Vout: opInMempool.Index,
			},
			{
				Txid: opNotInMempool.Hash.String(),
				Vout: opNotInMempool.Index,
			},
		},
	}

	// Call the method handler and assert the expected result is returned.
	closeChan = make(chan struct{})
	results, err = handleGetTxSpendingPrevOut(s, cmd, closeChan)
	require.NoError(err)
	require.Equal(expectedResults, results)
}
