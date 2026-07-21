// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"testing"
	"testing/synctest"

	"github.com/blinklabs-io/handshake-node/hnsjson"
)

func TestWsNotificationManagerSendersReturnAfterShutdown(t *testing.T) {
	manager := newWsNotificationManager(nil)
	close(manager.quit)
	client := &wsClient{quit: make(chan struct{})}

	tests := []struct {
		name string
		call func()
	}{
		{
			name: "block connected",
			call: func() { manager.NotifyBlockConnected(nil) },
		},
		{
			name: "block disconnected",
			call: func() { manager.NotifyBlockDisconnected(nil) },
		},
		{
			name: "mempool transaction",
			call: func() { manager.NotifyMempoolTx(nil, false) },
		},
		{
			name: "register blocks",
			call: func() { manager.RegisterBlockUpdates(client) },
		},
		{
			name: "unregister blocks",
			call: func() { manager.UnregisterBlockUpdates(client) },
		},
		{
			name: "register names",
			call: func() { manager.RegisterNameUpdates(client, nil) },
		},
		{
			name: "unregister names",
			call: func() { manager.UnregisterNameUpdates(client) },
		},
		{
			name: "register mempool transactions",
			call: func() { manager.RegisterNewMempoolTxsUpdates(client) },
		},
		{
			name: "unregister mempool transactions",
			call: func() { manager.UnregisterNewMempoolTxsUpdates(client) },
		},
		{
			name: "register spent requests",
			call: func() { manager.RegisterSpentRequests(client, nil) },
		},
		{
			name: "unregister spent request",
			call: func() { manager.UnregisterSpentRequest(client, nil) },
		},
		{
			name: "register address requests",
			call: func() { manager.RegisterTxOutAddressRequests(client, nil) },
		},
		{
			name: "unregister address request",
			call: func() { manager.UnregisterTxOutAddressRequest(client, "") },
		},
		{
			name: "remove client",
			call: func() { manager.RemoveClient(client) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.call()
		})
	}

	if manager.AddClient(client) {
		t.Fatal("client registered after manager shutdown")
	}
	if manager.enqueueNotification(struct{}{}) {
		t.Fatal("notification queued after manager shutdown")
	}
}

func TestWsClientClosedQuitOperations(t *testing.T) {
	quit := make(chan struct{})
	close(quit)
	client := &wsClient{
		serviceRequestSem: makeSemaphore(1),
		ntfnChan:          make(chan []byte, 1024),
		sendChan:          make(chan wsResponse, 1024),
		quit:              quit,
	}

	for range 1024 {
		if client.serviceRequestSem.acquire(client.quit) {
			t.Fatal("acquired service request slot after shutdown")
		}

		done := make(chan bool, 1)
		client.SendMessage([]byte("response"), done)
		select {
		case sent := <-done:
			if sent {
				t.Fatal("shutdown response reported as sent")
			}
		default:
			t.Fatal("shutdown response did not report completion")
		}

		if err := client.QueueNotification([]byte("notification")); err != ErrClientQuit {
			t.Fatalf("QueueNotification error = %v, want %v", err, ErrClientQuit)
		}
	}

	// An unread completion channel must not prevent shutdown from rejecting a
	// response.
	client.SendMessage([]byte("response"), make(chan bool))

	if len(client.serviceRequestSem) != 0 {
		t.Fatal("service request acquired a slot after shutdown")
	}
	if len(client.sendChan) != 0 {
		t.Fatal("response queued after shutdown")
	}
	if len(client.ntfnChan) != 0 {
		t.Fatal("notification queued after shutdown")
	}
}

func TestWsClientEnqueueDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &wsClient{
			ntfnChan: make(chan []byte, 1),
			quit:     make(chan struct{}),
		}
		client.ntfnChan <- []byte("occupy queue")

		queueResult := make(chan error)
		go func() {
			queueResult <- client.QueueNotification([]byte("pending"))
		}()
		synctest.Wait()

		drained := false
		go func() {
			client.enqueueWg.Wait()
			drained = true
		}()
		synctest.Wait()
		if drained {
			t.Fatal("enqueue drain completed while an admitted sender was blocked")
		}

		client.Lock()
		client.disconnected = true
		close(client.quit)
		client.Unlock()
		synctest.Wait()

		if err := <-queueResult; err != ErrClientQuit {
			t.Fatalf("QueueNotification error = %v, want %v", err, ErrClientQuit)
		}
		if !drained {
			t.Fatal("enqueue drain did not wait for admitted sender")
		}
	})
}

func TestWsClientServiceRequestLifecycle(t *testing.T) {
	const method = "test-ws-client-service-request-lifecycle"
	originalHandler, hadOriginal := wsHandlers[method]
	defer func() {
		if hadOriginal {
			wsHandlers[method] = originalHandler
		} else {
			delete(wsHandlers, method)
		}
	}()

	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		wsHandlers[method] = func(*wsClient, interface{}) (interface{}, error) {
			close(started)
			<-release
			return "done", nil
		}

		client := &wsClient{
			serviceRequestSem: makeSemaphore(1),
			sendChan:          make(chan wsResponse, 1),
			quit:              make(chan struct{}),
		}
		cmd := &parsedRPCCmd{
			jsonrpc: hnsjson.RpcVersion1,
			id:      1,
			method:  method,
		}
		if !client.serviceRequestAsync(cmd) {
			t.Fatal("service request rejected before shutdown")
		}
		<-started

		waitReturned := false
		go func() {
			client.WaitForShutdown()
			waitReturned = true
		}()
		synctest.Wait()
		if waitReturned {
			t.Fatal("shutdown completed while service request was running")
		}

		close(release)
		synctest.Wait()
		if !waitReturned {
			t.Fatal("shutdown did not complete after service request returned")
		}
		if len(client.serviceRequestSem) != 0 {
			t.Fatal("service request slot was not released")
		}
	})
}
