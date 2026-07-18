// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProfileServeMux(t *testing.T) {
	t.Parallel()

	mux := newProfileServeMux()
	tests := []struct {
		path        string
		wantPattern string
	}{
		{path: "/debug/pprof/", wantPattern: "/debug/pprof/"},
		{path: "/debug/pprof/cmdline", wantPattern: "/debug/pprof/cmdline"},
		{path: "/debug/pprof/profile", wantPattern: "/debug/pprof/profile"},
		{path: "/debug/pprof/symbol", wantPattern: "/debug/pprof/symbol"},
		{path: "/debug/pprof/trace", wantPattern: "/debug/pprof/trace"},
		{path: "/debug/pprof/goroutine", wantPattern: "/debug/pprof/"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			_, pattern := mux.Handler(req)
			require.Equal(t, test.wantPattern, pattern)
		})
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusSeeOther, recorder.Code)
	require.Equal(t, "/debug/pprof/", recorder.Header().Get("Location"))
	require.NotSame(t, http.DefaultServeMux, mux)

	postSymbol := httptest.NewRequest(http.MethodPost,
		"/debug/pprof/symbol", nil)
	_, pattern := mux.Handler(postSymbol)
	require.Equal(t, "/debug/pprof/symbol", pattern)
}

func TestProfileHTTPServerLoopbackAndShutdown(t *testing.T) {
	t.Parallel()

	profileServer, err := startProfileHTTPServer("0", nil)
	require.NoError(t, err)
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = profileServer.stop()
		}
	})

	host, port, err := net.SplitHostPort(profileServer.listener.Addr().String())
	require.NoError(t, err)
	require.True(t, net.ParseIP(host).IsLoopback())
	require.NotEqual(t, "0", port)
	require.Equal(t, profileReadHeaderTimeout,
		profileServer.server.ReadHeaderTimeout)
	require.Equal(t, profileReadTimeout, profileServer.server.ReadTimeout)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + profileServer.listener.Addr().String() +
		"/debug/pprof/")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, profileServer.stop())
	stopped = true
	select {
	case <-profileServer.done:
	default:
		t.Fatal("profile server goroutine still running after shutdown")
	}
}

func TestProfileHTTPServerReportsBindFailure(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
	})

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portString)
	require.NoError(t, err)

	profileServer, err := startProfileHTTPServer(strconv.Itoa(port), nil)
	require.Error(t, err)
	require.Nil(t, profileServer)
	require.ErrorContains(t, err, "profile server listen on 127.0.0.1:")
}
