// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpchealth"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/stretchr/testify/require"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/query/queryconnect"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/submit/submitconnect"
	syncpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/sync"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/sync/syncconnect"
)

func TestNewRejectsIncompleteConfig(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	_, err = New(nil)
	require.Error(t, err)

	_, err = New(&Config{Chain: newFakeChain(t, 1)})
	require.ErrorContains(t, err, "listener")

	_, err = New(&Config{Listeners: []net.Listener{listener}})
	require.ErrorContains(t, err, "chain")

	_, err = New(&Config{
		Listeners: []net.Listener{listener},
		Chain:     newFakeChain(t, 1),
	})
	require.ErrorContains(t, err, "chain params")
}

func TestNewAppliesDefaultLimits(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server, err := New(&Config{
		Listeners:   []net.Listener{listener},
		Chain:       newFakeChain(t, 1),
		ChainParams: &chaincfg.MainNetParams,
	})
	require.NoError(t, err)
	require.Equal(t, DefaultMaxBlockRefs, server.cfg.MaxBlockRefs)
	require.Equal(t, DefaultMaxUtxoKeys, server.cfg.MaxUtxoKeys)
	require.Equal(t, DefaultMaxHistoryItems, server.cfg.MaxHistoryItems)
}

func TestNewKeepsConfiguredLimits(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server, err := New(&Config{
		Listeners:       []net.Listener{listener},
		Chain:           newFakeChain(t, 1),
		ChainParams:     &chaincfg.MainNetParams,
		MaxBlockRefs:    7,
		MaxUtxoKeys:     8,
		MaxHistoryItems: 9,
	})
	require.NoError(t, err)
	require.Equal(t, 7, server.cfg.MaxBlockRefs)
	require.Equal(t, 8, server.cfg.MaxUtxoKeys)
	require.Equal(t, 9, server.cfg.MaxHistoryItems)
}

func TestStartAndStopAreIdempotent(t *testing.T) {
	server := newTestServer(t, &Config{Chain: newFakeChain(t, 1)})

	// A second Start must not bind the listeners again, and a second
	// Stop must not shut down an already closed server.
	server.Start()
	server.Stop()
	server.Stop()
}

func TestStopWithoutStartDoesNothing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	server, err := New(&Config{
		Listeners:   []net.Listener{listener},
		Chain:       newFakeChain(t, 1),
		ChainParams: &chaincfg.MainNetParams,
	})
	require.NoError(t, err)
	server.Stop()
}

func TestHealthReportsEveryRegisteredService(t *testing.T) {
	server := newTestServer(t, &Config{Chain: newFakeChain(t, 1)})
	client := grpchealth.NewClient(server.client(), server.url)

	for _, name := range serviceNames {
		resp, err := client.Check(t.Context(),
			&grpchealth.CheckRequest{Service: name})
		require.NoError(t, err)
		require.Equal(t, grpchealth.StatusServing, resp.Status)
	}
}

// Advertising only what the node can actually answer keeps clients from
// discovering a watch service that would reject every call.
func TestRegisteredServicesExcludeWatch(t *testing.T) {
	require.ElementsMatch(t, []string{
		syncconnect.SyncServiceName,
		queryconnect.QueryServiceName,
		submitconnect.SubmitServiceName,
	}, serviceNames)
}

// The point of the server is gRPC, so the gRPC protocol itself must
// work and not just connect's own protocol, which is the client
// default.
func TestServesGRPCProtocol(t *testing.T) {
	chain := newFakeChain(t, 4)
	server := newTestServer(t, &Config{Chain: chain})

	for name, option := range map[string]connect.ClientOption{
		"grpc":    connect.WithGRPC(),
		"grpcweb": connect.WithGRPCWeb(),
	} {
		t.Run(name, func(t *testing.T) {
			client := syncconnect.NewSyncServiceClient(
				server.client(), server.url, option)

			resp, err := client.ReadTip(t.Context(),
				connect.NewRequest(&syncpb.ReadTipRequest{}))
			require.NoError(t, err)
			require.EqualValues(t, 4, resp.Msg.GetTip().GetHeight())
		})
	}
}

func TestReflectionIsAvailable(t *testing.T) {
	server := newTestServer(t, &Config{Chain: newFakeChain(t, 1)})

	resp, err := server.client().Post(
		server.url+"/grpc.reflection.v1.ServerReflection/"+
			"ServerReflectionInfo",
		"application/grpc", http.NoBody)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServerServesOverTLSWithHTTP2(t *testing.T) {
	cert := selfSignedCert(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server, err := New(&Config{
		Listeners:   []net.Listener{listener},
		Chain:       newFakeChain(t, 2),
		ChainParams: &chaincfg.MainNetParams,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	})
	require.NoError(t, err)
	server.Start()
	t.Cleanup(server.Stop)

	// A TLS handshake must settle on h2, or gRPC clients fall back to
	// HTTP/1.1 and every call fails.
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	require.NoError(t, err)
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
	require.NoError(t, conn.Close())

	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // self-signed test certificate
			MinVersion:         tls.VersionTLS12,
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := syncconnect.NewSyncServiceClient(
		&http.Client{Transport: transport},
		"https://"+listener.Addr().String())

	resp, err := client.ReadTip(t.Context(),
		connect.NewRequest(&syncpb.ReadTipRequest{}))
	require.NoError(t, err)
	require.EqualValues(t, 2, resp.Msg.GetTip().GetHeight())
}

func TestHasALPN(t *testing.T) {
	require.False(t, hasALPN(nil, "h2"))
	require.False(t, hasALPN([]string{"http/1.1"}, "h2"))
	require.True(t, hasALPN([]string{"h2", "http/1.1"}, "h2"))
}

// selfSignedCert builds a throwaway certificate for the loopback
// listener used by the TLS test.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "handshake-node utxorpc test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}
