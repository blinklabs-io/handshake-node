// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/handshake-node/brontide"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	defaultTimeout         = 5 * time.Second
	defaultIdentityKeyFile = "hsdinterop-brontide.key"

	transportPlaintext transportMode = "plaintext"
	transportBrontide  transportMode = "brontide"
)

type transportMode string

type config struct {
	addr            string
	networkName     string
	chainParams     *chaincfg.Params
	timeout         time.Duration
	transport       transportMode
	remoteKey       []byte
	identityKeyPath string
	height          uint32
	noRelay         bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	cfg, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "hsdinterop: %v\n", err)
		return 1
	}

	if err := execute(cfg, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "hsdinterop: %v\n", err)
		return 1
	}
	return 0
}

func parseConfig(args []string, output io.Writer) (*config, error) {
	if output == nil {
		output = io.Discard
	}

	fs := flag.NewFlagSet("hsdinterop", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.Usage = func() {
		fmt.Fprintf(output, "Usage: %s --addr host:port [options]\n", fs.Name())
		fs.PrintDefaults()
	}

	addr := fs.String("addr", "", "Handshake peer address as host:port")
	network := fs.String("network", "mainnet", "Handshake network: mainnet|regtest")
	timeout := fs.Duration("timeout", defaultTimeout, "Maximum time allowed for dial and handshake")
	transport := fs.String("transport", string(transportPlaintext), "P2P transport: plaintext|brontide")
	remoteKeyHex := fs.String("remote-key", "", "Remote compressed secp256k1 static public key hex for brontide transport")
	identityKeyPath := fs.String("identity-key", "", "Path to local Brontide identity key; created if missing")
	height := fs.Uint("height", 0, "Local chain height to advertise")
	noRelay := fs.Bool("no-relay", false, "Advertise no transaction relay")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	params, canonicalNetwork, err := networkParams(*network)
	if err != nil {
		return nil, err
	}

	mode, err := parseTransport(*transport)
	if err != nil {
		return nil, err
	}

	if *timeout <= 0 {
		return nil, errors.New("timeout must be greater than zero")
	}

	normalizedAddr, err := normalizePeerAddr(*addr)
	if err != nil {
		return nil, err
	}

	if uint64(*height) > math.MaxUint32 {
		return nil, fmt.Errorf("height %d exceeds max uint32", *height)
	}

	if mode != transportBrontide {
		if *remoteKeyHex != "" {
			return nil, errors.New("remote-key requires --transport=brontide")
		}
		if *identityKeyPath != "" {
			return nil, errors.New("identity-key requires --transport=brontide")
		}
	} else if *identityKeyPath == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("default identity key path: %w", err)
		}
		*identityKeyPath = filepath.Join(configDir, "hsdinterop", defaultIdentityKeyFile)
	}

	var remoteKey []byte
	if *remoteKeyHex != "" {
		remoteKey, err = parseRemoteKey(*remoteKeyHex)
		if err != nil {
			return nil, err
		}
	}
	if mode == transportBrontide && len(remoteKey) == 0 {
		return nil, errors.New("remote-key is required with --transport=brontide")
	}

	return &config{
		addr:            normalizedAddr,
		networkName:     canonicalNetwork,
		chainParams:     params,
		timeout:         *timeout,
		transport:       mode,
		remoteKey:       remoteKey,
		identityKeyPath: *identityKeyPath,
		height:          uint32(*height),
		noRelay:         *noRelay,
	}, nil
}

func networkParams(name string) (*chaincfg.Params, string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "mainnet":
		return &chaincfg.MainNetParams, "mainnet", nil
	case "regtest":
		return &chaincfg.RegressionNetParams, "regtest", nil
	case "testnet", "simnet":
		return nil, "", fmt.Errorf(
			"network %q is not available in this branch's chaincfg (available: mainnet, regtest)",
			name,
		)
	default:
		return nil, "", fmt.Errorf("unknown network %q", name)
	}
}

func parseTransport(transport string) (transportMode, error) {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case string(transportPlaintext):
		return transportPlaintext, nil
	case string(transportBrontide):
		return transportBrontide, nil
	default:
		return "", fmt.Errorf("unknown transport %q", transport)
	}
}

func normalizePeerAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("addr is required")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("addr must be host:port: %w", err)
	}
	if strings.TrimSpace(host) == "" {
		return "", errors.New("addr host is required")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", fmt.Errorf("addr port must be numeric uint16: %w", err)
	}
	return net.JoinHostPort(host, port), nil
}

func parseRemoteKey(remoteKeyHex string) ([]byte, error) {
	remoteKeyHex = strings.TrimSpace(remoteKeyHex)
	key, err := hex.DecodeString(remoteKeyHex)
	if err != nil {
		return nil, fmt.Errorf("remote-key must be hex: %w", err)
	}
	if _, err := brontide.ParsePublicKey(key); err != nil {
		return nil, fmt.Errorf("remote-key must be a compressed secp256k1 public key: %w", err)
	}
	return key, nil
}

func execute(cfg *config, stdout, stderr io.Writer) error {
	deadline := time.Now().Add(cfg.timeout)
	dialer := net.Dialer{Deadline: deadline}
	rawConn, err := dialer.Dial("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.addr, err)
	}

	conn, err := wrapTransport(rawConn, cfg, stderr, deadline)
	if err != nil {
		_ = rawConn.Close()
		return err
	}
	defer conn.Close()

	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set handshake deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	if _, err := exchangeVersionVerack(conn, cfg, deadline, stdout); err != nil {
		return err
	}

	fmt.Fprintf(
		stdout,
		"handshake complete addr=%s network=%s magic=%#x transport=%s\n",
		cfg.addr,
		cfg.networkName,
		uint32(cfg.chainParams.Net),
		cfg.transport,
	)
	return nil
}

func wrapTransport(rawConn net.Conn, cfg *config, stderr io.Writer, deadline time.Time) (net.Conn, error) {
	switch cfg.transport {
	case transportPlaintext:
		return rawConn, nil
	case transportBrontide:
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.New("brontide client handshake: timeout expired")
		}

		localPriv, created, err := brontide.LoadOrCreateIdentityKey(cfg.identityKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load brontide identity %s: %w", cfg.identityKeyPath, err)
		}
		if created {
			fmt.Fprintf(stderr, "hsdinterop: created brontide identity %s\n", cfg.identityKeyPath)
		}

		conn, err := brontide.ClientHandshakeTimeout(rawConn, localPriv, cfg.remoteKey, remaining)
		if err != nil {
			return nil, fmt.Errorf("brontide client handshake: %w", err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported transport %q", cfg.transport)
	}
}

func exchangeVersionVerack(conn net.Conn, cfg *config, deadline time.Time, stdout io.Writer) (*wire.HnsMsgVersion, error) {
	localVersion, err := localVersionMessage(cfg, conn.RemoteAddr())
	if err != nil {
		return nil, err
	}

	if _, err := wire.WriteHandshakeMessageN(conn, localVersion, cfg.chainParams.Net); err != nil {
		return nil, fmt.Errorf("send version: %w", err)
	}

	var (
		remoteVersion *wire.HnsMsgVersion
		seenVerack    bool
		sentVerack    bool
	)
	for remoteVersion == nil || !seenVerack {
		if time.Now().After(deadline) {
			return remoteVersion, handshakeTimeoutError(remoteVersion, seenVerack)
		}

		_, remoteMsg, _, err := wire.ReadHandshakeMessageN(conn, cfg.chainParams.Net)
		if err != nil {
			if isTimeout(err) {
				return remoteVersion, handshakeTimeoutError(remoteVersion, seenVerack)
			}
			return remoteVersion, fmt.Errorf("read handshake message: %w", err)
		}

		switch msg := remoteMsg.(type) {
		case *wire.HnsMsgVersion:
			if remoteVersion != nil {
				return remoteVersion, errors.New("protocol failure: duplicate version")
			}
			remoteVersion = msg
			printRemoteVersion(stdout, msg)
			if msg.Version < wire.HnsMinProtocolVersion {
				return remoteVersion, fmt.Errorf(
					"protocol failure: remote protocol %d below minimum %d",
					msg.Version,
					wire.HnsMinProtocolVersion,
				)
			}
			if !sentVerack {
				if _, err := wire.WriteHandshakeMessageN(conn, &wire.HnsMsgVerack{}, cfg.chainParams.Net); err != nil {
					return remoteVersion, fmt.Errorf("send verack: %w", err)
				}
				sentVerack = true
			}
		case *wire.HnsMsgVerack:
			seenVerack = true
		default:
			return remoteVersion, fmt.Errorf("protocol failure: unexpected handshake message %s", remoteMsg.Type())
		}
	}

	return remoteVersion, nil
}

func handshakeTimeoutError(remoteVersion *wire.HnsMsgVersion, seenVerack bool) error {
	waiting := make([]string, 0, 2)
	if remoteVersion == nil {
		waiting = append(waiting, "version")
	}
	if !seenVerack {
		waiting = append(waiting, "verack")
	}
	return fmt.Errorf("handshake timed out waiting for %s", strings.Join(waiting, " and "))
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func localVersionMessage(cfg *config, remoteAddr net.Addr) (*wire.HnsMsgVersion, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	msg := &wire.HnsMsgVersion{
		Version:  wire.HnsProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Time:     uint64(time.Now().Unix()), //nolint:gosec
		Remote:   remoteAddressForVersion(remoteAddr),
		Agent:    wire.DefaultUserAgent + "hsdinterop:0.1/",
		Height:   cfg.height,
		NoRelay:  cfg.noRelay,
	}
	msg.SetNonce(nonce)
	return msg, nil
}

func remoteAddressForVersion(addr net.Addr) wire.HnsNetAddress {
	remote := wire.HnsNetAddress{
		Time:     uint64(time.Now().Unix()), //nolint:gosec
		Services: uint64(wire.SFNodeNetwork),
	}

	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		remote.Host = append(net.IP(nil), tcpAddr.IP...)
		remote.Port = uint16(tcpAddr.Port) //nolint:gosec
		return remote
	}

	if addr == nil {
		return remote
	}

	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return remote
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return remote
	}
	remote.Host = net.ParseIP(host)
	remote.Port = uint16(port)
	return remote
}

func randomNonce() (uint64, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(nonce[:]), nil
}

func printRemoteVersion(stdout io.Writer, msg *wire.HnsMsgVersion) {
	fmt.Fprintf(
		stdout,
		"received version agent=%q protocol=%d height=%d services=%s\n",
		msg.Agent,
		msg.Version,
		msg.Height,
		wire.ServiceFlag(msg.Services),
	)
}
