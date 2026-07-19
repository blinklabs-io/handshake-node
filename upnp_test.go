// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testUPnPTimeout = 500 * time.Millisecond

func testUPnPClient() *http.Client {
	client := newUPnPHTTPClient()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = (&net.Dialer{
		Timeout: testUPnPTimeout,
	}).DialContext
	transport.ResponseHeaderTimeout = testUPnPTimeout
	transport.TLSHandshakeTimeout = testUPnPTimeout
	client.Timeout = testUPnPTimeout
	return client
}

func TestUPnPHTTPClientIsBounded(t *testing.T) {
	client := newUPnPHTTPClient()
	if client.Timeout <= 0 {
		t.Fatal("UPnP HTTP client has no overall timeout")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("UPnP HTTP transport has type %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("UPnP HTTP transport has no response header timeout")
	}
	if transport.MaxResponseHeaderBytes <= 0 {
		t.Fatal("UPnP HTTP transport has no response header size limit")
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("UPnP HTTP transport has no TLS handshake timeout")
	}
	if transport.Proxy != nil {
		t.Fatal("UPnP HTTP transport must not use an environment proxy")
	}
}

func TestGetServiceURLSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, validUPnPDescription("/control"))
	}))
	t.Cleanup(server.Close)

	got, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err != nil {
		t.Fatalf("getServiceURLWithClient: %v", err)
	}
	want := server.URL + "/control"
	if got != want {
		t.Fatalf("service URL = %q, want %q", got, want)
	}
}

func TestGetServiceURLResolvesRelativeControlURLAfterRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/root.xml" {
			http.Redirect(w, r, "/devices/root.xml", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, validUPnPDescription("control"))
	}))
	t.Cleanup(server.Close)

	got, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err != nil {
		t.Fatalf("getServiceURLWithClient: %v", err)
	}
	want := server.URL + "/devices/control"
	if got != want {
		t.Fatalf("service URL = %q, want %q", got, want)
	}
}

func TestGetServiceURLUsesURLBase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		description := validUPnPDescriptionWithBase(serverURLFromRequest(r)+
			"/gateway/", "control")
		_, _ = io.WriteString(w, description)
	}))
	t.Cleanup(server.Close)

	got, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err != nil {
		t.Fatalf("getServiceURLWithClient: %v", err)
	}
	want := server.URL + "/gateway/control"
	if got != want {
		t.Fatalf("service URL = %q, want %q", got, want)
	}
}

func TestCombineUPnPURL(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		control string
		want    string
		wantErr bool
	}{
		{
			name:    "host root with absolute path",
			base:    "http://router.example:1234",
			control: "/control",
			want:    "http://router.example:1234/control",
		},
		{
			name:    "description directory with relative path",
			base:    "http://router.example:1234/devices/root.xml",
			control: "control",
			want:    "http://router.example:1234/devices/control",
		},
		{
			name:    "absolute control URL",
			base:    "http://router.example/root.xml",
			control: "https://router.example/control",
			want:    "https://router.example/control",
		},
		{
			name:    "missing control URL",
			base:    "http://router.example/root.xml",
			wantErr: true,
		},
		{
			name:    "unsupported control scheme",
			base:    "http://router.example/root.xml",
			control: "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "invalid base URL",
			base:    "router.example/root.xml",
			control: "/control",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := combineURL(test.base, test.control)
			if test.wantErr {
				if err == nil {
					t.Fatalf("combineURL() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("combineURL: %v", err)
			}
			if got != test.want {
				t.Fatalf("combineURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveUPnPServiceURLRestrictsHost(t *testing.T) {
	tests := []struct {
		name        string
		description string
		urlBase     string
		control     string
		want        string
		wantErr     bool
	}{
		{
			name:        "same host different port",
			description: "http://router.example:1234/devices/root.xml",
			urlBase:     "http://router.example:5678/gateway/",
			control:     "control",
			want:        "http://router.example:5678/gateway/control",
		},
		{
			name:        "cross-host URLBase",
			description: "http://router.example/root.xml",
			urlBase:     "http://other.example/gateway/",
			control:     "control",
			wantErr:     true,
		},
		{
			name:        "cross-host absolute control URL",
			description: "http://router.example/root.xml",
			control:     "http://other.example/control",
			wantErr:     true,
		},
		{
			name:        "cross-host scheme-relative control URL",
			description: "http://router.example/root.xml",
			control:     "//other.example/control",
			wantErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveUPnPServiceURL(test.description, test.urlBase,
				test.control)
			if test.wantErr {
				if err == nil {
					t.Fatalf("resolveUPnPServiceURL() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveUPnPServiceURL: %v", err)
			}
			if got != test.want {
				t.Fatalf("resolveUPnPServiceURL() = %q, want %q", got,
					test.want)
			}
		})
	}
}

func TestGetServiceURLRejectsOversizedDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxUPnPDescriptionSize+1))
	}))
	t.Cleanup(server.Close)

	_, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want response size error", err)
	}
}

func TestGetServiceURLRejectsOversizedResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("x",
			maxUPnPResponseHeaderSize+1024))
		_, _ = io.WriteString(w, validUPnPDescription("/control"))
	}))
	t.Cleanup(server.Close)

	_, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err == nil {
		t.Fatal("expected response header size error")
	}
}

func TestGetServiceURLRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	_, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want HTTP 503 error", err)
	}
}

func TestGetServiceURLTimesOutWaitingForHeaders(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)

	start := time.Now()
	_, err := getServiceURLWithClient(testUPnPClient(), server.URL+"/root.xml")
	close(release)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("stalled request took too long: %v", time.Since(start))
	}
}

func TestSOAPRequestSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("SOAPAction"); got != `"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"` {
			t.Errorf("SOAPAction = %q", got)
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, validSOAPResponse())
	}))
	t.Cleanup(server.Close)

	response, err := soapRequestWithClient(testUPnPClient(), server.URL,
		"GetExternalIPAddress", "<u:GetExternalIPAddress/>")
	if err != nil {
		t.Fatalf("soapRequestWithClient: %v", err)
	}
	if !strings.Contains(string(response), "203.0.113.10") {
		t.Fatalf("SOAP response = %q, want external IP", response)
	}
}

func TestSOAPRequestRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxUPnPSOAPResponseSize+1))
	}))
	t.Cleanup(server.Close)

	_, err := soapRequestWithClient(testUPnPClient(), server.URL, "test", "<test/>")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want response size error", err)
	}
}

func TestSOAPRequestRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "failure", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	_, err := soapRequestWithClient(testUPnPClient(), server.URL, "test", "<test/>")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want HTTP 500 error", err)
	}
}

func TestSOAPRequestTimesOutReadingBody(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<s:Envelope>")
		w.(http.Flusher).Flush()
		<-release
	}))
	t.Cleanup(server.Close)

	start := time.Now()
	_, err := soapRequestWithClient(testUPnPClient(), server.URL, "test", "<test/>")
	close(release)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("stalled response took too long: %v", time.Since(start))
	}
}

func TestUPnPResponseBodiesAreClosed(t *testing.T) {
	tests := []struct {
		name string
		call func(*http.Client) error
	}{
		{
			name: "device description status error",
			call: func(client *http.Client) error {
				_, err := getServiceURLWithClient(client, "http://router/root.xml")
				return err
			},
		},
		{
			name: "SOAP status error",
			call: func(client *http.Client) error {
				_, err := soapRequestWithClient(client, "http://router/control", "test", "<test/>")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReadCloser{Reader: strings.NewReader("failure")}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       body,
					Header:     make(http.Header),
				}, nil
			})}
			if err := test.call(client); err == nil {
				t.Fatal("expected status error")
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestUPnPResponseCloseErrorsAreReturned(t *testing.T) {
	closeErr := errors.New("close failed")
	tests := []struct {
		name string
		body string
		call func(*http.Client) error
	}{
		{
			name: "device description",
			body: validUPnPDescription("/control"),
			call: func(client *http.Client) error {
				_, err := getServiceURLWithClient(client, "http://router/root.xml")
				return err
			},
		},
		{
			name: "SOAP response",
			body: validSOAPResponse(),
			call: func(client *http.Client) error {
				_, err := soapRequestWithClient(client, "http://router/control",
					"GetExternalIPAddress", "<u:GetExternalIPAddress/>")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingReadCloser{
				Reader:   strings.NewReader(test.body),
				closeErr: closeErr,
			}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       body,
					Header:     make(http.Header),
				}, nil
			})}
			err := test.call(client)
			if !errors.Is(err, closeErr) {
				t.Fatalf("error = %v, want response close error", err)
			}
		})
	}
}

type trackingReadCloser struct {
	io.Reader
	closed   bool
	closeErr error
}

func (b *trackingReadCloser) Close() error {
	b.closed = true
	return b.closeErr
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func validUPnPDescription(controlURL string) string {
	return validUPnPDescriptionWithBase("", controlURL)
}

func validUPnPDescriptionWithBase(urlBase, controlURL string) string {
	urlBaseElement := ""
	if urlBase != "" {
		urlBaseElement = "<URLBase>" + urlBase + "</URLBase>"
	}
	return `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  ` + urlBaseElement + `
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <deviceList><device>
      <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <deviceList><device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList><service>
          <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
          <controlURL>` + controlURL + `</controlURL>
        </service></serviceList>
      </device></deviceList>
    </device></deviceList>
  </device>
</root>`
}

func serverURLFromRequest(r *http.Request) string {
	return "http://" + r.Host
}

func validSOAPResponse() string {
	return `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>203.0.113.10</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>`
}
