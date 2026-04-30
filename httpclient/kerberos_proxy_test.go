package httpclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// syncBuffer is a minimal concurrent-safe bytes.Buffer wrapper used by the
// capturing proxy.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) WriteString(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.WriteString(v)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// generateSelfSignedCert returns a PEM-encoded self-signed cert valid for the
// given IP. The TLS backend uses InsecureSkipVerify on the client side, so the
// cert only needs to parse — nothing trusts it.
func generateSelfSignedCert(ip string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP(ip)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func TestResolveProxyAuthType(t *testing.T) {
	t.Run("empty returns none", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "")
		got, err := resolveProxyAuthType("")
		require.NoError(t, err)
		require.Equal(t, proxyAuthNone, got)
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "Negotiate")
		got, err := resolveProxyAuthType("")
		require.NoError(t, err)
		require.Equal(t, proxyAuthNegotiate, got)
	})
	t.Run("config value overrides env", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "basic")
		got, err := resolveProxyAuthType("negotiate")
		require.NoError(t, err)
		require.Equal(t, proxyAuthNegotiate, got)
	})
	t.Run("kerberos alias", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "")
		got, err := resolveProxyAuthType("kerberos")
		require.NoError(t, err)
		require.Equal(t, proxyAuthNegotiate, got)
	})
	t.Run("basic is a no-op", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "")
		got, err := resolveProxyAuthType("basic")
		require.NoError(t, err)
		require.Equal(t, proxyAuthBasic, got)
	})
	t.Run("unknown is rejected", func(t *testing.T) {
		t.Setenv(proxyAuthEnvVar, "")
		_, err := resolveProxyAuthType("digest")
		require.Error(t, err)
		require.Contains(t, err.Error(), proxyAuthEnvVar)
	})
}

func TestCcachePathFromSpec(t *testing.T) {
	cases := []struct {
		in      string
		out     string
		wantErr bool
	}{
		{in: "/tmp/krb5cc_0", out: "/tmp/krb5cc_0"},
		{in: "FILE:/tmp/krb5cc_0", out: "/tmp/krb5cc_0"},
		{in: "file:/tmp/krb5cc_0", out: "/tmp/krb5cc_0"},
		{in: `C:\Users\alice\krb5cc`, out: `C:\Users\alice\krb5cc`},
		{in: "KCM:", wantErr: true},
		{in: "KEYRING:session:foo", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ccachePathFromSpec(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.out, got)
		})
	}
}

func TestHttpTransportRejectsInvalidProxyAuthType(t *testing.T) {
	t.Setenv(proxyAuthEnvVar, "")
	c := NewApiClient(ClientConfig{ProxyAuthType: "digest"})
	// The transport construction failure is deferred to the first request.
	err := c.Do(context.Background(), "GET", "https://example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), proxyAuthEnvVar)
}

func TestHttpTransportRejectsOpaqueCustomTransportWithKerberos(t *testing.T) {
	t.Setenv(proxyAuthEnvVar, "")
	opaque := hc(func(*http.Request) (*http.Response, error) { return nil, nil })
	c := NewApiClient(ClientConfig{
		ProxyAuthType: "negotiate",
		Transport:     opaque,
	})
	err := c.Do(context.Background(), "GET", "https://example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "*http.Transport")
}

func TestHttpTransportAttachesKerberosHookOnDefaults(t *testing.T) {
	t.Setenv(proxyAuthEnvVar, "negotiate")
	tr, err := ClientConfig{}.httpTransport()
	require.NoError(t, err)
	ht, ok := tr.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", tr)
	require.NotNil(t, ht.GetProxyConnectHeader, "Kerberos proxy hook should be installed")
	require.NotSame(t, defaultTransport, ht, "must not mutate the shared defaultTransport")
}

func TestHttpTransportClonesCustomTransportForKerberos(t *testing.T) {
	t.Setenv(proxyAuthEnvVar, "")
	custom := &http.Transport{MaxIdleConns: 7}
	tr, err := ClientConfig{
		ProxyAuthType: "negotiate",
		Transport:     custom,
	}.httpTransport()
	require.NoError(t, err)
	ht, ok := tr.(*http.Transport)
	require.True(t, ok)
	require.NotSame(t, custom, ht, "custom transport must be cloned, not mutated")
	require.Equal(t, 7, ht.MaxIdleConns, "cloned transport should preserve caller settings")
	require.NotNil(t, ht.GetProxyConnectHeader)
}

func TestKerberosProxyConnectHeader(t *testing.T) {
	backend := newTLSBackend(t)
	defer backend.Close()

	proxy, captured := newCapturingProxy(t)
	defer proxy.Close()

	base := makeDefaultTransport()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxyURL, err := url.Parse("http://" + proxy.Addr().String())
	require.NoError(t, err)
	base.Proxy = http.ProxyURL(proxyURL)

	wrapped := withKerberosProxyAuth(base)
	// Replace SPNEGO token generation with a deterministic stub so the test
	// does not require a functioning KDC.
	var stubCalls atomic.Int32
	auth := wrapped.GetProxyConnectHeader
	require.NotNil(t, auth)
	wrapped.GetProxyConnectHeader = func(ctx context.Context, p *url.URL, target string) (http.Header, error) {
		stubCalls.Add(1)
		require.Equal(t, proxyURL.Host, p.Host)
		require.Contains(t, target, backend.addr)
		return http.Header{"Proxy-Authorization": []string{"Negotiate " + base64.StdEncoding.EncodeToString([]byte("fake-token"))}}, nil
	}

	client := &http.Client{Transport: wrapped}
	resp, err := client.Get("https://" + backend.addr + "/ping")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "pong", string(body))

	require.Equal(t, int32(1), stubCalls.Load(), "hook should fire exactly once for the CONNECT tunnel")
	require.Contains(t, captured.String(), "Proxy-Authorization: Negotiate ")
}

func TestKerberosProxyAuthSurfacesInitError(t *testing.T) {
	t.Setenv("KRB5_CONFIG", "/definitely/does/not/exist/krb5.conf")
	t.Setenv("KRB5CCNAME", "/definitely/does/not/exist/ccache")

	k := newKerberosProxyAuth()
	proxyURL, err := url.Parse("http://proxy.example.com:8080")
	require.NoError(t, err)
	_, err = k.proxyAuthorization(proxyURL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "krb5")

	// Subsequent calls must return the same error without re-attempting load.
	_, err2 := k.proxyAuthorization(proxyURL)
	require.Equal(t, err.Error(), err2.Error())
}

func TestKerberosProxyAuthInvokesSPNEGOGenerator(t *testing.T) {
	var seenSPN string
	k := newKerberosProxyAuth()
	k.genHeader = func(cl *krb5client.Client, spn string) (string, error) {
		seenSPN = spn
		return "Negotiate stub", nil
	}
	// Pretend init succeeded.
	k.once.Do(func() {})

	proxyURL, err := url.Parse("http://proxy.corp.example:3128")
	require.NoError(t, err)
	val, err := k.proxyAuthorization(proxyURL)
	require.NoError(t, err)
	assert.Equal(t, "Negotiate stub", val)
	assert.Equal(t, "HTTP/proxy.corp.example", seenSPN)
}

// --- test helpers ------------------------------------------------------------

type tlsBackend struct {
	addr string
	srv  *http.Server
	ln   net.Listener
}

func (b *tlsBackend) Close() { _ = b.srv.Close() }

// newTLSBackend starts an in-process TLS server that responds to GET /ping
// with "pong". It returns the address so tests can construct a target URL.
func newTLSBackend(t *testing.T) *tlsBackend {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cert, key, err := generateSelfSignedCert(ln.Addr().(*net.TCPAddr).IP.String())
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(cert, key)
	require.NoError(t, err)
	srv := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
	}
	tlsLn := tls.NewListener(ln, srv.TLSConfig)
	go srv.Serve(tlsLn)
	return &tlsBackend{addr: ln.Addr().String(), srv: srv, ln: tlsLn}
}

type capturingProxy struct {
	ln  net.Listener
	buf *syncBuffer
}

func (p *capturingProxy) Addr() net.Addr { return p.ln.Addr() }
func (p *capturingProxy) Close()         { _ = p.ln.Close() }
func (p *capturingProxy) String() string { return p.buf.String() }

// newCapturingProxy starts a minimal HTTP CONNECT proxy that records the raw
// CONNECT request bytes (including headers) before tunneling traffic to the
// requested backend. This lets tests assert on the Proxy-Authorization header.
func newCapturingProxy(t *testing.T) (*capturingProxy, *syncBuffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	buf := &syncBuffer{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleCONNECT(conn, buf)
		}
	}()
	return &capturingProxy{ln: ln, buf: buf}, buf
}

func handleCONNECT(client net.Conn, capture *syncBuffer) {
	defer client.Close()
	r := bufio.NewReader(client)
	req, err := http.ReadRequest(r)
	if err != nil {
		return
	}
	var header strings.Builder
	fmt.Fprintf(&header, "%s %s %s\r\n", req.Method, req.URL.String(), req.Proto)
	if err := req.Header.Write(&header); err != nil {
		return
	}
	capture.WriteString(header.String())

	if req.Method != http.MethodConnect {
		client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	// Use the buffered reader so any bytes already read ahead by
	// http.ReadRequest are replayed to the upstream before new ones.
	go io.Copy(upstream, r)
	io.Copy(client, upstream)
}
