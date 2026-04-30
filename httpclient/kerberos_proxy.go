package httpclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	krb5credentials "github.com/jcmturner/gokrb5/v8/credentials"
	krb5spnego "github.com/jcmturner/gokrb5/v8/spnego"
)

const (
	// proxyAuthEnvVar is the single environment variable (and ClientConfig
	// field) introduced to opt into non-default proxy authentication schemes.
	proxyAuthEnvVar = "DATABRICKS_PROXY_AUTH_TYPE"

	proxyAuthNone      = ""
	proxyAuthBasic     = "basic"
	proxyAuthNegotiate = "negotiate"

	// Default Kerberos locations when the corresponding env vars are unset.
	defaultKrb5ConfPath = "/etc/krb5.conf"
)

// resolveProxyAuthType normalizes the caller-provided value, falling back to
// the DATABRICKS_PROXY_AUTH_TYPE environment variable when unset. It returns
// one of the proxyAuth* constants or an error for unsupported values.
func resolveProxyAuthType(configured string) (string, error) {
	v := strings.TrimSpace(configured)
	if v == "" {
		v = os.Getenv(proxyAuthEnvVar)
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return proxyAuthNone, nil
	case proxyAuthBasic:
		return proxyAuthBasic, nil
	case proxyAuthNegotiate, "kerberos", "spnego":
		return proxyAuthNegotiate, nil
	default:
		return "", fmt.Errorf("unsupported %s=%q (expected one of: basic, negotiate)", proxyAuthEnvVar, v)
	}
}

// withKerberosProxyAuth configures t to pre-emptively attach a SPNEGO
// Proxy-Authorization header on every CONNECT tunnel it establishes through
// an upstream proxy. The Kerberos client is initialized lazily on the first
// CONNECT so that a missing ticket cache surfaces as a request-time error
// rather than a construction-time panic.
func withKerberosProxyAuth(t *http.Transport) *http.Transport {
	k := newKerberosProxyAuth()
	prev := t.GetProxyConnectHeader
	t.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
		var header http.Header
		if prev != nil {
			h, err := prev(ctx, proxyURL, target)
			if err != nil {
				return nil, err
			}
			header = h.Clone()
		}
		if header == nil {
			header = http.Header{}
		}
		value, err := k.proxyAuthorization(proxyURL)
		if err != nil {
			return nil, err
		}
		header.Set("Proxy-Authorization", value)
		return header, nil
	}
	return t
}

// kerberosProxyAuth owns a single gokrb5 client constructed from the user's
// ticket cache and produces SPNEGO tokens targeted at the upstream proxy's
// service principal (HTTP/<proxy-host>).
type kerberosProxyAuth struct {
	once      sync.Once
	client    *krb5client.Client
	err       error
	genHeader func(cl *krb5client.Client, spn string) (string, error)
}

func newKerberosProxyAuth() *kerberosProxyAuth {
	return &kerberosProxyAuth{genHeader: spnegoNegotiateHeader}
}

func (k *kerberosProxyAuth) init() {
	k.once.Do(func() {
		cfg, err := loadKrb5Config()
		if err != nil {
			k.err = fmt.Errorf("load krb5 config: %w", err)
			return
		}
		ccache, err := loadKrb5CCache()
		if err != nil {
			k.err = fmt.Errorf("load kerberos ticket cache: %w", err)
			return
		}
		cl, err := krb5client.NewFromCCache(ccache, cfg, krb5client.DisablePAFXFAST(true))
		if err != nil {
			k.err = fmt.Errorf("initialize kerberos client: %w", err)
			return
		}
		k.client = cl
	})
}

func (k *kerberosProxyAuth) proxyAuthorization(proxyURL *url.URL) (string, error) {
	k.init()
	if k.err != nil {
		return "", k.err
	}
	return k.genHeader(k.client, "HTTP/"+proxyURL.Hostname())
}

// spnegoNegotiateHeader produces the "Negotiate <base64-token>" value for the
// given SPN.
//
// A fresh AP-REQ authenticator is required on every call (Kerberos replay
// protection), so the returned header cannot be cached across CONNECTs. The
// underlying service ticket for the SPN is cached inside the gokrb5 client,
// so repeated calls avoid KDC round trips after the first.
func spnegoNegotiateHeader(cl *krb5client.Client, spn string) (string, error) {
	s := krb5spnego.SPNEGOClient(cl, spn)
	if err := s.AcquireCred(); err != nil {
		return "", fmt.Errorf("acquire kerberos credential for %s: %w", spn, err)
	}
	token, err := s.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("init SPNEGO context for %s: %w", spn, err)
	}
	raw, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal SPNEGO token: %w", err)
	}
	return "Negotiate " + base64.StdEncoding.EncodeToString(raw), nil
}

// loadKrb5Config reads the Kerberos configuration from KRB5_CONFIG if set,
// falling back to /etc/krb5.conf.
func loadKrb5Config() (*krb5config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
	if path == "" {
		path = defaultKrb5ConfPath
	}
	return krb5config.Load(path)
}

// loadKrb5CCache locates the user's Kerberos ticket cache via KRB5CCNAME,
// falling back to the platform default (/tmp/krb5cc_<uid>). Only the FILE:
// ccache type is supported; keytabs are deliberately out of scope.
func loadKrb5CCache() (*krb5credentials.CCache, error) {
	raw := os.Getenv("KRB5CCNAME")
	if raw == "" {
		raw = defaultCCachePath()
	}
	path, err := ccachePathFromSpec(raw)
	if err != nil {
		return nil, err
	}
	return krb5credentials.LoadCCache(path)
}

// ccachePathFromSpec extracts a filesystem path from a KRB5CCNAME value.
// Values may be bare paths or use the canonical "TYPE:residual" form. Only the
// FILE: type (and the implicit bare-path form) are supported because the task
// explicitly scopes support to ticket caches — keytabs, KCM, API, etc. are
// out of scope.
func ccachePathFromSpec(spec string) (string, error) {
	// A leading single letter followed by ':' is a Windows drive letter
	// (e.g. "C:\\Users\\..."), which is a bare path — not a type prefix.
	idx := strings.Index(spec, ":")
	if idx <= 1 {
		return spec, nil
	}
	prefix := strings.ToUpper(spec[:idx])
	if prefix == "FILE" {
		return spec[idx+1:], nil
	}
	return "", fmt.Errorf("unsupported KRB5CCNAME type %q (only FILE ticket caches are supported)", spec[:idx])
}

// defaultCCachePath returns the platform default location of the Kerberos
// ticket cache when KRB5CCNAME is unset. MIT Kerberos uses
// /tmp/krb5cc_<uid> on Unix; we fall back to that when no uid is resolvable.
func defaultCCachePath() string {
	uid := ""
	if u, err := user.Current(); err == nil {
		uid = u.Uid
	}
	if uid == "" {
		uid = strconv.Itoa(os.Getuid())
	}
	return filepath.Join(os.TempDir(), "krb5cc_"+uid)
}
