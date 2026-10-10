package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

type testDoTServer struct {
	addr  string
	roots *x509.CertPool
}

func startTestDoTServer(t *testing.T, handler dns.HandlerFunc) testDoTServer {
	t.Helper()

	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certSource.TLS.Certificates[0]
	roots := certSource.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	certSource.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)

	started := make(chan struct{})
	server := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: handler, NotifyStartedFunc: func() { close(started) }}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
	})
	<-started

	return testDoTServer{addr: ln.Addr().String(), roots: roots}
}

func newTestDoTClient(server testDoTServer, roots *x509.CertPool) *dotClient {
	c := newDoTClient(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, server.addr)
	})
	c.tlsConfig.RootCAs = roots
	return c
}

func answerA(ip string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		rr, err := dns.NewRR(r.Question[0].Name + " 60 IN A " + ip)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	}
}

func TestDoTClient_Exchange(t *testing.T) {
	server := startTestDoTServer(t, answerA("192.0.2.10"))
	c := newTestDoTClient(server, server.roots)

	ctx, result := contextWithUpstreamProtocolResult(t.Context())
	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://example.com"}
	resp, _, err := c.exchange(ctx, target, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))

	require.NoError(t, err)
	require.Len(t, resp.Answer, 1, "the answer from the DoT server must be returned")
	assert.Contains(t, resp.Answer[0].String(), "192.0.2.10", "the answer must carry the server's record")
	assert.Equal(t, dotProtocol, result.protocol, "the exchange must report the dot upstream protocol")
}

func TestDoTClient_RejectsUntrustedCertificate(t *testing.T) {
	server := startTestDoTServer(t, answerA("192.0.2.10"))
	c := newTestDoTClient(server, x509.NewCertPool())

	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://example.com"}
	_, _, err := c.exchange(t.Context(), target, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dot handshake", "an untrusted certificate must fail the handshake")
}

func TestDoTClient_RejectsServerNameMismatch(t *testing.T) {
	server := startTestDoTServer(t, answerA("192.0.2.10"))
	c := newTestDoTClient(server, server.roots)

	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://dns.invalid"}
	_, _, err := c.exchange(t.Context(), target, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dot handshake", "a certificate for another name must fail the handshake")
}

func TestDoTClient_CancelUnblocksExchange(t *testing.T) {
	release := make(chan struct{})
	server := startTestDoTServer(t, func(dns.ResponseWriter, *dns.Msg) {
		<-release
	})
	t.Cleanup(func() { close(release) })
	c := newTestDoTClient(server, server.roots)

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://example.com"}
	_, _, err := c.exchange(ctx, target, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))

	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second, "cancelling the context must unblock a pending read")
}

func TestDoTEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		target         upstreamTarget
		wantServerName string
		wantAddr       string
		wantErr        bool
	}{
		{
			name:           "hostname uses the default port",
			target:         upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://dns.quad9.net"},
			wantServerName: "dns.quad9.net",
			wantAddr:       "dns.quad9.net:853",
		},
		{
			name:           "ip literal with port",
			target:         upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://9.9.9.9:8853"},
			wantServerName: "9.9.9.9",
			wantAddr:       "9.9.9.9:8853",
		},
		{
			name:           "ipv6 literal",
			target:         upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://[2620:fe::fe]"},
			wantServerName: "2620:fe::fe",
			wantAddr:       "[2620:fe::fe]:853",
		},
		{
			name:    "plain tcp scheme rejected",
			target:  upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tcp://9.9.9.9"},
			wantErr: true,
		},
		{
			name:    "path rejected",
			target:  upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://dns.quad9.net/dns-query"},
			wantErr: true,
		},
		{
			name:    "credentials rejected",
			target:  upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://user@dns.quad9.net"},
			wantErr: true,
		},
		{
			name:    "doh target rejected",
			target:  upstreamTarget{NSType: nbdns.DoHNameServerType, URL: "https://dns.quad9.net/dns-query"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverName, addr, err := dotEndpoint(tt.target)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantServerName, serverName, "server name must be the endpoint host")
			assert.Equal(t, tt.wantAddr, addr, "dial address must include the port")
		})
	}
}

func TestTruncateForUDPClient(t *testing.T) {
	largeResponse := func() *dns.Msg {
		m := new(dns.Msg).SetQuestion("example.org.", dns.TypeTXT)
		m.Response = true
		for i := 0; i < 20; i++ {
			rr, err := dns.NewRR(`example.org. 60 IN TXT "` + strings.Repeat("x", 200) + `"`)
			require.NoError(t, err)
			m.Answer = append(m.Answer, rr)
		}
		return m
	}
	query := new(dns.Msg).SetQuestion("example.org.", dns.TypeTXT)

	udpResp := largeResponse()
	truncateForUDPClient(contextWithDNSProtocol(t.Context(), protoUDP), query, udpResp)
	assert.LessOrEqual(t, udpResp.Len(), dns.MinMsgSize, "a UDP client must not receive more than its buffer")
	assert.True(t, udpResp.Truncated, "a shortened UDP response must set TC so the client retries over TCP")

	tcpResp := largeResponse()
	fullLen := tcpResp.Len()
	truncateForUDPClient(contextWithDNSProtocol(t.Context(), protoTCP), query, tcpResp)
	assert.Equal(t, fullLen, tcpResp.Len(), "a TCP client must receive the full response")
	assert.False(t, tcpResp.Truncated, "a TCP response must not be marked truncated")
}

func TestUpstreamResolver_DispatchesDoT(t *testing.T) {
	server := startTestDoTServer(t, answerA("192.0.2.20"))
	base := newUpstreamResolverBase(t.Context(), nil, "")
	base.dotClient = newTestDoTClient(server, server.roots)

	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://example.com"}
	resp, _, err := base.exchangeUpstream(t.Context(), target, new(dns.Msg).SetQuestion("example.org.", dns.TypeA))

	require.NoError(t, err)
	require.Len(t, resp.Answer, 1, "a DoT target must be resolved through the DoT client")
	assert.Contains(t, resp.Answer[0].String(), "192.0.2.20", "the answer must come from the DoT server")
}

func TestUpstreamResolver_TruncatesEncryptedResponseForUDPClient(t *testing.T) {
	server := startTestDoTServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		for i := 0; i < 20; i++ {
			rr, err := dns.NewRR(r.Question[0].Name + ` 60 IN TXT "` + strings.Repeat("x", 200) + `"`)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})
	base := newUpstreamResolverBase(t.Context(), nil, "")
	base.dotClient = newTestDoTClient(server, server.roots)

	ctx := contextWithDNSProtocol(t.Context(), protoUDP)
	target := upstreamTarget{NSType: nbdns.DoTNameServerType, URL: "tls://example.com"}
	resp, _, err := base.exchangeUpstream(ctx, target, new(dns.Msg).SetQuestion("example.org.", dns.TypeTXT))

	require.NoError(t, err)
	assert.LessOrEqual(t, resp.Len(), dns.MinMsgSize, "a UDP client must not receive a response larger than its buffer")
	assert.True(t, resp.Truncated, "the client must be told to retry over TCP")
}
