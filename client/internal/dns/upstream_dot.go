package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/dns"
)

const (
	dotProtocol    = "dot"
	dotDefaultPort = "853"
)

type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type dotClient struct {
	dial      dialContextFunc
	tlsConfig *tls.Config
}

func newDoTClient(dial dialContextFunc) *dotClient {
	return &dotClient{
		dial:      dial,
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

func (c *dotClient) exchange(ctx context.Context, target upstreamTarget, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	serverName, addr, err := dotEndpoint(target)
	if err != nil {
		return nil, 0, err
	}

	rawConn, err := c.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("dial dot upstream: %w", err)
	}

	cfg := c.tlsConfig.Clone()
	cfg.ServerName = serverName
	tlsConn := tls.Client(rawConn, cfg)
	defer func() {
		_ = tlsConn.Close()
	}()

	stop := context.AfterFunc(ctx, func() {
		_ = tlsConn.SetDeadline(time.Now())
	})
	defer stop()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, time.Since(start), fmt.Errorf("dot handshake: %w", err)
	}

	conn := &dns.Conn{Conn: tlsConn}
	if err := conn.WriteMsg(r); err != nil {
		return nil, time.Since(start), fmt.Errorf("write dot query: %w", err)
	}
	rm, err := conn.ReadMsg()
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("read dot response: %w", err)
	}
	if rm.Id != r.Id {
		return nil, time.Since(start), fmt.Errorf("dot response id mismatch")
	}

	setUpstreamProtocol(ctx, dotProtocol)
	return rm, time.Since(start), nil
}

func dotEndpoint(target upstreamTarget) (string, string, error) {
	if target.NSType != nbdns.DoTNameServerType {
		return "", "", fmt.Errorf("dotClient: unsupported nameserver type %s", target.NSType)
	}
	endpoint, err := url.Parse(target.URL)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return "", "", fmt.Errorf("invalid dot endpoint")
	}
	port := endpoint.Port()
	if port == "" {
		port = dotDefaultPort
	}
	return endpoint.Hostname(), net.JoinHostPort(endpoint.Hostname(), port), nil
}
