//go:build integration

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

// liveBootstrap returns a bootstrap callback that points at Cloudflare. The
// live tests need a way to resolve the DoH endpoint's hostname without
// depending on the host's pre-takeover DNS state (which production wires
// in but unit tests don't).
func liveBootstrap() func() []netip.AddrPort {
	return func() []netip.AddrPort {
		return []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:53"),
			netip.MustParseAddrPort("9.9.9.9:53"),
		}
	}
}

// TestDoHClient_Live_Cloudflare exercises a real DoH round trip against
// Cloudflare. Confirms TLS, HTTP/2, bootstrap resolution, packing, and
// parsing all work end-to-end. Build-tagged so CI without network access
// or against blocked egress doesn't fail.
//
// Run: go test -tags=integration -count=1 -run TestDoHClient_Live ./client/internal/dns/...
func TestDoHClient_Live_Cloudflare(t *testing.T) {
	c := newDoHClient()
	c.bootstrap = liveBootstrap()

	target := upstreamTarget{
		NSType: nbdns.DoHNameServerType,
		URL:    "https://cloudflare-dns.com/dns-query",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, rtt, err := c.exchange(ctx, target, q)
	require.NoError(t, err, "live DoH exchange failed")
	require.NotNil(t, resp)
	assert.True(t, resp.Response, "response flag must be set")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	assert.NotEmpty(t, resp.Answer, "expected at least one answer record")
	t.Logf("DoH cloudflare-dns.com rtt=%s answers=%d", rtt.Truncate(time.Millisecond), len(resp.Answer))
}
