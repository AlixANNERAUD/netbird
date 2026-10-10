package networkmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestDNSConfigForPeer(t *testing.T) {
	udp := &proto.NameServer{NSType: int64(nbdns.UDPNameServerType), IP: "192.0.2.1", Port: 53}
	doh := &proto.NameServer{NSType: int64(nbdns.DoHNameServerType), URL: "https://dns.example/query"}
	dot := &proto.NameServer{NSType: int64(nbdns.DoTNameServerType), URL: "tls://dns.example"}
	original := &proto.DNSConfig{
		ServiceEnable: true,
		NameServerGroups: []*proto.NameServerGroup{
			{NameServers: []*proto.NameServer{udp, doh, dot}, Primary: true},
			{NameServers: []*proto.NameServer{doh}, Domains: []string{"doh.example"}},
			{NameServers: []*proto.NameServer{dot}, Domains: []string{"dot.example"}},
		},
	}

	legacy := DNSConfigForPeer(original, NameServerSupport{})
	require.Len(t, legacy.NameServerGroups, 1, "old clients must not receive unsupported groups")
	assert.Equal(t, []*proto.NameServer{udp}, legacy.NameServerGroups[0].NameServers, "mixed groups must retain UDP")
	assert.True(t, legacy.NameServerGroups[0].Primary, "group properties must survive filtering")

	dohOnly := DNSConfigForPeer(original, NameServerSupport{DoH: true})
	require.Len(t, dohOnly.NameServerGroups, 2, "DoH-only clients must not receive DoT-only groups")
	assert.Equal(t, []*proto.NameServer{udp, doh}, dohOnly.NameServerGroups[0].NameServers, "DoH-only clients must keep UDP and DoH upstreams")
	assert.Equal(t, []string{"doh.example"}, dohOnly.NameServerGroups[1].Domains, "the DoH-only group must be kept")

	capable := DNSConfigForPeer(original, NameServerSupport{DoH: true, DoT: true})
	require.Len(t, capable.NameServerGroups, 3, "shared cached groups must remain intact for new clients")
	assert.Len(t, capable.NameServerGroups[0].NameServers, 3, "capable clients must receive encrypted upstreams")
	assert.Len(t, original.NameServerGroups[0].NameServers, 3, "filtering must not mutate the cached config")
}

func TestNameServerSupportOf(t *testing.T) {
	caps := map[int32]bool{nmdata.PeerCapabilityDNSOverTLS: true}
	support := NameServerSupportOf(func(c int32) bool { return caps[c] })
	assert.Equal(t, NameServerSupport{DoT: true}, support, "support must follow the advertised capabilities")
}
