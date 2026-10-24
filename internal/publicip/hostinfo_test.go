package publicip

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_nameserversToAllow(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		resolvConf  string
		nameservers []netip.Addr
	}{
		"empty": {},
		"public_nameservers": {
			resolvConf: "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
			nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("8.8.8.8"),
			},
		},
		"loopback_ignored": {
			resolvConf: "nameserver 127.0.0.53\n",
		},
		"ipv6_ignored": {
			resolvConf: "nameserver 2606:4700:4700::1111\nnameserver 192.168.1.1\n",
			nameservers: []netip.Addr{
				netip.MustParseAddr("192.168.1.1"),
			},
		},
		"docker_embedded_dns": {
			resolvConf: "nameserver 127.0.0.11\noptions ndots:0\n\n" +
				"# Based on host file: '/etc/resolv.conf' (internal resolver)\n" +
				"# ExtServers: [host(192.168.1.1) host(8.8.8.8)]\n",
			nameservers: []netip.Addr{
				netip.MustParseAddr("192.168.1.1"),
				netip.MustParseAddr("8.8.8.8"),
			},
		},
		"duplicates_removed": {
			resolvConf: "nameserver 8.8.8.8\n# ExtServers: [host(8.8.8.8)]\n",
			nameservers: []netip.Addr{
				netip.MustParseAddr("8.8.8.8"),
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			nameservers := nameserversToAllow(testCase.resolvConf)

			assert.Equal(t, testCase.nameservers, nameservers)
		})
	}
}

func Test_comparisonTable(t *testing.T) {
	t.Parallel()

	host := models.PublicIP{
		IP:           netip.MustParseAddr("203.0.113.5"),
		Country:      "Pakistan",
		City:         "Karachi",
		Organization: "AS1 Home ISP",
	}
	vpn := models.PublicIP{
		IP:      netip.MustParseAddr("198.51.100.7"),
		Country: "Germany",
		City:    "Frankfurt",
	}

	lines := comparisonTable(host, vpn)

	assert.Equal(t, "|              | Host         | VPN          |", lines[0])
	assert.Equal(t, "|--------------|--------------|--------------|", lines[1])
	assert.Equal(t, "| IP           | 203.0.113.5  | 198.51.100.7 |", lines[2])
	assert.Contains(t, lines, "| Country      | Pakistan     | Germany      |")
	assert.Contains(t, lines, "| City         | Karachi      | Frankfurt    |")
	assert.Contains(t, lines, "| Organization | AS1 Home ISP |              |")
	// Region, Timezone and Hostname are empty on both sides and skipped
	assert.Len(t, lines, 6)
}
