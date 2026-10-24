package publicip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/publicip/api"
)

// FetchHostData fetches the information of the public IP address of the host
// using ipinfo.io, outside the VPN. It must be called before the VPN is started.
// It temporarily allows DNS traffic to the nameservers and HTTPS traffic to ipinfo.io
// through the firewall, which is reverted before returning.
// It does nothing if the host comparison is not enabled.
func (l *Loop) FetchHostData(ctx context.Context) (err error) {
	l.settingsMutex.RLock()
	enabled := *l.settings.Enabled && *l.settings.HostCompare
	ipInfoToken := findIPInfoToken(l.settings.APIs)
	l.settingsMutex.RUnlock()
	if !enabled {
		return nil
	}

	l.logger.Info("fetching host public IP address information outside the VPN")

	const ipInfoHost = "ipinfo.io"
	ipInfoIPs, revert, err := l.allowHostLookup(ctx, ipInfoHost)
	defer func() {
		if revert == nil {
			return
		}
		revertErr := revert(context.Background())
		if revertErr != nil && err == nil {
			err = fmt.Errorf("reverting firewall changes: %w", revertErr)
		}
	}()
	if err != nil {
		return fmt.Errorf("allowing host public IP lookup in the firewall: %w", err)
	}

	// Pin the connections to the IP addresses allowed in the firewall.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ipInfoIPs[0].String(), port))
			},
		},
	}
	defer client.CloseIdleConnections()

	fetchers, err := api.New([]api.NameToken{{Name: string(api.IPInfo), Token: ipInfoToken}}, client)
	if err != nil {
		return fmt.Errorf("creating fetcher: %w", err)
	}

	hostData, err := fetchers[0].FetchInfo(ctx, netip.Addr{})
	if err != nil {
		return fmt.Errorf("fetching host public IP address information: %w", err)
	}

	l.hostDataMutex.Lock()
	l.hostData = hostData
	l.hostDataMutex.Unlock()

	l.logger.Info("host public IP address is " + hostData.IP.String() +
		" (" + hostData.Country + ", " + hostData.Region + ", " + hostData.City + ")")
	return nil
}

func findIPInfoToken(apis []settings.PublicIPAPI) (token string) {
	for _, publicIPAPI := range apis {
		if strings.EqualFold(publicIPAPI.Name, string(api.IPInfo)) {
			return publicIPAPI.Token
		}
	}
	return ""
}

// allowHostLookup temporarily allows DNS traffic to the nameservers, resolves the host
// and allows HTTPS traffic to the IPv4 addresses found. The revert function is not nil
// if any rule was added, even if an error is returned.
func (l *Loop) allowHostLookup(ctx context.Context, host string) (
	ips []netip.Addr, revert func(ctx context.Context) error, err error,
) {
	var reverts []func(ctx context.Context) error
	revert = func(ctx context.Context) error {
		var errs []error
		for _, revertFunc := range reverts {
			errs = append(errs, revertFunc(ctx))
		}
		return errors.Join(errs...)
	}

	resolvConf, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, revert, fmt.Errorf("reading resolv.conf: %w", err)
	}
	for _, nameserver := range nameserversToAllow(string(resolvConf)) {
		for _, protocol := range [...]string{constants.UDP, constants.TCP} {
			const dnsPort = 53
			revertFunc, err := l.firewall.TempAllowOutput(ctx, protocol, nameserver, dnsPort)
			if err != nil {
				return nil, revert, fmt.Errorf("allowing DNS traffic to %s: %w", nameserver, err)
			}
			reverts = append(reverts, revertFunc)
		}
	}

	ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return nil, revert, fmt.Errorf("resolving %s: %w", host, err)
	} else if len(ips) == 0 {
		return nil, revert, fmt.Errorf("no IPv4 address found for %s", host)
	}

	for _, ip := range ips {
		const httpsPort = 443
		revertFunc, err := l.firewall.TempAllowOutput(ctx, constants.TCP, ip, httpsPort)
		if err != nil {
			return nil, revert, fmt.Errorf("allowing HTTPS traffic to %s: %w", ip, err)
		}
		reverts = append(reverts, revertFunc)
	}

	return ips, revert, nil
}

var regexExtServers = regexp.MustCompile(`host\(([^)]+)\)`)

// nameserversToAllow returns the non loopback nameserver addresses to allow
// in the firewall in order to resolve hostnames outside the VPN. Loopback
// nameservers are always reachable, but when it is the Docker embedded DNS server
// the upstream servers it forwards queries to, which Docker writes in a comment of the
// resolv.conf file, are returned instead.
func nameserversToAllow(resolvConf string) (nameservers []netip.Addr) {
	seen := make(map[netip.Addr]struct{})
	add := func(s string) {
		address, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || address.IsLoopback() || address.Is6() {
			return
		}
		if _, ok := seen[address]; ok {
			return
		}
		seen[address] = struct{}{}
		nameservers = append(nameservers, address)
	}

	for _, line := range strings.Split(resolvConf, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "nameserver "):
			add(strings.TrimPrefix(line, "nameserver "))
		case strings.HasPrefix(line, "# ExtServers:"):
			for _, match := range regexExtServers.FindAllStringSubmatch(line, -1) {
				add(match[1])
			}
		}
	}
	return nameservers
}

// GetHostData returns the host public IP data obtained before the VPN was started.
func (l *Loop) GetHostData() (data models.PublicIP) {
	l.hostDataMutex.RLock()
	defer l.hostDataMutex.RUnlock()
	return l.hostData.Copy()
}

// comparisonTable returns the lines of a table comparing the host
// and VPN public IP address information.
func comparisonTable(host, vpn models.PublicIP) (lines []string) {
	rows := [...][3]string{
		{"", "Host", "VPN"},
		{"IP", host.IP.String(), vpn.IP.String()},
		{"Country", host.Country, vpn.Country},
		{"Region", host.Region, vpn.Region},
		{"City", host.City, vpn.City},
		{"Organization", host.Organization, vpn.Organization},
		{"Timezone", host.Timezone, vpn.Timezone},
		{"Hostname", host.Hostname, vpn.Hostname},
	}

	var widths [3]int
	for _, row := range rows {
		for i, cell := range row {
			widths[i] = max(widths[i], len(cell))
		}
	}

	for i, row := range rows {
		isOptionalRow := i >= 2 // skip rows with no information at all
		if isOptionalRow && row[1] == "" && row[2] == "" {
			continue
		}
		line := fmt.Sprintf("| %-*s | %-*s | %-*s |",
			widths[0], row[0], widths[1], row[1], widths[2], row[2])
		lines = append(lines, line)
		if i == 0 {
			separator := "|" + strings.Repeat("-", widths[0]+2) +
				"|" + strings.Repeat("-", widths[1]+2) +
				"|" + strings.Repeat("-", widths[2]+2) + "|"
			lines = append(lines, separator)
		}
	}
	return lines
}
