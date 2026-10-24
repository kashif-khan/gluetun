package firewall

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/netlink"
)

func (c *Config) Version(ctx context.Context) (version string, err error) {
	return c.impl.Version(ctx)
}

// TempDropOutputTCPRST temporarily drops outgoing TCP RST packets to the specified address and port,
// for any TCP packets not marked with the excludeMark given.
// This is necessary for TCP path MTU discovery to work, as the kernel will try to terminate the connection
// by sending a TCP RST packet, although we want to handle the connection manually.
func (c *Config) TempDropOutputTCPRST(ctx context.Context,
	src, dst netip.AddrPort, excludeMark int) (
	revert func(ctx context.Context) error, err error,
) {
	return c.impl.TempDropOutputTCPRST(ctx, src, dst, excludeMark)
}

func (c *Config) AcceptOutput(ctx context.Context, protocol, intf string,
	ip netip.Addr, port uint16, remove bool,
) error {
	return c.impl.AcceptOutput(ctx, protocol, intf, ip, port, remove)
}

func (c *Config) AcceptOutputFromIPPortToIPPort(ctx context.Context,
	protocol, intf string, source, destination netip.AddrPort, remove bool,
) error {
	return c.impl.AcceptOutputFromIPPortToIPPort(ctx, protocol, intf,
		source, destination, remove)
}

// TempAllowOutput temporarily allows outgoing traffic to the address and port given
// through the default route network interfaces matching the address IP family.
// It does nothing if the firewall is disabled. The returned revert function must
// always be called to remove the rules, and is not nil if there is no error.
func (c *Config) TempAllowOutput(ctx context.Context, protocol string,
	ip netip.Addr, port uint16,
) (revert func(ctx context.Context) error, err error) {
	c.stateMutex.Lock()
	defer c.stateMutex.Unlock()

	if !c.enabled {
		return func(context.Context) error { return nil }, nil
	}

	family := netlink.FamilyV4
	if ip.Is6() {
		family = netlink.FamilyV6
	}

	var interfaces []string
	for _, defaultRoute := range c.defaultRoutes {
		if defaultRoute.Family == family {
			interfaces = append(interfaces, defaultRoute.NetInterface)
		}
	}

	revert = func(ctx context.Context) error {
		const remove = true
		var firstErr error
		for _, intf := range interfaces {
			err := c.impl.AcceptOutput(ctx, protocol, intf, ip, port, remove)
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("removing output rule on interface %s: %w", intf, err)
			}
		}
		return firstErr
	}

	const remove = false
	for _, intf := range interfaces {
		err = c.impl.AcceptOutput(ctx, protocol, intf, ip, port, remove)
		if err != nil {
			_ = revert(context.Background())
			return nil, fmt.Errorf("allowing output on interface %s: %w", intf, err)
		}
	}

	return revert, nil
}
