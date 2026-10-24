package publicip

import (
	"context"
	"net/netip"
)

type Logger interface {
	Info(s string)
	Warn(s string)
	Error(s string)
}

type Firewall interface {
	TempAllowOutput(ctx context.Context, protocol string, ip netip.Addr, port uint16) (
		revert func(ctx context.Context) error, err error)
}
