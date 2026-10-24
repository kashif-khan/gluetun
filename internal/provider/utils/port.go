package utils

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
)

func getPort(selection settings.ServerSelection,
	defaultOpenVPNTCP, defaultOpenVPNUDP, defaultWireguard uint16,
) (port uint16) {
	switch selection.VPN {
	case vpn.Wireguard:
		customPort := *selection.Wireguard.EndpointPort
		if customPort > 0 {
			return customPort
		}
		checkDefined("Wireguard", defaultWireguard)
		return defaultWireguard
	default: // OpenVPN
		customPort := *selection.OpenVPN.CustomPort
		if customPort > 0 {
			return customPort
		}
		if selection.OpenVPN.Protocol == constants.TCP {
			checkDefined("OpenVPN TCP", defaultOpenVPNTCP)
			return defaultOpenVPNTCP
		}

		checkDefined("OpenVPN UDP", defaultOpenVPNUDP)
		return defaultOpenVPNUDP
	}
}

// getServerPort returns the port found for the server and selected
// OpenVPN protocol, unless the user specified a custom port or the
// server has no port set, in which case it returns defaultPort.
func getServerPort(selection settings.ServerSelection, server models.Server,
	defaultPort uint16,
) (port uint16) {
	switch {
	case selection.VPN != vpn.OpenVPN, *selection.OpenVPN.CustomPort > 0:
		return defaultPort
	case selection.OpenVPN.Protocol == constants.TCP && server.TCPPort > 0:
		return server.TCPPort
	case selection.OpenVPN.Protocol != constants.TCP && server.UDPPort > 0:
		return server.UDPPort
	default:
		return defaultPort
	}
}

func checkDefined(portName string, port uint16) {
	if port > 0 {
		return
	}
	message := fmt.Sprintf("no default %s port is defined!", portName)
	panic(message)
}
