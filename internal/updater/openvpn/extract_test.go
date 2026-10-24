package openvpn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ExtractPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content    string
		port       uint16
		errMessage string
	}{
		"remote_with_port": {
			content: "client\nremote host.example.com 1194\nproto udp\n",
			port:    1194,
		},
		"first_remote_used": {
			content: "remote a.example.com 80\nremote b.example.com 443\n",
			port:    80,
		},
		"remote_without_port": {
			content: "remote host.example.com\n",
		},
		"no_remote": {
			content:    "client\nproto udp\n",
			errMessage: "remote line not found",
		},
		"invalid_port": {
			content:    "remote host.example.com abc\n",
			errMessage: "parsing remote port",
		},
		"port_too_large": {
			content:    "remote host.example.com 70000\n",
			errMessage: "parsing remote port",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			port, err := ExtractPort([]byte(testCase.content))

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.port, port)
		})
	}
}
