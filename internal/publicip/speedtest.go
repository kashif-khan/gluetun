package publicip

import (
	"context"
	"fmt"
	"time"

	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/speedtest"
)

// logHostComparison logs a table comparing the host and VPN public IP
// information, if the host public IP information was obtained.
func (l *Loop) logHostComparison(vpnData models.PublicIP) {
	hostData := l.GetHostData()
	if !hostData.IP.IsValid() {
		return
	}

	for _, line := range comparisonTable(hostData, vpnData) {
		l.logger.Info(line)
	}
}

// startSpeedTest runs a speed test in the background if enabled,
// replacing any speed test already running. It is stopped by ClearData,
// which is called when the VPN connection goes down.
func (l *Loop) startSpeedTest() {
	l.settingsMutex.RLock()
	enabled := *l.settings.SpeedTest
	l.settingsMutex.RUnlock()
	if !enabled {
		return
	}

	l.speedTestMutex.Lock()
	defer l.speedTestMutex.Unlock()

	if l.speedTestCancel != nil {
		l.speedTestCancel()
	}
	const timeout = time.Minute
	ctx, cancel := context.WithTimeout(l.runCtx, timeout)
	l.speedTestCancel = cancel

	go func() {
		defer cancel()
		l.logger.Info("running speed test through the VPN")
		result, err := speedtest.Run(ctx, l.httpClient)
		if err != nil {
			if ctx.Err() == nil {
				l.logger.Warn("speed test failed: " + err.Error())
			}
			return
		}
		l.logger.Info(fmt.Sprintf("speed test: download %.2f Mbps (%.1f MB in %s), latency %s",
			result.DownloadMbps(), float64(result.DownloadedBytes)/1e6, //nolint:mnd
			result.DownloadDuration.Round(time.Millisecond),
			result.Latency.Round(time.Millisecond)))
	}()
}

func (l *Loop) stopSpeedTest() {
	l.speedTestMutex.Lock()
	defer l.speedTestMutex.Unlock()
	if l.speedTestCancel != nil {
		l.speedTestCancel()
		l.speedTestCancel = nil
	}
}
