package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Result struct {
	// Latency is the time to receive the response headers
	// of an empty request on an established connection.
	Latency time.Duration
	// DownloadedBytes is the number of bytes downloaded.
	DownloadedBytes uint64
	// DownloadDuration is the time it took to download the DownloadedBytes.
	DownloadDuration time.Duration
}

// DownloadMbps returns the download speed in megabits per second.
func (r Result) DownloadMbps() float64 {
	if r.DownloadDuration <= 0 {
		return 0
	}
	const bitsPerByte = 8
	const bitsPerMegabit = 1_000_000
	return float64(r.DownloadedBytes) * bitsPerByte / r.DownloadDuration.Seconds() / bitsPerMegabit
}

// Run measures the latency and download speed using the Cloudflare speed test
// download endpoint. The context should have a deadline or be canceled
// when the measurement should be abandoned.
func Run(ctx context.Context, client *http.Client) (result Result, err error) {
	const baseURL = "https://speed.cloudflare.com/__down"
	const downloadBytes = 25_000_000
	return run(ctx, client, baseURL, downloadBytes)
}

func run(ctx context.Context, client *http.Client, baseURL string, downloadBytes uint64) (
	result Result, err error,
) {
	// The shared client has a timeout which could be too short
	// for slow links, the context takes care of the timeout instead.
	clientCopy := *client
	clientCopy.Timeout = 0
	client = &clientCopy

	// First request to establish the connection, so the latency
	// measured next excludes the TCP and TLS handshakes.
	_, _, err = download(ctx, client, baseURL, 0)
	if err != nil {
		return result, fmt.Errorf("connecting: %w", err)
	}

	result.Latency, _, err = download(ctx, client, baseURL, 0)
	if err != nil {
		return result, fmt.Errorf("measuring latency: %w", err)
	}

	_, result.DownloadedBytes, result.DownloadDuration, err = downloadTimed(ctx, client, baseURL, downloadBytes)
	if err != nil {
		return result, fmt.Errorf("downloading: %w", err)
	}

	return result, nil
}

func download(ctx context.Context, client *http.Client, baseURL string, bytes uint64) (
	headersLatency time.Duration, downloaded uint64, err error,
) {
	headersLatency, downloaded, _, err = downloadTimed(ctx, client, baseURL, bytes)
	return headersLatency, downloaded, err
}

func downloadTimed(ctx context.Context, client *http.Client, baseURL string, bytes uint64) (
	headersLatency time.Duration, downloaded uint64, bodyDuration time.Duration, err error,
) {
	url := fmt.Sprintf("%s?bytes=%d", baseURL, bytes)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("creating request: %w", err)
	}

	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, 0, 0, err
	}
	defer response.Body.Close()
	headersLatency = time.Since(start)

	if response.StatusCode != http.StatusOK {
		return 0, 0, 0, fmt.Errorf("unexpected status code: %s", response.Status)
	}

	bodyStart := time.Now()
	written, err := io.Copy(io.Discard, response.Body)
	bodyDuration = time.Since(bodyStart)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("reading response body: %w", err)
	}

	return headersLatency, uint64(written), bodyDuration, nil //nolint:gosec
}
