package speedtest

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Result_DownloadMbps(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		result Result
		mbps   float64
	}{
		"zero_duration": {
			result: Result{DownloadedBytes: 1000},
		},
		"one_megabyte_per_second": {
			result: Result{DownloadedBytes: 1_000_000, DownloadDuration: time.Second},
			mbps:   8,
		},
		"half_second": {
			result: Result{DownloadedBytes: 1_000_000, DownloadDuration: 500 * time.Millisecond},
			mbps:   16,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.InDelta(t, testCase.mbps, testCase.result.DownloadMbps(), 0.0001)
		})
	}
}

func Test_run(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			size, err := strconv.Atoi(r.URL.Query().Get("bytes"))
			require.NoError(t, err)
			_, _ = w.Write(make([]byte, size))
		}))
		t.Cleanup(server.Close)

		const downloadBytes = 100_000
		result, err := run(t.Context(), server.Client(), server.URL, downloadBytes)

		require.NoError(t, err)
		assert.Equal(t, uint64(downloadBytes), result.DownloadedBytes)
		assert.Positive(t, result.Latency)
		assert.Positive(t, result.DownloadDuration)
	})

	t.Run("bad_status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		t.Cleanup(server.Close)

		_, err := run(t.Context(), server.Client(), server.URL, 100)

		assert.ErrorContains(t, err, "unexpected status code")
	})
}
