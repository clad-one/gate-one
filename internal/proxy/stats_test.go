package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatsWriterFlushes guards SSE/streaming through the stats wrapper:
// Go's ReverseProxy flushes immediately for text/event-stream via
// http.NewResponseController, which needs Flush or Unwrap.
func TestStatsWriterFlushes(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statsWriter{ResponseWriter: rec}

	if _, ok := any(sw).(http.Flusher); !ok {
		t.Fatal("statsWriter must implement http.Flusher")
	}
	if _, ok := any(sw).(interface{ Unwrap() http.ResponseWriter }); !ok {
		t.Fatal("statsWriter must implement Unwrap")
	}

	sw.WriteHeader(http.StatusOK)
	if _, err := sw.Write([]byte("data: x\n\n")); err != nil {
		t.Fatal(err)
	}
	sw.Flush()
	if !rec.Flushed {
		t.Fatal("Flush did not reach the underlying writer")
	}
	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("ResponseController.Flush: %v", err)
	}
}
