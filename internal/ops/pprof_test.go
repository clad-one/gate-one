package ops

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStartPprofDisabled(t *testing.T) {
	srv, err := StartPprof("")
	if err != nil {
		t.Fatal(err)
	}
	if srv != nil {
		t.Fatalf("empty addr started a server: %+v", srv)
	}
}

func TestStartPprofBadAddr(t *testing.T) {
	if _, err := StartPprof("not-an-address"); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestServePprofServesProfiles(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := ServePprof(ln)
	defer srv.Close()

	base := "http://" + ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	// The listener is bound before ServePprof returns: the first
	// request must already work.
	resp, err := client.Get(base + "/debug/pprof/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "goroutine") {
		t.Fatal("index does not list the goroutine profile")
	}

	// A named profile is routed by pprof.Index.
	resp2, err := client.Get(base + "/debug/pprof/goroutine?debug=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("goroutine profile = %d", resp2.StatusCode)
	}
	if !strings.Contains(string(body2), "goroutine") {
		t.Fatal("goroutine profile looks empty")
	}
}
