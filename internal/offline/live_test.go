package offline

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"mhp/internal/web"
)

// TestAgainstLive compares an exported offline copy with the mhp it came from (both must cover the same data, so
// run it right after the export, while that mhp's tracer is paused or its target idle):
//
//	MHP_OFFLINE_FILE=copy.html MHP_LIVE_URL=http://127.0.0.1:8080 go test ./internal/offline -run AgainstLive -v
func TestAgainstLive(t *testing.T) {
	file, base := os.Getenv("MHP_OFFLINE_FILE"), os.Getenv("MHP_LIVE_URL")
	if file == "" || base == "" {
		t.Skip("set MHP_OFFLINE_FILE and MHP_LIVE_URL")
	}
	page, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`<script id="mhp-data" type="application/octet-stream">([^<]*)</script>`).FindSubmatch(page)
	if m == nil {
		t.Fatal("no snapshot in the page")
	}
	t0 := time.Now()
	raw, err := base64.StdEncoding.DecodeString(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	sn, err := web.DecodeSnapshot(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := web.OfflineServer(sn)
	if err != nil {
		t.Fatal(err)
	}
	recs := 0
	for _, tk := range sn.Agg.Ticks {
		recs += len(tk.Recs)
	}
	t.Logf("page %.1f MB, snapshot %.1f MB gzipped; %d ticks, %d records, %d stacks, %d frames, %d source locations; decoded in %v",
		float64(len(page))/1e6, float64(len(raw))/1e6, len(sn.Agg.Ticks), recs, len(sn.Agg.Stacks), len(sn.Agg.Frames), len(sn.Sources),
		time.Since(t0).Round(time.Millisecond))
	h := srv.Handler()
	off := func(url string) []byte {
		rec := httptest.NewRecorder()
		t1 := time.Now()
		h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
		t.Logf("offline %-60.60s %6d bytes in %v", url, rec.Body.Len(), time.Since(t1).Round(time.Microsecond))
		return rec.Body.Bytes()
	}
	on := func(url string) []byte {
		r, err := http.Get(base + url)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return b
	}
	n := len(sn.Agg.Ticks)
	if n < 4 {
		t.Fatalf("only %d ticks", n)
	}
	for _, span := range [][2]int{{0, n - 1}, {n / 3, n / 2}, {n - 6, n - 1}} {
		url := fmt.Sprintf("/range?from=%d&to=%d", sn.Agg.Ticks[span[0]].T, sn.Agg.Ticks[span[1]].T)
		var a, b map[string]any
		json.Unmarshal(off(url), &a)
		json.Unmarshal(on(url), &b)
		delete(a, "oldest")
		delete(b, "oldest") // the live timeline may have dropped old ticks since the export
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if !bytes.Equal(ja, jb) {
			t.Errorf("%s differs:\noffline %.400s\nlive    %.400s", url, ja, jb)
		}
		off(fmt.Sprintf("/stacks?metric=range_alloc&from=%d&to=%d", sn.Agg.Ticks[span[0]].T, sn.Agg.Ticks[span[1]].T))
	}
	off(fmt.Sprintf("/report.html?from=%d&to=%d", sn.Agg.Ticks[n/3].T, sn.Agg.Ticks[n/2].T))
	off("/history")
}
