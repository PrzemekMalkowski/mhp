package offline

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
	"testing"

	"mhp/internal/agg"
	"mhp/internal/live"
	"mhp/internal/web"
)

func TestPage(t *testing.T) {
	srv := &web.Server{Hub: live.NewHub(4), Dump: func() *agg.Dump { return &agg.Dump{Frames: []string{"main"}} },
		Info: func() any { return map[string]any{"cmd": "run"} }}
	srv.Hub.Publish(live.View{T: 1000})
	sn, err := srv.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := Write(&page, web.Index(), sn.Encode); err != nil {
		t.Fatal(err)
	}
	p := page.String()
	for _, want := range []string{"<title>mhp offline copy</title>", "<h1>mhp offline copy</h1>", "globalThis.Go", "mhpOffline",
		"if(window.mhpOffline)return mhpOffline.download(url)", "const es=new EventSource('/events')"} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Index(p, "mhpOffline={") > strings.Index(p, "const $=") {
		t.Error("boot script must run before the UI script")
	}
	blob := func(id string) []byte {
		m := regexp.MustCompile(`<script id="` + id + `" type="application/octet-stream">([^<]*)</script>`).FindStringSubmatch(p)
		if m == nil {
			t.Fatalf("no %s blob", id)
		}
		b, err := base64.StdEncoding.DecodeString(m[1])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	z, err := gzip.NewReader(bytes.NewReader(blob("mhp-wasm")))
	if err != nil {
		t.Fatal(err)
	}
	wasm, _ := io.ReadAll(z)
	if !bytes.HasPrefix(wasm, []byte("\x00asm")) {
		t.Errorf("mhp-wasm is not a WebAssembly module")
	}
	sn2, err := web.DecodeSnapshot(bytes.NewReader(blob("mhp-data")))
	if err != nil || len(sn2.Agg.Frames) != 1 {
		t.Fatalf("snapshot: %v", err)
	}
	t.Logf("page %d bytes (wasm %d bytes uncompressed)", page.Len(), len(wasm))
}
