// Package offline writes an offline copy: the UI page with mhp's handlers compiled to WebAssembly and a snapshot of
// the recorded data embedded, so it can be opened from a file and queried (time ranges, Explore, reports) without
// mhp. Build the WebAssembly part first: go generate ./internal/offline
package offline

//go:generate sh gen.sh

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"io"
)

//go:embed mhp.wasm.gz wasm_exec.js boot.js
var files embed.FS

// Write writes the page: index is the UI page; snapshot streams the gzipped snapshot.
func Write(w io.Writer, index []byte, snapshot func(io.Writer) error) error {
	at := bytes.Index(index, []byte("<script>\nconst $="))
	if at < 0 {
		return fmt.Errorf("offline: UI script not found in index.html")
	}
	head := bytes.Replace(index[:at], []byte("mhp live memory</title>"), []byte("mhp offline copy</title>"), 1)
	head = bytes.Replace(head, []byte("<h1>mhp live memory</h1>"), []byte("<h1>mhp offline copy</h1>"), 1)
	if _, err := w.Write(head); err != nil {
		return err
	}
	runtime, _ := files.ReadFile("wasm_exec.js")
	boot, _ := files.ReadFile("boot.js")
	wasm, _ := files.ReadFile("mhp.wasm.gz")
	fmt.Fprintf(w, "<script>\n%s\n</script>\n<script id=\"mhp-wasm\" type=\"application/octet-stream\">", runtime)
	if err := b64(w, func(e io.Writer) error { _, err := e.Write(wasm); return err }); err != nil {
		return err
	}
	io.WriteString(w, "</script>\n<script id=\"mhp-data\" type=\"application/octet-stream\">")
	if err := b64(w, snapshot); err != nil {
		return err
	}
	fmt.Fprintf(w, "</script>\n<script>\n%s</script>\n", boot)
	_, err := w.Write(index[at:])
	return err
}

func b64(w io.Writer, fill func(io.Writer) error) error {
	e := base64.NewEncoder(base64.StdEncoding, w)
	if err := fill(e); err != nil {
		return err
	}
	return e.Close()
}
