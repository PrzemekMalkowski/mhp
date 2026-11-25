//go:build js && wasm

// mhpwasm runs inside an offline copy (internal/offline): it restores the embedded snapshot and answers the page's
// requests with the live server's handlers. JS API: mhpLoad(gzipBytes) -> error text or "";
// mhpServe(url) -> {status, type, disp, body: Uint8Array}. It calls mhpReady() once both are defined.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall/js"

	"mhp/internal/web"
)

var handler http.Handler

func main() {
	js.Global().Set("mhpLoad", js.FuncOf(load))
	js.Global().Set("mhpServe", js.FuncOf(serve))
	if f := js.Global().Get("mhpReady"); f.Type() == js.TypeFunction {
		f.Invoke()
	}
	select {}
}

func load(_ js.Value, args []js.Value) any {
	b := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(b, args[0])
	sn, err := web.DecodeSnapshot(bytes.NewReader(b))
	if err != nil {
		return err.Error()
	}
	srv, err := web.OfflineServer(sn)
	if err != nil {
		return err.Error()
	}
	handler = srv.Handler()
	return ""
}

func serve(_ js.Value, args []js.Value) (out any) {
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if r := recover(); r != nil {
				rec = httptest.NewRecorder()
				rec.WriteHeader(500)
				fmt.Fprint(rec, r)
			}
		}()
		if handler == nil {
			panic("no snapshot loaded")
		}
		handler.ServeHTTP(rec, httptest.NewRequest("GET", args[0].String(), nil))
	}()
	body := js.Global().Get("Uint8Array").New(rec.Body.Len())
	js.CopyBytesToJS(body, rec.Body.Bytes())
	o := js.Global().Get("Object").New()
	o.Set("status", rec.Code)
	o.Set("type", rec.Header().Get("Content-Type"))
	o.Set("disp", rec.Header().Get("Content-Disposition"))
	o.Set("body", body)
	return o
}
