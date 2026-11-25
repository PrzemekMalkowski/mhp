package web

import (
	"bytes"
	"embed"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
)

// The UI's two typefaces (latin subsets, variable weight) are embedded and inlined into the page as data: URLs,
// so the live UI and the offline copy look the same without any network access.
//
//go:embed fonts
var fontFiles embed.FS

// fontFaces returns the @font-face rules that replace the /*@fonts*/ marker in index.html.
func fontFaces() string {
	files := []struct{ family, weight, file string }{
		{"Antonio", "400 700", "Antonio-latin.woff2"},
		{"Azeret Mono", "400 600", "AzeretMono-latin.woff2"},
	}
	var sb strings.Builder
	for _, f := range files {
		b, err := fontFiles.ReadFile("fonts/" + f.file)
		if err != nil {
			continue // the page falls back to system fonts
		}
		fmt.Fprintf(&sb, "@font-face{font-family:'%s';font-style:normal;font-weight:%s;font-display:swap;src:url(data:font/woff2;base64,%s) format('woff2')}\n",
			f.family, f.weight, base64.StdEncoding.EncodeToString(b))
	}
	return sb.String()
}

var (
	index     []byte
	indexOnce sync.Once
)

// Index is the UI page with its fonts inlined (the offline copy is built from it).
func Index() []byte {
	indexOnce.Do(func() {
		b, _ := static.ReadFile("static/index.html")
		index = bytes.Replace(b, []byte("/*@fonts*/"), []byte(fontFaces()), 1)
	})
	return index
}
