package shim

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"

	"github.com/PrzemekMalkowski/mhp/internal/model"
)

// ParseMallocInfo reads glibc's malloc_info() XML (version 1, glibc 2.10 and later). A truncated document (more
// arenas than the buffer held) yields the arenas read completely and truncated = true; the process-wide totals
// are then summed from those arenas.
func ParseMallocInfo(b []byte) (st *model.ArenaStats, truncated bool) {
	st = &model.ArenaStats{}
	d := xml.NewDecoder(bytes.NewReader(b))
	var cur *model.Arena
	depth, done := 0, false
	attr := func(e xml.StartElement, k string) string {
		for _, a := range e.Attr {
			if a.Name.Local == k {
				return a.Value
			}
		}
		return ""
	}
	num := func(e xml.StartElement, k string) int64 { n, _ := strconv.ParseInt(attr(e, k), 10, 64); return n }
	var totFree, totSize, totMax int64
	haveTot := map[string]bool{}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil { // cut mid-element: keep what was complete
			truncated = true
			break
		}
		switch e := tok.(type) {
		case xml.StartElement:
			depth++
			switch e.Name.Local {
			case "heap":
				n, _ := strconv.Atoi(attr(e, "nr"))
				cur = &model.Arena{N: n}
			case "size", "unsorted":
				if cur == nil {
					continue
				}
				from, to, total := num(e, "from"), num(e, "to"), num(e, "total")
				switch {
				case from < 1024:
					cur.FreeSmall += total
				case from < 128<<10:
					cur.FreeMid += total
				default:
					cur.FreeLarge += total
				}
				if total > 0 && to > cur.Largest {
					cur.Largest = to
				}
			case "total":
				count, size := num(e, "count"), num(e, "size")
				if cur != nil {
					switch attr(e, "type") {
					case "fast":
						cur.FastFree = size
						cur.Free += size
						cur.FreeChunks += count
					case "rest":
						cur.Free += size
						cur.FreeChunks += count
					}
				} else {
					switch attr(e, "type") {
					case "fast", "rest":
						totFree += size
						haveTot["free"] = true
					case "mmap":
						st.MmapChunks, st.Mmapped = count, size
					}
				}
			case "system":
				size := num(e, "size")
				switch t := attr(e, "type"); {
				case cur != nil && t == "current":
					cur.Size = size
				case cur != nil && t == "max":
					cur.MaxSize = size
				case cur == nil && t == "current":
					totSize, haveTot["size"] = size, true
				case cur == nil && t == "max":
					totMax, haveTot["max"] = size, true
				}
			case "aspace":
				if cur != nil && attr(e, "type") == "subheaps" {
					cur.Subheaps = num(e, "size")
				}
			}
		case xml.EndElement:
			depth--
			switch e.Name.Local {
			case "heap":
				if cur != nil {
					// malloc_info counts the top chunk in "rest" but lists only the bins (fastbins included)
					cur.Top = max(0, cur.Free-cur.FreeSmall-cur.FreeMid-cur.FreeLarge)
					st.Top += cur.Top
					st.Arenas = append(st.Arenas, *cur)
					cur = nil
				}
			case "malloc":
				done = true
			}
		}
	}
	if !done {
		truncated = true
	}
	for _, a := range st.Arenas {
		if !haveTot["free"] {
			st.Free += a.Free
		}
		if !haveTot["size"] {
			st.Size += a.Size
		}
		if !haveTot["max"] {
			st.MaxSize += a.MaxSize
		}
	}
	if haveTot["free"] {
		st.Free = totFree
	}
	if haveTot["size"] {
		st.Size = totSize
	}
	if haveTot["max"] {
		st.MaxSize = totMax
	}
	st.Truncated = truncated
	return st, truncated
}
