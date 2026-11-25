package web

import (
	"compress/gzip"
	"io"
	"strings"
	"time"

	"mhp/internal/agg"
	"mhp/internal/sym"
)

// pprof sample type names per mhp metric (unit bytes; pprof shows "space" types as memory)
var pprofTypes = map[string]string{"live": "inuse_space", "growth": "growth_space", "alloc": "alloc_space",
	"faults": "faulted_space", "faults_window": "faulted_window_space", "range_alloc": "alloc_space",
	"range_free": "free_space", "range_net": "net_space", "range_faults": "faulted_space"}

// PprofOpts describe the profile.
type PprofOpts struct {
	Metric   string
	Comments []string
	Time     time.Time
	Duration time.Duration
	// Source gives a frame's file and line (nil or a miss: the function only), within Budget in total.
	Source func(string) (sym.SourceLoc, bool)
	Budget time.Duration
}

// WritePprof writes stacks as a gzipped profile.proto (go tool pprof, pprof.me, Speedscope, Grafana Pyroscope):
// one sample per stack with its value in bytes, plus the sampled count for range metrics, and the sub-system as a
// label. Frames are functions; file and line come from Source when given. Negative values (growth, net) stay.
func WritePprof(w io.Writer, stacks []agg.WeightedStack, o PprofOpts) error {
	var b pbuf
	strs := map[string]int64{"": 0}
	strTab := []string{""}
	str := func(s string) int64 {
		if i, ok := strs[s]; ok {
			return i
		}
		strs[s] = int64(len(strTab))
		strTab = append(strTab, s)
		return strs[s]
	}
	typ := pprofTypes[o.Metric]
	if typ == "" {
		typ = o.Metric + "_space"
	}
	withN := false
	for _, s := range stacks {
		if s.N != 0 {
			withN = true
			break
		}
	}
	valueType := func(field int, t, unit string) {
		var v pbuf
		v.varint(1, uint64(str(t)))
		v.varint(2, uint64(str(unit)))
		b.bytes(field, v.b)
	}
	valueType(1, typ, "bytes")
	if withN {
		valueType(1, "samples", "count")
	}

	type loc struct{ id, fn uint64 }
	locs := map[string]loc{}
	var locOrder []string
	deadline := time.Now().Add(o.Budget)
	for _, s := range stacks {
		if s.Value == 0 {
			continue
		}
		var smp, ids pbuf
		for i := len(s.Frames) - 1; i >= 0; i-- { // leaf first
			f := s.Frames[i]
			l, ok := locs[f]
			if !ok {
				l = loc{id: uint64(len(locs) + 1), fn: uint64(len(locs) + 1)}
				locs[f] = l
				locOrder = append(locOrder, f)
			}
			ids.raw(l.id)
		}
		smp.bytes(1, ids.b) // packed location ids
		var vals pbuf
		vals.raw(uint64(s.Value))
		if withN {
			vals.raw(uint64(s.N))
		}
		smp.bytes(2, vals.b)
		if s.Area != "" {
			var lb pbuf
			lb.varint(1, uint64(str("subsystem")))
			lb.varint(2, uint64(str(s.Area)))
			smp.bytes(3, lb.b)
		}
		b.bytes(2, smp.b)
	}
	for _, f := range locOrder {
		l := locs[f]
		var lp, ln, fn pbuf
		var line int64
		file := ""
		if o.Source != nil && time.Now().Before(deadline) {
			if src, ok := o.Source(f); ok {
				file, line = src.File, int64(src.Line)
			}
		}
		lp.varint(1, l.id)
		ln.varint(1, l.fn)
		if line > 0 {
			ln.varint(2, uint64(line))
		}
		lp.bytes(4, ln.b)
		b.bytes(4, lp.b)
		fn.varint(1, l.fn)
		fn.varint(2, uint64(str(f)))
		fn.varint(3, uint64(str(f)))
		if file != "" {
			fn.varint(4, uint64(str(file)))
		}
		b.bytes(5, fn.b)
	}
	if !o.Time.IsZero() {
		b.varint(9, uint64(o.Time.UnixNano()))
	}
	if o.Duration > 0 {
		b.varint(10, uint64(o.Duration.Nanoseconds()))
	}
	var pt pbuf
	pt.varint(1, uint64(str("space")))
	pt.varint(2, uint64(str("bytes")))
	b.bytes(11, pt.b)
	for _, c := range o.Comments {
		b.varint(13, uint64(str(c)))
	}
	b.varint(14, uint64(str(typ)))
	for _, s := range strTab { // string table last: every index is known now
		b.bytes(6, []byte(s))
	}
	z := gzip.NewWriter(w)
	if _, err := z.Write(b.b); err != nil {
		return err
	}
	return z.Close()
}

// pbuf is a minimal protocol-buffers writer (varint and length-delimited fields).
type pbuf struct{ b []byte }

func (p *pbuf) raw(v uint64) {
	for v >= 0x80 {
		p.b = append(p.b, byte(v)|0x80)
		v >>= 7
	}
	p.b = append(p.b, byte(v))
}

func (p *pbuf) varint(field int, v uint64) {
	p.raw(uint64(field) << 3)
	p.raw(v)
}

func (p *pbuf) bytes(field int, v []byte) {
	p.raw(uint64(field)<<3 | 2)
	p.raw(uint64(len(v)))
	p.b = append(p.b, v...)
}

// pprofComments describe an export the way the SVG's subtitle does.
func pprofComments(o exportOpts) []string {
	return []string{"mhp " + o.Title, strings.TrimSpace(strings.ReplaceAll(o.Subtitle, " · alloc wrappers hidden", ""))}
}
