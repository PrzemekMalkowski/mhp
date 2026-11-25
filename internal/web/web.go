// Package web serves the live UI: static page, history, SSE stream and folded-stack export.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"mhp/internal/agg"
	"mhp/internal/live"
	"mhp/internal/sym"
)

//go:embed static
var static embed.FS

type Server struct {
	Hub    *live.Hub
	Folded func() string                        // nil in replay
	Stacks func(agg.Filter) []agg.WeightedStack // nil in replay
	Range  func(agg.Filter) agg.RangeTotals     // nil in replay
	// RangeThreads and Meta feed the HTML report: per-thread totals, and ordered context (host, server build, …)
	RangeThreads  func(agg.Filter) []agg.ThreadTotals
	Meta          func() [][2]string
	Toggle        func(on bool) error                      // nil without an allocation tracer
	RefreshArenas func()                                   // asks libmhp for a new malloc_info (nil without one)
	Info          func() any                               // diagnostics (symbol sources, mode)
	Source        func(frame string) (sym.SourceLoc, bool) // nil in replay
	Repos         *SourceRepos                             // nil when the server version is unknown
	// Dump and OfflinePage make /offline.html: the UI with a Snapshot embedded (OfflinePage writes the page,
	// streaming the snapshot via the callback)
	Dump        func() *agg.Dump
	OfflinePage func(w io.Writer, snapshot func(io.Writer) error) error
	Peaks       *Peaks // offline copies taken at the RSS high-water mark / near the cgroup limit (nil = off)
}

var metricNames = map[string]string{"live": "live heap bytes", "growth": "heap growth (window)",
	"alloc": "heap allocated total", "faults": "page faults (total)", "faults_window": "page faults (window)",
	"range_alloc": "heap allocated in time range", "range_free": "heap freed in time range",
	"range_net": "heap net change in time range", "range_faults": "page faults in time range"}

// filter reads the drill-down filters shared by /stacks, /range and the exports.
func filter(r *http.Request) agg.Filter {
	q := r.URL.Query()
	tid, _ := strconv.Atoi(q.Get("tid"))
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	return agg.Filter{TID: tid, Role: q.Get("role"), Subsys: q.Get("subsys"), Metric: q.Get("metric"), From: from, To: to}
}

type exportOpts struct {
	FlameOpts
	file string
}

// export reads the Explore filters (metric, tid, role, subsys, view=flame|callers, wrappers=hide|show).
func (s *Server) export(r *http.Request) (agg.Filter, exportOpts) {
	q := r.URL.Query()
	f := filter(r)
	if f.Metric == "" {
		f.Metric = "live"
	}
	o := exportOpts{FlameOpts: FlameOpts{Callers: q.Get("view") == "callers", HideWrappers: q.Get("wrappers") != "show",
		Unit: "bytes"}}
	now := time.Now()
	var target string
	if s.Info != nil {
		if m, ok := s.Info().(map[string]any); ok {
			target = fmt.Sprintf("mhp %v, pid %v", m["cmd"], m["pid"])
			if t, ok := m["since"].(string); ok {
				target += ", tracing since " + t
			}
		}
	}
	view := "flame graph (root at top)"
	if o.Callers {
		view = "callers (allocating function / faulting mapping at top)"
	}
	o.Title = fmt.Sprintf("%s: %s", metricNames[f.Metric], view)
	sub := []string{target, now.Format("2006-01-02 15:04:05")}
	if f.IsRange() {
		sub = append(sub, "range "+time.UnixMilli(f.From).Format("15:04:05")+" → "+time.UnixMilli(f.To).Format("15:04:05"))
	}
	for _, kv := range [][2]string{{"tid", q.Get("tid")}, {"role", f.Role}, {"sub-system", f.Subsys}} {
		if kv[1] != "" {
			sub = append(sub, kv[0]+" "+kv[1])
		}
	}
	if o.HideWrappers {
		sub = append(sub, "alloc wrappers hidden")
	}
	o.Subtitle = strings.Join(sub, " · ")
	o.file = fmt.Sprintf("mhp-%s-%s", f.Metric, now.Format("20060102-150405"))
	return f, o
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(static, "static")
	files := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			files.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(Index()) // index.html with the fonts inlined
	})
	mux.HandleFunc("/history", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Hub.HistoryNoArenas())
	})
	mux.HandleFunc("/folded", func(w http.ResponseWriter, r *http.Request) {
		if s.Folded == nil {
			http.Error(w, "not available in replay", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.RawQuery == "" { // legacy: live heap bytes, prefixed by thread role
			fmt.Fprint(w, s.Folded())
			return
		}
		f, o := s.export(r)
		w.Header().Set("Content-Disposition", `attachment; filename="`+o.file+`.folded"`)
		Folded(w, s.Stacks(f), o.FlameOpts)
	})
	mux.HandleFunc("/pprof", func(w http.ResponseWriter, r *http.Request) {
		if s.Stacks == nil {
			http.Error(w, "not available in replay", http.StatusNotFound)
			return
		}
		f, o := s.export(r)
		po := PprofOpts{Metric: f.Metric, Comments: pprofComments(o), Time: time.Now(), Source: s.Source, Budget: 10 * time.Second}
		if f.IsRange() {
			po.Time, po.Duration = time.UnixMilli(f.From), time.Duration(f.To-f.From)*time.Millisecond
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+o.file+`.pb.gz"`)
		if err := WritePprof(w, s.Stacks(f), po); err != nil {
			log.Printf("pprof export: %v", err)
		}
	})
	mux.HandleFunc("/source", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{}
		if s.Source != nil {
			if loc, ok := s.Source(r.URL.Query().Get("f")); ok {
				out["file"], out["line"], out["object"] = loc.File, loc.Line, loc.Object
				out["links"] = s.Repos.Links(loc.Object, loc.File, loc.Line)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/flame.svg", func(w http.ResponseWriter, r *http.Request) {
		if s.Stacks == nil {
			http.Error(w, "not available in replay", http.StatusNotFound)
			return
		}
		f, o := s.export(r)
		w.Header().Set("Content-Type", "image/svg+xml")
		if r.URL.Query().Get("download") != "" {
			w.Header().Set("Content-Disposition", `attachment; filename="`+o.file+`.svg"`)
		}
		FlameSVG(w, s.Stacks(f), o.FlameOpts)
	})
	mux.HandleFunc("/stacks", func(w http.ResponseWriter, r *http.Request) {
		if s.Stacks == nil {
			http.Error(w, "not available in replay", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Stacks(filter(r)))
	})
	mux.HandleFunc("/arenas", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if s.RefreshArenas == nil {
				http.Error(w, "no per-arena source (needs libmhp over glibc malloc)", http.StatusNotFound)
				return
			}
			s.RefreshArenas()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if t, err := strconv.ParseInt(r.URL.Query().Get("t"), 10, 64); err == nil { // the reading at or before t
			json.NewEncoder(w).Encode(s.Hub.ArenasAt(t))
			return
		}
		json.NewEncoder(w).Encode(s.Hub.Arenas())
	})
	mux.HandleFunc("/peak.html", func(w http.ResponseWriter, r *http.Request) {
		if s.Peaks == nil {
			http.Error(w, "peak copies are off (-peak off)", http.StatusNotFound)
			return
		}
		s.Peaks.serve(w, r)
	})
	mux.HandleFunc("/peaks", func(w http.ResponseWriter, r *http.Request) {
		out := []PeakCopy{}
		if s.Peaks != nil {
			out = append(out, s.Peaks.List()...)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/report.html", s.report)
	mux.HandleFunc("/offline.html", func(w http.ResponseWriter, r *http.Request) {
		if s.Dump == nil || s.OfflinePage == nil {
			http.Error(w, "no offline copy here", http.StatusNotFound)
			return
		}
		t0 := time.Now()
		sn, err := s.Snapshot()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		host, _ := os.Hostname()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mhp-offline-full-%s-%s.html"`, host, time.Now().Format("20060102-150405")))
		cw := &countWriter{w: w}
		if err := s.OfflinePage(cw, sn.Encode); err != nil {
			log.Printf("offline copy: %v", err)
			return
		}
		log.Printf("offline copy: %d views, %d ticks, %d stacks, %d source locations, %.1f MB in %v", s.Hub.Len(),
			len(sn.Agg.Ticks), len(sn.Agg.Stacks), len(sn.Sources), float64(cw.n)/1e6, time.Since(t0).Round(time.Millisecond))
	})
	mux.HandleFunc("/range", func(w http.ResponseWriter, r *http.Request) {
		if s.Range == nil {
			http.Error(w, "not available in replay", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.Range(filter(r)))
	})
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		meta := [][2]string{}
		if s.Meta != nil {
			meta = s.Meta()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		var v any = map[string]any{"tracer": s.Toggle != nil, "drilldown": s.Stacks != nil}
		if s.Info != nil {
			v = s.Info()
		}
		if m, ok := v.(map[string]any); ok {
			m["paused"] = s.Hub.TracerPaused.Load()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("/tracer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || s.Toggle == nil {
			http.Error(w, "POST /tracer?on=0|1 with an attached tracer", http.StatusBadRequest)
			return
		}
		on := r.URL.Query().Get("on") != "0"
		if err := s.Toggle(on); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.Hub.TracerPaused.Store(!on)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		ch, cancel := s.Hub.Subscribe()
		defer cancel()
		for {
			select {
			case <-r.Context().Done():
				return
			case v := <-ch:
				b, _ := json.Marshal(v)
				fmt.Fprintf(w, "data: %s\n\n", b)
				fl.Flush()
			}
		}
	})
	return mux
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
