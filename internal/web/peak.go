package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Peaks keeps offline copies taken at the moments that matter for memory cases, so they exist even when nobody
// pressed "save offline copy" in time:
//   - "peak": the process's RSS high-water mark. Once RSS rose by Margin over the last copy's, a copy is taken at
//     once, from the view that shows the new high: a transient (a big temporary table, a sort) can be freed a second
//     later, and a copy taken after that shows the high but not what held it. While RSS keeps climbing, copies are
//     at least MinGap apart, unless RSS jumped by BigRise or more; a high reached within the gap otherwise is copied
//     when it ends. Each replaces the previous one.
//   - "cgroup": RSS crossed CgroupPct of the cgroup memory limit (an OOM kill may follow). Taken at once, again
//     after RSS went back under the threshold minus 5 points and crossed it again.
//
// Each copy is the full offline copy (history, stacks, timeline, the latest malloc_info; a fresh one is asked for at
// the same time, for the next copy and the live UI, since waiting for it could miss the moment) kept
// gzipped in memory and served at /peak.html?kind=..., and written to Dir as HTML when Dir is set.
type Peaks struct {
	Srv       *Server
	Dir       string        // also write each copy here ("" = memory only)
	Label     string        // file name part, e.g. "host-pid1234"
	CgroupPct int           // 0 = off
	MinGap    time.Duration // shortest time between two peak copies (15 s)
	Margin    float64       // relative RSS rise over the last copy that arms a new one
	MinAge    time.Duration

	mu     sync.Mutex
	copies map[string]*PeakCopy
	finish chan struct{} // bounds the copies being finished (source lookups, encoding) at once
}

// PeakCopy is one kept copy.
type PeakCopy struct {
	Kind   string `json:"kind"`
	T      int64  `json:"t"`   // view time the copy was taken at, unix ms
	RSS    int64  `json:"rss"` // RSS then
	Limit  int64  `json:"limit,omitempty"`
	Bytes  int    `json:"bytes"` // snapshot size (gzipped)
	File   string `json:"file,omitempty"`
	Reason string `json:"reason"`
	snap   []byte
}

func (p *Peaks) defaults() {
	if p.MinGap == 0 {
		p.MinGap = 15 * time.Second
	}
	if p.Margin == 0 {
		p.Margin = 0.03
	}
	if p.MinAge == 0 {
		p.MinAge = 20 * time.Second
	}
}

// Run follows the published views until ctx ends.
func (p *Peaks) Run(ctx context.Context) {
	p.defaults()
	ch, cancel := p.Srv.Hub.Subscribe()
	defer cancel()
	var high, captured, start int64
	var lastCap time.Time
	cgArmed := true
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-ch:
			rss, lim := v.Proc["rss"], v.Proc["cgroup_limit"]
			if rss == 0 {
				continue
			}
			if start == 0 {
				start = v.T
			}
			atHigh := rss >= high
			if rss > high {
				high = rss
			}
			if p.CgroupPct > 0 && lim > 0 {
				thr := lim / 100 * int64(p.CgroupPct)
				if cgArmed && rss >= thr {
					cgArmed = false
					p.take(ctx, "cgroup", v.T, rss, lim, fmt.Sprintf("RSS %s reached %d%% of the cgroup limit %s", gib(rss), p.CgroupPct, gib(lim)))
				} else if !cgArmed && rss < lim/100*int64(p.CgroupPct-5) {
					cgArmed = true
				}
			}
			if v.T-start < p.MinAge.Milliseconds() || float64(high) < float64(captured)*(1+p.Margin) || high-captured < 16<<20 {
				continue
			}
			// within the gap, only a big jump (a temporary table, a sort buffer) is copied at once
			since := time.Since(lastCap)
			if since < p.MinGap && !(atHigh && high-captured >= BigRise && since >= 2*time.Second) {
				continue
			}
			why := "new RSS high-water mark " + gib(high)
			if !atHigh { // the high came within the gap after the previous copy
				why += fmt.Sprintf(" (reached within %v of the previous copy; RSS %s now)", p.MinGap, gib(rss))
			}
			if p.take(ctx, "peak", v.T, rss, lim, why) {
				captured, lastCap = high, time.Now()
			}
		}
	}
}

// BigRise is the RSS rise over the last peak copy that is copied even within MinGap of it (2 s at least).
const BigRise = 256 << 20

func gib(n int64) string { return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30)) }

// take captures the state now (aggregator, history: fast) and finishes the copy in the background (source
// locations, encoding, writing: seconds), so a copy in progress never delays the next capture. False on an error.
func (p *Peaks) take(ctx context.Context, kind string, t, rss, lim int64, reason string) bool {
	t0 := time.Now()
	sn, info0, err := p.Srv.snapshotState() // at once: the moment is what the copy is for
	if p.Srv.RefreshArenas != nil {
		p.Srv.RefreshArenas() // per-arena detail (and arena residency) for the live UI and the next copy
	}
	if err != nil {
		log.Printf("%s copy: %v", kind, err)
		return false
	}
	p.mu.Lock()
	if p.finish == nil {
		p.finish = make(chan struct{}, 2)
	}
	p.mu.Unlock()
	go func() {
		p.finish <- struct{}{}
		defer func() { <-p.finish }()
		if err := p.Srv.finishSnapshot(sn, info0); err != nil {
			log.Printf("%s copy: %v", kind, err)
			return
		}
		// say in the copy what it is: the Context tab and reports show Meta, the chart marks info.capture
		when := time.UnixMilli(t).Format("2006-01-02 15:04:05")
		sn.Meta = append([][2]string{{"Copy taken", fmt.Sprintf("%s by mhp at %s: %s", kind, when, reason)}}, sn.Meta...)
		info := map[string]any{}
		if json.Unmarshal(sn.Info, &info) == nil {
			info["capture"] = map[string]any{"kind": kind, "t": t, "rss": rss, "reason": reason}
			if b, err := json.Marshal(info); err == nil {
				sn.Info = b
			}
		}
		var buf bytes.Buffer
		if err := sn.Encode(&buf); err != nil {
			log.Printf("%s copy: %v", kind, err)
			return
		}
		c := &PeakCopy{Kind: kind, T: t, RSS: rss, Limit: lim, Bytes: buf.Len(), Reason: reason, snap: buf.Bytes()}
		p.mu.Lock()
		if p.copies == nil {
			p.copies = map[string]*PeakCopy{}
		}
		old := p.copies[kind]
		p.mu.Unlock()
		if kind == "peak" && old != nil && old.T > t { // a later copy finished first: it stays
			log.Printf("%s copy of %s dropped: a later one is kept", kind, time.UnixMilli(t).Format("15:04:05"))
			return
		}
		if p.Dir != "" {
			name := fmt.Sprintf("mhp-%s-%s-%s.html", kind, p.Label, time.UnixMilli(t).Format("20060102-150405"))
			path := filepath.Join(p.Dir, name)
			if err := p.write(path, c.snap); err != nil {
				log.Printf("%s copy: %v", kind, err)
			} else {
				c.File = path
				if old != nil && old.File != "" && kind == "peak" { // keep one high-water copy; every cgroup one
					os.Remove(old.File)
				}
			}
		}
		p.mu.Lock()
		p.copies[kind] = c
		p.mu.Unlock()
		where := "kept in memory (/peak.html?kind=" + kind + ")"
		if c.File != "" {
			where = "written to " + c.File
		}
		log.Printf("%s copy: %s; %.2f MB snapshot %s in %v", kind, reason, float64(c.Bytes)/1e6, where, time.Since(t0).Round(time.Millisecond))
	}()
	return true
}

func (p *Peaks) write(path string, snap []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	err = p.Srv.OfflinePage(f, func(w io.Writer) error { _, err := w.Write(snap); return err })
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// List returns the kept copies, newest first.
func (p *Peaks) List() []PeakCopy {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []PeakCopy
	for _, c := range p.copies {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T > out[j].T })
	return out
}

// serve answers /peak.html?kind=peak|cgroup (the page) and /peaks (the list).
func (p *Peaks) serve(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "peak"
	}
	p.mu.Lock()
	c := p.copies[kind]
	p.mu.Unlock()
	if c == nil {
		http.Error(w, "no "+kind+" copy taken yet", http.StatusNotFound)
		return
	}
	host, _ := os.Hostname()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mhp-%s-%s-%s.html"`, kind, host, time.UnixMilli(c.T).Format("20060102-150405")))
	if err := p.Srv.OfflinePage(w, func(w io.Writer) error { _, err := w.Write(c.snap); return err }); err != nil {
		log.Printf("%s copy: %v", kind, err)
	}
}
