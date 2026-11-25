package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PrzemekMalkowski/mhp/internal/agg"
	"github.com/PrzemekMalkowski/mhp/internal/heapfile"
	"github.com/PrzemekMalkowski/mhp/internal/live"
	"github.com/PrzemekMalkowski/mhp/internal/model"
	"github.com/PrzemekMalkowski/mhp/internal/sym"
	"github.com/PrzemekMalkowski/mhp/internal/web"
)

// allocatorObject: frames inside the allocator itself (its own backtrace and malloc entry), cut from the leaf.
var allocatorObject = regexp.MustCompile(`^lib(jemalloc|tcmalloc[a-z_]*)\.so`)

// allocatorFrame: the same for an allocator linked into the executable.
var allocatorFrame = regexp.MustCompile(`^(je_[a-z_]+|prof_backtrace\w*|imalloc\w*|ialloc\w*|malloc_default|tc_[a-z_]+|` +
	`MallocHook::\w+|HeapProfileTable::\w+|NewHook|MallocHook_\w+|\(anonymous namespace\)::do_\w+)$`)

// importProfile loads a jemalloc / gperftools heap profile into the aggregator, as one point in time: in-use bytes
// per stack (live), and cumulative allocations when the file has them (alloc). Addresses are symbolized with the
// binaries the profile's MAPPED_LIBRARIES name, read under root.
func importProfile(a *agg.Agg, hub *live.Hub, srv *web.Server, info map[string]any, path, root, srcVersion string, maps []web.SourceMap) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	p, err := heapfile.Parse(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	root = strings.TrimSuffix(root, "/")
	sy := sym.NewStatic(strings.NewReader(p.Maps), root)
	objs := sy.Objects()
	exe := ""
	if len(objs) > 0 {
		exe = objs[0]
	}
	if fi, err := os.Stat(root + exe); err == nil && fi.ModTime().After(st.ModTime()) {
		log.Printf("warning: %s changed after the profile was written: if it is another build, the names are wrong", root+exe)
	}

	t := st.ModTime()
	tick := model.Tick{T: t}
	var cut int
	for _, s := range p.Stacks {
		addrs := s.Addrs
		for len(addrs) > 1 {
			if o := sy.Object(addrs[0]); o != "" && allocatorObject.MatchString(filepath.Base(o)) {
				addrs, cut = addrs[1:], cut+1
				continue
			}
			if allocatorFrame.MatchString(sy.Frame(addrs[0])) {
				addrs, cut = addrs[1:], cut+1
				continue
			}
			break
		}
		d := model.AllocDelta{Stack: sy.Frames(addrs), TID: 1, Thread: "heap profile", Alloc: s.InuseB, N: s.InuseN}
		if p.Cumulative && s.AllocB >= s.InuseB {
			d.Alloc, d.Free = s.AllocB, s.AllocB-s.InuseB
		}
		tick.Allocs = append(tick.Allocs, d)
	}
	a.Ingest(tick)
	// two views a second apart, so the chart has a line; both hold the same state
	hub.Publish(a.Snapshot(t.Add(-time.Second)))
	hub.Publish(a.Snapshot(t))

	var missing []string
	for o, src := range sy.Sources() {
		if strings.HasPrefix(src, "error:") {
			missing = append(missing, o)
		}
	}
	if len(missing) > 0 {
		log.Printf("warning: cannot read %d mapped object(s), their frames stay addresses: %s (pass -root if the files are elsewhere)",
			len(missing), strings.Join(missing, ", "))
	}
	how := "every allocation recorded"
	if p.Period > 0 {
		how = fmt.Sprintf("sampled every %s on average, scaled up the way jeprof / pprof do", byteSize(p.Period))
	}
	src := fmt.Sprintf("%s profile %s (%s)", p.Format, path, how)
	info["cmd"], info["since"] = "import", t.Format("2006-01-02 15:04:05")
	info["heap"], info["drilldown"], info["tracer"], info["imported"] = true, true, false, true
	info["heap_src"], info["symbols"] = src, sy.Sources
	srv.Source = sy.Source
	if exe != "" {
		sourceLinksExe(srv, root+exe, srcVersion, maps)
	}
	cum := "not recorded (jemalloc: add prof_accum:true)"
	if p.Cumulative {
		cum = fmt.Sprintf("%s in %d objects", byteSize(p.AllocB), p.AllocN)
	}
	meta := [][2]string{{"Imported profile", fmt.Sprintf("%s, written %s", src, t.Format("2006-01-02 15:04:05"))},
		{"Profile totals", fmt.Sprintf("in use %s in %d objects, %d stacks; allocated in total: %s", byteSize(p.InuseB), p.InuseN, len(p.Stacks), cum)}}
	if exe != "" {
		banner, id := web.BuildInfo(root + exe)
		server := srv.Repos.String()
		if banner != "" {
			server += ", " + banner
		}
		meta = append(meta, [2]string{"Server", server})
		if id != "" {
			exe += ", build ID " + id
		}
		meta = append(meta, [2]string{"Server binary", exe + " (as read now: the profile does not record which build it came from)"})
	}
	if root != "" {
		meta = append(meta, [2]string{"Objects read under", root})
	}
	if ex, err := os.Executable(); err == nil {
		meta = append(meta, [2]string{"mhp", fmt.Sprintf("mhp %s import (%s)", Version, ex)})
	}
	srv.Meta = func() [][2]string { return meta }
	log.Printf("imported %s: %s, %d stacks, in use %s (%d allocator frames cut from the leaves)", path, p.Format, len(p.Stacks), byteSize(p.InuseB), cut)
	return nil
}

func byteSize(n int64) string {
	switch f := float64(n); {
	case f >= 1<<30:
		return fmt.Sprintf("%.2f GiB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MiB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.1f KiB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
