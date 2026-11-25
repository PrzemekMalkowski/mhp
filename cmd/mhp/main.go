// mhp: Multi-dimensional Heap Profiler, a live memory profiler for mysqld. See DESIGN.md.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mhp/internal/agg"
	"mhp/internal/classify"
	"mhp/internal/ebpf"
	"mhp/internal/inject"
	"mhp/internal/live"
	"mhp/internal/model"
	"mhp/internal/offline"
	"mhp/internal/perf"
	"mhp/internal/pfs"
	"mhp/internal/procfs"
	"mhp/internal/shim"
	"mhp/internal/sim"
	"mhp/internal/sym"
	"mhp/internal/web"

	"golang.org/x/sys/unix"
)

// Version is mhp's version, shown by "mhp version", in the UI's Context tab and in reports.
const Version = "0.1.7"

func usage() {
	fmt.Fprint(os.Stderr, `mhp `+Version+`: Multi-dimensional Heap Profiler

usage: mhp <command> [flags]
  watch -pid N          live view of a running process: /proc always; allocation stacks too
                        if it was started with LD_PRELOAD=libmhp.so (ring /dev/shm/mhp.<pid>),
                        else from the eBPF tracer (root)
  watch -pid N -inject  load libmhp.so into the running process (root, ptrace) and sample its
                        allocations like a preload would; undone when mhp stops. Works on glibc
                        malloc and on a preloaded jemalloc / tcmalloc
  run [flags] -- CMD..  launch CMD under libmhp.so (full allocation tracing from the start);
                        -malloc-lib jemalloc|tcmalloc|PATH preloads that allocator under it
  demo                  synthetic MySQL-like workload, to try the UI
  replay FILE           replay a recording made with -record
  import [-o OUT.html] [-root DIR] FILE
                        load a heap profile written by jemalloc (MALLOC_CONF=prof:true, jeprof.*.heap) or
                        tcmalloc (HEAPPROFILE=..., *.heap) and explore it in the UI, or write an offline copy
  version               print the version
flags: -addr 0.0.0.0:8080  -record FILE  -rules FILE  -growth 60  -interval 1s  -retention 10m  -timeline 1048576
       -shim auto|off (watch)  -lib PATH (run, watch -inject)  -sample-bytes N
       -ebpf auto|on|off      eBPF uprobe heap stacks when there is no libmhp ring (watch; root, uprobe_multi + BTF)
       -arenas 30s (glibc per-arena malloc_info; 0 = off)  -peak on|off  -peak-dir DIR  -peak-cgroup 90
       -faults auto|on|off  -fault-src auto|bpf|perf  -fault-period N (perf)
                            page-fault stacks (root; auto = when root; bpf counts in-kernel, perf samples)
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Println("mhp", Version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:8080", "listen address")
	record := fs.String("record", "", "write views to this JSONL file")
	rules := fs.String("rules", "", "sub-system rules JSON (default: built-in MySQL rules)")
	growth := fs.Int("growth", 60, "growth window in seconds")
	retention := fs.Duration("retention", agg.DefaultRetention, "history kept for the chart and time-range queries (in mhp and in the browser)")
	timeline := fs.Int("timeline", agg.DefaultTimeline, "max per-tick records kept for time-range queries (~56 bytes each; oldest dropped first)")
	pid := fs.Int("pid", 0, "target pid (watch)")
	interval := fs.Duration("interval", time.Second, "UI / /proc sampling interval")
	smaps := fs.Duration("smaps", 5*time.Second, "shortest interval between /proc/PID/smaps reads (regions view, THP); stretched to 100x the read time on big servers; 0 = off")
	shimMode := fs.String("shim", "auto", "attach to libmhp ring if present: auto|off (watch)")
	ebpfMode := fs.String("ebpf", "auto", "eBPF uprobe heap tracer: auto (watch, no libmhp ring, root)|on|off")
	lib := fs.String("lib", "", "path to libmhp.so (run, watch -inject; default: next to the mhp binary)")
	mallocLibFlag := fs.String("malloc-lib", "", "run: allocator to preload under libmhp: jemalloc, tcmalloc or a library path (default: glibc malloc)")
	injectLib := fs.Bool("inject", false, "watch: load libmhp.so into the running target (root, ptrace; glibc, or preloaded jemalloc / tcmalloc) instead of eBPF")
	sampleBytes := fs.Int64("sample-bytes", 256<<10, "mean bytes between sampled allocations")
	faults := fs.String("faults", "auto", "perf page-fault sampling: auto|on|off")
	faultPeriod := fs.Uint64("fault-period", 1, "sample every Nth page fault (perf)")
	faultSrc := fs.String("fault-src", "auto", "page-fault stacks from: auto (bpf, else perf)|bpf|perf")
	pfsMode := fs.String("pfs", "auto", "Performance Schema cross-check via the mysql CLI: auto|off")
	mysqlArgs := fs.String("mysql-args", "", "extra mysql client args for -pfs (e.g. \"-uroot -S /run/mysqld/mysqld.sock\")")
	srcVersion := fs.String("source-version", "", "server version for source links when it cannot be read from the binary: X.Y.Z, percona-X.Y.Z-R, mariadb-X.Y.Z")
	pfsEvery := fs.Duration("pfs-interval", 5*time.Second, "Performance Schema poll interval")
	peakMode := fs.String("peak", "on", "keep offline copies taken at the RSS high-water mark and near the cgroup limit: on|off (served at /peak.html)")
	peakDir := fs.String("peak-dir", "", "also write those copies here as HTML files (one high-water copy, replaced as RSS rises; one per cgroup-limit crossing)")
	peakCgroup := fs.Int("peak-cgroup", 90, "take a copy when RSS reaches this percentage of the cgroup memory limit (0 = off)")
	outFile := fs.String("o", "", "import: write the offline copy (HTML) to this file and exit, instead of serving the UI")
	importRoot := fs.String("root", "", "import: read the profile's binaries under this directory (a copy of the server's filesystem)")
	arenasFlag := fs.Duration("arenas", 30*time.Second, "glibc per-arena detail (malloc_info inside the target, libmhp): shortest interval; stretched to 200x what it costs; 0 = off")
	debugDir := fs.String("debug-dir", "", "extra debug-symbol dirs (':'-separated, each holding .build-id/), searched before /usr/lib/debug")
	var srcMaps []web.SourceMap
	fs.Func("source-map", "PREFIX=URL: source links for files under PREFIX go to URL (repeatable), e.g. a submodule:\n"+
		"storage/rocksdb/rocksdb/=https://github.com/percona/rocksdb/blob/<commit>/", func(v string) error {
		m, err := web.ParseSourceMap(v)
		srcMaps = append(srcMaps, m)
		return err
	})
	fs.Parse(os.Args[2:])
	arenasEvery = *arenasFlag
	if *debugDir != "" {
		sym.ExtraDebugDirs = strings.Split(*debugDir, ":")
	}

	// bind first: failing later would leave a "run" target running unsupervised
	var ln net.Listener
	if cmd != "import" || *outFile == "" {
		var err error
		if ln, err = net.Listen("tcp", *addr); err != nil {
			log.Fatal(err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hub := live.NewHub(max(2, int(*retention / *interval)))
	info := map[string]any{"cmd": cmd, "since": time.Now().Format("2006-01-02 15:04:05"), "retention_s": int(retention.Seconds()),
		"history_views": max(2, int(*retention / *interval))}
	srv := &web.Server{Hub: hub, Info: func() any {
		out := map[string]any{}
		for k, v := range info {
			switch f := v.(type) { // evaluated per request (e.g. symbol sources)
			case func() map[string]string:
				v = f()
			case func() map[string]int:
				v = f()
			case func() string:
				v = f()
			}
			out[k] = v
		}
		return out
	}}
	if *record != "" {
		go recorder(ctx, hub, *record)
	}

	newAgg := func() *agg.Agg {
		cls, err := classify.New(*rules)
		if err != nil {
			log.Fatal(err)
		}
		a := agg.New(cls, *growth)
		a.Timeline, a.Retention = *timeline, *retention
		info["agg"] = func() map[string]int { return a.Stats() }
		info["mem"] = func() map[string]int {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			return map[string]int{"heap_alloc_mb": int(m.HeapAlloc >> 20), "heap_sys_mb": int(m.HeapSys >> 20),
				"gc_cycles": int(m.NumGC), "views": hub.Len()}
		}
		srv.Folded, srv.Stacks, srv.Range, srv.RangeThreads = a.Folded, a.Stacks, a.Range, a.RangeThreads
		srv.Dump = a.Export
		srv.OfflinePage = func(w io.Writer, snapshot func(io.Writer) error) error {
			return offline.Write(w, web.Index(), snapshot)
		}
		return a
	}

	switch cmd {
	case "demo":
		a := newAgg()
		pipeline(ctx, stop, a, hub, *interval, &sim.Source{Interval: 500 * time.Millisecond})
	case "watch":
		if *pid == 0 {
			usage()
		}
		a := newAgg()
		sy := sym.New(*pid)
		pf := procfs.New(*pid, *interval, *smaps)
		info["smaps"] = smapsInfo(pf)
		srcs := []model.Source{pf}
		if *injectLib {
			s, undo, err := injectShim(*pid, *lib, *sampleBytes, sy, a.Subsystem, srv, info)
			if err != nil {
				log.Fatal(err)
			}
			atExit = append(atExit, undo)
			srcs = append(srcs, s)
		} else if *shimMode != "off" {
			switch st := shim.RingState(*pid); st {
			case shim.Preloaded, shim.Injected:
				s, err := attachShim(*pid, false, st == shim.Injected, sy, a.Subsystem, srv, info)
				if err != nil {
					log.Fatal(err)
				}
				if s.FromStart {
					info["from_start"] = true
				}
				if st == shim.Injected {
					log.Printf("libmhp was injected into pid %d by an mhp that did not undo it: its calls stay redirected (run with -inject to undo them on exit)", *pid)
				}
				srcs = append(srcs, s)
			case shim.Undone:
				log.Printf("libmhp was injected into pid %d earlier and undone: not using its ring (-inject redirects the calls again)", *pid)
			case shim.StaleRing:
				log.Printf("ignoring %s: pid %d does not map it (left by an earlier process)", shim.RingPath(*pid), *pid)
			}
		}
		if len(srcs) == 1 {
			if e := attachEBPF(*ebpfMode, *pid, uint64(*sampleBytes), sy, a.Subsystem, srv, info); e != nil {
				srcs = append(srcs, e)
			} else {
				log.Printf("no heap stacks: no %s and no eBPF tracer (start the target with LD_PRELOAD=libmhp.so, or run mhp as root)", shim.RingPath(*pid))
			}
		}
		if f := attachFaults(*faults, *faultSrc, *pid, *faultPeriod, sy, info); f != nil {
			srcs = append(srcs, f)
		}
		info["pid"] = *pid
		arenasWithSmaps(srv, pf)
		info["symbols"] = sy.Sources
		sourceLinks(srv, sy, *pid, *srcVersion, srcMaps)
		srv.Meta = reportMeta(info, srv, *pid, *sampleBytes, *retention)
		srcs = append(srcs, pfsSource(*pfsMode, *pid, *mysqlArgs, *pfsEvery)...)
		startPeaks(ctx, srv, *peakMode, *peakDir, *peakCgroup, *pid)
		pipeline(ctx, stop, a, hub, *interval, srcs...)
	case "run":
		if fs.NArg() < 1 {
			usage()
		}
		child, err := launch(*lib, *mallocLibFlag, *sampleBytes, fs.Args())
		if err != nil {
			log.Fatal(err)
		}
		cg := ownCgroup(child.Process.Pid)
		exited := make(chan struct{})
		childExited = exited
		go func() {
			child.Wait()
			if cg != "" {
				os.Remove(cg)
			}
			os.Remove(shim.RingPath(child.Process.Pid)) // libmhp's ring lives in /dev/shm (RAM) until removed
			close(exited)
			stop()
		}()
		go func() {
			<-ctx.Done()
			select {
			case <-exited:
			default:
				log.Printf("stopping pid %d (SIGTERM), waiting for it to exit", child.Process.Pid)
				child.Process.Signal(syscall.SIGTERM)
			}
		}()
		a := newAgg()
		cpid := child.Process.Pid
		sy := sym.New(cpid)
		s, err := attachShim(cpid, true, false, sy, a.Subsystem, srv, info)
		if err != nil {
			child.Process.Kill()
			log.Fatal(err)
		}
		pf := procfs.New(cpid, *interval, *smaps)
		info["smaps"] = smapsInfo(pf)
		srcs := []model.Source{pf, s}
		if f := attachFaults(*faults, *faultSrc, cpid, *faultPeriod, sy, info); f != nil {
			srcs = append(srcs, f)
		}
		info["pid"] = cpid
		arenasWithSmaps(srv, pf)
		info["symbols"] = sy.Sources
		sourceLinks(srv, sy, cpid, *srcVersion, srcMaps)
		srv.Meta = reportMeta(info, srv, cpid, *sampleBytes, *retention)
		srcs = append(srcs, pfsSource(*pfsMode, cpid, *mysqlArgs, *pfsEvery)...)
		startPeaks(ctx, srv, *peakMode, *peakDir, *peakCgroup, cpid)
		pipeline(ctx, stop, a, hub, *interval, srcs...)
	case "import":
		if fs.NArg() < 1 {
			usage()
		}
		a := newAgg()
		if err := importProfile(a, hub, srv, info, fs.Arg(0), *importRoot, *srcVersion, srcMaps); err != nil {
			log.Fatal(err)
		}
		if *outFile != "" {
			if err := writeOffline(srv, *outFile); err != nil {
				log.Fatal(err)
			}
			return
		}
	case "replay":
		if fs.NArg() < 1 {
			usage()
		}
		go replay(ctx, hub, fs.Arg(0), *interval)
	default:
		usage()
	}

	hs := &http.Server{Addr: *addr, Handler: srv.Handler()}
	go func() { <-ctx.Done(); hs.Close() }()
	log.Printf("mhp %s: UI on http://%s", cmd, *addr)
	if err := hs.Serve(ln); err != nil && ctx.Err() == nil {
		log.Print(err)
		stop()
	}
	for _, f := range atExit {
		f()
	}
	if childExited != nil { // run: never leave the server running unsupervised (a restart would find it holding its files)
		select {
		case <-childExited:
		case <-time.After(10 * time.Minute):
			log.Printf("target still running after 10 minutes; leaving it")
		}
	}
}

// startPeaks keeps offline copies of the RSS high-water mark and of cgroup-limit crossings (-peak).
func startPeaks(ctx context.Context, srv *web.Server, mode, dir string, cgroupPct, pid int) {
	if mode == "off" {
		return
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("-peak-dir: %v", err)
		}
	}
	host, _ := os.Hostname()
	srv.Peaks = &web.Peaks{Srv: srv, Dir: dir, Label: fmt.Sprintf("%s-pid%d", host, pid), CgroupPct: cgroupPct}
	go srv.Peaks.Run(ctx)
}

// writeOffline writes the offline copy of what the server holds (mhp import -o).
func writeOffline(srv *web.Server, path string) error {
	sn, err := srv.Snapshot()
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := srv.OfflinePage(f, sn.Encode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fi, _ := os.Stat(path)
	log.Printf("offline copy written to %s (%.1f MB)", path, float64(fi.Size())/1e6)
	return nil
}

// childExited is closed when the target started by "run" exits (nil for other commands).
var childExited chan struct{}

// atExit runs after the UI server stopped (watch -inject: undo the injection).
var atExit []func()

// arenasWithSmaps makes an asked-for malloc_info reading (refresh button, peak copy) come with an smaps read, so
// the arenas' resident size is as of the same moment: after a malloc_trim, free chunks stay in malloc_info's free
// but leave RSS. The periodic readings use the smaps read in effect.
func arenasWithSmaps(srv *web.Server, pf *procfs.Source) {
	if r := srv.RefreshArenas; r != nil && pf.SmapsInterval > 0 {
		srv.RefreshArenas = func() { pf.ReadSmapsSoon(); r() }
	}
}

// arenasEvery is -arenas (glibc malloc_info interval) for attachShim.
var arenasEvery time.Duration

func attachShim(pid int, fromStart, injected bool, sy *sym.Symbolizer, area func([]string) string, srv *web.Server, info map[string]any) (*shim.Source, error) {
	s := &shim.Source{PID: pid, FromStart: fromStart, IfComplete: !injected, Sym: sy, Area: area, StatsEvery: 5 * time.Second,
		ArenasEvery: arenasEvery}
	if err := s.Open(15 * time.Second); err != nil {
		return nil, err
	}
	if s.HasArenas() {
		srv.RefreshArenas = s.RequestArenas
		info["arenas"] = true
	}
	fromStart = s.FromStart
	srv.Toggle = func(on bool) error { s.SetEnabled(on); return nil }
	info["tracer"], info["drilldown"], info["heap"] = true, true, true
	info["heap_src"] = "libmhp preload (" + map[bool]string{true: "from process start", false: "since attach"}[fromStart] + ")"
	if injected {
		info["heap_src"] = "libmhp injected (since attach)"
		return s, nil
	}
	if fromStart {
		log.Printf("attached to libmhp ring of pid %d: complete since process start", pid)
	} else {
		log.Printf("attached to libmhp ring of pid %d: tracing since attach (the ring was read before, dropped events, or was started with MHP_START=0)", pid)
	}
	return s, nil
}

// injectShim loads libmhp into the running pid (watch -inject) and attaches to its ring; undo restores the
// target's calls.
func injectShim(pid int, lib string, sampleBytes int64, sy *sym.Symbolizer, area func([]string) string, srv *web.Server, info map[string]any) (*shim.Source, func(), error) {
	switch shim.RingState(pid) {
	case shim.Preloaded:
		log.Printf("libmhp is preloaded in pid %d already: attaching to it (-inject not needed)", pid)
		s, err := attachShim(pid, false, false, sy, area, srv, info)
		if err == nil && s.FromStart {
			info["from_start"] = true
		}
		return s, func() {}, err
	}
	// rings of processes that are gone (an injected ring stays until its process exits); pid's own when stale
	rings, _ := filepath.Glob(filepath.Join(filepath.Dir(shim.RingPath(pid)), "mhp.*"))
	for _, r := range rings {
		if p, err := strconv.Atoi(strings.TrimPrefix(filepath.Ext(r), ".")); err == nil {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", p)); os.IsNotExist(err) || p == pid && shim.RingState(pid) == shim.StaleRing {
				os.Remove(r)
			}
		}
	}
	if lib == "" {
		exe, _ := os.Executable()
		lib = filepath.Join(filepath.Dir(exe), "libmhp.so")
	}
	lib, _ = filepath.Abs(lib)
	mine, err := os.Stat(lib)
	if err != nil {
		return nil, nil, fmt.Errorf("libmhp.so not found (%v); build it with: make -C shim, or pass -lib", err)
	}
	if theirs, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, lib)); err != nil || !os.SameFile(mine, theirs) {
		return nil, nil, fmt.Errorf("pid %d does not see %s at that path (another mount namespace: container?): copy it there and pass -lib", pid, lib)
	}
	t0 := time.Now()
	res, err := inject.Attach(pid, lib, uint64(sampleBytes), 0)
	if err != nil {
		if prof, _ := os.ReadFile(fmt.Sprintf("/proc/%d/attr/current", pid)); bytes.Contains(prof, []byte("(enforce)")) {
			err = fmt.Errorf("%w\n(the target is confined by AppArmor profile %s: it must allow \"%s mr,\" and \"/dev/shm/mhp.* rw,\")", err, bytes.TrimSpace(prof), lib)
		}
		return nil, nil, err
	}
	how := "dlopen'ed " + lib
	if !res.Loaded {
		how = "libmhp was loaded already"
	}
	log.Printf("injected into pid %d in %v through thread %d (waiting in %s): %s, %d call sites redirected",
		pid, time.Since(t0).Round(time.Microsecond), res.TID, res.Syscall, how, res.Slots)
	undo := func() {
		if r, err := inject.Detach(pid); err != nil {
			log.Printf("could not undo the injection into pid %d: %v (sampling is off; its calls still go through libmhp)", pid, err)
		} else {
			log.Printf("injection undone: %d call sites of pid %d point at the allocator again (libmhp stays mapped, idle; %s stays until it exits)", r.Slots, pid, shim.RingPath(pid))
		}
	}
	s, err := attachShim(pid, false, true, sy, area, srv, info)
	if err != nil {
		undo()
		return nil, nil, err
	}
	info["injected"] = true
	return s, undo, nil
}

// sourceLinks enables frame -> source file:line lookups, with GitHub/Doxygen links when the target is a MySQL
// or Percona Server binary that reports its version.
func sourceLinks(srv *web.Server, sy *sym.Symbolizer, pid int, override string, maps []web.SourceMap) {
	srv.Source = sy.Source
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return
	}
	// read through the target's root: a containerised server's binary is not at the same path on the host
	sourceLinksExe(srv, fmt.Sprintf("/proc/%d/root%s", pid, strings.TrimSuffix(exe, " (deleted)")), override, maps)
}

// sourceLinksExe sets the GitHub / docs links for a server binary (mysqld, mariadbd) read at path.
func sourceLinksExe(srv *web.Server, path, override string, maps []web.SourceMap) {
	if override == "" && !strings.Contains(filepath.Base(path), "mysqld") && !strings.Contains(filepath.Base(path), "mariadbd") {
		return
	}
	r, err := web.DetectRepos(path, override)
	if err != nil {
		log.Printf("source links off: %v (set -source-version)", err)
		return
	}
	r.Maps = maps
	srv.Repos = r
	log.Printf("source links for %s", r)
	for _, m := range maps {
		log.Printf("source links for %s* -> %s", m.Prefix, m.URL)
	}
}

// attachEBPF starts the uprobe heap tracer; mode auto enables it only when running as root.
func attachEBPF(mode string, pid int, sampleBytes uint64, sy *sym.Symbolizer, area func([]string) string, srv *web.Server, info map[string]any) model.Source {
	if mode == "off" || (mode == "auto" && os.Geteuid() != 0) {
		return nil
	}
	e := &ebpf.Source{PID: pid, SampleBytes: sampleBytes, Sym: sy, Area: area}
	if err := e.Open(); err != nil {
		if mode == "on" {
			log.Fatal(err)
		}
		log.Printf("eBPF heap tracer unavailable: %v", err)
		return nil
	}
	srv.Toggle = func(on bool) error { e.SetEnabled(on); return nil }
	info["tracer"], info["drilldown"], info["heap"] = true, true, true
	where := e.Libc
	if e.Alloc != "" {
		where = e.Alloc + " (malloc, operator new/delete), " + e.MmapIn + " (mmap)"
	}
	kind := "session uprobes"
	if e.Legacy {
		kind = "entry + return uprobes (kernel without session uprobes: every call runs both)"
	}
	info["heap_src"] = "eBPF uprobes on " + where + " (since attach; " + kind + ")"
	log.Printf("eBPF heap tracer attached to %s of pid %d (sampling every %d bytes, %s)", where, pid, sampleBytes, kind)
	return e
}

// pfsSource polls Performance Schema when the target looks like mysqld and a mysql client exists.
func pfsSource(mode string, pid int, args string, every time.Duration) []model.Source {
	if mode == "off" {
		return nil
	}
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if !strings.HasPrefix(strings.TrimSpace(string(comm)), "mysqld") && !strings.HasPrefix(strings.TrimSpace(string(comm)), "mariadbd") {
		return nil
	}
	if _, err := exec.LookPath("mysql"); err != nil {
		log.Print("no mysql client in PATH: Performance Schema cross-check off")
		return nil
	}
	return []model.Source{&pfs.Source{Args: strings.Fields(args), Interval: every, PID: pid, Ask: askCredentials()}}
}

// askCredentials asks on mhp's terminal for the user and password the server cross-check connects with, when
// the server refuses the default ones; nil when stdin is not a terminal. The password is not echoed and not kept
// anywhere but in memory (the mysql client reads it from a pipe).
func askCredentials() pfs.Ask {
	fd := int(os.Stdin.Fd())
	if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
		return nil
	}
	var mu sync.Mutex
	in := bufio.NewReader(os.Stdin) // one reader: a typed-ahead password stays buffered for the second read
	return func(ctx context.Context, why string) (string, string, bool) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(os.Stderr, "\nmhp: the server refused the connection for its memory cross-check:\n  %s\n"+
			"Enter a user and password to read Performance Schema / Memory_used with (empty user: skip).\n", why)
		type line struct {
			s  string
			ok bool
		}
		read := func() line {
			ch := make(chan line, 1)
			go func() {
				s, err := in.ReadString('\n')
				ch <- line{strings.TrimRight(s, "\r\n"), err == nil}
			}()
			select {
			case l := <-ch:
				return l
			case <-ctx.Done():
				return line{}
			}
		}
		fmt.Fprint(os.Stderr, "MySQL user: ")
		u := read()
		if !u.ok || u.s == "" {
			fmt.Fprintln(os.Stderr, "skipped: no server cross-check")
			return "", "", false
		}
		if old, err := unix.IoctlGetTermios(fd, unix.TCGETS); err == nil { // echo off before the prompt shows
			quiet := *old
			quiet.Lflag &^= unix.ECHO
			unix.IoctlSetTermios(fd, unix.TCSETS, &quiet)
			defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
		}
		fmt.Fprint(os.Stderr, "password: ")
		p := read()
		fmt.Fprintln(os.Stderr)
		if !p.ok {
			return "", "", false
		}
		return u.s, p.s, true
	}
}

// attachFaults starts page-fault stack sampling, in-kernel BPF counting if possible, else perf records;
// mode auto enables it only when running as root.
func attachFaults(mode, src string, pid int, period uint64, sy *sym.Symbolizer, info map[string]any) model.Source {
	if mode == "off" || (mode == "auto" && os.Geteuid() != 0) {
		return nil
	}
	fail := func(err error) model.Source {
		if mode == "on" {
			log.Fatal(err)
		}
		log.Printf("page-fault sampling unavailable: %v", err)
		return nil
	}
	if src != "perf" {
		b := &ebpf.FaultSource{PID: pid, Sym: sy}
		err := b.Open()
		if err == nil {
			info["faults"], info["drilldown"], info["fault_scope"] = true, true, "bpf, in-kernel counts"
			log.Printf("BPF page-fault counting on (%d frameless libc ranges for the leaf fix)", b.Leaves)
			return b
		}
		if src == "bpf" {
			return fail(err)
		}
		log.Printf("BPF page-fault counting unavailable (%v), using perf", err)
	}
	f := &perf.FaultSource{PID: pid, Period: period, Sym: sy}
	if err := f.Open(); err != nil {
		return fail(err)
	}
	info["faults"], info["drilldown"], info["fault_scope"] = true, true, f.Scope
	log.Printf("perf page-fault sampling on (every %d fault(s), %s)", period, f.Scope)
	return f
}

// launch starts argv with libmhp preloaded, ahead of mallocLib (jemalloc, tcmalloc or a path; "" = glibc malloc)
// and of whatever LD_PRELOAD mhp itself was started with.
func launch(lib, mallocLib string, sampleBytes int64, argv []string) (*exec.Cmd, error) {
	if lib == "" {
		exe, _ := os.Executable()
		lib = filepath.Join(filepath.Dir(exe), "libmhp.so")
	}
	lib, _ = filepath.Abs(lib)
	if _, err := os.Stat(lib); err != nil {
		return nil, fmt.Errorf("libmhp.so not found (%v); build it with: make -C shim", err)
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, nil
	pre, with := lib, lib
	if mallocLib != "" {
		m, err := shim.FindMallocLib(mallocLib)
		if err != nil {
			return nil, err
		}
		pre += ":" + m
		with += " over " + m
	}
	if old := os.Getenv("LD_PRELOAD"); old != "" {
		pre += ":" + old
	}
	c.Env = append(os.Environ(), "LD_PRELOAD="+pre, fmt.Sprintf("MHP_SAMPLE_BYTES=%d", sampleBytes))
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // Ctrl-C goes to mhp, which stops the child cleanly
	if err := c.Start(); err != nil {
		return nil, err
	}
	log.Printf("started %s (pid %d) with %s", strings.Join(argv, " "), c.Process.Pid, with)
	return c, nil
}

// ownCgroup moves pid into a fresh child cgroup (v2) of mhp's own, so perf can filter faults in-kernel.
// Best effort: it fails harmlessly when cgroupfs is read-only or controllers forbid it.
func ownCgroup(pid int) string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	cur := ""
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "0::"); ok {
			cur = rest
		}
	}
	base := filepath.Join("/sys/fs/cgroup", cur)
	if _, err := os.Stat(base); err != nil {
		base = "/sys/fs/cgroup" // container: the mount is already our subtree
	}
	dir := filepath.Join(base, fmt.Sprintf("mhp-%d", pid))
	if err := os.Mkdir(dir, 0755); err != nil {
		return ""
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0); err != nil {
		os.Remove(dir)
		return ""
	}
	log.Printf("moved pid %d to cgroup %s", pid, dir)
	return dir
}

// pipeline runs sources into the aggregator and publishes a View every interval.
func pipeline(ctx context.Context, stop func(), a *agg.Agg, hub *live.Hub, every time.Duration, srcs ...model.Source) {
	ticks := make(chan model.Tick, 256)
	for _, src := range srcs {
		go func(src model.Source) {
			if err := src.Run(ctx, ticks); err != nil {
				log.Print(err)
			}
			stop()
		}(src)
	}
	go func() {
		tk := time.NewTicker(every)
		defer tk.Stop()
		for {
			select {
			case t := <-ticks:
				a.Ingest(t)
			case now := <-tk.C:
				hub.Publish(a.Snapshot(now))
			case <-ctx.Done():
				return
			}
		}
	}()
}

func recorder(ctx context.Context, hub *live.Hub, path string) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	ch, cancel := hub.Subscribe()
	defer cancel()
	for {
		select {
		case v := <-ch:
			enc.Encode(v)
			w.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func replay(ctx context.Context, hub *live.Hub, path string, every time.Duration) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var v live.View
		if json.Unmarshal(sc.Bytes(), &v) != nil {
			continue
		}
		hub.Publish(v)
		select {
		case <-time.After(every):
		case <-ctx.Done():
			return
		}
	}
	log.Print("replay finished")
}

// smapsInfo says how often smaps is read now: "off", or the interval in effect and what the last read cost.
func smapsInfo(p *procfs.Source) func() string {
	return func() string {
		every := p.SmapsEvery()
		if every == 0 {
			return "off"
		}
		s := "every " + every.String()
		if c := p.SmapsCost(); c > 0 {
			s += fmt.Sprintf(", last read took %s", c.Round(100*time.Microsecond))
			if every > p.SmapsInterval {
				s += fmt.Sprintf(" (interval stretched from %s to keep it under 1%% of the time)", p.SmapsInterval)
			}
		}
		return s
	}
}

// reportMeta returns the context block of HTML reports: host, server build and process, and how mhp traced it.
// The static part is read once, on the first report.
func reportMeta(info map[string]any, srv *web.Server, pid int, sampleBytes int64, retention time.Duration) func() [][2]string {
	var static [][2]string
	var once sync.Once
	return func() [][2]string {
		once.Do(func() {
			host, _ := os.Hostname()
			kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
			mem := ""
			if b, err := os.ReadFile("/proc/meminfo"); err == nil {
				var kb int64
				fmt.Sscanf(strings.TrimPrefix(strings.SplitN(string(b), "\n", 2)[0], "MemTotal:"), "%d", &kb)
				mem = fmt.Sprintf(", %.1f GiB RAM", float64(kb)/(1<<20))
			}
			static = append(static, [2]string{"Host", fmt.Sprintf("%s (Linux %s, %d CPUs%s)", host,
				strings.TrimSpace(string(kernel)), runtime.NumCPU(), mem)})
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
				exe = strings.TrimSuffix(exe, " (deleted)")
				banner, id := web.BuildInfo(fmt.Sprintf("/proc/%d/root%s", pid, exe))
				server := srv.Repos.String()
				if banner != "" {
					server += ", " + banner
				}
				static = append(static, [2]string{"Server", server})
				if id != "" {
					exe += ", build ID " + id
				}
				static = append(static, [2]string{"Server binary", exe})
			}
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				static = append(static, [2]string{"Server process", fmt.Sprintf("pid %d: %s", pid,
					strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " ")))})
			}
			if m := mallocLib(pid); m != "" {
				static = append(static, [2]string{"Memory allocator", m})
			}
			if exe, err := os.Executable(); err == nil {
				static = append(static, [2]string{"mhp binary", exe})
			}
			if l, err := os.Readlink("/proc/self/fd/2"); err == nil {
				static = append(static, [2]string{"mhp log", l + " (standard error)"})
			}
		})
		out := append([][2]string(nil), static...)
		str := func(k string) string { v, _ := info[k].(string); return v }
		if h := str("heap_src"); h != "" {
			out = append(out, [2]string{"Heap tracing", h}, [2]string{"Sampling", fmt.Sprintf("%d KiB", sampleBytes>>10)})
		}
		faults := str("fault_scope")
		if faults == "" {
			faults = "off"
		}
		if f, ok := info["smaps"].(func() string); ok {
			out = append(out, [2]string{"Regions (smaps)", f()})
		}
		out = append(out, [2]string{"Page faults", faults},
			[2]string{"mhp", fmt.Sprintf("mhp %s %s, tracing since %s, history kept %s", Version, str("cmd"), str("since"), retention)})
		return out
	}
}

// mallocLib names the malloc implementation the target uses, with its version: an allocator library mapped into
// it (jemalloc, tcmalloc, mimalloc...) or else glibc's, plus LD_PRELOAD and malloc tuning from its environment.
// With a libmhp ring, libmhp says which allocator its calls really go to.
func mallocLib(pid int) string {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return ""
	}
	var alloc, libc, shimLib string
	for _, l := range strings.Split(string(maps), "\n") {
		f := strings.Fields(l)
		if len(f) < 6 || !strings.HasPrefix(f[5], "/") {
			continue
		}
		path, base := f[5], filepath.Base(f[5])
		switch {
		case alloc == "" && (strings.HasPrefix(base, "libjemalloc") || strings.HasPrefix(base, "libtcmalloc") ||
			strings.HasPrefix(base, "libmimalloc") || strings.HasPrefix(base, "libhoard") || strings.HasPrefix(base, "libsnmalloc")):
			alloc = strings.TrimPrefix(strings.SplitN(base, ".so", 2)[0], "lib")
			if v := allocVersion(fmt.Sprintf("/proc/%d/root%s", pid, path)); v != "" {
				alloc = v
			}
			alloc += " (" + path + ")"
		case libc == "" && strings.HasPrefix(base, "libc.so"), libc == "" && strings.HasPrefix(base, "libc-"):
			libc = path
		case strings.HasPrefix(base, "libmhp"):
			shimLib = path
		}
	}
	out := alloc
	if (out == "" || shim.AllocKind(pid) == "glibc") && libc != "" {
		out = "glibc malloc (ptmalloc2), "
		if v := glibcVersion(fmt.Sprintf("/proc/%d/root%s", pid, libc)); v != "" {
			out += v + ", "
		}
		out += libc
		if alloc != "" { // e.g. pulled in by a plugin, or preloaded after libmhp was told otherwise
			out += "; " + alloc + " is mapped but not the malloc in use"
		}
	}
	if shimLib != "" {
		out += "; libmhp sampling shim " + shimLib + map[int]string{shim.Injected: " (injected: calls redirected)",
			shim.Undone: " (injected earlier, undone: idle)", shim.Preloaded: " (preloaded)"}[shim.RingState(pid)]
	}
	if env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		for _, e := range strings.Split(string(env), "\x00") {
			if strings.HasPrefix(e, "LD_PRELOAD=") || strings.HasPrefix(e, "MALLOC_") || strings.HasPrefix(e, "GLIBC_TUNABLES=") ||
				strings.HasPrefix(e, "TCMALLOC_") || strings.HasPrefix(e, "MIMALLOC_") {
				out += "; " + e
			}
		}
	}
	return out
}

// allocVersion reads the version an allocator library carries in its text: jemalloc's "5.3.0-0-g<commit>" (what
// mallctl "version" returns) or gperftools' "gperftools 2.15" (tcmalloc).
var allocVersionRe = regexp.MustCompile(`\x00(\d+\.\d+\.\d+-\d+-g[0-9a-f]{40})\x00|\x00(gperftools \d+\.\d+(?:\.\d+)?)\x00`)

func allocVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	m := allocVersionRe.FindSubmatch(b)
	switch {
	case m == nil:
		return ""
	case len(m[1]) > 0:
		return "jemalloc " + string(m[1][:len(m[1])-28]) // 12 digits of the commit are plenty
	default:
		return "tcmalloc (" + string(m[2]) + ")"
	}
}

// glibcVersion reads the release banner glibc carries ("GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.6) stable
// release version 2.39.").
func glibcVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	i := bytes.Index(b, []byte("GNU C Library ("))
	if i < 0 {
		return ""
	}
	s := string(b[i+len("GNU C Library ("):])
	if j := strings.IndexByte(s, ')'); j > 0 && j < 80 {
		return s[:j]
	}
	return ""
}
