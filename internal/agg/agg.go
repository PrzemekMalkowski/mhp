// Package agg merges ticks from any number of sources into per-interval Views
// and answers drill-down queries (stacks filtered by thread / role / sub-system).
package agg

import (
	"maps"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PrzemekMalkowski/mhp/internal/classify"
	"github.com/PrzemekMalkowski/mhp/internal/live"
	"github.com/PrzemekMalkowski/mhp/internal/model"
	"github.com/PrzemekMalkowski/mhp/internal/procfs"
)

const (
	marks      = 12 // growth window resolution: live bytes are remembered every growthSecs/marks
	maxEntries = 200000
	topN       = 15
	maxThreads = 2000
	// DefaultTimeline bounds the per-tick history kept for time-range queries (~56 bytes per record), on top of
	// Retention: the oldest ticks are dropped first. ~400 records/s at 300 sysbench tx/s; a paused tracer writes none.
	DefaultTimeline  = 1 << 20
	DefaultRetention = 10 * time.Minute
	clkTck           = 100 // USER_HZ
)

type stackInfo struct {
	frames []string // root first
	subsys string
	area   string // subsys with its sub-area, "InnoDB · buffer pool" (= subsys when it has none)
}

type entKey struct {
	sid  int
	tid  int
	kind model.Kind
}

type entry struct {
	live     int64 // heap: live bytes; fault: cumulative faulted bytes
	allocCum int64
	mark     [marks]int64 // ring of past live values, oldest at markPos
}

// rangeRec is what one (stack, thread, kind) did during one tick.
type rangeRec struct {
	k           entKey
	alloc, free int64
	n, max      int64
}

type tframe struct {
	t    int64 // unix ms of the snapshot that closed the tick; the tick covers (previous t, t]
	recs []rangeRec
	// traced heap per area ("" = all) at the end of the tick, and its highest value within the tick (areas that
	// rose only; others peaked at their end value)
	end, peak map[string]int64
}

type thread struct {
	comm, role        string
	entry             string // the thread's start function, from its first complete stack
	alive             bool
	lastSeen          time.Time
	cur               model.ThreadStat
	curT              time.Time
	winAlloc, winFree int64
	winFault          int64
	// rates between the last two /proc samples
	minfltRate, majfltRate, cpuPct float64
}

type Agg struct {
	mu         sync.Mutex
	cls        *classify.Classifier
	stackIDs   map[string]int
	stacks     []stackInfo
	entries    map[entKey]*entry
	threads    map[int]*thread
	proc       *model.ProcStats
	regions    map[string]int64
	regionSwap map[string]int64
	tracers    map[string]model.TracerStats
	pfs        *model.PFSStats
	heap       *model.HeapStats
	arenas     *model.ArenaStats
	hasTrace   bool // heap tracer (libmhp / eBPF) seen
	hasFaults  bool // perf fault sampler seen
	winAlloc   int64
	winFree    int64
	winFault   int64
	growthSecs int
	markPos    int
	lastMark   time.Time
	lastSnap   time.Time
	start      time.Time

	Timeline  int           // max records kept in frames (0 = DefaultTimeline)
	Retention time.Duration // max age of frames (0 = DefaultRetention)
	cur       map[entKey]*rangeRec
	frames    []tframe
	frameRecs int
	dropped   int64            // end (unix ms) of the newest tick dropped from frames; 0 = the timeline is complete
	run       map[string]int64 // heap live per area ("" = all) in ingest order (unaffected by prune)
	peak      map[string]int64 // highest run (or tracer-reported peak) per area since the last snapshot
}

// Stats reports the aggregator's own size, for /info.
func (a *Agg) Stats() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	keyBytes := 0
	for k := range a.stackIDs {
		keyBytes += len(k)
	}
	return map[string]int{"stacks": len(a.stacks), "stack_key_bytes": keyBytes, "entries": len(a.entries),
		"threads": len(a.threads), "timeline_ticks": len(a.frames), "timeline_records": a.frameRecs}
}

// Subsystem classifies a root-first stack with the aggregator's rules (for tracers' per-area peaks).
func (a *Agg) Subsystem(stack []string) string { return a.cls.Subsystem(stack) }

func New(cls *classify.Classifier, growthSecs int) *Agg {
	return &Agg{cls: cls, stackIDs: map[string]int{}, entries: map[entKey]*entry{},
		threads: map[int]*thread{}, tracers: map[string]model.TracerStats{}, growthSecs: growthSecs, start: time.Now(),
		cur: map[entKey]*rangeRec{}, run: map[string]int64{}, peak: map[string]int64{}}
}

// unnamedComm matches threads that kept the process name: MariaDB before 11.8 names none of its threads.
var unnamedComm = regexp.MustCompile(`^(mysqld|mariadbd|mysqld-debug|mariadbd-debug)$`)

// threadStart matches the frames above a thread's own start function.
var threadStart = regexp.MustCompile(`^(__clone3?|start_thread|libstdc\+\+\.so[.0-9]*\+0x[0-9a-f]+|pfs_spawn_thread|std::execute_native_thread_routine|std::thread::_State_impl<.*>::_M_run|std::__invoke.*|std::thread::_Invoker<.*)$`)

// threadEntry returns the start function of the thread a root-first stack belongs to: the first frame below
// clone/start_thread and spawn wrappers. "" for the main thread and for stacks truncated at the root.
func threadEntry(stack []string) string {
	if len(stack) == 0 || !strings.HasPrefix(stack[0], "__clone") && stack[0] != "start_thread" {
		return ""
	}
	for _, f := range stack {
		if !threadStart.MatchString(f) {
			if strings.HasPrefix(f, "[") { // a pseudo-frame ([fault: …], [unknown]): no start function seen
				return ""
			}
			if i := strings.IndexByte(f, '('); i > 0 {
				f = f[:i]
			}
			return f
		}
	}
	return ""
}

// roleName groups threads by name without its number; threads left with the process name are named by their
// start function (handle_one_connection, tpool::thread_pool_generic::worker_main...).
func (t *thread) roleName() string {
	if t.entry != "" && unnamedComm.MatchString(t.comm) {
		return t.entry
	}
	return procfs.Role(t.comm)
}

func (a *Agg) thread(tid int) *thread {
	t := a.threads[tid]
	if t == nil {
		t = &thread{comm: "?", role: "?"}
		a.threads[tid] = t
	}
	return t
}

// Ingest merges one tick. Safe for concurrent use by several sources.
func (a *Agg) Ingest(t model.Tick) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.Proc != nil {
		p := *t.Proc
		a.proc = &p
	}
	if t.Regions != nil {
		a.regions, a.regionSwap = t.Regions, t.RegionSwap
	}
	if t.Tracer != nil {
		a.tracers[t.Tracer.Name] = *t.Tracer
	}
	if t.PFS != nil {
		a.pfs = t.PFS
	}
	if t.Heap != nil {
		a.heap = t.Heap
	}
	if t.Arenas != nil {
		a.arenas = t.Arenas
	}
	if t.Threads != nil {
		seen := make(map[int]bool, len(t.Threads))
		for _, ts := range t.Threads {
			th := a.thread(ts.TID)
			seen[ts.TID] = true
			if dt := t.T.Sub(th.curT).Seconds(); th.alive && dt > 0 {
				th.minfltRate = float64(ts.MinFlt-th.cur.MinFlt) / dt
				th.majfltRate = float64(ts.MajFlt-th.cur.MajFlt) / dt
				th.cpuPct = 100 * float64(ts.CPU-th.cur.CPU) / clkTck / dt
			}
			th.cur, th.curT, th.alive, th.lastSeen = ts, t.T, true, t.T
			th.comm = ts.Comm
			th.role = th.roleName()
		}
		for tid, th := range a.threads {
			if !seen[tid] && th.alive {
				th.alive = false
				th.minfltRate, th.majfltRate, th.cpuPct = 0, 0, 0
			}
		}
	}
	// a tracer's rise is relative to its own previous tick, which is where our running totals are now
	cand := map[string]int64{}
	if t.PeakRise > 0 {
		cand[""] = a.run[""] + t.PeakRise
	}
	for area, r := range t.AreaRise {
		cand[area] = a.run[area] + r
	}
	for _, d := range t.Allocs {
		key := strings.Join(d.Stack, "\x00")
		sid, ok := a.stackIDs[key]
		if !ok {
			sid = len(a.stacks)
			a.stackIDs[key] = sid
			sub := a.cls.Subsystem(d.Stack)
			a.stacks = append(a.stacks, stackInfo{frames: d.Stack, subsys: sub, area: a.cls.Full(d.Stack, sub)})
		}
		ek := entKey{sid, d.TID, d.Kind}
		e := a.entries[ek]
		if e == nil {
			e = &entry{}
			a.entries[ek] = e
		}
		e.live += d.Alloc - d.Free
		e.allocCum += d.Alloc
		r := a.cur[ek]
		if r == nil {
			r = &rangeRec{k: ek}
			a.cur[ek] = r
		}
		r.alloc += d.Alloc
		r.free += d.Free
		r.n += d.N
		r.max = max(r.max, d.Max)
		th := a.thread(d.TID)
		if d.Thread != "" && th.comm == "?" { // /proc polling (if any) has the final name
			th.comm = d.Thread
			th.role = th.roleName()
		}
		if th.entry == "" {
			if th.entry = threadEntry(d.Stack); th.entry != "" {
				th.role = th.roleName()
			}
		}
		if d.Kind == model.KindFault {
			a.hasFaults = true
			a.winFault += d.Alloc
			th.winFault += d.Alloc
			continue
		}
		a.hasTrace = true
		if n := d.Alloc - d.Free; n != 0 {
			area := a.stacks[sid].subsys
			a.run[""] += n
			a.run[area] += n
			cand[area] = max(cand[area], a.run[area])
			cand[""] = max(cand[""], a.run[""])
		}
		a.winAlloc += d.Alloc
		a.winFree += d.Free
		th.winAlloc += d.Alloc
		th.winFree += d.Free
	}
	for area, v := range cand {
		if p, ok := a.peak[area]; !ok || v > p {
			a.peak[area] = v
		}
	}
}

func (e *entry) growth(pos int) int64 { return e.live - e.mark[pos] }

// Snapshot builds a View from the current state and resets rate windows.
func (a *Agg) Snapshot(now time.Time) live.View {
	a.mu.Lock()
	defer a.mu.Unlock()

	secs := now.Sub(a.lastSnap).Seconds()
	if a.lastSnap.IsZero() || secs <= 0 {
		secs = 1
	}
	a.lastSnap = now

	window := int(now.Sub(a.start).Seconds())
	if window > a.growthSecs {
		window = a.growthSecs
	}

	v := live.View{
		T: now.UnixMilli(), HasTrace: a.hasTrace, HasFaults: a.hasFaults, GrowthSecs: window,
		Proc: map[string]int64{}, Regions: map[string]int64{},
		BySubsys: map[string]int64{}, ByArea: map[string]int64{}, ByThread: map[string]int64{},
		AllocRate: int64(float64(a.winAlloc) / secs), FreeRate: int64(float64(a.winFree) / secs),
		FaultRate: int64(float64(a.winFault) / secs), PFS: a.pfs, Heap: a.heap,
		Arenas: a.arenas, // only in the first view after a new malloc_info (the UI keeps the latest)
	}
	a.arenas = nil
	a.winAlloc, a.winFree, a.winFault = 0, 0, 0
	for _, ts := range a.tracers {
		v.Tracers = append(v.Tracers, ts)
	}
	sort.Slice(v.Tracers, func(i, j int) bool { return v.Tracers[i].Name < v.Tracers[j].Name })
	if p := a.proc; p != nil {
		v.Proc = map[string]int64{
			"rss": p.RSS, "anon": p.Anon, "file": p.File, "shmem": p.Shmem, "swap": p.Swap,
			"thp": p.THP, "cgroup_limit": p.CgroupLimit, "threads": int64(p.Threads),
			"minflt": int64(p.MinFlt), "majflt": int64(p.MajFlt),
		}
		if p.ArenaMapped > 0 {
			v.Proc["arena_mapped"], v.Proc["arena_rss"], v.Proc["arena_heaps"], v.Proc["arena_t"] = p.ArenaMapped, p.ArenaRSS, int64(p.ArenaHeaps), p.ArenaT
		}
	}
	for k, n := range a.regions {
		v.Regions[k] = n
	}
	if len(a.regionSwap) > 0 {
		v.RegionSwap = maps.Clone(a.regionSwap)
	}

	type agg2 struct{ live, growth int64 }
	perStack := map[int]*agg2{}
	perThread := map[int]*agg2{}
	faultStack := map[int]*agg2{}
	faultThread := map[int]*agg2{}
	for k, e := range a.entries {
		g := e.growth(a.markPos)
		if k.kind == model.KindFault {
			for _, m := range []struct {
				mp map[int]*agg2
				id int
			}{{faultStack, k.sid}, {faultThread, k.tid}} {
				x := m.mp[m.id]
				if x == nil {
					x = &agg2{}
					m.mp[m.id] = x
				}
				x.live += e.live
				x.growth += g
			}
			continue
		}
		v.Traced += e.live
		v.BySubsys[a.stacks[k.sid].subsys] += e.live
		v.ByArea[a.stacks[k.sid].area] += e.live
		ps := perStack[k.sid]
		if ps == nil {
			ps = &agg2{}
			perStack[k.sid] = ps
		}
		ps.live += e.live
		ps.growth += g
		pt := perThread[k.tid]
		if pt == nil {
			pt = &agg2{}
			perThread[k.tid] = pt
		}
		pt.live += e.live
		pt.growth += g
	}
	if a.hasTrace && a.proc != nil {
		v.Gap = a.proc.Anon - v.Traced
	}
	if a.hasTrace {
		v.TracedPeak = v.Traced
		if p, ok := a.peak[""]; ok {
			v.TracedPeak += max(0, p-a.run[""])
		}
	}
	a.closeFrame(now)

	rows := make([]live.StackRow, 0, len(perStack))
	for sid, s := range perStack {
		si := a.stacks[sid]
		rows = append(rows, live.StackRow{Stack: si.frames, Subsystem: si.subsys, Area: si.area, Live: s.live, Growth: s.growth})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Live > rows[j].Live })
	v.Top = clip(rows)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Growth > rows[j].Growth })
	v.Growers = clip(rows)
	if a.hasFaults {
		frows := make([]live.StackRow, 0, len(faultStack))
		for sid, s := range faultStack {
			si := a.stacks[sid]
			frows = append(frows, live.StackRow{Stack: si.frames, Subsystem: si.subsys, Area: si.area, Live: s.live, Growth: s.growth})
		}
		sort.Slice(frows, func(i, j int) bool { return frows[i].Growth > frows[j].Growth })
		v.Faulters = clip(frows)
	}

	// threads
	for tid, th := range a.threads {
		pt := perThread[tid]
		if !th.alive && (pt == nil || pt.live == 0) && faultThread[tid] == nil && now.Sub(th.lastSeen) > time.Minute {
			delete(a.threads, tid)
			continue
		}
		r := live.ThreadRow{TID: tid, Comm: th.comm, Role: th.role, Alive: th.alive,
			AllocRate: int64(float64(th.winAlloc) / secs), FreeRate: int64(float64(th.winFree) / secs),
			MinFltRate: th.minfltRate, MajFltRate: th.majfltRate, CPUPct: th.cpuPct,
			MinFlt: th.cur.MinFlt, MajFlt: th.cur.MajFlt}
		r.FaultRate = int64(float64(th.winFault) / secs)
		th.winAlloc, th.winFree, th.winFault = 0, 0, 0
		if pt != nil {
			r.Live, r.Growth = pt.live, pt.growth
		}
		if a.pfs != nil {
			if pt, ok := a.pfs.Threads[tid]; ok {
				r.PFS = &pt
			}
		}
		if ft := faultThread[tid]; ft != nil {
			r.Faulted, r.FaultWin = ft.live, ft.growth
		}
		v.ByThread[th.role] += r.Live
		v.Threads = append(v.Threads, r)
	}
	sort.Slice(v.Threads, func(i, j int) bool {
		if v.Threads[i].Live != v.Threads[j].Live {
			return v.Threads[i].Live > v.Threads[j].Live
		}
		return v.Threads[i].MinFltRate > v.Threads[j].MinFltRate
	})
	if len(v.Threads) > maxThreads {
		v.Threads = v.Threads[:maxThreads]
	}
	a.rotateMarks(now)
	a.prune()
	return v
}

// rotateMarks records live bytes once per growthSecs/marks elapsed, so the oldest mark is ~growthSecs old.
func (a *Agg) rotateMarks(now time.Time) {
	step := time.Duration(float64(a.growthSecs) / marks * float64(time.Second))
	if a.lastMark.IsZero() {
		a.lastMark = now
	}
	n := int(now.Sub(a.lastMark) / step)
	if n > marks {
		n = marks
	}
	if n == 0 {
		return
	}
	a.lastMark = now
	for i := 0; i < n; i++ {
		for _, e := range a.entries {
			e.mark[a.markPos] = e.live
		}
		a.markPos = (a.markPos + 1) % marks
	}
}

// closeFrame moves this tick's records to the timeline and drops the oldest ticks beyond the record budget.
func (a *Agg) closeFrame(now time.Time) {
	f := tframe{t: now.UnixMilli(), recs: make([]rangeRec, 0, len(a.cur)), end: make(map[string]int64, len(a.run))}
	for _, r := range a.cur {
		f.recs = append(f.recs, *r)
	}
	for area, v := range a.run {
		f.end[area] = v
	}
	for area, p := range a.peak {
		if p > a.run[area] {
			if f.peak == nil {
				f.peak = map[string]int64{}
			}
			f.peak[area] = p
		}
	}
	a.cur, a.peak = map[entKey]*rangeRec{}, map[string]int64{}
	a.frames = append(a.frames, f)
	a.frameRecs += len(f.recs)
	budget, keep := a.Timeline, a.Retention
	if budget == 0 {
		budget = DefaultTimeline
	}
	if keep == 0 {
		keep = DefaultRetention
	}
	oldest := now.Add(-keep).UnixMilli()
	n := 0
	for n < len(a.frames)-1 && (a.frameRecs > budget || a.frames[n].t < oldest) {
		a.frameRecs -= len(a.frames[n].recs)
		n++
	}
	if n > 0 {
		a.dropped = a.frames[n-1].t
		a.frames = append([]tframe(nil), a.frames[n:]...)
	}
}

func clip(r []live.StackRow) []live.StackRow {
	if len(r) > topN {
		r = r[:topN]
	}
	return append([]live.StackRow(nil), r...)
}

// prune drops entries with nothing live, then the smallest, when over the cap.
func (a *Agg) prune() {
	if len(a.entries) <= maxEntries {
		return
	}
	for k, e := range a.entries {
		if e.live == 0 {
			delete(a.entries, k)
		}
	}
	if len(a.entries) <= maxEntries {
		return
	}
	type kv struct {
		k entKey
		n int64
	}
	all := make([]kv, 0, len(a.entries))
	for k, e := range a.entries {
		all = append(all, kv{k, e.live})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n < all[j].n })
	for _, e := range all[:len(all)-maxEntries] {
		delete(a.entries, e.k)
	}
}

// Filter selects entries for drill-down. Zero values match everything.
type Filter struct {
	TID    int
	Role   string
	Subsys string // a sub-system ("InnoDB"), or one of its sub-areas ("InnoDB · buffer pool")
	Metric string // heap: "live" (default), "growth", "alloc" (cumulative allocated); perf: "faults" (total), "faults_window";
	// time range (From, To]: "range_alloc", "range_free", "range_net" (alloc - free), "range_faults"
	From, To int64 // unix ms
}

func (f Filter) IsRange() bool { return strings.HasPrefix(f.Metric, "range_") }

type WeightedStack struct {
	Frames []string `json:"f"`
	Value  int64    `json:"v"`
	N      int64    `json:"n,omitempty"` // range metrics: samples (heap) or pages (faults)
	Max    int64    `json:"m,omitempty"` // range metrics: largest sampled request, bytes
	Area   string   `json:"a,omitempty"` // range metrics: sub-system
}

// match applies the thread / role / sub-system part of a filter.
func (a *Agg) match(f Filter, k entKey) bool {
	if f.TID != 0 && k.tid != f.TID {
		return false
	}
	if f.Role != "" {
		if th := a.threads[k.tid]; th == nil || th.role != f.Role {
			return false
		}
	}
	if f.Subsys == "" {
		return true
	}
	if si := a.stacks[k.sid]; strings.Contains(f.Subsys, classify.Sep) {
		return si.area == f.Subsys
	} else {
		return si.subsys == f.Subsys
	}
}

// frameSpan returns the frames of ticks inside (from, to].
func (a *Agg) frameSpan(from, to int64) []tframe {
	i := sort.Search(len(a.frames), func(i int) bool { return a.frames[i].t > from })
	j := sort.Search(len(a.frames), func(i int) bool { return a.frames[i].t > to })
	return a.frames[i:j]
}

func (a *Agg) rangeStacks(f Filter) []WeightedStack {
	type acc struct{ v, n, max int64 }
	sum := map[int]*acc{}
	kind := model.KindHeap
	if f.Metric == "range_faults" {
		kind = model.KindFault
	}
	for _, fr := range a.frameSpan(f.From, f.To) {
		for _, r := range fr.recs {
			if r.k.kind != kind || !a.match(f, r.k) {
				continue
			}
			s := sum[r.k.sid]
			if s == nil {
				s = &acc{}
				sum[r.k.sid] = s
			}
			switch f.Metric {
			case "range_free":
				s.v += r.free
				continue
			case "range_net":
				s.v += r.alloc - r.free
			default:
				s.v += r.alloc
			}
			s.n += r.n
			s.max = max(s.max, r.max)
		}
	}
	out := make([]WeightedStack, 0, len(sum))
	for sid, s := range sum {
		if s.v != 0 {
			out = append(out, WeightedStack{Frames: a.stacks[sid].frames, Value: s.v, N: s.n, Max: s.max, Area: a.stacks[sid].subsys})
		}
	}
	return out
}

// RangeTotals summarizes the ticks in (from, to]. A tick covers (previous tick, its own time], and the first tick
// covers everything up to its time (from process start under mhp run, else from attach): a range includes it only
// when From is before its time. Oldest is the start of the retained timeline: the time (unix ms) of the newest
// tick already dropped, 0 when none was. A range that starts before it misses data.
type RangeTotals struct {
	AreaTotals
	Ticks   int          `json:"ticks"`
	Records int          `json:"records"` // timeline records in the range (all threads; for sizing -timeline)
	Oldest  int64        `json:"oldest"`
	Areas   []AreaTotals `json:"areas"` // by sub-system, largest allocated first
	// SubAreas: the same by sub-area, for the sub-systems that have them ("InnoDB · buffer pool"); no PeakRise
	SubAreas []AreaTotals `json:"sub_areas,omitempty"`
}

type AreaTotals struct {
	Area    string `json:"area,omitempty"`
	Alloc   int64  `json:"alloc"`
	Free    int64  `json:"free"`
	Samples int64  `json:"samples"`
	Max     int64  `json:"max"` // largest sampled request
	Faulted int64  `json:"faulted"`
	// PeakRise is how far traced live bytes rose above their value at the start of the range, at the highest point
	// (event order). Per area only for the whole process (thread / role filters do not apply to it).
	PeakRise int64 `json:"peak_rise"`
}

func (a *Agg) Range(f Filter) RangeTotals {
	a.mu.Lock()
	defer a.mu.Unlock()
	var t RangeTotals
	t.Oldest = a.dropped
	span := a.frameSpan(f.From, f.To)
	t.Ticks = len(span)
	by := map[string]*AreaTotals{}
	area := func(name string) *AreaTotals {
		x := by[name]
		if x == nil {
			x = &AreaTotals{Area: name}
			by[name] = x
		}
		return x
	}
	subBy := map[string]*AreaTotals{}
	subArea := func(name string) *AreaTotals {
		x := subBy[name]
		if x == nil {
			x = &AreaTotals{Area: name}
			subBy[name] = x
		}
		return x
	}
	net0 := map[string]int64{} // heap net change in the first tick, to find the values at the start of the range
	for i, fr := range span {
		t.Records += len(fr.recs)
		for _, r := range fr.recs {
			if i == 0 && r.k.kind == model.KindHeap {
				net0[a.stacks[r.k.sid].subsys] += r.alloc - r.free
				net0[""] += r.alloc - r.free
			}
			if !a.match(f, r.k) {
				continue
			}
			xs := []*AreaTotals{&t.AreaTotals, area(a.stacks[r.k.sid].subsys)}
			if si := a.stacks[r.k.sid]; si.area != si.subsys {
				xs = append(xs, subArea(si.area))
			}
			for _, x := range xs {
				if r.k.kind == model.KindFault {
					x.Faulted += r.alloc
					continue
				}
				x.Alloc += r.alloc
				x.Free += r.free
				x.Samples += r.n
				x.Max = max(x.Max, r.max)
			}
		}
	}
	if len(span) > 0 {
		for name, x := range by {
			x.PeakRise = peakRise(span, name, net0[name])
		}
		t.PeakRise = peakRise(span, "", net0[""])
	}
	for _, x := range by {
		t.Areas = append(t.Areas, *x)
	}
	for _, x := range subBy {
		t.SubAreas = append(t.SubAreas, *x)
	}
	for _, l := range [][]AreaTotals{t.Areas, t.SubAreas} {
		sort.Slice(l, func(i, j int) bool {
			return l[i].Alloc > l[j].Alloc || l[i].Alloc == l[j].Alloc && l[i].Area < l[j].Area
		})
	}
	return t
}

// ThreadTotals is what one thread did in a time range.
type ThreadTotals struct {
	TID     int    `json:"tid"`
	Comm    string `json:"comm"`
	Role    string `json:"role"`
	Alloc   int64  `json:"alloc"`
	Free    int64  `json:"free"`
	Samples int64  `json:"samples"`
	Max     int64  `json:"max"`
	Faulted int64  `json:"faulted"`
}

// RangeThreads returns per-thread totals for the ticks in (From, To], most allocated (then faulted) first. Frees are
// credited to the thread that made the allocation.
func (a *Agg) RangeThreads(f Filter) []ThreadTotals {
	a.mu.Lock()
	defer a.mu.Unlock()
	by := map[int]*ThreadTotals{}
	for _, fr := range a.frameSpan(f.From, f.To) {
		for _, r := range fr.recs {
			if !a.match(f, r.k) {
				continue
			}
			t := by[r.k.tid]
			if t == nil {
				t = &ThreadTotals{TID: r.k.tid, Comm: "?", Role: "?"}
				if th := a.threads[r.k.tid]; th != nil {
					t.Comm, t.Role = th.comm, th.role
				}
				by[r.k.tid] = t
			}
			if r.k.kind == model.KindFault {
				t.Faulted += r.alloc
				continue
			}
			t.Alloc += r.alloc
			t.Free += r.free
			t.Samples += r.n
			t.Max = max(t.Max, r.max)
		}
	}
	out := make([]ThreadTotals, 0, len(by))
	for _, t := range by {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alloc != out[j].Alloc {
			return out[i].Alloc > out[j].Alloc
		}
		if out[i].Faulted != out[j].Faulted {
			return out[i].Faulted > out[j].Faulted
		}
		return out[i].TID < out[j].TID
	})
	return out
}

// peakRise is the highest value of an area's traced live bytes within the span, above its value at the start.
func peakRise(span []tframe, area string, firstNet int64) int64 {
	start := span[0].end[area] - firstNet
	hi := start
	for _, fr := range span {
		hi = max(hi, fr.end[area])
		if p, ok := fr.peak[area]; ok {
			hi = max(hi, p)
		}
	}
	return hi - start
}

// Stacks returns per-stack values (summed over matching threads), for flame graphs and trees.
func (a *Agg) Stacks(f Filter) []WeightedStack {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.IsRange() {
		return a.rangeStacks(f)
	}
	sum := map[int]int64{}
	kind := model.KindHeap
	if strings.HasPrefix(f.Metric, "faults") {
		kind = model.KindFault
	}
	for k, e := range a.entries {
		if k.kind != kind {
			continue
		}
		if !a.match(f, k) {
			continue
		}
		switch f.Metric {
		case "growth", "faults_window":
			sum[k.sid] += e.growth(a.markPos)
		case "alloc":
			sum[k.sid] += e.allocCum
		default:
			sum[k.sid] += e.live
		}
	}
	out := make([]WeightedStack, 0, len(sum))
	for sid, n := range sum {
		if n != 0 {
			out = append(out, WeightedStack{Frames: a.stacks[sid].frames, Value: n})
		}
	}
	return out
}

// Folded returns flamegraph.pl-style folded stacks weighted by live bytes, prefixed by thread role.
func (a *Agg) Folded() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for k, e := range a.entries {
		if e.live <= 0 || k.kind != model.KindHeap {
			continue
		}
		role := "?"
		if th := a.threads[k.tid]; th != nil {
			role = th.role
		}
		b.WriteString(role + ";" + strings.Join(a.stacks[k.sid].frames, ";") + " ")
		b.WriteString(strconv.FormatInt(e.live, 10))
		b.WriteByte('\n')
	}
	return b.String()
}
