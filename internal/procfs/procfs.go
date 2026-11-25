// Package procfs is the tier-0 source: unprivileged /proc polling.
package procfs

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PrzemekMalkowski/mhp/internal/model"
)

type Source struct {
	PID      int
	Interval time.Duration
	// SmapsInterval is the shortest time between smaps reads (regions view, THP, swap by region); 0 turns them off.
	// A read walks every resident page of the process, so the time grows with RSS: the interval is stretched to
	// SmapsDuty times the last read's duration, keeping the walk under 1 % of the time on any size of server.
	SmapsInterval time.Duration
	smapsCost     atomic.Int64 // duration of the last smaps read, ns
	root          string       // "/proc" (overridable for tests)
	thp           int64        // AnonHugePages summed over the last smaps read
	arena         ArenaMaps    // glibc arena mappings in the last smaps read
	smapsSoon     atomic.Bool  // read smaps on the next tick, whatever the interval
}

// ArenaMaps is what smaps says about glibc malloc's arenas: the main arena's [heap] (brk) and the other arenas'
// heaps, which glibc maps at 64 MiB-aligned addresses (HEAP_MAX_SIZE on 64-bit) as read-write pages followed by
// a PROT_NONE reservation up to the next 64 MiB boundary. Mapped is the read-write size (what malloc_info calls
// "system current"), RSS the part resident: free chunks whose pages malloc_trim released, or never touched,
// count in malloc_info's free but not here.
type ArenaMaps struct {
	Mapped, RSS int64
	Heaps       int       // non-main arena heaps found
	T           time.Time // when smaps was read
}

// ReadSmapsSoon makes the next tick read smaps (for a malloc_info reading asked for now, e.g. before a copy).
func (s *Source) ReadSmapsSoon() { s.smapsSoon.Store(true) }

func New(pid int, interval, smapsInterval time.Duration) *Source {
	return &Source{PID: pid, Interval: interval, SmapsInterval: smapsInterval, root: "/proc"}
}

func (s *Source) dir() string { return filepath.Join(s.root, strconv.Itoa(s.PID)) }

func (s *Source) Run(ctx context.Context, out chan<- model.Tick) error {
	tk := time.NewTicker(s.Interval)
	defer tk.Stop()
	var lastSmaps time.Time
	for {
		t := model.Tick{T: time.Now()}
		p, err := s.readProc()
		if err != nil {
			return fmt.Errorf("pid %d: %w", s.PID, err)
		}
		t.Threads = s.readThreads()
		if s.SmapsInterval > 0 && (time.Since(lastSmaps) >= s.SmapsEvery() || s.smapsSoon.Swap(false)) {
			start := time.Now()
			if r, sw, err := s.readRegions(); err == nil {
				t.Regions, t.RegionSwap = r, sw
				p.THP = s.thp
				if s.arena.Mapped > 0 {
					p.ArenaMapped, p.ArenaRSS, p.ArenaHeaps, p.ArenaT = s.arena.Mapped, s.arena.RSS, s.arena.Heaps, s.arena.T.UnixMilli()
				}
			}
			lastSmaps = time.Now()
			s.smapsCost.Store(int64(lastSmaps.Sub(start)))
		}
		t.Proc = p
		select {
		case out <- t:
		case <-ctx.Done():
			return nil
		}
		select {
		case <-tk.C:
		case <-ctx.Done():
			return nil
		}
	}
}

// SmapsDuty is how many times longer than one smaps read the pause before the next one is at least.
const SmapsDuty = 100

// SmapsCost is how long the last smaps read took (0 before the first).
func (s *Source) SmapsCost() time.Duration { return time.Duration(s.smapsCost.Load()) }

// SmapsEvery is the interval between smaps reads in effect now; 0 when they are off.
func (s *Source) SmapsEvery() time.Duration {
	if s.SmapsInterval <= 0 {
		return 0
	}
	return max(s.SmapsInterval, (SmapsDuty * s.SmapsCost()).Round(time.Second))
}

func (s *Source) readProc() (*model.ProcStats, error) {
	st, err := os.Open(filepath.Join(s.dir(), "status"))
	if err != nil {
		return nil, err
	}
	defer st.Close()
	p := &model.ProcStats{}
	sc := bufio.NewScanner(st)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch k {
		case "VmRSS":
			p.RSS = kb(v)
		case "RssAnon":
			p.Anon = kb(v)
		case "RssFile":
			p.File = kb(v)
		case "RssShmem":
			p.Shmem = kb(v)
		case "VmSwap":
			p.Swap = kb(v)
		case "Threads":
			p.Threads, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	p.THP = -1 // unknown without smaps
	if s.SmapsInterval > 0 {
		p.THP = s.thp // from the last smaps read: smaps_rollup would walk every page of the process each second
		if a := s.arena; a.Mapped > 0 {
			p.ArenaMapped, p.ArenaRSS, p.ArenaHeaps, p.ArenaT = a.Mapped, a.RSS, a.Heaps, a.T.UnixMilli()
		}
	}
	if b, err := os.ReadFile(filepath.Join(s.dir(), "stat")); err == nil {
		// fields after the last ')' : state is index 0, minflt is index 7, majflt index 9
		str := string(b)
		if i := strings.LastIndexByte(str, ')'); i >= 0 {
			f := strings.Fields(str[i+1:])
			if len(f) > 9 {
				p.MinFlt, _ = strconv.ParseUint(f[7], 10, 64)
				p.MajFlt, _ = strconv.ParseUint(f[9], 10, 64)
			}
		}
	}
	p.CgroupLimit = s.cgroupLimit()
	return p, nil
}

// cgroupLimit returns the memory limit that applies to the process (cgroup v2): the lowest memory.max of its
// cgroup and the cgroups above it (a service's limit still applies when the process sits in a child group), or 0.
func (s *Source) cgroupLimit() int64 {
	b, err := os.ReadFile(filepath.Join(s.dir(), "cgroup"))
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(l, "0::"); ok {
			return lowestMax("/sys/fs/cgroup", rest)
		}
	}
	return 0
}

func lowestMax(root, group string) int64 {
	var lim int64
	for g := filepath.Clean("/" + group); ; g = filepath.Dir(g) {
		if v, err := os.ReadFile(filepath.Join(root, g, "memory.max")); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64); err == nil && (lim == 0 || n < lim) {
				lim = n // else "max"
			}
		}
		if g == "/" {
			return lim
		}
	}
}

// readRegions sums Rss and Swap from smaps by region class (swap is nil when nothing is swapped out), and
// AnonHugePages over all mappings into s.thp.
func (s *Source) readRegions() (map[string]int64, map[string]int64, error) {
	f, err := os.Open(filepath.Join(s.dir(), "smaps"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	out, swap := map[string]int64{}, map[string]int64(nil)
	class, thp := "other", int64(0)
	var ar arenaScan
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !strings.HasSuffix(f[0], ":") { // mapping header
			path := ""
			if len(f) >= 6 {
				path = f[5]
			}
			ar.header(f[0], f[1], path)
			class = RegionClass(path, f[1], len(f) >= 7 && f[len(f)-1] == "(deleted)")
			continue
		}
		switch f[0] {
		case "Rss:":
			out[class] += kb(f[1])
			ar.rss(kb(f[1]))
		case "AnonHugePages:":
			thp += kb(f[1])
		case "Swap:":
			if n := kb(f[1]); n > 0 {
				if swap == nil {
					swap = map[string]int64{}
				}
				swap[class] += n
			}
		}
	}
	if sc.Err() == nil {
		s.thp = thp
		ar.header("", "", "")
		s.arena = ArenaMaps{Mapped: ar.mapped, RSS: ar.rssSum, Heaps: ar.heaps, T: time.Now()}
	}
	return out, swap, sc.Err()
}

// heapMax is glibc's HEAP_MAX_SIZE on 64-bit (2 * DEFAULT_MMAP_THRESHOLD_MAX): non-main arena heaps are mapped
// at multiples of it.
const heapMax = 64 << 20

// arenaScan picks glibc arena mappings out of smaps, one mapping header at a time. A non-main arena heap is an
// anonymous rw-p mapping starting at a 64 MiB boundary and ending at one, or followed directly by the anonymous
// ---p rest of its reservation that does (full adjacent heaps merge into one mapping, which the rule covers).
type arenaScan struct {
	mapped, rssSum int64
	heaps          int
	// candidate rw-p mapping whose fate depends on the next header
	cand                 bool
	candEnd, candSize    uint64
	candRSS              int64
	curIsCand, curIsHeap bool // the mapping whose fields follow
}

func (a *arenaScan) header(rng, perms, path string) {
	var start, end uint64
	if lo, hi, ok := strings.Cut(rng, "-"); ok {
		start, _ = strconv.ParseUint(lo, 16, 64)
		end, _ = strconv.ParseUint(hi, 16, 64)
	}
	if a.cand { // settle the previous candidate
		ok := a.candEnd%heapMax == 0 ||
			(path == "" && perms == "---p" && start == a.candEnd && end%heapMax == 0)
		if ok {
			a.mapped += int64(a.candSize)
			a.rssSum += a.candRSS
			a.heaps += int((a.candSize + heapMax - 1) / heapMax)
		}
		a.cand = false
	}
	a.curIsCand, a.curIsHeap = false, false
	switch {
	case rng == "":
	case path == "[heap]":
		a.curIsHeap = true
		a.mapped += int64(end - start)
	case path == "" && perms == "rw-p" && start%heapMax == 0 && end > start:
		a.cand, a.curIsCand = true, true
		a.candEnd, a.candSize, a.candRSS = end, end-start, 0
	}
}

func (a *arenaScan) rss(n int64) {
	switch {
	case a.curIsHeap:
		a.rssSum += n
	case a.curIsCand:
		a.candRSS += n
	}
}

// RegionClass is ClassOf for the regions view, with file mappings split: Galera's gcache (galera.cache ring buffer,
// gcache.page.* overflow pages), code & libs (private mappings: the binary's and libraries' segments, locale
// files), deleted shared files (e.g. TempTable mmap files, unlinked at creation) and other shared data files.
func RegionClass(path, perms string, deleted bool) string {
	c := ClassOf(path)
	if c != "file" {
		return c
	}
	base := filepath.Base(path)
	switch {
	case base == "galera.cache" || strings.HasPrefix(base, "gcache.page."):
		return "file: galera gcache"
	case len(perms) == 4 && perms[3] == 'p':
		return "file: code & libs"
	case deleted:
		return "file: deleted (temp)"
	}
	return "file: data"
}

// ClassOf names the mapping class of a /proc/<pid>/maps path.
func ClassOf(path string) string {
	switch {
	case path == "":
		return "anon-mmap"
	case path == "[heap]":
		return "heap(brk)"
	case strings.HasPrefix(path, "[stack"):
		return "stack"
	case strings.HasPrefix(path, "["):
		return "other"
	case strings.HasPrefix(path, "/memfd:") || strings.HasPrefix(path, "/dev/shm"):
		return "shmem"
	default:
		return "file"
	}
}

// kb parses "  1234 kB" into bytes.
func kb(v string) int64 {
	f := strings.Fields(v)
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(f[0], 10, 64)
	return n * 1024
}

// readThreads samples every task's stat: comm, page faults and CPU ticks.
func (s *Source) readThreads() []model.ThreadStat {
	dir := filepath.Join(s.dir(), "task")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]model.ThreadStat, 0, len(ents))
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "stat"))
		if err != nil {
			continue // thread exited
		}
		if ts, ok := parseTaskStat(tid, string(b)); ok {
			out = append(out, ts)
		}
	}
	return out
}

func parseTaskStat(tid int, str string) (model.ThreadStat, bool) {
	l, r := strings.IndexByte(str, '('), strings.LastIndexByte(str, ')')
	if l < 0 || r < l {
		return model.ThreadStat{}, false
	}
	f := strings.Fields(str[r+1:])
	if len(f) < 13 {
		return model.ThreadStat{}, false
	}
	ts := model.ThreadStat{TID: tid, Comm: str[l+1 : r]}
	ts.MinFlt, _ = strconv.ParseUint(f[7], 10, 64)
	ts.MajFlt, _ = strconv.ParseUint(f[9], 10, 64)
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	ts.CPU = ut + st
	return ts, true
}

// ThreadRoles counts threads by comm with trailing digits stripped (e.g. "ib_io_rd-3" -> "ib_io_rd").
func ThreadRoles(pid int) map[string]int {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil
	}
	m := map[string]int{}
	for _, e := range ents {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/comm", pid, e.Name()))
		if err != nil {
			continue
		}
		m[Role(strings.TrimSpace(string(b)))]++
	}
	return m
}

// Role normalises a thread name to a role.
func Role(comm string) string {
	r := strings.TrimRight(comm, "0123456789-_")
	if r == "" {
		return comm
	}
	return r
}
