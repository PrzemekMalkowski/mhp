// Package perf samples page faults of a target process with user call chains via perf_event_open.
//
// It is the attach-anything stack source: no restart, no LD_PRELOAD, no eBPF. It needs root or
// CAP_PERFMON (cpu-wide events). A fault means a page was first touched (or re-read from a file/swap),
// so the totals show where RSS growth comes from, but not frees, since the kernel reclaims pages lazily.
//
// Events are opened per CPU, so threads created after attach are covered automatically. When the target
// lives in its own cgroup (e.g. systemd's mysql.service) the kernel filters by cgroup (PERF_FLAG_PID_CGROUP);
// otherwise events are system-wide and filtered by PID here, and other processes' faults compete for ring space.
package perf

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"mhp/internal/model"
	"mhp/internal/procfs"
	"mhp/internal/sym"
)

const (
	pageSize = 4096
	// x86_64 perf_regs order: AX BX CX DX SI DI BP SP IP ...
	regBP, regSP, regIP = 6, 7, 8
	regMask             = 1<<regBP | 1<<regSP | 1<<regIP
	contextMax          = ^uint64(4095 - 1) // (u64)PERF_CONTEXT_MAX = -4095
	stackDump           = 64                // bytes of user stack copied per sample; [sp] is the leaf's return address
	sampleType          = unix.PERF_SAMPLE_IP | unix.PERF_SAMPLE_TID | unix.PERF_SAMPLE_ADDR |
		unix.PERF_SAMPLE_CALLCHAIN | unix.PERF_SAMPLE_REGS_USER | unix.PERF_SAMPLE_STACK_USER
)

// Leaf functions written without a frame (glibc string/memory routines): the FP chain skips their caller,
// so the return address is recovered from the top of the sampled user stack instead.
var LeafNoFP = regexp.MustCompile(`^_*(mem|str|stp|wmem|wcs|rawmem)[a-z]*(_[a-z0-9_]+)?$`)

type FaultSource struct {
	PID    int
	Period uint64 // sample every Nth fault (1 = all)
	Pages  int    // ring data pages per CPU (power of two)
	Poll   time.Duration
	Sym    *sym.Symbolizer

	rings   []*ring
	Scope   string // "cgroup <path>" or "system-wide"
	regions regions
	stacks  map[string][]string
	comms   map[int]string
	lost    uint64
	samples uint64
}

type ring struct {
	fd   int
	mem  []byte
	data []byte
}

// Open creates one sampling event and ring per online CPU.
func (s *FaultSource) Open() error {
	if s.Period == 0 {
		s.Period = 1
	}
	if s.Pages == 0 {
		s.Pages = 512 // 2 MiB per CPU
	}
	cpus, err := onlineCPUs()
	if err != nil {
		return err
	}
	attr := unix.PerfEventAttr{
		Type:              unix.PERF_TYPE_SOFTWARE,
		Config:            unix.PERF_COUNT_SW_PAGE_FAULTS,
		Sample:            s.Period,
		Sample_type:       sampleType,
		Bits:              unix.PerfBitDisabled | unix.PerfBitExcludeCallchainKernel,
		Sample_regs_user:  regMask,
		Sample_stack_user: stackDump,
		Sample_max_stack:  64,
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	target, flags := -1, unix.PERF_FLAG_FD_CLOEXEC
	s.Scope = "system-wide"
	if cg, path := cgroupFD(s.PID); cg >= 0 {
		defer unix.Close(cg)
		target, flags = cg, flags|unix.PERF_FLAG_PID_CGROUP
		s.Scope = "cgroup " + path
	}
	for _, cpu := range cpus {
		fd, err := unix.PerfEventOpen(&attr, target, cpu, -1, flags)
		if err != nil {
			s.Close()
			return fmt.Errorf("perf_event_open(page-faults, cpu %d): %w (needs root or CAP_PERFMON)", cpu, err)
		}
		mem, err := unix.Mmap(fd, 0, (1+s.Pages)*pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			unix.Close(fd)
			s.Close()
			return fmt.Errorf("perf mmap: %w", err)
		}
		s.rings = append(s.rings, &ring{fd: fd, mem: mem, data: mem[pageSize:]})
	}
	for _, r := range s.rings {
		unix.IoctlSetInt(r.fd, unix.PERF_EVENT_IOC_ENABLE, 0)
	}
	s.stacks = map[string][]string{}
	s.comms = map[int]string{}
	s.regions.pid = s.PID
	s.regions.reload()
	return nil
}

func (s *FaultSource) Close() {
	for _, r := range s.rings {
		unix.IoctlSetInt(r.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		unix.Munmap(r.mem)
		unix.Close(r.fd)
	}
	s.rings = nil
}

// cgroupFD opens the target's cgroup v2 directory if it differs from ours (so filtering by it helps).
func cgroupFD(pid int) (int, string) {
	read := func(p string) string {
		b, _ := os.ReadFile(p)
		for _, l := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(l, "0::"); ok {
				return rest
			}
		}
		return ""
	}
	path := read(fmt.Sprintf("/proc/%d/cgroup", pid))
	if path == "" || path == "/" || path == read("/proc/self/cgroup") {
		return -1, ""
	}
	fd, err := unix.Open("/sys/fs/cgroup"+path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ""
	}
	return fd, path
}

func onlineCPUs() ([]int, error) {
	b, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	var cpus []int
	for _, part := range strings.Split(strings.TrimSpace(string(b)), ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, err
		}
		z := a
		if isRange {
			if z, err = strconv.Atoi(hi); err != nil {
				return nil, err
			}
		}
		for c := a; c <= z; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}

func (s *FaultSource) Run(ctx context.Context, out chan<- model.Tick) error {
	defer s.Close()
	poll := s.Poll
	if poll == 0 {
		poll = 20 * time.Millisecond
	}
	tk := time.NewTicker(poll)
	defer tk.Stop()
	var buf []byte
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
		}
		acc := map[[2]any]*model.AllocDelta{}
		for _, r := range s.rings {
			buf = s.drain(r, buf, acc)
		}
		t := model.Tick{T: time.Now(), Tracer: &model.TracerStats{
			Name: "perf page-faults (" + strings.Fields(s.Scope)[0] + ")", Sampled: s.samples, Drops: s.lost, SampleRate: s.Period,
		}}
		for _, d := range acc {
			t.Allocs = append(t.Allocs, *d)
		}
		select {
		case out <- t:
		case <-ctx.Done():
			return nil
		}
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", s.PID)); err != nil {
			return fmt.Errorf("target %d exited", s.PID)
		}
	}
}

func (s *FaultSource) drain(r *ring, buf []byte, acc map[[2]any]*model.AllocDelta) []byte {
	head := atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.mem[1024]))) // perf_event_mmap_page.data_head
	tailp := (*uint64)(unsafe.Pointer(&r.mem[1032]))                   // data_tail
	tail := *tailp
	size := uint64(len(r.data))
	for tail < head {
		hdr := r.copy(tail, 8, buf[:0])
		typ := binary.LittleEndian.Uint32(hdr)
		n := uint64(binary.LittleEndian.Uint16(hdr[6:]))
		if n < 8 || n > size {
			tail = head // corrupt; resync
			break
		}
		buf = r.copy(tail, n, buf[:0])
		switch typ {
		case unix.PERF_RECORD_SAMPLE:
			s.sample(buf[8:], acc)
		case unix.PERF_RECORD_LOST:
			if len(buf) >= 24 {
				s.lost += binary.LittleEndian.Uint64(buf[16:])
			}
		}
		tail += n
	}
	atomic.StoreUint64(tailp, tail)
	return buf
}

// copy reads n bytes at ring position pos, handling wrap-around.
func (r *ring) copy(pos, n uint64, dst []byte) []byte {
	size := uint64(len(r.data))
	off := pos % size
	if off+n <= size {
		return append(dst, r.data[off:off+n]...)
	}
	dst = append(dst, r.data[off:]...)
	return append(dst, r.data[:n-(size-off)]...)
}

func (s *FaultSource) sample(b []byte, acc map[[2]any]*model.AllocDelta) {
	le := binary.LittleEndian
	if len(b) < 32 {
		return
	}
	ip := le.Uint64(b[0:])
	pid := int(le.Uint32(b[8:]))
	tid := int(le.Uint32(b[12:]))
	if pid != s.PID {
		return
	}
	addr := le.Uint64(b[16:])
	nr := le.Uint64(b[24:])
	p := 32
	if uint64(len(b)) < uint64(p)+nr*8 {
		return
	}
	chain := make([]uint64, 0, nr+1)
	for i := uint64(0); i < nr; i++ {
		v := le.Uint64(b[p+int(i)*8:])
		if v >= contextMax { // context marker (user/kernel/...)
			continue
		}
		chain = append(chain, v)
	}
	p += int(nr) * 8
	var sp uint64
	if len(b) >= p+8 && le.Uint64(b[p:]) != 0 { // regs abi
		regs := b[p+8:]
		if len(regs) >= 24 {
			sp = le.Uint64(regs[8:]) // order follows the mask bits: BP, SP, IP
		}
		p += 8 + 24
	} else {
		p += 8
	}
	var top uint64 // value at [sp]
	if len(b) >= p+8 {
		if sz := le.Uint64(b[p:]); sz >= 8 && len(b) >= p+16 && sp != 0 {
			top = le.Uint64(b[p+8:])
		}
	}
	s.samples++

	// leaf-first return addresses; the first entry is the sampled IP itself
	if len(chain) == 0 || chain[0] != ip {
		chain = append([]uint64{ip}, chain...)
	}
	if top != 0 && (len(chain) < 2 || chain[1] != top) && s.Sym.IsCode(top) && LeafNoFP.MatchString(s.Sym.FrameAt(ip)) {
		chain = append(chain[:1], append([]uint64{top}, chain[1:]...)...)
	}
	region := "[fault: " + s.regions.class(addr) + "]"
	key := region + string(unsafe.Slice((*byte)(unsafe.Pointer(&chain[0])), len(chain)*8))
	fr, ok := s.stacks[key]
	if !ok {
		chain[0]++ // Frames() looks up addr-1 (return addresses); the IP is exact
		fr = append(s.Sym.Frames(chain), region)
		s.stacks[key] = fr
	}
	k := [2]any{key, tid}
	d := acc[k]
	if d == nil {
		d = &model.AllocDelta{Stack: fr, TID: tid, Thread: s.comm(tid), Kind: model.KindFault}
		acc[k] = d
	}
	d.Alloc += int64(s.Period * pageSize)
	d.N += int64(s.Period)
}

func (s *FaultSource) comm(tid int) string {
	c, ok := s.comms[tid]
	if !ok {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/comm", s.PID, tid)); err == nil {
			c = strings.TrimSpace(string(b))
		}
		s.comms[tid] = c
	}
	return c
}

// regions classifies fault addresses by mapping (heap, anon, file, stack, ...).
type regions struct {
	pid  int
	maps []mapEnt
	last time.Time
}

type mapEnt struct {
	lo, hi uint64
	class  string
}

func (r *regions) reload() {
	r.last = time.Now()
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", r.pid))
	if err != nil {
		return
	}
	defer f.Close()
	var ms []mapEnt
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 5 {
			continue
		}
		lo, hi, _ := strings.Cut(fl[0], "-")
		var m mapEnt
		m.lo, _ = strconv.ParseUint(lo, 16, 64)
		m.hi, _ = strconv.ParseUint(hi, 16, 64)
		path := ""
		if len(fl) >= 6 {
			path = fl[5]
		}
		m.class = procfs.ClassOf(path)
		ms = append(ms, m)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].lo < ms[j].lo })
	r.maps = ms
}

func (r *regions) class(addr uint64) string {
	for try := 0; try < 2; try++ {
		i := sort.Search(len(r.maps), func(i int) bool { return r.maps[i].hi > addr })
		if i < len(r.maps) && r.maps[i].lo <= addr {
			return r.maps[i].class
		}
		if try == 0 && time.Since(r.last) > 20*time.Millisecond { // mapped after our last read (common at startup)
			r.reload()
		} else {
			break
		}
	}
	return "short-lived mapping" // mapped at fault time, already unmapped when we looked
}
