// Package ebpf is the attach-without-restart heap tracer: uprobes on the malloc family of the target's allocator
// (glibc, or a jemalloc/tcmalloc/mimalloc/... library or binary that defines malloc; bpf/memtrace.bpf.c, embedded), sampled in the kernel like libmhp, events via a BPF ring buffer.
// Needs root (or CAP_BPF+CAP_PERFMON) and Linux 6.13+ (session uprobes).
package ebpf

import (
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"mhp/internal/model"
	"mhp/internal/sym"
	"mhp/internal/track"
)

//go:embed memtrace.bpf.o
var object []byte

// legacyObject is the same tracer for kernels without session uprobes (before 6.13, e.g. RHEL 9): every
// malloc-family call runs an entry and a return probe.
//
//go:embed memtrace_legacy.bpf.o
var legacyObject []byte

// sessionUprobes reports whether the kernel can attach session uprobes (BPF_TRACE_UPROBE_SESSION, Linux 6.13+).
func sessionUprobes() bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var e *btf.Enum
	if err := spec.TypeByName("bpf_attach_type", &e); err != nil {
		return false
	}
	for _, v := range e.Values {
		if v.Name == "BPF_TRACE_UPROBE_SESSION" {
			return true
		}
	}
	return false
}

// Attach types (include/uapi/linux/bpf.h); cilium/ebpf only attaches uprobe_multi links.
const (
	attachUprobeMulti   = 48
	attachUprobeSession = 57
)

// probes: program -> symbols of the allocator (malloc family) or of whatever provides mmap (libc, or an allocator
// that overrides it, like tcmalloc). Aliases resolving to one address are attached once. operator new/delete and
// jemalloc's *allocx are probed where the allocator defines them (jemalloc, tcmalloc), as callers bind to them
// rather than to libstdc++'s, which calls malloc/free. All operator new variants take the size first, all deletes
// the pointer first, like mallocx/rallocx/dallocx/sdallocx.
var probes = []struct {
	prog string
	mmap bool // attach where mmap is provided, else to the allocator
	syms []string
}{
	{"malloc_s", false, []string{"malloc", "mallocx", "_Znwm", "_Znam", "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t",
		"_ZnwmSt11align_val_t", "_ZnamSt11align_val_t", "_ZnwmSt11align_val_tRKSt9nothrow_t", "_ZnamSt11align_val_tRKSt9nothrow_t"}},
	{"calloc_s", false, []string{"calloc"}},
	{"realloc_s", false, []string{"realloc", "rallocx"}},
	{"memalign_s", false, []string{"memalign", "aligned_alloc", "valloc", "pvalloc"}},
	{"posix_memalign_s", false, []string{"posix_memalign"}},
	{"free_e", false, []string{"free", "cfree", "free_sized", "free_aligned_sized", "dallocx", "sdallocx",
		"_ZdlPv", "_ZdaPv", "_ZdlPvm", "_ZdaPvm", "_ZdlPvRKSt9nothrow_t", "_ZdaPvRKSt9nothrow_t",
		"_ZdlPvSt11align_val_t", "_ZdaPvSt11align_val_t", "_ZdlPvmSt11align_val_t", "_ZdaPvmSt11align_val_t",
		"_ZdlPvSt11align_val_tRKSt9nothrow_t", "_ZdaPvSt11align_val_tRKSt9nothrow_t"}},
	{"mmap_s", true, []string{"mmap", "mmap64"}},
	{"munmap_e", true, []string{"munmap"}},
	{"mprotect_e", true, []string{"mprotect"}},
}

type Source struct {
	PID         int
	SampleBytes uint64 // mean bytes between samples (default 256 KiB)
	Poll        time.Duration
	Sym         *sym.Symbolizer
	Libc        string                // libc path as mapped in the target (found by Open)
	Alloc       string                // allocator providing malloc when it is not libc: library or binary path (found by Open)
	MmapIn      string                // where mmap/munmap are probed: libc, or the allocator when it overrides them
	Area        func([]string) string // sub-system of a stack, for per-area peaks (optional)
	Legacy      bool                  // set by Open: entry + return probes (no session uprobes in this kernel)

	coll  *ebpf.Collection
	rd    *ringbuf.Reader
	links []int
	tr    *track.Tracker
}

// Open loads the BPF program and attaches it to the target's allocator and libc.
func (s *Source) Open() error {
	if s.SampleBytes == 0 {
		s.SampleBytes = 256 << 10
	}
	lo, hi, path, err := libcText(s.PID)
	if err != nil {
		return err
	}
	s.Libc = path
	root := func(p string) string { return fmt.Sprintf("/proc/%d/root%s", s.PID, p) } // a containerised target's own files
	libcOffs, err := symbolOffsets(root(path))
	if err != nil {
		return err
	}
	al, err := allocator(s.PID, path)
	if err != nil {
		return err
	}
	allocOffs, allocPath := libcOffs, path
	if al != nil {
		s.Alloc, allocOffs, allocPath = al.path, al.offs, al.path
	}
	s.MmapIn = path
	obj := object
	if s.Legacy = !sessionUprobes(); s.Legacy {
		obj = legacyObject
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return err
	}
	var tab [1024]uint32
	for i := range tab {
		tab[i] = uint32(-math.Log((float64(i)+0.5)/1024) * 65536)
	}
	vars := map[string]any{"sample_bytes": s.SampleBytes, "libc_lo": lo, "libc_hi": hi, "exp_tab": tab}
	if al != nil {
		vars["alloc_lo"], vars["alloc_hi"] = al.lo, al.hi
	}
	for k, v := range vars {
		if err := spec.Variables[k].Set(v); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
	}
	s.coll, err = ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("BPF verifier: %+v", ve)
		}
		return err
	}
	for _, p := range probes {
		offs, path := allocOffs, allocPath
		if p.mmap { // libc's, unless the allocator overrides it (callers bind to the allocator's)
			offs, path = libcOffs, s.Libc
			if _, ok := allocOffs[p.syms[0]]; ok && al != nil {
				offs, path = allocOffs, allocPath
				s.MmapIn = allocPath
			}
		}
		target := root(path)
		var addrs []uint64
		seen := map[uint64]bool{}
		for _, name := range p.syms {
			if o, ok := offs[name]; ok && !seen[o] {
				seen[o] = true
				addrs = append(addrs, o)
			}
		}
		if len(addrs) == 0 && p.prog != "malloc_s" && p.prog != "free_e" && al != nil {
			continue // an allocator without e.g. pvalloc or posix_memalign
		}
		if len(addrs) == 0 {
			s.Close()
			return fmt.Errorf("%s: none of %v found", path, p.syms)
		}
		typ := uint32(attachUprobeSession)
		if strings.HasSuffix(p.prog, "_e") || s.Legacy {
			typ = attachUprobeMulti
		}
		fd, err := attach(s.coll.Programs[p.prog], target, addrs, typ, 0, s.PID)
		if err != nil {
			s.Close()
			return fmt.Errorf("attach %s to %s: %w", p.prog, path, err)
		}
		s.links = append(s.links, fd)
		if s.Legacy && strings.HasSuffix(p.prog, "_s") { // the return half, on every call
			ret := "alloc_r"
			if p.prog == "mmap_s" {
				ret = "mmap_r"
			}
			fd, err := attach(s.coll.Programs[ret], target, addrs, attachUprobeMulti, uprobeMultiReturn, s.PID)
			if err != nil {
				s.Close()
				return fmt.Errorf("attach %s to %s: %w", ret, path, err)
			}
			s.links = append(s.links, fd)
		}
	}
	if s.rd, err = ringbuf.NewReader(s.coll.Maps["events"]); err != nil {
		s.Close()
		return err
	}
	s.tr = track.New(s.PID, s.Sym)
	s.tr.Area = s.Area
	return nil
}

func (s *Source) Close() {
	for _, fd := range s.links {
		unix.Close(fd)
	}
	s.links = nil
	if s.rd != nil {
		s.rd.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
}

// SetEnabled toggles sampling. Probes stay attached: an unsampled call still costs one uprobe hit.
func (s *Source) SetEnabled(on bool) {
	v := uint32(0)
	if on {
		v = 1
	}
	s.coll.Variables["enabled"].Set(v)
}

func (s *Source) counter(name string) uint64 {
	var v uint64
	s.coll.Variables[name].Get(&v)
	return v
}

func (s *Source) Run(ctx context.Context, out chan<- model.Tick) error {
	defer s.Close()
	poll := s.Poll
	if poll == 0 {
		poll = 20 * time.Millisecond
	}
	R := float64(s.SampleBytes)
	var rec ringbuf.Record
	for {
		acc := track.Acc{}
		s.rd.SetDeadline(time.Now().Add(poll))
		for {
			err := s.rd.ReadInto(&rec)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return err
			}
			b := rec.RawSample
			if len(b) < track.SlotSize {
				continue
			}
			if binary.LittleEndian.Uint32(b[8:]) == track.EvAlloc {
				n := float64(binary.LittleEndian.Uint64(b[24:]))
				binary.LittleEndian.PutUint64(b[32:], uint64(n/-math.Expm1(-n/R)))
			} else {
				copy(b[32:40], b[24:32]) // mmap weight = length
			}
			s.tr.Event(b, acc)
			if ctx.Err() != nil {
				break
			}
		}
		t := model.Tick{T: time.Now(), Allocs: acc.Deltas(), Tracer: &model.TracerStats{
			Name: "ebpf", Sampled: s.counter("sampled"), Drops: s.counter("drops"), TableDrops: s.counter("table_drops"),
			Backlog: uint64(s.rd.AvailableBytes() / track.SlotSize), SampleRate: s.SampleBytes, LivePtrs: s.tr.Live(),
		}}
		t.PeakRise, t.AreaRise = s.tr.TakePeak()
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

// libcText finds the executable mapping of libc in the target.
func libcText(pid int) (lo, hi uint64, path string, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, 0, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || !strings.Contains(fl[1], "x") || !strings.HasPrefix(filepath.Base(fl[5]), "libc.so") {
			continue
		}
		a, b, _ := strings.Cut(fl[0], "-")
		lo, _ = strconv.ParseUint(a, 16, 64)
		hi, _ = strconv.ParseUint(b, 16, 64)
		return lo, hi, fl[5], nil
	}
	return 0, 0, "", fmt.Errorf("pid %d: no libc.so mapping (static binary or other allocator?)", pid)
}

type allocLib struct {
	path   string
	lo, hi uint64 // text mapping in the target
	offs   map[string]uint64
}

// allocator finds the object providing malloc in the target when it is not libc: a mapped library or the binary
// itself (statically linked jemalloc, exported by -rdynamic) whose dynamic symbols define malloc and free. With
// several, the one in the target's LD_PRELOAD wins (it binds first). nil means glibc's malloc.
func allocator(pid int, libc string) (*allocLib, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	text := map[string]*allocLib{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || !strings.Contains(fl[1], "x") || !strings.HasPrefix(fl[5], "/") || fl[5] == libc {
			continue
		}
		base := filepath.Base(fl[5])
		if strings.HasPrefix(base, "ld-linux") || strings.HasPrefix(base, "ld64") || strings.HasPrefix(base, "libmhp") {
			continue
		}
		a, b, _ := strings.Cut(fl[0], "-")
		lo, _ := strconv.ParseUint(a, 16, 64)
		hi, _ := strconv.ParseUint(b, 16, 64)
		if l := text[fl[5]]; l != nil {
			l.lo, l.hi = min(l.lo, lo), max(l.hi, hi)
			continue
		}
		text[fl[5]] = &allocLib{path: fl[5], lo: lo, hi: hi}
		order = append(order, fl[5])
	}
	var found []*allocLib
	for _, p := range order {
		offs, err := symbolOffsets(fmt.Sprintf("/proc/%d/root%s", pid, p))
		if err != nil {
			continue
		}
		_, m := offs["malloc"]
		_, fr := offs["free"]
		if m && fr {
			text[p].offs = offs
			found = append(found, text[p])
		}
	}
	if len(found) <= 1 {
		if len(found) == 1 {
			return found[0], nil
		}
		return nil, nil
	}
	env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	for _, e := range strings.Split(string(env), "\x00") {
		if v, ok := strings.CutPrefix(e, "LD_PRELOAD="); ok {
			for _, pre := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' }) {
				for _, l := range found {
					if filepath.Base(l.path) == filepath.Base(pre) {
						return l, nil
					}
				}
			}
		}
	}
	return found[0], nil
}

// symbolOffsets maps dynamic function symbols of an ELF file to file offsets (what uprobes take).
func symbolOffsets(path string) (map[string]uint64, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	out := map[string]uint64{}
	for _, sy := range syms {
		if sy.Value == 0 || sy.Section == 0 {
			continue
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && sy.Value >= p.Vaddr && sy.Value < p.Vaddr+p.Memsz {
				out[sy.Name] = sy.Value - p.Vaddr + p.Off
			}
		}
	}
	return out, nil
}

// attach creates a uprobe_multi (or session) link for prog on path at the given file offsets, limited to pid.
// uprobeMultiReturn is BPF_F_UPROBE_MULTI_RETURN: attach at function return.
const uprobeMultiReturn = 1

func attach(prog *ebpf.Program, path string, offsets []uint64, typ, flags uint32, pid int) (int, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	// union bpf_attr, link_create with uprobe_multi
	var attr struct {
		progFd, targetFd, attachType, flags   uint32
		path, offsets, refCtrOffsets, cookies uint64
		cnt, umFlags, pid, _                  uint32
	}
	attr.progFd = uint32(prog.FD())
	attr.attachType = typ
	attr.path = uint64(uintptr(unsafe.Pointer(p)))
	attr.offsets = uint64(uintptr(unsafe.Pointer(&offsets[0])))
	attr.cnt = uint32(len(offsets))
	attr.pid = uint32(pid)
	attr.umFlags = flags
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_LINK_CREATE, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(p) // the kernel reads both during the syscall
	runtime.KeepAlive(offsets)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
