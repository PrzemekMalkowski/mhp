package ebpf

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"mhp/internal/model"
	"mhp/internal/perf"
	"mhp/internal/sym"
)

//go:embed faults.bpf.o
var faultsObject []byte

const (
	pageSize  = 4096
	maxLeaf   = 1024
	inserted  = 1 << 63 // tag on a frame added by the leaf fix
	idleTicks = 120     // drop counters of (stack, tid, class) idle this long, so exited threads do not fill the map
)

var batchSize = 4096 // counters per batch-lookup syscall (a variable for tests)

// Region classes as numbered in bpf/faults.bpf.c; names follow procfs.ClassOf.
var classNames = []string{"unknown", "anon-mmap", "heap(brk)", "stack", "file", "shmem", "other"}

type fkey struct {
	Stack      uint64
	TID, Class uint32
}

// FaultSource counts page faults of the target per (user stack, thread, region class) in the kernel
// (bpf/faults.bpf.c). Unlike perf.FaultSource it has no per-fault records to lose, classifies the mapping at fault
// time (so short-lived mappings are named), and needs no cgroup for scoping.
type FaultSource struct {
	PID  int
	Poll time.Duration // counter read interval (default 250 ms)
	Sym  *sym.Symbolizer

	Leaves   int   // frameless libc routines whose caller is recovered from [sp]
	BatchErr error // why the counters are read one by one (nil: batch reads)

	noBatch bool
	keys    []fkey
	vals    []uint64

	coll   *ebpf.Collection
	links  []link.Link
	prev   map[fkey]uint64
	idle   map[fkey]int
	stacks map[[2]uint64][]string // (stack hash, class) -> root-first frames
	comms  map[int]string
}

func (s *FaultSource) Open() error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(faultsObject))
	if err != nil {
		return err
	}
	leaves := s.Sym.Ranges(func(p string) bool { return strings.HasPrefix(filepath.Base(p), "libc.so") },
		perf.LeafNoFP.MatchString)
	if len(leaves) > maxLeaf {
		leaves = leaves[:maxLeaf]
	}
	s.Leaves = len(leaves)
	var lo, hi [maxLeaf]uint64
	for i, r := range leaves {
		lo[i], hi[i] = r[0], r[1]
	}
	clo, chi, _, err := libcText(s.PID)
	if err != nil {
		clo, chi = 0, 0 // no libc: only the mem*/str* leaf fix (also none) applies
	}
	for k, v := range map[string]any{"tgid": uint32(s.PID), "nleaf": uint32(len(leaves)), "leaf_lo": lo, "leaf_hi": hi,
		"libc_lo": clo, "libc_hi": chi} {
		if err := spec.Variables[k].Set(v); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
	}
	if s.coll, err = ebpf.NewCollection(spec); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("BPF verifier: %+v", ve)
		}
		return err
	}
	for _, p := range []string{"pf"} {
		l, err := link.AttachTracing(link.TracingOptions{Program: s.coll.Programs[p]})
		if err != nil {
			s.Close()
			return fmt.Errorf("attach %s: %w", p, err)
		}
		s.links = append(s.links, l)
	}
	s.prev, s.idle = map[fkey]uint64{}, map[fkey]int{}
	s.stacks, s.comms = map[[2]uint64][]string{}, map[int]string{}
	return nil
}

func (s *FaultSource) Close() {
	if s.coll != nil {
		log.Printf("BPF page faults: %d counted (%d in kernel mode or get_user_pages)", s.counter("faults"), s.counter("kernel_faults"))
	}
	for _, l := range s.links {
		l.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
	}
}

func (s *FaultSource) counter(name string) uint64 {
	var v uint64
	s.coll.Variables[name].Get(&v)
	return v
}

func (s *FaultSource) Run(ctx context.Context, out chan<- model.Tick) error {
	defer s.Close()
	poll := s.Poll
	if poll == 0 {
		poll = 250 * time.Millisecond
	}
	tk := time.NewTicker(poll)
	defer tk.Stop()
	counts := s.coll.Maps["counts"]
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
		}
		acc := map[fkey]*model.AllocDelta{}
		seen := map[fkey]bool{}
		s.readCounts(counts, func(k fkey, v uint64) {
			if seen[k] { // a batch read can return an entry twice when the table changes under it
				return
			}
			seen[k] = true
			d := v - s.prev[k]
			if d == 0 {
				s.idle[k]++
				return
			}
			s.prev[k], s.idle[k] = v, 0
			acc[k] = &model.AllocDelta{Kind: model.KindFault, Stack: s.frames(k), TID: int(k.TID),
				Thread: s.comm(int(k.TID)), Alloc: int64(d * pageSize), N: int64(d)}
		})
		for k, n := range s.idle {
			if !seen[k] || n >= idleTicks { // a few faults between our read and the delete are lost
				if seen[k] {
					counts.Delete(k)
				}
				delete(s.idle, k)
				delete(s.prev, k)
			}
		}
		t := model.Tick{T: time.Now(), Tracer: &model.TracerStats{
			Name: "bpf page-faults", Sampled: s.counter("faults"), Drops: s.counter("count_drops"),
			TableDrops: s.counter("stack_drops"), LivePtrs: len(s.prev),
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

// readCounts calls f for every counter. It reads the table in batches (one syscall per batchSize entries; Linux
// 5.6+) and falls back to one entry at a time (two syscalls each) where the kernel has no batch lookup.
func (s *FaultSource) readCounts(counts *ebpf.Map, f func(fkey, uint64)) {
	if !s.noBatch {
		if s.keys == nil {
			s.keys, s.vals = make([]fkey, batchSize), make([]uint64, batchSize)
		}
		var cur ebpf.MapBatchCursor
		for {
			n, err := counts.BatchLookup(&cur, s.keys, s.vals, nil)
			for i := range n {
				f(s.keys[i], s.vals[i])
			}
			if errors.Is(err, ebpf.ErrKeyNotExist) { // end of the table
				return
			}
			if err != nil {
				// Not supported, or one hash bucket holds more than a batch: entries seen so far are counted,
				// the rest by the walk below (f ignores the repeats).
				s.noBatch = true
				s.BatchErr = err
				log.Printf("BPF page-fault counters: batch read failed (%v), reading one by one", err)
				break
			}
		}
	}
	var k fkey
	var v uint64
	it := counts.Iterate()
	for it.Next(&k, &v) {
		f(k, v)
	}
}

// frames symbolizes a stack hash once per region class; the leaf pseudo-frame names the faulting mapping.
func (s *FaultSource) frames(k fkey) []string {
	ck := [2]uint64{k.Stack, uint64(k.Class)}
	if fr, ok := s.stacks[ck]; ok {
		return fr
	}
	class := "unknown"
	if int(k.Class) < len(classNames) {
		class = classNames[k.Class]
	}
	region := "[fault: " + class + "]"
	var st [64]uint64
	var fr []string
	if err := s.coll.Maps["stacks"].Lookup(k.Stack, &st); err != nil {
		fr = []string{"[stack table full]", region}
	} else {
		n := 0
		for n < len(st) && st[n] != 0 {
			n++
		}
		chain := st[:n]
		if n > 1 && st[1]&inserted != 0 { // return address recovered from [sp] (leaf fix): keep it only if in code
			if ra := st[1] &^ inserted; s.Sym.IsCode(ra) {
				st[1] = ra
			} else {
				chain = append(st[:1:1], st[2:n]...)
			}
		}
		if len(chain) > 0 {
			chain[0]++ // Frames() looks up addr-1 (return addresses); the IP is exact
		}
		fr = append(s.Sym.Frames(chain), region)
	}
	s.stacks[ck] = fr
	return fr
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
