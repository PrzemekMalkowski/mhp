// Package track turns sampled allocation events (libmhp ring slots, eBPF records) into live-bytes deltas:
// it remembers sampled pointers and anonymous mappings, and interns and symbolizes their stacks.
package track

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/PrzemekMalkowski/mhp/internal/model"
	"github.com/PrzemekMalkowski/mhp/internal/sym"
)

// Event types and layout mirror shim/mhp_ring.h (slot: commit, type, tid, ptr, size, weight, depth, frames).
const (
	EvAlloc  = 1
	EvFree   = 2
	EvMmap   = 3
	EvMunmap = 4
	MaxDepth = 62
	SlotSize = 48 + 8*MaxDepth
)

type live struct {
	key    string // stack key
	tid    int
	weight int64
}

type region struct {
	start, len uint64
	key        string
	tid        int
}

type Tracker struct {
	PID  int
	Sym  *sym.Symbolizer
	Area func(stack []string) string // optional: sub-system of a stack, for per-area peaks

	ptrs    map[uint64]live
	regions map[uint64]*region
	stacks  map[string][]string // raw-address key -> symbolized root-first frames
	comms   map[int]string      // tid -> comm at first sight (threads may exit before /proc polling sees them)

	cur, base, hi int64 // running live total in event order; its value and maximum since TakePeak
	areas         map[string]*areaRun
	areaOf        map[string]*areaRun // stack key -> its area's counters
}

type areaRun struct{ cur, base, hi int64 }

func New(pid int, sy *sym.Symbolizer) *Tracker {
	return &Tracker{PID: pid, Sym: sy, ptrs: map[uint64]live{}, regions: map[uint64]*region{},
		stacks: map[string][]string{}, comms: map[int]string{}, areas: map[string]*areaRun{}, areaOf: map[string]*areaRun{}}
}

// Live is the number of sampled pointers currently held.
func (t *Tracker) Live() int { return len(t.ptrs) }

// TakePeak returns how far the live total rose above its value at the previous call, at its highest point, and the
// same per area (only areas that rose; nil without Area).
func (t *Tracker) TakePeak() (int64, map[string]int64) {
	r := t.hi - t.base
	t.base, t.hi = t.cur, t.cur
	var by map[string]int64
	for name, a := range t.areas {
		if a.hi > a.base {
			if by == nil {
				by = map[string]int64{}
			}
			by[name] = a.hi - a.base
		}
		a.base, a.hi = a.cur, a.cur
	}
	return r, by
}

// Acc collects deltas per (stack, tid) between ticks.
type Acc map[[2]any]*model.AllocDelta

func (a Acc) Deltas() []model.AllocDelta {
	out := make([]model.AllocDelta, 0, len(a))
	for _, d := range a {
		out = append(out, *d)
	}
	return out
}

// stack interns a raw leaf-first frame block (keyed by its bytes) and symbolizes it once.
func (t *Tracker) stack(raw []byte, mmap bool) string {
	k := string(raw)
	if mmap {
		k += "m"
	}
	if _, ok := t.stacks[k]; !ok {
		addrs := make([]uint64, len(raw)/8)
		for i := range addrs {
			addrs[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		fr := t.Sym.Frames(addrs)
		if mmap {
			fr = append(fr, "[anon mmap]")
		}
		t.stacks[k] = fr
		if t.Area != nil {
			name := t.Area(fr)
			a := t.areas[name]
			if a == nil {
				a = &areaRun{}
				t.areas[name] = a
			}
			t.areaOf[k] = a
		}
	}
	return k
}

func (t *Tracker) add(acc Acc, key string, tid int, alloc, free, size int64) {
	k := [2]any{key, tid}
	d := acc[k]
	if d == nil {
		d = &model.AllocDelta{Stack: t.stacks[key], TID: tid, Thread: t.comm(tid)}
		acc[k] = d
	}
	d.Alloc += alloc
	d.Free += free
	if alloc > 0 {
		d.N++
		d.Max = max(d.Max, size)
	}
	t.cur += alloc - free
	t.hi = max(t.hi, t.cur)
	if a := t.areaOf[key]; a != nil {
		a.cur += alloc - free
		a.hi = max(a.hi, a.cur)
	}
}

func (t *Tracker) comm(tid int) string {
	c, ok := t.comms[tid]
	if !ok {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/comm", t.PID, tid))
		if err == nil {
			c = strings.TrimSpace(string(b))
		}
		t.comms[tid] = c
	}
	return c
}

// Event applies one slot-layout record.
func (t *Tracker) Event(b []byte, acc Acc) {
	le := binary.LittleEndian
	typ := le.Uint32(b[8:])
	tid := int(le.Uint32(b[12:]))
	ptr := le.Uint64(b[16:])
	size := le.Uint64(b[24:])
	weight := int64(le.Uint64(b[32:]))
	depth := int(le.Uint16(b[40:]))
	if depth > MaxDepth {
		depth = MaxDepth
	}
	raw := b[48 : 48+8*depth]
	switch typ {
	case EvAlloc:
		key := t.stack(raw, false)
		if old, ok := t.ptrs[ptr]; ok { // missed free (e.g. table probe limit): retire the old one
			t.add(acc, old.key, old.tid, 0, old.weight, 0)
		}
		t.ptrs[ptr] = live{key: key, tid: tid, weight: weight}
		t.add(acc, key, tid, weight, 0, int64(size))
	case EvFree:
		if l, ok := t.ptrs[ptr]; ok {
			delete(t.ptrs, ptr)
			t.add(acc, l.key, l.tid, 0, l.weight, 0)
		}
	case EvMmap:
		key := t.stack(raw, true)
		t.unmap(ptr, size, acc) // MAP_FIXED over an existing tracked range
		t.regions[ptr] = &region{start: ptr, len: size, key: key, tid: tid}
		t.add(acc, key, tid, int64(size), 0, int64(size))
	case EvMunmap:
		t.unmap(ptr, size, acc)
	}
}

// unmap releases [a, a+n) from tracked regions, splitting partially covered ones.
func (t *Tracker) unmap(a, n uint64, acc Acc) {
	end := a + n
	for start, r := range t.regions {
		rend := r.start + r.len
		if rend <= a || r.start >= end {
			continue
		}
		lo, hi := max(r.start, a), min(rend, end)
		t.add(acc, r.key, r.tid, 0, int64(hi-lo), 0)
		delete(t.regions, start)
		if r.start < lo {
			t.regions[r.start] = &region{start: r.start, len: lo - r.start, key: r.key, tid: r.tid}
		}
		if hi < rend {
			t.regions[hi] = &region{start: hi, len: rend - hi, key: r.key, tid: r.tid}
		}
	}
}
