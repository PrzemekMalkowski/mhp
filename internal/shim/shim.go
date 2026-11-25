// Package shim reads the shared-memory ring written by libmhp.so (see shim/mhp_ring.h).
package shim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/PrzemekMalkowski/mhp/internal/model"
	"github.com/PrzemekMalkowski/mhp/internal/sym"
	"github.com/PrzemekMalkowski/mhp/internal/track"
)

// Offsets mirror shim/mhp_ring.h.
const (
	magic        = 0x3152504d48
	hdrSize      = 4096
	offSlotSz    = 12
	offNSlots    = 16
	offHead      = 24
	offTail      = 32
	offDrops     = 40
	offEnabled   = 48
	offGen       = 52
	offSample    = 56
	offTDrops    = 72
	offSampled   = 80
	offArmed     = 88
	offInject    = 92
	offRescan    = 104
	offAllocKind = 120
	offStatReq   = 256
	offStatSeq   = 272
	offStatNs    = 280
	offMI        = 288
	offArReq     = 384
	offArSeq     = 400
	offArNs      = 408
	offArLen     = 416
	offAuxOff    = 424
	offAuxCap    = 432
	version      = 3
	offVersion   = 8
)

func RingPath(pid int) string { return fmt.Sprintf("/dev/shm/mhp.%d", pid) }

// The allocator underneath libmhp (header field alloc_kind).
const (
	allocGlibc = iota
	allocJemalloc
	allocTcmalloc
	allocOther
)

var allocNames = map[uint32]string{allocGlibc: "glibc", allocJemalloc: "jemalloc", allocTcmalloc: "tcmalloc"}

// heapStats decodes the statistics libmhp took from the allocator (ring header field mi).
func heapStats(kind uint32, mi func(uint64) int64, costNs int64) *model.HeapStats {
	h := &model.HeapStats{Allocator: allocNames[kind], CostNs: costNs}
	switch kind {
	case allocGlibc:
		h.Arena, h.FreeChunks, h.MmapChunks, h.Mmapped = mi(0), mi(1), mi(3), mi(4)
		h.FastFree, h.InUse, h.Free, h.Releasable = mi(6), mi(7), mi(8), mi(9)
	case allocJemalloc:
		h.InUse, h.Active, h.Metadata, h.Resident, h.Mapped, h.Retained = mi(0), mi(1), mi(2), mi(3), mi(4), mi(5)
		h.Free = max(0, h.Resident-h.InUse-h.Metadata)
	case allocTcmalloc:
		h.InUse, h.HeapSize, h.PageHeapFree, h.Unmapped = mi(0), mi(1), mi(2), mi(3)
		h.CentralFree, h.TransferFree, h.ThreadFree = mi(4), mi(5), mi(6)
		h.Free = h.PageHeapFree + h.CentralFree + h.TransferFree + h.ThreadFree
	default:
		return nil
	}
	return h
}

// Ring states (header field inject).
const (
	Preloaded  = 0 // LD_PRELOAD: libmhp interposes from the start
	Injected   = 1 // mhp watch -inject: calls redirected
	Undone     = 2 // injected, then detached: nothing is recorded
	NoRing     = -1
	StaleRing  = -2 // a ring file, but pid does not map it: left by an earlier process with the same pid
	unreadable = -3
)

// RingState tells how pid's ring (if any) is fed.
func RingState(pid int) int {
	f, err := os.Open(RingPath(pid))
	if err != nil {
		return NoRing
	}
	defer f.Close()
	if m, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)); err == nil && !bytes.Contains(m, []byte(" "+RingPath(pid)+"\n")) {
		return StaleRing
	}
	var h [hdrSize]byte
	if _, err := f.ReadAt(h[:], 0); err != nil || *(*uint64)(unsafe.Pointer(&h[0])) != magic {
		return unreadable
	}
	return int(*(*uint32)(unsafe.Pointer(&h[offInject])))
}

// AllocKind names the allocator libmhp found underneath it in pid ("glibc", "jemalloc", "tcmalloc", "other"),
// "" when pid has no ring.
func AllocKind(pid int) string {
	f, err := os.Open(RingPath(pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	var h [hdrSize]byte
	if _, err := f.ReadAt(h[:], 0); err != nil || *(*uint64)(unsafe.Pointer(&h[0])) != magic {
		return ""
	}
	if n, ok := allocNames[*(*uint32)(unsafe.Pointer(&h[offAllocKind]))]; ok {
		return n
	}
	return "other"
}

type Source struct {
	StatsEvery time.Duration // interval of requests for the allocator's heap statistics (0 = off)
	// ArenasEvery is the shortest interval between glibc malloc_info() requests (per-arena detail; 0 = off). It is
	// stretched to 200x what the last one took in the target, so a huge heap is not walked too often.
	ArenasEvery time.Duration
	PID         int
	FromStart   bool // consume what is already in the ring (launch mode); else start fresh (attach)
	// IfComplete (attach): consume the ring from its start anyway when it still holds everything since the target
	// started: sampling was on from the start (MHP_START=1), no collector has read it and nothing was dropped.
	// Open then sets FromStart.
	IfComplete bool
	Poll       time.Duration
	Sym        *sym.Symbolizer
	Area       func([]string) string // sub-system of a stack, for per-area peaks (optional)

	arenasNow atomic.Bool // RequestArenas: ask now (peak capture, UI refresh)

	mem    []byte
	nslots uint64
	slotSz uint64
	tr     *track.Tracker
}

func (s *Source) u64(off uint64) *uint64 { return (*uint64)(unsafe.Pointer(&s.mem[off])) }
func (s *Source) u32(off uint64) *uint32 { return (*uint32)(unsafe.Pointer(&s.mem[off])) }

// Open maps the ring; it waits up to `wait` for the target to create it.
func (s *Source) Open(wait time.Duration) error {
	path := RingPath(s.PID)
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			defer f.Close()
			st, _ := f.Stat()
			if st.Size() > hdrSize {
				s.mem, err = syscall.Mmap(int(f.Fd()), 0, int(st.Size()), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
				if err != nil {
					return err
				}
				if atomic.LoadUint64(s.u64(0)) == magic {
					break
				}
				syscall.Munmap(s.mem)
			}
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("ring not initialised")
			}
			return fmt.Errorf("%s: %w (is the target running with LD_PRELOAD=libmhp.so?)", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v := *s.u32(offVersion); v != version {
		return fmt.Errorf("libmhp ring version %d, collector expects %d: rebuild both (make -C shim; go build)", v, version)
	}
	s.slotSz = uint64(*s.u32(offSlotSz))
	s.nslots = *s.u64(offNSlots)
	if s.slotSz != track.SlotSize || uint64(len(s.mem)) < hdrSize+s.nslots*s.slotSz {
		return fmt.Errorf("ring layout mismatch (slot %d)", s.slotSz)
	}
	s.tr = track.New(s.PID, s.Sym)
	s.tr.Area = s.Area
	if !s.FromStart && s.IfComplete && atomic.LoadUint32(s.u32(offGen)) == 1 && atomic.LoadUint64(s.u64(offTail)) == 0 &&
		atomic.LoadUint64(s.u64(offDrops)) == 0 && atomic.LoadUint32(s.u32(offEnabled)) == 1 {
		s.FromStart = true
	}
	if !s.FromStart {
		// New baseline: pointers sampled before now belong to an old generation and are ignored.
		atomic.StoreUint32(s.u32(offArmed), 0)
		atomic.AddUint32(s.u32(offGen), 1)
		atomic.StoreUint64(s.u64(offTail), atomic.LoadUint64(s.u64(offHead)))
	}
	atomic.StoreUint32(s.u32(offEnabled), 1)
	return nil
}

// SetEnabled pauses or resumes sampling inside the target (near-zero cost when off). Frees of pointers sampled
// earlier keep being reported while paused, so live bytes stay right across a pause.
// RequestArenas asks the target for a fresh malloc_info() at the next poll (glibc; the target answers on its
// next sampled allocation, so not while tracing is paused).
func (s *Source) RequestArenas() { s.arenasNow.Store(true) }

// HasArenas tells whether this ring can carry malloc_info() (glibc underneath libmhp).
func (s *Source) HasArenas() bool {
	return s.ArenasEvery > 0 && *s.u64(offAuxCap) > 0 && atomic.LoadUint32(s.u32(offAllocKind)) == allocGlibc
}

func (s *Source) SetEnabled(on bool) {
	v := uint32(0)
	if on {
		v = 1
	}
	atomic.StoreUint32(s.u32(offEnabled), v)
}

func (s *Source) Run(ctx context.Context, out chan<- model.Tick) error {
	defer syscall.Munmap(s.mem)
	defer s.SetEnabled(false)
	poll := s.Poll
	if poll == 0 {
		poll = 20 * time.Millisecond
	}
	tk := time.NewTicker(poll)
	defer tk.Stop()
	var stuckSince, lastReq, lastRescan, lastArReq time.Time
	var seenSeq, seenArSeq, arPending uint64
	var arCost time.Duration
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
		}
		acc := track.Acc{}
		tail := atomic.LoadUint64(s.u64(offTail))
		head := atomic.LoadUint64(s.u64(offHead))
		for tail < head {
			off := hdrSize + (tail%s.nslots)*s.slotSz
			if atomic.LoadUint64(s.u64(off)) != tail+1 {
				// producer still writing; if it never finishes (thread killed mid-write) skip the slot
				if stuckSince.IsZero() {
					stuckSince = time.Now()
				} else if time.Since(stuckSince) > time.Second {
					tail++
					stuckSince = time.Time{}
					continue
				}
				break
			}
			stuckSince = time.Time{}
			s.tr.Event(s.mem[off:off+s.slotSz], acc)
			tail++
		}
		atomic.StoreUint64(s.u64(offTail), tail)

		t := model.Tick{T: time.Now(), Tracer: &model.TracerStats{
			Name: "libmhp", Sampled: atomic.LoadUint64(s.u64(offSampled)), Drops: atomic.LoadUint64(s.u64(offDrops)),
			TableDrops: atomic.LoadUint64(s.u64(offTDrops)), Backlog: head - tail,
			SampleRate: *s.u64(offSample), LivePtrs: s.tr.Live(),
		}}
		t.Allocs = acc.Deltas()
		t.PeakRise, t.AreaRise = s.tr.TakePeak()
		if s.StatsEvery > 0 {
			if seq := atomic.LoadUint64(s.u64(offStatSeq)); seq != seenSeq {
				seenSeq = seq
				mi := func(i uint64) int64 { return int64(*s.u64(offMI + 8*i)) }
				t.Heap = heapStats(atomic.LoadUint32(s.u32(offAllocKind)), mi, int64(*s.u64(offStatNs)))
			}
			if time.Since(lastReq) >= s.StatsEvery {
				atomic.AddUint64(s.u64(offStatReq), 1)
				lastReq = time.Now()
			}
		}
		if s.ArenasEvery > 0 && *s.u64(offAuxCap) > 0 {
			if seq := atomic.LoadUint64(s.u64(offArSeq)); seq != seenArSeq && seq == arPending {
				seenArSeq = seq
				arCost = time.Duration(*s.u64(offArNs))
				if n := *s.u64(offArLen); n > 0 {
					off := *s.u64(offAuxOff)
					st, _ := ParseMallocInfo(s.mem[off : off+n])
					st.T, st.CostNs = time.Now().UnixMilli(), int64(arCost)
					t.Arenas = st
				}
			}
			every := max(s.ArenasEvery, 200*arCost)
			if arPending == seenArSeq && (time.Since(lastArReq) >= every || s.arenasNow.Swap(false)) {
				arPending = atomic.AddUint64(s.u64(offArReq), 1)
				lastArReq = time.Now()
			}
		}
		// injected: have objects loaded since (plugins, components) redirected too
		if atomic.LoadUint32(s.u32(offInject)) == Injected && time.Since(lastRescan) >= time.Second {
			atomic.AddUint64(s.u64(offRescan), 1)
			lastRescan = time.Now()
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
