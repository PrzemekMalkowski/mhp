package agg

import (
	"mhp/internal/classify"

	"time"

	"mhp/internal/model"
)

// Dump is the aggregator state the UI's queries need, for an offline copy: the stack table, thread names, the
// current per-stack values (live, allocated total, growth window) and the retained timeline. Frame names are
// interned; stacks refer to them by index.
type Dump struct {
	Frames     []string
	Stacks     []DumpStack
	Threads    []DumpThread
	Entries    []DumpEntry
	Ticks      []DumpTick
	GrowthSecs int
	Dropped    int64 // see Agg.dropped
}

type DumpStack struct {
	F    []int32 // root first, indexes into Frames
	Sub  string
	Area string // with its sub-area ("" in copies made before 0.1.7: classified again on load)
}

type DumpThread struct {
	TID        int
	Comm, Role string
}

type DumpEntry struct {
	SID, TID               int32
	Kind                   model.Kind
	Live, AllocCum, Growth int64
}

type DumpTick struct {
	T         int64
	End, Peak map[string]int64
	Recs      []DumpRec
}

type DumpRec struct {
	SID, TID            int32
	Kind                model.Kind
	Alloc, Free, N, Max int64
}

// Export copies the state under the lock; the timeline frames are immutable once closed, so they are shared.
func (a *Agg) Export() *Dump {
	a.mu.Lock()
	stacks := a.stacks
	frames := a.frames
	d := &Dump{GrowthSecs: a.growthSecs, Dropped: a.dropped}
	for tid, t := range a.threads {
		d.Threads = append(d.Threads, DumpThread{TID: tid, Comm: t.comm, Role: t.role})
	}
	for k, e := range a.entries {
		d.Entries = append(d.Entries, DumpEntry{SID: int32(k.sid), TID: int32(k.tid), Kind: k.kind, Live: e.live,
			AllocCum: e.allocCum, Growth: e.growth(a.markPos)})
	}
	a.mu.Unlock()

	ids := map[string]int32{}
	for _, s := range stacks {
		ds := DumpStack{F: make([]int32, len(s.frames)), Sub: s.subsys, Area: s.area}
		for i, f := range s.frames {
			id, ok := ids[f]
			if !ok {
				id = int32(len(d.Frames))
				ids[f] = id
				d.Frames = append(d.Frames, f)
			}
			ds.F[i] = id
		}
		d.Stacks = append(d.Stacks, ds)
	}
	for _, fr := range frames {
		t := DumpTick{T: fr.t, End: fr.end, Peak: fr.peak, Recs: make([]DumpRec, len(fr.recs))}
		for i, r := range fr.recs {
			t.Recs[i] = DumpRec{SID: int32(r.k.sid), TID: int32(r.k.tid), Kind: r.k.kind, Alloc: r.alloc, Free: r.free, N: r.n, Max: r.max}
		}
		d.Ticks = append(d.Ticks, t)
	}
	return d
}

// Restore rebuilds a query-only aggregator (Stacks, Range, RangeThreads, Folded) from a Dump.
func Restore(d *Dump) *Agg {
	a := New(nil, d.GrowthSecs)
	a.start = time.Time{}
	a.dropped = d.Dropped
	for _, s := range d.Stacks {
		fr := make([]string, len(s.F))
		for i, id := range s.F {
			fr[i] = d.Frames[id]
		}
		area := s.Area
		if area == "" { // a copy from before 0.1.7: sub-areas by the built-in rules
			if a.cls == nil {
				a.cls, _ = classify.New("")
			}
			area = a.cls.Full(fr, s.Sub)
		}
		a.stacks = append(a.stacks, stackInfo{frames: fr, subsys: s.Sub, area: area})
	}
	for _, t := range d.Threads {
		a.threads[t.TID] = &thread{comm: t.Comm, role: t.Role}
	}
	for _, e := range d.Entries {
		x := &entry{live: e.Live, allocCum: e.AllocCum}
		for i := range x.mark {
			x.mark[i] = e.Live - e.Growth
		}
		a.entries[entKey{sid: int(e.SID), tid: int(e.TID), kind: e.Kind}] = x
	}
	for _, t := range d.Ticks {
		fr := tframe{t: t.T, end: t.End, peak: t.Peak, recs: make([]rangeRec, len(t.Recs))}
		for i, r := range t.Recs {
			fr.recs[i] = rangeRec{k: entKey{sid: int(r.SID), tid: int(r.TID), kind: r.Kind}, alloc: r.Alloc, free: r.Free, n: r.N, max: r.Max}
		}
		a.frames = append(a.frames, fr)
		a.frameRecs += len(fr.recs)
	}
	return a
}
