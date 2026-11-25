// Package live holds the View type and a Hub that keeps history and fans out to subscribers.
package live

import (
	"sync"
	"sync/atomic"

	"mhp/internal/model"
)

type StackRow struct {
	Stack     []string `json:"stack"`
	Thread    string   `json:"thread,omitempty"`
	Subsystem string   `json:"subsystem"`
	Area      string   `json:"area,omitempty"` // with its sub-area: "InnoDB · buffer pool"
	Live      int64    `json:"live"`
	Growth    int64    `json:"growth"` // live-bytes change over the growth window
}

// ThreadRow is the pidstat-like per-thread line. Live/Growth/AllocRate attribute sampled
// allocations to the allocating thread (memory freed by another thread is credited back to it).
type ThreadRow struct {
	TID        int              `json:"tid"`
	Comm       string           `json:"comm"`
	Role       string           `json:"role"`
	Alive      bool             `json:"alive"`
	Live       int64            `json:"live"`
	Growth     int64            `json:"growth"`
	AllocRate  int64            `json:"alloc_rate"`
	FreeRate   int64            `json:"free_rate"`
	MinFltRate float64          `json:"minflt_s"`
	MajFltRate float64          `json:"majflt_s"`
	MinFlt     uint64           `json:"minflt"`
	MajFlt     uint64           `json:"majflt"`
	CPUPct     float64          `json:"cpu"`
	FaultRate  int64            `json:"fault_rate"` // perf: bytes of pages faulted in per second
	Faulted    int64            `json:"faulted"`    // perf: cumulative since attach
	FaultWin   int64            `json:"fault_win"`  // perf: within the growth window
	PFS        *model.PFSThread `json:"pfs,omitempty"`
}

// View is one UI frame (one per aggregation interval).
type View struct {
	T          int64               `json:"t"` // unix ms
	Proc       map[string]int64    `json:"proc"`
	Regions    map[string]int64    `json:"regions"`
	BySubsys   map[string]int64    `json:"by_subsys"`
	ByArea     map[string]int64    `json:"by_area,omitempty"` // by sub-system and sub-area ("InnoDB · buffer pool")
	ByThread   map[string]int64    `json:"by_thread"`
	Traced     int64               `json:"traced"`                // sum of live bytes seen by the tracer
	TracedPeak int64               `json:"traced_peak,omitempty"` // highest traced live since the previous view (event order)
	HasTrace   bool                `json:"has_trace"`
	Gap        int64               `json:"gap"` // RSS anon minus traced live bytes (only if HasTrace)
	AllocRate  int64               `json:"alloc_rate"`
	FreeRate   int64               `json:"free_rate"`
	GrowthSecs int                 `json:"growth_secs"`
	Top        []StackRow          `json:"top"`
	Growers    []StackRow          `json:"growers"`
	Threads    []ThreadRow         `json:"threads"`
	Tracers    []model.TracerStats `json:"tracers,omitempty"`
	HasFaults  bool                `json:"has_faults"`
	PFS        *model.PFSStats     `json:"pfs,omitempty"`
	Heap       *model.HeapStats    `json:"heap,omitempty"`
	Arenas     *model.ArenaStats   `json:"arenas,omitempty"`   // glibc malloc_info read in this view (libmhp, glibc); kept in old views
	FaultRate  int64               `json:"fault_rate"`         // perf: bytes/s of pages faulted in
	Faulters   []StackRow          `json:"faulters,omitempty"` // perf: by faulted bytes in the window (Growth); Live = total
	// Paused: allocation tracing was paused from the UI at this view. Frees are still reported then, so the traced
	// series only fall; the chart leaves them out.
	Paused     bool             `json:"paused,omitempty"`
	RegionSwap map[string]int64 `json:"region_swap,omitempty"` // swapped-out bytes by mapping class (smaps; when any)
}

// Len is the number of views kept.
func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.hist)
}

type Hub struct {
	TracerPaused atomic.Bool // stamped on published views

	mu   sync.Mutex
	hist []View
	cap  int
	subs map[chan View]struct{}
	last *View
	// arenas is the latest malloc_info seen
	arenas *model.ArenaStats
}

// Detail is how many of the newest views keep their tables (threads, stacks, PFS, tracers): the UI's sparklines
// look back 120 views and everything else uses the last one. Older views keep only what the timeline chart needs,
// which cuts a view from ~50 KB (100+ threads) to ~2 KB.
const Detail = 120

func (v *View) slim() {
	// Arenas stay: one reading per 30 s or more, for the arenas panel at a selected time (ArenasAt)
	v.Threads, v.Top, v.Growers, v.Faulters, v.Tracers, v.PFS, v.Heap = nil, nil, nil, nil, nil, nil, nil
}

func NewHub(capacity int) *Hub {
	return &Hub{cap: capacity, subs: map[chan View]struct{}{}}
}

func (h *Hub) Publish(v View) {
	v.Paused = v.Paused || h.TracerPaused.Load()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hist = append(h.hist, v)
	if len(h.hist) > h.cap {
		h.hist = append([]View(nil), h.hist[len(h.hist)-h.cap:]...)
	}
	if v.Arenas != nil {
		h.arenas = v.Arenas
	}
	if n := len(h.hist) - 1 - Detail; n >= 0 {
		h.hist[n].slim()
	}
	h.last = &h.hist[len(h.hist)-1]
	for ch := range h.subs {
		select {
		case ch <- v:
		default: // slow consumer: drop frame
		}
	}
}

func (h *Hub) History() []View {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]View(nil), h.hist...)
}

// HistoryNoArenas is History without the malloc_info readings (the UI's /history: the panel asks /arenas?t=).
func (h *Hub) HistoryNoArenas() []View {
	out := h.History()
	for i := range out {
		out[i].Arenas = nil
	}
	return out
}

// ArenasAt returns the malloc_info reading taken at or before t (unix ms), or nil if none is kept from then.
func (h *Hub) ArenasAt(t int64) *model.ArenaStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.hist) - 1; i >= 0; i-- {
		if a := h.hist[i].Arenas; a != nil && a.T <= t {
			return a
		}
	}
	return nil
}

// Arenas returns the latest malloc_info seen (nil if none).
func (h *Hub) Arenas() *model.ArenaStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.arenas
}

func (h *Hub) Last() *View {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.last
}

// Subscribe returns a channel and a cancel func.
func (h *Hub) Subscribe() (<-chan View, func()) {
	ch := make(chan View, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}
