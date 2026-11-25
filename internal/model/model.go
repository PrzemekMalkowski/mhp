// Package model holds the data types shared by sources, the aggregator and the UI.
package model

import (
	"context"
	"time"
)

// ProcStats is process-level memory accounting, normally from /proc.
type ProcStats struct {
	RSS         int64  `json:"rss"`
	Anon        int64  `json:"anon"`
	File        int64  `json:"file"`
	Shmem       int64  `json:"shmem"`
	Swap        int64  `json:"swap"`
	THP         int64  `json:"thp"`
	CgroupLimit int64  `json:"cgroup_limit"` // 0 = unlimited/unknown
	Threads     int    `json:"threads"`
	MinFlt      uint64 `json:"minflt"`
	MajFlt      uint64 `json:"majflt"`
	// glibc arena mappings from the last smaps read (0 when smaps is off or no arena mapping was found):
	// read-write size, resident part, non-main heaps found, read time (unix ms)
	ArenaMapped int64 `json:"arena_mapped,omitempty"`
	ArenaRSS    int64 `json:"arena_rss,omitempty"`
	ArenaHeaps  int   `json:"arena_heaps,omitempty"`
	ArenaT      int64 `json:"arena_t,omitempty"`
}

// AllocDelta is a change of live bytes attributed to one (stack, allocating thread).
// Stack is root-first. Alloc/Free are gross (weighted) bytes since the previous delta.
// Thread is an optional role override; normally the aggregator names TID from ThreadStats.
type AllocDelta struct {
	Kind   Kind     `json:"kind,omitempty"`
	Stack  []string `json:"stack"`
	TID    int      `json:"tid"`
	Thread string   `json:"thread,omitempty"`
	Alloc  int64    `json:"alloc"`
	Free   int64    `json:"free"`
	N      int64    `json:"n,omitempty"`   // samples (heap) or pages (faults) behind Alloc
	Max    int64    `json:"max,omitempty"` // largest single request among the samples, bytes
}

// Kind separates what a delta measures. Live heap deltas have allocs and frees; fault deltas
// only accumulate (bytes of pages first touched), since the kernel reclaims pages lazily.
type Kind uint8

const (
	KindHeap  Kind = 0 // sampled malloc/mmap (libmhp, eBPF)
	KindFault Kind = 1 // page faults (perf)
)

// ThreadStat is a per-thread /proc/<pid>/task/<tid>/stat sample (cumulative counters).
// Linux has no per-thread RSS: the address space is shared. Faults and CPU are per thread.
type ThreadStat struct {
	TID    int    `json:"tid"`
	Comm   string `json:"comm"`
	MinFlt uint64 `json:"minflt"`
	MajFlt uint64 `json:"majflt"`
	CPU    uint64 `json:"cpu"` // utime+stime, clock ticks
}

// TracerStats is self-monitoring of an allocation tracer.
type TracerStats struct {
	Name       string `json:"name"`
	Sampled    uint64 `json:"sampled"`
	Drops      uint64 `json:"drops"`       // events lost (ring full)
	TableDrops uint64 `json:"table_drops"` // sampled allocations not tracked
	Backlog    uint64 `json:"backlog"`     // unread events
	SampleRate uint64 `json:"sample_bytes"`
	LivePtrs   int    `json:"live_ptrs"`
}

// Tick is what a Source emits. Any part may be empty: the aggregator merges
// whatever it gets, so a procfs source and an eBPF source can feed it together.
type Tick struct {
	T       time.Time        `json:"t"`
	Proc    *ProcStats       `json:"proc,omitempty"`
	Regions map[string]int64 `json:"regions,omitempty"` // RSS by mapping class
	// RegionSwap is swapped-out bytes by mapping class, read with Regions; nil when nothing is swapped out.
	RegionSwap map[string]int64 `json:"region_swap,omitempty"`
	Allocs     []AllocDelta     `json:"allocs,omitempty"`
	Threads    []ThreadStat     `json:"threads,omitempty"`
	Tracer     *TracerStats     `json:"tracer,omitempty"`
	PFS        *PFSStats        `json:"pfs,omitempty"`
	Heap       *HeapStats       `json:"heap,omitempty"`
	// PeakRise is how far the tracer's live total rose above its value at the previous tick, at its highest
	// point in event order: a spike allocated and freed between ticks still shows.
	PeakRise int64            `json:"peak_rise,omitempty"`
	AreaRise map[string]int64 `json:"area_rise,omitempty"` // the same per sub-system (tracers given a classifier)
	Arenas   *ArenaStats      `json:"arenas,omitempty"`
}

// ArenaStats is glibc's malloc_info() taken inside the target by libmhp: every arena's size and the free memory
// glibc keeps in it. glibc returns memory to the OS only from the top of an arena (and from whole sub-heaps), so
// free chunks below a live one stay in RSS until malloc_trim, unless their pages were never touched.
type ArenaStats struct {
	T         int64   `json:"t"` // unix ms
	CostNs    int64   `json:"cost_ns"`
	Truncated bool    `json:"truncated,omitempty"` // more arenas than fit the ring's aux area: the list is cut
	Arenas    []Arena `json:"arenas"`
	// process-wide, from malloc_info's closing totals
	MmapChunks int64 `json:"mmap_chunks"` // allocations served by their own mmap (not in any arena)
	Mmapped    int64 `json:"mmapped"`
	Size       int64 `json:"size"`     // sum of arena sizes
	MaxSize    int64 `json:"max_size"` // sum of the arenas' high-water marks
	Free       int64 `json:"free"`
	Top        int64 `json:"top"` // of Free, in the arenas' top chunks
}

// Arena is one malloc_info <heap>: nr 0 is the main arena (brk heap), the others are mmapped arenas made of
// sub-heaps (64 MiB each by default).
type Arena struct {
	N          int   `json:"n"`
	Size       int64 `json:"size"`     // obtained from the OS (system current)
	MaxSize    int64 `json:"max_size"` // its high-water mark (system max)
	Free       int64 `json:"free"`     // free chunks, fast + rest
	FastFree   int64 `json:"fast_free,omitempty"`
	FreeChunks int64 `json:"free_chunks"`
	Subheaps   int64 `json:"subheaps,omitempty"`
	// free bytes in the bins by chunk size: < 1 KiB, 1 KiB .. 128 KiB, >= 128 KiB (whole pages malloc_trim can
	// release); the top chunk is apart (Top)
	FreeSmall int64 `json:"free_small"`
	FreeMid   int64 `json:"free_mid"`
	FreeLarge int64 `json:"free_large"`
	Largest   int64 `json:"largest"` // upper bound of the largest free chunk in the bins (its bin's "to")
	// Top is the arena's top chunk: free space at its end, counted in Free but not in the bins. glibc gives it back
	// by itself once it exceeds the trim threshold (128 KiB, or twice the dynamic mmap threshold: up to 64 MiB).
	Top int64 `json:"top"`
}

// HeapStats is the allocator's own view of its heap, taken inside the target by libmhp: glibc (mallinfo2, all
// arenas), jemalloc (mallctl stats.*) or tcmalloc (MallocExtension properties). InUse and Free mean the same for
// all three; the other fields belong to one allocator.
type HeapStats struct {
	Allocator string `json:"allocator"` // "glibc", "jemalloc", "tcmalloc"
	InUse     int64  `json:"in_use"`    // bytes the program holds (glibc: in arenas only, see Mmapped; tcache entries count as in use)
	Free      int64  `json:"free"`      // free memory the allocator keeps: not returned to the OS, still in RSS
	CostNs    int64  `json:"cost_ns"`   // time the query took in the target

	// glibc
	Arena      int64 `json:"arena,omitempty"`       // bytes obtained via brk/heaps for arenas (excl. mmapped chunks)
	FastFree   int64 `json:"fast_free,omitempty"`   // part of Free in fastbins
	FreeChunks int64 `json:"free_chunks,omitempty"` // number of free chunks (fragmentation indicator)
	Mmapped    int64 `json:"mmapped,omitempty"`     // large allocations served by mmap
	MmapChunks int64 `json:"mmap_chunks,omitempty"`
	Releasable int64 `json:"releasable,omitempty"` // top-most free space malloc_trim could release

	// jemalloc: Free = Resident - InUse - Metadata (unused space in active pages, plus dirty pages)
	Active   int64 `json:"active,omitempty"`   // pages holding live allocations
	Metadata int64 `json:"metadata,omitempty"` // jemalloc's own bookkeeping
	Resident int64 `json:"resident,omitempty"` // physically resident pages mapped by jemalloc
	Mapped   int64 `json:"mapped,omitempty"`   // active extents mapped
	Retained int64 `json:"retained,omitempty"` // address space kept after its pages were returned to the OS (not in RSS)

	// tcmalloc: Free = PageHeapFree + CentralFree + TransferFree + ThreadFree
	HeapSize     int64 `json:"heap_size,omitempty"`     // obtained from the OS (includes PageHeapUnmapped)
	PageHeapFree int64 `json:"pageheap_free,omitempty"` // free pages, still mapped
	Unmapped     int64 `json:"unmapped,omitempty"`      // free pages returned to the OS (not in RSS)
	CentralFree  int64 `json:"central_free,omitempty"`  // free objects in the central lists
	TransferFree int64 `json:"transfer_free,omitempty"` // ... in the transfer caches
	ThreadFree   int64 `json:"thread_free,omitempty"`   // ... in the per-thread caches
}

// PFSStats is what the server's own accounting claims (optional reference, not ground truth): Performance Schema,
// or on MariaDB without it, Memory_used and the connections' MEMORY_USED.
type PFSStats struct {
	Source     string            `json:"source"`                // "performance_schema" or "mariadb"
	MemoryUsed int64             `json:"memory_used,omitempty"` // MariaDB: the Memory_used status variable
	Total      int64             `json:"total"`
	ByArea     map[string]int64  `json:"by_area"` // e.g. innodb, sql, performance_schema
	Threads    map[int]PFSThread `json:"-"`       // by OS thread id
}

type PFSThread struct {
	Name     string `json:"name"`
	ConnID   int64  `json:"conn_id"`
	User     string `json:"user"`
	Command  string `json:"command"`
	Bytes    int64  `json:"bytes"`
	MaxBytes int64  `json:"max_bytes,omitempty"` // MariaDB: MAX_MEMORY_USED of the connection
}

// Source produces ticks until ctx is done or the target goes away.
type Source interface {
	Run(ctx context.Context, out chan<- Tick) error
}
