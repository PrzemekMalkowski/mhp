// Package sim is a synthetic source with MySQL-looking stacks, for demos and UI work.
package sim

import (
	"context"
	"math"
	"math/rand"
	"time"

	"mhp/internal/model"
)

type workload struct {
	tid    int
	thread string
	stack  []string
	base   int64                     // steady-state live bytes
	wobble float64                   // fraction of base that oscillates
	leak   int64                     // bytes leaked per second
	burst  func(sec float64) float64 // optional multiplier
}

var loads = []workload{
	{tid: 1001, thread: "ib_buf_pool", stack: []string{"start_thread", "buf_pool_init", "os_mem_alloc_large", "mmap"}, base: 512 << 20},
	{tid: 1002, thread: "connection", stack: []string{"start_thread", "handle_connection", "dispatch_command", "Item_func_concat::val_str", "my_malloc", "malloc"}, base: 40 << 20, wobble: 0.5},
	{tid: 1003, thread: "connection", stack: []string{"start_thread", "handle_connection", "dispatch_command", "Filesort::alloc_sort_buffer", "my_malloc", "malloc"}, base: 20 << 20, wobble: 0.8,
		burst: func(s float64) float64 { return 1 + 6*math.Max(0, math.Sin(s/25)) }},
	{tid: 1004, thread: "connection", stack: []string{"start_thread", "handle_connection", "temptable::Allocator::allocate", "mmap"}, base: 8 << 20, wobble: 0.3},
	{tid: 1005, thread: "ib_log", stack: []string{"start_thread", "log_writer", "log_buffer_resize", "ut::malloc_withkey", "malloc"}, base: 64 << 20},
	{tid: 1006, thread: "connection", stack: []string{"start_thread", "handle_connection", "row_search_mvcc", "mem_heap_create_block", "malloc"}, base: 30 << 20, wobble: 0.2, leak: 1 << 20},
	{tid: 1007, thread: "connection", stack: []string{"start_thread", "handle_connection", "SSL_read", "CRYPTO_malloc", "malloc"}, base: 6 << 20, wobble: 0.1, leak: 150 << 10},
	{tid: 1008, thread: "binlog_dump", stack: []string{"start_thread", "Binlog_sender::run", "Binlog_sender::send_events", "my_malloc", "malloc"}, base: 12 << 20, wobble: 0.4},
}

type Source struct{ Interval time.Duration }

func (s *Source) Run(ctx context.Context, out chan<- model.Tick) error {
	rng := rand.New(rand.NewSource(1))
	start := time.Now()
	cur := make([]int64, len(loads))
	tk := time.NewTicker(s.Interval)
	defer tk.Stop()
	var minflt uint64
	cpu, flt, prevLive := make([]uint64, len(loads)), make([]uint64, len(loads)), make([]int64, len(loads))
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-tk.C:
			sec := now.Sub(start).Seconds()
			dt := s.Interval.Seconds()
			t := model.Tick{T: now}
			var traced int64
			for i, w := range loads {
				target := float64(w.base)
				if w.burst != nil {
					target *= w.burst(sec)
				}
				target *= 1 + w.wobble*math.Sin(sec/7+float64(i))*0.5 + rng.Float64()*0.02
				target += float64(w.leak) * sec
				next := int64(target)
				delta := next - cur[i]
				churn := int64(float64(w.base) * 0.05 * dt)
				d := model.AllocDelta{Stack: w.stack, TID: w.tid, Alloc: churn, Free: churn}
				if delta > 0 {
					d.Alloc += delta
				} else {
					d.Free -= delta
				}
				cur[i] = next
				traced += next
				t.Allocs = append(t.Allocs, d)
			}
			frag := int64(0.12*float64(traced)) + int64(30<<20*(1+math.Sin(sec/40))/2) // glibc-ish retention untraced by PFS
			anon := traced + frag + (200 << 20)
			minflt += uint64(math.Max(0, float64(delta(anon, traced))/4096))
			t.Proc = &model.ProcStats{RSS: anon + (60 << 20), Anon: anon, File: 60 << 20, Threads: 140, MinFlt: minflt, CgroupLimit: 4 << 30}
			for i, w := range loads {
				cpu[i] += uint64(rng.Intn(30))
				flt[i] += uint64(max(0, cur[i]-prevLive[i]) / 4096)
				prevLive[i] = cur[i]
				t.Threads = append(t.Threads, model.ThreadStat{TID: w.tid, Comm: w.thread, MinFlt: flt[i], CPU: cpu[i]})
			}
			t.Regions = map[string]int64{"heap(brk)": frag / 2, "anon-mmap": anon - frag/2, "file": 60 << 20, "stack": 2 << 20}
			select {
			case out <- t:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func delta(a, b int64) int64 { return (a - b) / 64 }
