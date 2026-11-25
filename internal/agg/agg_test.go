package agg

import (
	"testing"
	"time"

	"mhp/internal/classify"
	"mhp/internal/live"
	"mhp/internal/model"
)

func TestGrowthAndGap(t *testing.T) {
	cls, _ := classify.New("")
	a := New(cls, 3)
	st := []string{"start_thread", "row_ins", "mem_heap_create_block", "malloc"}
	now := time.Unix(1000, 0)
	a.Ingest(model.Tick{Proc: &model.ProcStats{Anon: 1000}})
	var v = a.Snapshot(now)
	for i := 1; i <= 4; i++ {
		a.Ingest(model.Tick{Allocs: []model.AllocDelta{{Stack: st, Thread: "connection", Alloc: 100}}})
		v = a.Snapshot(now.Add(time.Duration(i) * time.Second))
	}
	if v.Traced != 400 || v.BySubsys["InnoDB"] != 400 || v.Gap != 600 {
		t.Fatalf("unexpected view %+v", v)
	}
	if len(v.Growers) != 1 || v.Growers[0].Growth != 300 {
		t.Fatalf("growth: %+v", v.Growers)
	}
}

func TestRangeAndPeak(t *testing.T) {
	cls, _ := classify.New("")
	a := New(cls, 60)
	t0 := time.Unix(1000, 0)
	json := []string{"main", "dispatch_command", "audit_log_filter::LogRecordFormatter::apply", "malloc"}
	other := []string{"main", "buf_pool_init", "malloc"}
	tick := func(sec int, rise int64, d ...model.AllocDelta) live.View {
		var area map[string]int64
		if rise > 0 {
			area = map[string]int64{"AuditLog": rise}
		}
		a.Ingest(model.Tick{T: t0, Allocs: d, PeakRise: rise, AreaRise: area})
		return a.Snapshot(t0.Add(time.Duration(sec) * time.Second))
	}
	tick(1, 0, model.AllocDelta{Stack: other, TID: 1, Alloc: 100 << 20, N: 400, Max: 1 << 20})
	// tick 2: a 64 MiB spike allocated and freed within the tick (the tracer saw it rise 64 MiB in event order)
	v := tick(2, 64<<20, model.AllocDelta{Stack: json, TID: 7, Alloc: 64 << 20, Free: 64 << 20, N: 3, Max: 48 << 20})
	if v.Traced != 100<<20 || v.TracedPeak != 164<<20 {
		t.Fatalf("traced %d peak %d", v.Traced, v.TracedPeak)
	}
	if v = tick(3, 0); v.TracedPeak != 100<<20 {
		t.Fatalf("peak not reset: %d", v.TracedPeak)
	}
	ms := func(sec int) int64 { return t0.Add(time.Duration(sec) * time.Second).UnixMilli() }
	r := a.Range(Filter{From: ms(1), To: ms(3)})
	if r.Alloc != 64<<20 || r.Free != 64<<20 || r.Samples != 3 || r.Max != 48<<20 || r.Ticks != 2 {
		t.Fatalf("range %+v", r)
	}
	st := a.Stacks(Filter{Metric: "range_alloc", From: ms(1), To: ms(2)})
	if len(st) != 1 || st[0].Value != 64<<20 || st[0].N != 3 || st[0].Max != 48<<20 {
		t.Fatalf("range stacks %+v", st)
	}
	if st := a.Stacks(Filter{Metric: "range_net", From: ms(1), To: ms(3)}); len(st) != 0 {
		t.Fatalf("net should be empty: %+v", st)
	}
	if st := a.Stacks(Filter{Metric: "range_alloc", From: ms(1), To: ms(3), TID: 1}); len(st) != 0 {
		t.Fatalf("tid filter: %+v", st)
	}
	// per area: the stack passes through audit_log_filter::, so it is AuditLog even though a JSON frame is nearer
	byArea := map[string]AreaTotals{}
	for _, x := range r.Areas {
		byArea[x.Area] = x
	}
	if a.Subsystem(json) != "AuditLog" {
		t.Fatal(a.Subsystem(json))
	}
	if x := byArea["AuditLog"]; x.Alloc != 64<<20 || x.PeakRise != 64<<20 {
		t.Fatalf("area %+v", byArea)
	}
	if r.PeakRise != 64<<20 {
		t.Fatalf("total peak rise %d", r.PeakRise)
	}
	// the first tick holds everything before the first snapshot: a range reaches it only from before its time,
	// and nothing is reported as dropped while the timeline is complete
	if r := a.Range(Filter{From: ms(1), To: ms(3)}); r.Oldest != 0 || r.Ticks != 2 {
		t.Fatalf("from the first tick's time: %+v", r)
	}
	if r := a.Range(Filter{From: ms(1) - 1, To: ms(3)}); r.Oldest != 0 || r.Ticks != 3 {
		t.Fatalf("from before the first tick: %+v", r)
	}
	// the record budget drops the oldest ticks first
	a.Timeline = 1
	tick(4, 0, model.AllocDelta{Stack: other, TID: 1, Alloc: 1})
	if r := a.Range(Filter{From: 0, To: ms(4)}); r.Oldest != ms(2) || r.Alloc != 1 { // tick 3 had no records, so it is kept; tick 2 was the last dropped
		t.Fatalf("budget: %+v", r)
	}
}

func TestThreadEntryRole(t *testing.T) {
	for _, c := range []struct {
		comm  string
		stack []string
		want  string
	}{
		{"mariadbd", []string{"__clone3", "start_thread", "pfs_spawn_thread", "handle_one_connection", "do_command"}, "handle_one_connection"},
		{"mariadbd", []string{"__clone3", "start_thread", "std::execute_native_thread_routine",
			"std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (tpool::thread_pool_generic::*)(tpool::worker_data*), tpool::thread_pool_generic*, tpool::worker_data*> > >::_M_run",
			"tpool::thread_pool_generic::worker_main(tpool::worker_data*)", "tpool::task::execute"}, "tpool::thread_pool_generic::worker_main"},
		{"mariadbd", []string{"_start", "__libc_start_main", "mysqld_main"}, "mariadbd"},        // main thread
		{"mariadbd", []string{"dispatch_command", "mysql_parse"}, "mariadbd"},                   // truncated at the root
		{"connection", []string{"__clone3", "start_thread", "handle_connection"}, "connection"}, // named (MySQL)
		{"mariadbd", []string{"__clone3", "start_thread", "libstdc++.so.6.0.33+0xecf8c", "tpool::thread_pool_generic::worker_main(tpool::worker_data*)"}, "tpool::thread_pool_generic::worker_main"},
		{"mariadbd", []string{"__clone3", "start_thread", "[fault: anon-mmap]"}, "mariadbd"},
		{"ib_io_wr-3", []string{"__clone3", "start_thread", "io_handler_thread"}, "ib_io_wr"},
	} {
		th := &thread{comm: c.comm, entry: threadEntry(c.stack)}
		if got := th.roleName(); got != c.want {
			t.Errorf("%s %v: role %q, want %q", c.comm, c.stack, got, c.want)
		}
	}
}
