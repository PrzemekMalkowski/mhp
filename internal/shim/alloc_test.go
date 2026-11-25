package shim

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"mhp/internal/inject"
	"mhp/internal/model"
	"mhp/internal/sym"
)

const MiB = 1 << 20

// TargetLive is what testdata/target.cc leaves live per function; functions not listed must leave nothing.
var TargetLive = map[string]int64{"t_malloc": 8 * MiB, "t_calloc": 4 * MiB, "t_realloc": 6 * MiB,
	"t_posix_memalign": 2 * MiB, "t_aligned_alloc": 2 * MiB, "t_memalign": 2 * MiB, "t_new": 3 * MiB,
	"t_new_array": 8 * MiB, "t_new_nothrow": 5 * MiB, "t_new_aligned": 5 * MiB, "t_new_aligned_nothrow": 2 * MiB,
	"t_mmap": 32 * MiB, "t_reserve": 12 * MiB}

// TargetAllocated is what the functions that free everything had allocated.
var TargetAllocated = map[string]int64{"t_freed_malloc": 16 * MiB, "t_freed_new": 16 * MiB, "t_freed_sized": 12 * MiB,
	"t_freed_aligned": 12 * MiB, "t_new_freed_by_free": 4 * MiB, "t_munmap": 16 * MiB}

// buildTargets compiles testdata/target.cc as a PIE and as a non-PIE program ("nopie").
func buildTargets(t *testing.T) map[string]string {
	out := map[string]string{}
	for name, flag := range map[string]string{"pie": "-pie", "nopie": "-no-pie"} {
		bin := filepath.Join(t.TempDir(), "target-"+name)
		args := []string{"-O1", "-g", "-std=c++17", "-fno-omit-frame-pointer", "-pthread", flag, "-o", bin, "testdata/target.cc"}
		if name == "pie" {
			args = append([]string{"-fPIE"}, args...)
		} else {
			args = append([]string{"-fno-pie"}, args...)
		}
		if msg, err := exec.Command("c++", args...).CombinedOutput(); err != nil {
			t.Skipf("no C++ compiler: %v %s", err, msg)
		}
		out[name] = bin
	}
	return out
}

// cases lists allocator x program kind.
func cases(t *testing.T) (names []string, bin, lib map[string]string) {
	bins, allocs := buildTargets(t), Allocators()
	bin, lib = map[string]string{}, map[string]string{}
	for a, path := range allocs {
		for k, b := range bins {
			n := a + "/" + k
			names = append(names, n)
			bin[n], lib[n] = b, path
		}
	}
	sort.Strings(names)
	return
}

var kinds = map[string]uint32{"glibc": allocGlibc, "jemalloc": allocJemalloc, "tcmalloc": allocTcmalloc, "tcmalloc_minimal": allocTcmalloc}

func kindOf(name string) uint32 { return kinds[strings.Split(name, "/")[0]] }

// Allocators lists the allocators to test under: glibc ("") and the jemalloc / tcmalloc libraries installed.
func Allocators() map[string]string {
	out := map[string]string{"glibc": ""}
	for _, n := range []string{"jemalloc", "tcmalloc"} {
		if p, err := FindMallocLib(n); err == nil {
			out[n] = p
		}
	}
	for _, dir := range libDirs {
		if m, _ := filepath.Glob(filepath.Join(dir, "libtcmalloc_minimal.so.[0-9]")); len(m) > 0 {
			out["tcmalloc_minimal"] = m[0]
			break
		}
	}
	return out
}

// WaitLine reads the target's stdout until a line equals want. If it does not come, the target's thread stacks
// are logged (when gdb is there).
func WaitLine(t *testing.T, r *bufio.Reader, want string, pid ...int) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if strings.TrimSpace(l) == want {
				done <- nil
				return
			}
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("target ended before %q: %v", want, err)
		}
	case <-time.After(10 * time.Second):
		if len(pid) > 0 {
			bt, _ := exec.Command("gdb", "-p", fmt.Sprint(pid[0]), "-batch", "-ex", "thread apply all bt 12").CombinedOutput()
			t.Logf("target stacks:\n%s", bt)
		}
		t.Fatalf("no %q from the target", want)
	}
}

// checkRing reads pid's ring for a moment and compares what each t_* function allocated and still holds with
// what target.cc does. kind is the allocator the ring must report.
func checkRing(t *testing.T, pid int, kind uint32) {
	t.Helper()
	s := &Source{PID: pid, FromStart: true, Sym: sym.New(pid), StatsEvery: 50 * time.Millisecond}
	if err := s.Open(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if k := *s.u32(offAllocKind); k != kind {
		t.Errorf("ring reports allocator kind %d, want %d", k, kind)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	ticks := make(chan model.Tick, 1024)
	go func() { s.Run(ctx, ticks); close(ticks) }()
	live, alloc := map[string]int64{}, map[string]int64{}
	var heap *model.HeapStats
	var other int64
	for tk := range ticks {
		if tk.Heap != nil {
			heap = tk.Heap
		}
		for _, d := range tk.Allocs {
			fn := ""
			for _, f := range d.Stack {
				if strings.HasPrefix(f, "t_") {
					fn = f
				}
			}
			if fn == "" {
				other += d.Alloc - d.Free
				continue
			}
			live[fn] += d.Alloc - d.Free
			alloc[fn] += d.Alloc
		}
	}
	near := func(got, want int64) bool { d := got - want; return d >= -want/100 && d <= want/100 }
	for fn, want := range TargetLive {
		if !near(live[fn], want) || !near(alloc[fn], want) && fn != "t_realloc" && fn != "t_reserve" {
			t.Errorf("%s: live %.2f MiB, allocated %.2f MiB, want %d MiB", fn, float64(live[fn])/MiB, float64(alloc[fn])/MiB, want/MiB)
		}
	}
	for fn, want := range TargetAllocated {
		if live[fn] != 0 || !near(alloc[fn], want) {
			t.Errorf("%s: live %.2f MiB (want 0), allocated %.2f MiB (want %d)", fn, float64(live[fn])/MiB, float64(alloc[fn])/MiB, want/MiB)
		}
	}
	if !near(alloc["t_reserve"], 16*MiB) { // 64 GiB reserved (not counted), 16 committed, 4 decommitted
		t.Errorf("t_reserve: allocated %.2f MiB, want 16", float64(alloc["t_reserve"])/MiB)
	}
	// 200,000 strings of 100..999 bytes and vectors of 4..2048 bytes: about 310 MiB requested, sampled
	if a := alloc["t_small"]; live["t_small"] != 0 || a < 250*MiB || a > 370*MiB {
		t.Errorf("t_small: live %d, allocated %.1f MiB, want 0 and about 310", live["t_small"], float64(a)/MiB)
	}
	// nothing else may hold much: an allocator's own mappings (jemalloc extents, tcmalloc spans) are not recorded
	if other > 2*MiB || other < -MiB {
		t.Errorf("%.2f MiB live outside the test functions", float64(other)/MiB)
	}
	if kind != allocOther {
		if heap == nil {
			t.Errorf("no heap statistics from the allocator")
		} else if use := heap.InUse + heap.Mmapped; heap.Allocator != allocNames[kind] || use < 40*MiB || use > 120*MiB {
			t.Errorf("heap statistics: %+v", *heap)
		} else {
			t.Logf("%s: %+v", heap.Allocator, *heap)
		}
	}
}

// TestPreload runs the target with libmhp preloaded over each allocator, and once behind one (where it must stay
// out of the way).
func TestPreload(t *testing.T) {
	lib, _ := filepath.Abs("../../bin/libmhp.so")
	if _, err := os.Stat(lib); err != nil {
		t.Skip("build libmhp first: make -C shim")
	}
	names, bins, libs := cases(t)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(bins[name])
			cmd.Env = append(os.Environ(), "LD_PRELOAD="+strings.TrimSpace(lib+" "+libs[name]))
			out, _ := cmd.StdoutPipe()
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait(); os.Remove(RingPath(cmd.Process.Pid)) }()
			rd := bufio.NewReader(out)
			WaitLine(t, rd, "bad_alloc caught")
			WaitLine(t, rd, "done")
			checkRing(t, cmd.Process.Pid, kindOf(name))
		})
	}
}

// TestInject starts the target on each allocator without libmhp, injects it (root needed), and checks what the
// target allocates afterwards; then undoes the injection.
func TestInject(t *testing.T) {
	lib, _ := filepath.Abs("../../bin/libmhp.so")
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skip("build libmhp first: make -C shim")
	}
	names, bins, libs := cases(t)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(bins[name])
			cmd.Env = append(os.Environ(), "MHP_T_WAIT=1")
			if libs[name] != "" {
				cmd.Env = append(cmd.Env, "LD_PRELOAD="+libs[name])
			}
			out, _ := cmd.StdoutPipe()
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pid := cmd.Process.Pid
			defer func() { cmd.Process.Kill(); cmd.Wait(); os.Remove(RingPath(pid)) }()
			rd := bufio.NewReader(out)
			WaitLine(t, rd, "waiting")
			time.Sleep(100 * time.Millisecond)
			r, err := inject.Attach(pid, lib, 256<<10, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("attach: %+v", r)
			// enable sampling before the target allocates
			s := &Source{PID: pid}
			if err := s.Open(time.Second); err != nil {
				t.Fatal(err)
			}
			syscall.Munmap(s.mem)
			cmd.Process.Signal(syscall.SIGUSR1)
			WaitLine(t, rd, "bad_alloc caught", pid)
			WaitLine(t, rd, "done", pid)
			checkRing(t, pid, kindOf(name))
			d, err := inject.Detach(pid)
			if err != nil || d.Slots != r.Slots {
				t.Errorf("detach: %+v %v (attach redirected %d)", d, err, r.Slots)
			}
			time.Sleep(200 * time.Millisecond) // the churn thread keeps allocating through the restored slots
			if err := syscall.Kill(pid, 0); err != nil {
				t.Fatalf("target died: %v", err)
			}
		})
	}
}

// TestPreloadedBehind: with another allocator preloaded ahead of it, libmhp's malloc is never called; the functions
// only it defines (reallocarray with jemalloc) must reach that allocator, and no ring is created.
func TestPreloadedBehind(t *testing.T) {
	lib, _ := filepath.Abs("../../bin/libmhp.so")
	je, err := FindMallocLib("jemalloc")
	if _, e := os.Stat(lib); e != nil || err != nil {
		t.Skip("needs bin/libmhp.so and jemalloc")
	}
	cmd := exec.Command(buildTargets(t)["pie"])
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+je+" "+lib)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait(); os.Remove(RingPath(cmd.Process.Pid)) }()
	WaitLine(t, bufio.NewReader(out), "done")
	if st := RingState(cmd.Process.Pid); st != NoRing {
		t.Errorf("ring state %d, want none", st)
	}
}
