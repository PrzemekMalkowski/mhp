//go:build linux && amd64

package inject

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ptraceSeize     = 0x4206
	ptraceInterrupt = 0x4207
	sigsegvBit      = 1 << (syscall.SIGSEGV - 1)
)

// waiting system calls a thread can be borrowed from (x86_64 numbers), best first: a thread blocked in one holds
// no allocator or loader lock. futex last: a lock waiter may hold another lock.
var waits = map[uint64]struct {
	name string
	rank int
}{
	7: {"poll", 0}, 271: {"ppoll", 0}, 23: {"select", 0}, 270: {"pselect6", 0}, 232: {"epoll_wait", 0},
	281: {"epoll_pwait", 0}, 441: {"epoll_pwait2", 0}, 43: {"accept", 0}, 288: {"accept4", 0},
	128: {"rt_sigtimedwait", 0}, 130: {"rt_sigsuspend", 0}, 34: {"pause", 0}, 35: {"nanosleep", 0},
	230: {"clock_nanosleep", 0}, 61: {"wait4", 0}, 208: {"io_getevents", 1}, 333: {"io_pgetevents", 1},
	219: {"restart_syscall", 0}, // a poll, nanosleep or futex wait resumed after a stop
	202: {"futex", 2},
}

type caller struct {
	pid, tid int
	saved    syscall.PtraceRegs
	sp       uint64 // scratch space grows down from here (below the red zone)
}

// borrow stops one waiting thread of pid, runs fn with it and puts it back.
func borrow(pid int, res *Result, fn func(*caller) error) error {
	if os.Geteuid() != 0 {
		return errors.New("-inject needs root (ptrace)")
	}
	cands, err := candidates(pid)
	if err != nil {
		return err
	}
	if len(cands) == 0 {
		return fmt.Errorf("pid %d: no thread is blocked in a waiting system call with SIGSEGV deliverable; try again", pid)
	}
	runtime.LockOSThread() // ptrace requests must come from the tracing thread
	defer runtime.UnlockOSThread()
	var last error
	for _, tid := range cands {
		c := &caller{pid: pid, tid: tid}
		sig, nr, err := c.seize()
		if err != nil {
			last = err
			continue
		}
		w, ok := waits[nr]
		if !ok { // it left the wait between the look and the stop
			c.release(sig)
			last = fmt.Errorf("thread %d was not waiting", tid)
			continue
		}
		res.TID, res.Syscall = tid, w.name
		err = fn(c)
		if rerr := c.release(sig); err == nil {
			err = rerr
		}
		return err
	}
	return fmt.Errorf("pid %d: could not borrow a thread: %v", pid, last)
}

// candidates lists threads blocked in a waiting system call, best first (the main thread wins ties), skipping
// those that block or ignore SIGSEGV (the kernel would reset its handler when we raise it).
func candidates(pid int) ([]int, error) {
	dir := fmt.Sprintf("/proc/%d/task", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type cand struct{ tid, rank int }
	var cs []cand
	for _, e := range ents {
		tid, _ := strconv.Atoi(e.Name())
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "syscall"))
		if err != nil {
			continue
		}
		nr, err := strconv.ParseUint(strings.Fields(string(b) + " x")[0], 10, 64)
		w, ok := waits[nr]
		if err != nil || !ok || masked(filepath.Join(dir, e.Name(), "status")) {
			continue
		}
		r := w.rank * 2
		if tid != pid {
			r++
		}
		cs = append(cs, cand{tid, r})
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].rank < cs[j].rank })
	out := make([]int, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.tid)
	}
	return out, nil
}

func masked(status string) bool {
	b, err := os.ReadFile(status)
	if err != nil {
		return true
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, ":")
		if k == "SigBlk" || k == "SigIgn" {
			if m, _ := strconv.ParseUint(strings.TrimSpace(v), 16, 64); m&sigsegvBit != 0 {
				return true
			}
		}
	}
	return false
}

func ptrace(req, tid int, addr, data uintptr) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(req), uintptr(tid), addr, data, 0, 0); e != 0 {
		return e
	}
	return nil
}

// wait waits for the next stop of the borrowed thread.
func (c *caller) wait() (syscall.WaitStatus, error) {
	var ws syscall.WaitStatus
	warned := time.Now()
	for {
		n, err := syscall.Wait4(c.tid, &ws, syscall.WALL|syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return ws, err
		}
		if n == c.tid {
			if ws.Exited() || ws.Signaled() {
				return ws, fmt.Errorf("thread %d exited", c.tid)
			}
			return ws, nil
		}
		// No timeout: giving up while the thread runs our call would leave it returning to address 0.
		if time.Since(warned) > 5*time.Second {
			log.Printf("inject: still waiting for thread %d of pid %d", c.tid, c.pid)
			warned = time.Now()
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// seize stops the thread; it returns a signal that was being delivered (to deliver on release) and the
// system call it is in.
func (c *caller) seize() (syscall.Signal, uint64, error) {
	if err := ptrace(ptraceSeize, c.tid, 0, 0); err != nil {
		return 0, 0, fmt.Errorf("ptrace(SEIZE, %d): %w", c.tid, err)
	}
	if err := ptrace(ptraceInterrupt, c.tid, 0, 0); err != nil {
		syscall.PtraceDetach(c.tid)
		return 0, 0, err
	}
	ws, err := c.wait()
	if err != nil {
		return 0, 0, err
	}
	var sig syscall.Signal
	if ws.Stopped() && uint32(ws)>>16 == 0 {
		sig = ws.StopSignal() // a signal-delivery-stop came before the interrupt's PTRACE_EVENT_STOP
	}
	if err := syscall.PtraceGetRegs(c.tid, &c.saved); err != nil {
		c.release(sig)
		return 0, 0, err
	}
	c.sp = (c.saved.Rsp - 256) &^ 15 // past the 128-byte red zone
	return sig, c.saved.Orig_rax, nil
}

// release restores the registers and lets the thread go: an interrupted system call restarts.
func (c *caller) release(sig syscall.Signal) error {
	err := syscall.PtraceSetRegs(c.tid, &c.saved)
	if derr := ptrace(syscall.PTRACE_DETACH, c.tid, 0, uintptr(sig)); err == nil {
		err = derr
	}
	return err
}

// str copies s (NUL-terminated) into the scratch space and returns its address in the target.
func (c *caller) str(s string) (uint64, error) {
	c.sp = (c.sp - uint64(len(s)) - 1) &^ 15
	_, err := syscall.PtracePokeData(c.tid, uintptr(c.sp), append([]byte(s), 0))
	return c.sp, err
}

// call runs fn(args...) in the thread and returns its result.
func (c *caller) call(fn uint64, args ...uint64) (uint64, error) {
	r := c.saved
	argRegs := []*uint64{&r.Rdi, &r.Rsi, &r.Rdx, &r.Rcx, &r.R8, &r.R9}
	for i, a := range args {
		*argRegs[i] = a
	}
	r.Rsp = (c.sp &^ 15) - 8 // as after a call instruction: rsp+8 is 16-byte aligned
	if _, err := syscall.PtracePokeData(c.tid, uintptr(r.Rsp), make([]byte, 8)); err != nil {
		return 0, err // return address 0
	}
	r.Rip, r.Rax = fn, 0
	r.Orig_rax = ^uint64(0) // not in a system call: no restart on resume
	r.Eflags &^= 0x500      // TF, DF
	if err := syscall.PtraceSetRegs(c.tid, &r); err != nil {
		return 0, err
	}
	sig := 0
	for {
		if err := syscall.PtraceCont(c.tid, sig); err != nil {
			return 0, err
		}
		ws, err := c.wait()
		if err != nil {
			return 0, err
		}
		sig = 0
		if !ws.Stopped() || uint32(ws)>>16 != 0 { // event stops (group stop, interrupt)
			continue
		}
		if s := ws.StopSignal(); s == syscall.SIGSEGV {
			if err := syscall.PtraceGetRegs(c.tid, &r); err != nil {
				return 0, err
			}
			if r.Rip == 0 {
				return r.Rax, nil
			}
			return 0, fmt.Errorf("SIGSEGV at %#x in the call", r.Rip)
		} else {
			sig = int(s) // a signal for the target arrived meanwhile: deliver it
		}
	}
}

func (c *caller) libcSym(names ...string) (uint64, error) {
	return symbol(c.pid, func(p string) bool { return strings.HasPrefix(filepath.Base(p), "libc.so") }, names...)
}

func (c *caller) libmhpSym(name string) (uint64, error) {
	a, err := symbol(c.pid, func(p string) bool { return filepath.Base(p) == "libmhp.so" }, name)
	if err != nil {
		return 0, fmt.Errorf("libmhp.so in pid %d: %w", c.pid, err)
	}
	return a, nil
}

// dlerror returns the target's dlerror() text.
func (c *caller) dlerror() string {
	fn, err := c.libcSym("dlerror")
	if err != nil {
		return "(no dlerror)"
	}
	p, err := c.call(fn)
	if err != nil || p == 0 {
		return "(unknown error)"
	}
	buf := make([]byte, 512)
	n, _ := syscall.PtracePeekData(c.tid, uintptr(p), buf)
	if i := bytes.IndexByte(buf[:n], 0); i >= 0 {
		n = i
	}
	return string(buf[:n])
}
