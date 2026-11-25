// Package inject loads libmhp.so into a running process (mhp watch -inject) and asks it to redirect the process's
// malloc & co to its sampling wrappers, as LD_PRELOAD would have from the start.
//
// One thread of the target is borrowed through ptrace: a thread blocked in a waiting system call (poll, accept,
// sigtimedwait, nanosleep, futex…), so it holds no allocator or loader lock. It is stopped with PTRACE_SEIZE +
// PTRACE_INTERRUPT (the other threads keep running), made to call dlopen() and then mhp_attach() in libmhp, and
// put back exactly as it was: its interrupted system call restarts. Each call returns to address 0; the
// SIGSEGV that raises is caught by ptrace and never delivered.
package inject

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Result describes an injection.
type Result struct {
	TID     int    // the borrowed thread
	Syscall string // what it was waiting in
	Loaded  bool   // libmhp was dlopen'ed now (false: it was mapped already, from an earlier -inject)
	Slots   int    // GOT slots redirected (or restored, for Detach)
}

// Mapped returns the path of libmhp.so mapped in pid, and whether it is there.
func Mapped(pid int) (string, bool) {
	m, err := maps(pid)
	if err != nil {
		return "", false
	}
	for _, e := range m {
		if filepath.Base(e.path) == "libmhp.so" {
			return e.path, true
		}
	}
	return "", false
}

// Attach makes libmhp (lib, a path valid in the target's mount namespace) sample the allocations of pid: it is
// dlopen'ed unless already mapped, then mhp_attach(sampleBytes, slots) creates the ring (disabled until the
// collector enables it) and redirects the calls.
func Attach(pid int, lib string, sampleBytes, slots uint64) (Result, error) {
	var res Result
	err := borrow(pid, &res, func(c *caller) error {
		if _, ok := Mapped(pid); !ok {
			open, err := c.libcSym("dlopen", "__libc_dlopen_mode")
			if err != nil {
				return err
			}
			path, err := c.str(lib)
			if err != nil {
				return err
			}
			h, err := c.call(open, path, 2) // RTLD_NOW
			if err != nil {
				return fmt.Errorf("dlopen: %w", err)
			}
			if h == 0 {
				return fmt.Errorf("dlopen %s in pid %d failed: %s", lib, pid, c.dlerror())
			}
			res.Loaded = true
		}
		fn, err := c.libmhpSym("mhp_attach")
		if err != nil {
			return err
		}
		r, err := c.call(fn, sampleBytes, slots)
		if err != nil {
			return fmt.Errorf("mhp_attach: %w", err)
		}
		switch n := int32(r); {
		case n == -1:
			return errors.New("the target's malloc is built into its executable, so calls to it cannot be redirected: use the eBPF tracer (the default without -inject)")
		case n == -2:
			return errors.New("libmhp is preloaded in the target already: attach without -inject")
		case n < 0:
			return fmt.Errorf("libmhp could not create its ring in the target: %v", syscall.Errno(-n))
		default:
			res.Slots = int(n)
		}
		return nil
	})
	return res, err
}

// Detach points the target's calls back at libc and stops sampling (libmhp and its ring stay in the process).
func Detach(pid int) (Result, error) {
	var res Result
	err := borrow(pid, &res, func(c *caller) error {
		fn, err := c.libmhpSym("mhp_detach")
		if err != nil {
			return err
		}
		r, err := c.call(fn)
		if err != nil {
			return fmt.Errorf("mhp_detach: %w", err)
		}
		if int32(r) < 0 {
			return errors.New("libmhp in the target was not injected")
		}
		res.Slots = int(int32(r))
		return nil
	})
	return res, err
}

type mapping struct {
	lo, hi, off uint64
	perms, path string
}

func maps(pid int) ([]mapping, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []mapping
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || !strings.HasPrefix(fl[5], "/") {
			continue
		}
		a, b, _ := strings.Cut(fl[0], "-")
		var m mapping
		m.lo, _ = strconv.ParseUint(a, 16, 64)
		m.hi, _ = strconv.ParseUint(b, 16, 64)
		m.off, _ = strconv.ParseUint(fl[2], 16, 64)
		m.perms, m.path = fl[1], fl[5]
		out = append(out, m)
	}
	return out, sc.Err()
}

// symbol returns the run-time address in pid of the first of names defined by the mapped object whose file
// name satisfies match. The object is read through /proc/pid/map_files, so it is the file the target mapped.
func symbol(pid int, match func(string) bool, names ...string) (uint64, error) {
	m, err := maps(pid)
	if err != nil {
		return 0, err
	}
	for _, e := range m {
		if e.off != 0 || !match(e.path) {
			continue
		}
		f, err := elf.Open(fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, e.lo, e.hi))
		if err != nil {
			return 0, err
		}
		defer f.Close()
		var first uint64 // vaddr mapped at file offset 0
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Off == 0 {
				first = p.Vaddr
				break
			}
		}
		syms, err := f.DynamicSymbols()
		if err != nil {
			return 0, fmt.Errorf("%s: %w", e.path, err)
		}
		for _, n := range names {
			for _, s := range syms {
				if s.Name == n && s.Value != 0 && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
					return e.lo - first + s.Value, nil
				}
			}
		}
		return 0, fmt.Errorf("%s defines none of %v", e.path, names)
	}
	return 0, errors.New("object not mapped")
}
