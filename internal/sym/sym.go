// Package sym resolves return addresses of a live process to demangled function names.
// Symbols come from the build-id debug file (/usr/lib/debug/.build-id/xx/yyyy.debug, e.g. percona-server-dbg)
// when present, else the binary's own .symtab, else .dynsym.
package sym

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ianlancetaylor/demangle"
)

type mapping struct {
	lo, hi, off uint64
	path        string
}

type symbol struct {
	addr, size uint64
	name       string
}

type object struct {
	file   string // ELF file with the symbols (debug file or the object itself), for source lookups
	syms   []symbol
	loads  []elf.ProgHeader
	source string // which file the symbols came from
	err    error
}

type Symbolizer struct {
	pid        int
	mu         sync.Mutex
	maps       []mapping
	objs       map[string]*object
	cache      map[uint64]string
	lastReload time.Time
	DebugDirs  []string
	src        sources
	// static: maps came from a file (NewStatic), not from a live process; root prefixes their paths
	static bool
	root   string
}

// ExtraDebugDirs are searched before /usr/lib/debug (mhp -debug-dir), e.g. an unpacked -dbg package.
var ExtraDebugDirs []string

func New(pid int) *Symbolizer {
	s := &Symbolizer{pid: pid, objs: map[string]*object{}, cache: map[uint64]string{},
		DebugDirs: append(append([]string{}, ExtraDebugDirs...), "/usr/lib/debug")}
	s.reload()
	return s
}

// NewStatic symbolizes addresses of a process that is gone, from its /proc/PID/maps text as saved in a heap
// profile (jemalloc / gperftools MAPPED_LIBRARIES). The objects are read at their paths under root ("" = /):
// they must be the same builds the process ran.
func NewStatic(maps io.Reader, root string) *Symbolizer {
	s := &Symbolizer{objs: map[string]*object{}, cache: map[uint64]string{}, static: true, root: root,
		DebugDirs: append(append([]string{}, ExtraDebugDirs...), "/usr/lib/debug")}
	s.maps = parseMaps(maps)
	return s
}

// Objects lists the mapped files, in address order (the executable is normally first).
func (s *Symbolizer) Objects() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	seen := map[string]bool{}
	for _, m := range s.maps {
		if !seen[m.path] {
			seen[m.path] = true
			out = append(out, m.path)
		}
	}
	return out
}

// Object returns the object addr falls in ("" if none).
func (s *Symbolizer) Object(addr uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m := s.find(addr); m != nil {
		return m.path
	}
	return ""
}

func (s *Symbolizer) reload() {
	s.lastReload = time.Now()
	if s.static {
		return
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", s.pid))
	if err != nil {
		return
	}
	defer f.Close()
	s.maps = parseMaps(f)
}

// parseMaps reads the executable file mappings of a maps listing, sorted by address.
func parseMaps(r io.Reader) []mapping {
	var ms []mapping
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 6 || !strings.Contains(fl[1], "x") || !strings.HasPrefix(fl[5], "/") {
			continue
		}
		lo, hi, _ := strings.Cut(fl[0], "-")
		var m mapping
		m.lo, _ = strconv.ParseUint(lo, 16, 64)
		m.hi, _ = strconv.ParseUint(hi, 16, 64)
		m.off, _ = strconv.ParseUint(fl[2], 16, 64)
		m.path = strings.TrimSuffix(strings.Join(fl[5:], " "), " (deleted)")
		ms = append(ms, m)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].lo < ms[j].lo })
	return ms
}

// Frame returns a display name for a return address (it looks up addr-1, the call instruction).
func (s *Symbolizer) Frame(addr uint64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.cache[addr]; ok {
		return n
	}
	n, ok := s.resolve(addr - 1)
	if ok {
		s.cache[addr] = n // misses are retried: the object may be mapped later (startup, dlopen)
	}
	return n
}

// FrameAt names an exact instruction address (e.g. a sampled IP), not a return address.
func (s *Symbolizer) FrameAt(ip uint64) string { return s.Frame(ip + 1) }

// IsCode reports whether addr falls in an executable file mapping of the target.
func (s *Symbolizer) IsCode(addr uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.find(addr) != nil
}

// Frames symbolizes a leaf-first address list into a root-first name list.
func (s *Symbolizer) Frames(addrs []uint64) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[len(addrs)-1-i] = s.Frame(a)
	}
	return out
}

func (s *Symbolizer) find(addr uint64) *mapping {
	i := sort.Search(len(s.maps), func(i int) bool { return s.maps[i].hi > addr })
	if i < len(s.maps) && s.maps[i].lo <= addr {
		return &s.maps[i]
	}
	return nil
}

func (s *Symbolizer) resolve(addr uint64) (string, bool) {
	m := s.find(addr)
	if m == nil && time.Since(s.lastReload) > 10*time.Millisecond { // newly mapped object? (misses are rare once running)
		s.reload()
		m = s.find(addr)
	}
	if m == nil {
		return fmt.Sprintf("[unknown 0x%x]", addr), false
	}
	o := s.objs[m.path]
	if o == nil {
		o = s.load(m.path)
		s.objs[m.path] = o
	}
	base := filepath.Base(m.path)
	fo := addr - m.lo + m.off
	vaddr, ok := uint64(0), false
	for _, p := range o.loads {
		if fo >= p.Off && fo < p.Off+p.Filesz {
			vaddr, ok = fo-p.Off+p.Vaddr, true
			break
		}
	}
	if !ok || len(o.syms) == 0 {
		return fmt.Sprintf("%s+0x%x", base, fo), true
	}
	i := sort.Search(len(o.syms), func(i int) bool { return o.syms[i].addr > vaddr }) - 1
	if i < 0 || (o.syms[i].size > 0 && vaddr >= o.syms[i].addr+o.syms[i].size) {
		return fmt.Sprintf("%s+0x%x", base, vaddr), true
	}
	return pretty(o.syms[i].name), true
}

func pretty(name string) string {
	if d, err := demangle.ToString(name, demangle.NoParams, demangle.NoTemplateParams, demangle.NoClones); err == nil {
		return d
	}
	return name
}

func (s *Symbolizer) load(path string) *object {
	o := &object{}
	opened := path
	if s.static {
		opened = s.root + path
	}
	f, err := elf.Open(opened)
	if err != nil && !s.static {
		opened = fmt.Sprintf("/proc/%d/root%s", s.pid, path)
		f, err = elf.Open(opened)
	}
	if err != nil {
		o.err = err
		return o
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			o.loads = append(o.loads, p.ProgHeader)
		}
	}
	var syms []elf.Symbol
	if id := buildID(f); id != "" && len(id) > 2 {
		for _, dir := range s.DebugDirs {
			dp := filepath.Join(dir, ".build-id", id[:2], id[2:]+".debug")
			if df, err := elf.Open(dp); err == nil {
				syms, _ = df.Symbols()
				df.Close()
				if len(syms) > 0 {
					o.source, o.file = dp, dp
					break
				}
			}
		}
	}
	if len(syms) == 0 {
		syms, _ = f.Symbols()
		o.source, o.file = path+" (.symtab)", opened
	}
	if len(syms) == 0 {
		syms, _ = f.DynamicSymbols()
		o.source = path + " (.dynsym only)"
	}
	for _, sy := range syms {
		if elf.ST_TYPE(sy.Info) == elf.STT_FUNC && sy.Value != 0 {
			o.syms = append(o.syms, symbol{addr: sy.Value, size: sy.Size, name: sy.Name})
		}
	}
	sort.Slice(o.syms, func(i, j int) bool { return o.syms[i].addr < o.syms[j].addr })
	return o
}

func buildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	b, err := sec.Data()
	if err != nil || len(b) < 16 {
		return ""
	}
	namesz := binary.LittleEndian.Uint32(b[0:])
	descsz := binary.LittleEndian.Uint32(b[4:])
	off := 12 + (namesz+3)&^3
	if int(off+descsz) > len(b) {
		return ""
	}
	return hex.EncodeToString(b[off : off+descsz])
}

// Sources reports where symbols came from for each loaded object (for diagnostics).
func (s *Symbolizer) Sources() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]string{}
	for p, o := range s.objs {
		if o.err != nil {
			m[p] = "error: " + o.err.Error()
		} else {
			m[p] = fmt.Sprintf("%s, %d functions", o.source, len(o.syms))
		}
	}
	return m
}

// Ranges returns the sorted, merged runtime address ranges [lo, hi) of functions named by fn in the target's
// mapped objects whose path matches obj.
func (s *Symbolizer) Ranges(obj, fn func(string) bool) [][2]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][2]uint64
	for _, m := range s.maps {
		if !obj(m.path) {
			continue
		}
		o := s.objs[m.path]
		if o == nil {
			o = s.load(m.path)
			s.objs[m.path] = o
		}
		for _, sy := range o.syms {
			if sy.size == 0 || !fn(sy.name) {
				continue
			}
			for _, p := range o.loads {
				if sy.addr < p.Vaddr || sy.addr >= p.Vaddr+p.Filesz {
					continue
				}
				fo := sy.addr - p.Vaddr + p.Off
				if fo >= m.off && fo < m.off+(m.hi-m.lo) {
					lo := fo - m.off + m.lo
					out = append(out, [2]uint64{lo, lo + sy.size})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	merged := out[:0]
	for _, r := range out {
		if n := len(merged); n > 0 && r[0] <= merged[n-1][1]+64 { // bridge alignment padding
			merged[n-1][1] = max(merged[n-1][1], r[1])
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}
