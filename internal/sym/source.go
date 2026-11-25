package sym

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
)

// SourceLoc is where a function is defined, from DWARF line info via llvm-symbolizer.
type SourceLoc struct {
	File   string `json:"file"` // as compiled, cleaned (relative to the source tree when the build used relative paths)
	Line   int    `json:"line"`
	Object string `json:"object"` // mapped object the function lives in, e.g. /usr/sbin/mysqld
}

type fnAt struct {
	file, object string
	addr         uint64
	clone        bool // compiler-split part (.cold, .part.N, .isra...): its first line is not the definition
}

// sources looks up function definitions with one long-running llvm-symbolizer per ELF file. It parses only the
// compilation unit it needs, so mhp never loads the (GB-sized, compressed) DWARF of mysqld itself. The first lookup
// in a file takes a few seconds.
type sources struct {
	mu    sync.Mutex
	byFn  map[string]*SourceLoc // frame name -> location (nil = unknown)
	procs map[string]*symProc
	index map[string]fnAt // frame name -> where to look it up, built from the loaded objects
	n     int             // objects indexed
}

type symProc struct {
	in  io.Writer
	out *bufio.Reader
}

// Source returns where the function shown as frame name was defined.
func (s *Symbolizer) Source(name string) (SourceLoc, bool) {
	s.src.mu.Lock()
	defer s.src.mu.Unlock()
	if l, ok := s.src.byFn[name]; ok {
		if l == nil {
			return SourceLoc{}, false
		}
		return *l, true
	}
	if s.src.byFn == nil {
		s.src.byFn, s.src.procs = map[string]*SourceLoc{}, map[string]*symProc{}
	}
	s.mu.Lock()
	for _, m := range s.maps { // normally already loaded by symbolization
		if s.objs[m.path] == nil {
			s.objs[m.path] = s.load(m.path)
		}
	}
	if s.src.index == nil || s.src.n != len(s.objs) {
		s.src.index, s.src.n = map[string]fnAt{}, len(s.objs)
		for obj, o := range s.objs {
			if o.file == "" {
				continue
			}
			for _, sy := range o.syms {
				p := pretty(sy.name)
				clone := strings.Contains(sy.name, ".")
				if old, ok := s.src.index[p]; !ok || old.clone && !clone {
					s.src.index[p] = fnAt{file: o.file, object: obj, addr: sy.addr, clone: clone}
				}
			}
		}
	}
	at, ok := s.src.index[name]
	s.mu.Unlock()
	var loc *SourceLoc
	if ok {
		if loc = s.src.lookup(at.file, at.addr); loc != nil {
			loc.Object = at.object
		}
	}
	s.src.byFn[name] = loc
	if loc == nil {
		return SourceLoc{}, false
	}
	return *loc, true
}

func (c *sources) lookup(file string, addr uint64) *SourceLoc {
	p := c.procs[file]
	if p == nil {
		cmd := exec.Command("llvm-symbolizer", "--output-style=JSON", "--obj="+file)
		in, err1 := cmd.StdinPipe()
		out, err2 := cmd.StdoutPipe()
		if err1 != nil || err2 != nil || cmd.Start() != nil {
			c.procs[file] = &symProc{} // not installed: remember the failure
			return nil
		}
		p = &symProc{in: in, out: bufio.NewReader(out)}
		c.procs[file] = p
	}
	if p.in == nil {
		return nil
	}
	if _, err := fmt.Fprintf(p.in, "0x%x\n", addr); err != nil {
		p.in = nil
		return nil
	}
	line, err := p.out.ReadString('\n')
	if err != nil {
		p.in = nil
		return nil
	}
	var r struct {
		Symbol []struct {
			FileName, StartFileName string
			Line, StartLine         int
		}
	}
	if json.Unmarshal([]byte(line), &r) != nil || len(r.Symbol) == 0 {
		return nil
	}
	sy := r.Symbol[len(r.Symbol)-1]        // outermost frame when the entry is inlined
	f, l := sy.StartFileName, sy.StartLine // the definition; StartFileName is empty when it equals FileName
	if f == "" {
		f = sy.FileName
	}
	if l == 0 {
		l = sy.Line
	}
	if f == "" || l == 0 {
		return nil
	}
	return &SourceLoc{File: cleanSource(f), Line: l}
}

// treeDir is the source tree's own directory when a build kept it in its paths: the binary tarballs of Percona Server
// record "./obj/sql/../../../percona-server-8.4.11-12/sql/sql_parse.cc" (likewise mysql-8.4.6/, mariadb-11.8.10/).
var treeDir = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.+]*(?:-[A-Za-z][A-Za-z0-9_.+]*)*-[0-9][^/]*/`)

// cleanSource turns "./obj/sql/../storage/innobase/../../../storage/innobase/buf/buf0buf.cc" into
// "storage/innobase/buf/buf0buf.cc", relative to the source tree; absolute paths (system headers) stay absolute.
func cleanSource(f string) string {
	c := path.Clean(f)
	for strings.HasPrefix(c, "../") {
		c = c[3:]
	}
	if c != f || strings.HasPrefix(f, "./") { // only for paths relative to the build directory
		c = treeDir.ReplaceAllString(c, "")
	}
	return c
}
