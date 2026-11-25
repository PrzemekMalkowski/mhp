package ebpf

import (
	"bufio"
	"maps"
	"os"
	"os/exec"
	"testing"

	"mhp/internal/sym"
)

// TestFaultCountsBatch checks that the batched read of the fault counters returns exactly what the entry-by-entry
// walk does, and that the counters cover the pages a multi-threaded target touched.
func TestFaultCountsBatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const threads, mib = 12, 8
	// Each thread touches its own mapping page by page, then all wait: many (stack, tid) counters, none changing.
	c := exec.Command("python3", "-c", `
import mmap, sys, threading
sys.stdin.readline()
def touch():
    m = mmap.mmap(-1, 8 << 20)
    m.madvise(mmap.MADV_NOHUGEPAGE)
    for i in range(0, len(m), 4096):
        m[i] = 1
    keep.append(m)
keep = []
ts = [threading.Thread(target=touch) for _ in range(12)]
[x.start() for x in ts]
[x.join() for x in ts]
print("done", flush=True)
sys.stdin.readline()
`)
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		t.Skip(err)
	}
	defer c.Process.Kill()
	s := &FaultSource{PID: c.Process.Pid, Sym: sym.New(c.Process.Pid)}
	if err := s.Open(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	in.Write([]byte("\n"))
	if l, _ := bufio.NewReader(out).ReadString('\n'); l != "done\n" {
		t.Fatalf("target said %q", l)
	}
	read := func(noBatch bool) (map[fkey]uint64, uint64) {
		s.noBatch = noBatch
		m, sum := map[fkey]uint64{}, uint64(0)
		s.readCounts(s.coll.Maps["counts"], func(k fkey, v uint64) {
			if _, dup := m[k]; !dup {
				m[k] = v
				sum += v
			}
		})
		return m, sum
	}
	batchSize = 8 // several batches, the last one partial
	defer func() { batchSize = 4096 }()
	batch, pages := read(false)
	if s.BatchErr != nil {
		t.Fatalf("batch read not used: %v", s.BatchErr)
	}
	walk, _ := read(true)
	if !maps.Equal(batch, walk) {
		t.Fatalf("batch read %d counters, walk %d, or values differ", len(batch), len(walk))
	}
	if want := uint64(threads * mib << 20 / pageSize); pages < want || pages > want*12/10 {
		t.Fatalf("counted %d page faults, target touched %d pages", pages, want)
	}
	tids := map[uint32]bool{}
	for k := range batch {
		tids[k.TID] = true
	}
	if len(tids) < threads {
		t.Fatalf("counters for %d threads, want at least %d", len(tids), threads)
	}
	t.Logf("%d counters, %d threads, %d faults (target touched %d pages)", len(batch), len(tids), pages, threads*mib<<20/pageSize)
}
