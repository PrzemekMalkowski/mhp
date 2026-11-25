package procfs

import (
	"context"
	"fmt"
	"time"

	"mhp/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestSelf(t *testing.T) {
	s := New(os.Getpid(), 0, 0)
	p, err := s.readProc()
	if err != nil {
		t.Fatal(err)
	}
	if p.RSS <= 0 || p.Threads <= 0 {
		t.Fatalf("bad stats %+v", p)
	}
	r, _, err := s.readRegions()
	if err != nil || len(r) == 0 {
		t.Fatalf("regions %v %v", r, err)
	}
	th := s.readThreads()
	if len(th) == 0 || th[0].Comm == "" {
		t.Fatalf("threads %v", th)
	}
	t.Logf("%+v %v %+v", p, r, th[0])
}

func TestRegionClass(t *testing.T) {
	for _, c := range []struct {
		path, perms string
		deleted     bool
		want        string
	}{
		{"/usr/sbin/mysqld", "r--p", false, "file: code & libs"},
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", "r-xp", false, "file: code & libs"},
		{"/var/lib/mysql/galera.cache", "rw-s", false, "file: galera gcache"},
		{"/var/lib/mysql/gcache.page.000003", "rw-s", false, "file: galera gcache"},
		{"/tmp/mysql_temptable.uHVrZm", "rw-s", true, "file: deleted (temp)"},
		{"/var/lib/mysql/some.dat", "rw-s", false, "file: data"},
		{"", "rw-p", false, "anon-mmap"},
		{"/dev/shm/mhp.1", "rw-s", false, "shmem"},
	} {
		if got := RegionClass(c.path, c.perms, c.deleted); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.path, c.perms, got, c.want)
		}
	}
}

func TestRole(t *testing.T) {
	if Role("ib_io_rd-3") != "ib_io_rd" || Role("connection") != "connection" {
		t.Fatal("role")
	}
}

func TestSmapsOffAndAdaptive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := func(s *Source) model.Tick {
		out := make(chan model.Tick)
		go s.Run(ctx, out)
		return <-out
	}
	if tk := first(New(os.Getpid(), time.Second, 0)); tk.Regions != nil || tk.Proc.THP != -1 {
		t.Fatalf("smaps off: regions %v, THP %d", tk.Regions, tk.Proc.THP)
	}
	s := New(os.Getpid(), time.Second, 5*time.Second)
	if tk := first(s); len(tk.Regions) == 0 || tk.Proc.THP < 0 || s.SmapsCost() <= 0 {
		t.Fatalf("smaps on: regions %v, THP %d, cost %v", tk.Regions, tk.Proc.THP, s.SmapsCost())
	}
	for _, c := range []struct{ cost, want time.Duration }{
		{8 * time.Millisecond, 5 * time.Second},  // 0.8 s < 5 s: the configured interval
		{50 * time.Millisecond, 5 * time.Second}, // exactly 1 %
		{400 * time.Millisecond, 40 * time.Second},
		{4 * time.Second, 400 * time.Second},
	} {
		s.smapsCost.Store(int64(c.cost))
		if got := s.SmapsEvery(); got != c.want {
			t.Errorf("read takes %v: interval %v, want %v", c.cost, got, c.want)
		}
	}
	if off := New(1, time.Second, 0); off.SmapsEvery() != 0 {
		t.Error("off must report interval 0")
	}
}

func TestLowestMax(t *testing.T) {
	root := t.TempDir()
	for dir, v := range map[string]string{"a": "1000\n", "a/b": "max\n", "a/b/c": "5000\n"} {
		os.MkdirAll(filepath.Join(root, dir), 0o755)
		os.WriteFile(filepath.Join(root, dir, "memory.max"), []byte(v), 0o644)
	}
	if n := lowestMax(root, "/a/b/c"); n != 1000 {
		t.Errorf("lowest %d, want 1000", n)
	}
	if n := lowestMax(root, "/x"); n != 0 {
		t.Errorf("no limit: %d", n)
	}
}

// TestArenaMaps: [heap] plus non-main arena heaps (rw-p from a 64 MiB boundary, then ---p up to the next one, or
// full heaps merged into one mapping); other anonymous mappings are not arenas.
func TestArenaMaps(t *testing.T) {
	m := func(rng, perms, path string, rss int) string {
		return fmt.Sprintf("%s %s 00000000 00:00 0 %s\nSize: 1 kB\nRss: %d kB\nAnonHugePages: 0 kB\n", rng, perms, path, rss)
	}
	smaps := m("55d000000000-55d000021000", "rw-p", "[heap]", 100) +
		m("7f0000000000-7f0001000000", "rw-p", "", 1000) + // 16 MiB used of a heap
		m("7f0001000000-7f0004000000", "---p", "", 0) +
		m("7f0004000000-7f000c000000", "rw-p", "", 2000) + // two full heaps, merged
		m("7f000c000000-7f000c800000", "rw-p", "", 3000) + // 8 MiB of the next one...
		m("7f000c800000-7f0010000000", "---p", "", 0) + // ...and its reservation
		m("7f0020000000-7f0020100000", "rw-p", "", 5000) + // aligned, but no reservation after: an mmapped chunk
		m("7f0030001000-7f0030002000", "rw-p", "", 4) + // unaligned
		m("7f0040000000-7f0040400000", "rw-p", "", 7000) // last mapping, ends unaligned: not a heap
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "1"), 0o755)
	os.WriteFile(filepath.Join(dir, "1", "smaps"), []byte(smaps), 0o644)
	s := &Source{PID: 1, root: dir}
	if _, _, err := s.readRegions(); err != nil {
		t.Fatal(err)
	}
	a := s.arena
	want := int64(0x21000 + 16<<20 + 128<<20 + 8<<20)
	if a.Mapped != want || a.RSS != (100+1000+2000+3000)*1024 || a.Heaps != 4 {
		t.Errorf("got %+v, want mapped %d rss %d heaps 4", a, want, (100+1000+2000+3000)*1024)
	}
}
