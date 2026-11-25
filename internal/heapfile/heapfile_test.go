package heapfile

import (
	"math"
	"os"
	"strings"
	"testing"
)

const jeProfile = `heap_v2/524288
  t*: 3: 3000 [0: 0]
  t0: 3: 3000 [0: 0]
@ 0x7f0000001010 0x400123 0x400456
  t*: 2: 2000 [0: 0]
  t0: 2: 2000 [0: 0]
@ 0x7f0000001010 0x400789
  t*: 1: 1048576 [0: 0]
  t3: 1: 1048576 [0: 0]

MAPPED_LIBRARIES:
00400000-00500000 r-xp 00000000 fd:01 1 /usr/sbin/mysqld
7f0000000000-7f0000100000 r-xp 00000000 fd:01 2 /usr/lib/libjemalloc.so.2
`

const gpProfile = `heap profile:      3:     3000 [     5:     5000] @ heapprofile
     2:     2000 [     4:     4000] @ 0x400123 0x400456
     1:     1000 [     1:     1000] @ 0x400789

MAPPED_LIBRARIES:
00400000-00500000 r-xp 00000000 fd:01 1 /usr/sbin/mysqld
`

func TestJemalloc(t *testing.T) {
	p, err := Parse(strings.NewReader(jeProfile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "jemalloc heap_v2" || p.Period != 524288 || len(p.Stacks) != 2 || p.Cumulative {
		t.Fatalf("%+v", p)
	}
	// 2 samples of 1000 B: each stands for 1/(1-exp(-1000/524288)) objects (~524.8)
	f := 1 / (1 - math.Exp(-1000.0/524288))
	if s := p.Stacks[0]; s.InuseN != int64(math.Round(2*f)) || s.InuseB != int64(math.Round(2000*f)) || len(s.Addrs) != 3 || s.Addrs[0] != 0x7f0000001010 {
		t.Errorf("stack 0: %+v", s)
	}
	// a 1 MiB sample is nearly exact (scale 1/(1-e^-2) = 1.157)
	if s := p.Stacks[1]; s.InuseB != int64(math.Round(1048576/(1-math.Exp(-2)))) {
		t.Errorf("stack 1: %+v", s)
	}
	if !strings.Contains(p.Maps, "/usr/sbin/mysqld") {
		t.Error("maps")
	}
}

func TestGperftools(t *testing.T) {
	p, err := Parse(strings.NewReader(gpProfile))
	if err != nil {
		t.Fatal(err)
	}
	if p.Format != "gperftools heapprofile" || p.Period != 0 || len(p.Stacks) != 2 || !p.Cumulative ||
		p.InuseB != 3000 || p.AllocB != 5000 || p.Stacks[0].AllocN != 4 {
		t.Fatalf("%+v", p)
	}
}

func TestReject(t *testing.T) {
	if _, err := Parse(strings.NewReader("hello\n")); err == nil {
		t.Error("accepted garbage")
	}
	if _, err := Parse(strings.NewReader("heap_v2/1\n@ 0x1\n  t*: 1: 1 [0: 0]\n")); err == nil {
		t.Error("accepted a profile without maps")
	}
}

// TestRealFiles reads profiles given in MHP_HEAP_FILES (space-separated), e.g. from jemalloc and tcmalloc runs.
func TestRealFiles(t *testing.T) {
	files := strings.Fields(os.Getenv("MHP_HEAP_FILES"))
	if len(files) == 0 {
		t.Skip("MHP_HEAP_FILES not set")
	}
	for _, f := range files {
		r, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(r)
		r.Close()
		if err != nil {
			t.Fatal(f, err)
		}
		t.Logf("%s: %s, period %d, %d stacks, in use %.1f MiB (%d objects), allocated %.1f MiB", f, p.Format, p.Period,
			len(p.Stacks), float64(p.InuseB)/(1<<20), p.InuseN, float64(p.AllocB)/(1<<20))
	}
}
