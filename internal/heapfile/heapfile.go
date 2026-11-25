// Package heapfile reads the heap profiles allocators write themselves: jemalloc's (MALLOC_CONF=prof:true,
// "heap_v2/<period>") and gperftools tcmalloc's (HEAPPROFILE, "heap profile: ... @ heapprofile", or a sampled
// "@ heap_v2/<period>"). Both list stacks as return addresses with in-use (and cumulative) counts and bytes, then
// the process's /proc/self/maps after "MAPPED_LIBRARIES:".
package heapfile

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Stack is one allocation site; Addrs are return addresses, leaf first.
type Stack struct {
	Addrs                          []uint64
	InuseN, InuseB, AllocN, AllocB int64
}

type Profile struct {
	Format string // "jemalloc heap_v2", "gperftools heapprofile", "gperftools heap_v2"
	Period int64  // mean bytes between samples (0: every allocation recorded)
	Stacks []Stack
	Maps   string
	// Totals as the file states them (scaled the same way as the stacks)
	InuseB, InuseN, AllocB, AllocN int64
	Cumulative                     bool // the file carries cumulative counts (jemalloc prof_accum, gperftools always)
}

var (
	jeHeader = regexp.MustCompile(`^heap_v2/(\d+)\s*$`)
	jeCounts = regexp.MustCompile(`^\s*t\*:\s*(\d+):\s*(\d+)\s*\[\s*(\d+):\s*(\d+)\s*\]`)
	gpLine   = regexp.MustCompile(`^\s*(\d+):\s*(\d+)\s*\[\s*(\d+):\s*(\d+)\s*\]\s*@\s*(.*)$`)
	gpHeader = regexp.MustCompile(`^heap profile:\s*(\d+):\s*(\d+)\s*\[\s*(\d+):\s*(\d+)\s*\]\s*@\s*(\S+)`)
)

// Parse reads a profile. Sampled values are scaled up the way jeprof/pprof do: a stack seen with n samples of
// mean size s stands for n/(1-exp(-s/period)) objects.
func Parse(r io.Reader) (*Profile, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	first, err := br.ReadString('\n')
	if err != nil && first == "" {
		return nil, fmt.Errorf("empty profile")
	}
	first = strings.TrimRight(first, "\r\n")
	p := &Profile{}
	var lines []string
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	maps := false
	var mb strings.Builder
	for sc.Scan() {
		l := sc.Text()
		if maps {
			mb.WriteString(l)
			mb.WriteByte('\n')
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "MAPPED_LIBRARIES:") || strings.HasPrefix(l, "%MAPPED_LIBRARIES") {
			maps = true
			continue
		}
		lines = append(lines, l)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	p.Maps = mb.String()
	switch {
	case jeHeader.MatchString(first):
		p.Format = "jemalloc heap_v2"
		p.Period, _ = strconv.ParseInt(jeHeader.FindStringSubmatch(first)[1], 10, 64)
		p.Cumulative = true
		var cur *Stack
		for _, l := range lines {
			if strings.HasPrefix(l, "@") {
				cur = &Stack{Addrs: addrs(strings.TrimPrefix(l, "@"))}
				continue
			}
			m := jeCounts.FindStringSubmatch(l)
			if m == nil || cur == nil {
				continue
			}
			c := counts(m[1:5])
			cur.InuseN, cur.InuseB = scale(c[0], c[1], p.Period)
			cur.AllocN, cur.AllocB = scale(c[2], c[3], p.Period)
			p.Stacks = append(p.Stacks, *cur)
			cur = nil // per-thread lines follow; t* is the total
		}
	case gpHeader.MatchString(first):
		h := gpHeader.FindStringSubmatch(first)
		kind := h[5]
		switch {
		case kind == "heapprofile":
			p.Format = "gperftools heapprofile"
		case strings.HasPrefix(kind, "heap_v2/"):
			p.Format = "gperftools heap_v2"
			p.Period, _ = strconv.ParseInt(strings.TrimPrefix(kind, "heap_v2/"), 10, 64)
		default:
			return nil, fmt.Errorf("gperftools heap profile kind %q not supported (heapprofile and heap_v2/N are)", kind)
		}
		p.Cumulative = true
		for _, l := range lines {
			m := gpLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			c := counts(m[1:5])
			st := Stack{Addrs: addrs(m[5])}
			st.InuseN, st.InuseB = scale(c[0], c[1], p.Period)
			st.AllocN, st.AllocB = scale(c[2], c[3], p.Period)
			p.Stacks = append(p.Stacks, st)
		}
	default:
		return nil, fmt.Errorf("not a jemalloc or gperftools heap profile (first line %q)", trunc(first, 60))
	}
	if p.Maps == "" {
		return nil, fmt.Errorf("%s profile without MAPPED_LIBRARIES: cannot symbolize it", p.Format)
	}
	allZero := true
	for _, s := range p.Stacks {
		p.InuseB += s.InuseB
		p.InuseN += s.InuseN
		p.AllocB += s.AllocB
		p.AllocN += s.AllocN
		if s.AllocB != 0 {
			allZero = false
		}
	}
	if allZero {
		p.Cumulative = false // jemalloc without prof_accum writes [0: 0]
	}
	return p, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func counts(f []string) [4]int64 {
	var c [4]int64
	for i := range c {
		c[i], _ = strconv.ParseInt(f[i], 10, 64)
	}
	return c
}

func addrs(s string) []uint64 {
	var out []uint64
	for _, f := range strings.Fields(s) {
		if a, err := strconv.ParseUint(strings.TrimPrefix(f, "0x"), 16, 64); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// scale unsamples n objects of b bytes taken with a mean sampling period (bytes); period 0: exact.
func scale(n, b, period int64) (int64, int64) {
	if period <= 0 || n == 0 {
		return n, b
	}
	ratio := float64(b) / float64(n) / float64(period)
	f := 1 / (1 - math.Exp(-ratio))
	return int64(math.Round(float64(n) * f)), int64(math.Round(float64(b) * f))
}
