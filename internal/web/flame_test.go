package web

import (
	"bytes"
	"encoding/xml"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PrzemekMalkowski/mhp/internal/agg"
	"github.com/PrzemekMalkowski/mhp/internal/live"
)

var testStacks = []agg.WeightedStack{
	{Frames: []string{"main", "buf_pool_init", "ut::malloc_withkey", "malloc"}, Value: 3 << 20},
	{Frames: []string{"main", "log_sys_init", "operator new", "malloc"}, Value: 1 << 20},
	{Frames: []string{"main", "a<b&c>"}, Value: 1 << 10},
	{Frames: []string{"main", "shrunk"}, Value: -5},
}

func TestFlameSVG(t *testing.T) {
	var b bytes.Buffer
	FlameSVG(&b, testStacks, FlameOpts{Title: "t", HideWrappers: true, Unit: "bytes"})
	s := b.String()
	d := xml.NewDecoder(strings.NewReader(s))
	for {
		if _, err := d.Token(); err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("not well-formed: %v", err)
			}
			break
		}
	}
	if strings.Contains(s, `data-n="malloc"`) || !strings.Contains(s, `data-n="buf_pool_init"`) {
		t.Error("alloc wrappers not hidden")
	}
	if !strings.Contains(s, "buf_pool_init (3.0 MiB, 74.98%)") || !strings.Contains(s, "5 B shrank") {
		t.Error("tooltip value or shrink note missing")
	}
}

func TestFoldedCallers(t *testing.T) {
	var b bytes.Buffer
	Folded(&b, testStacks[:1], FlameOpts{Callers: true})
	if got := b.String(); got != "malloc;ut::malloc_withkey;buf_pool_init;main 3145728\n" {
		t.Errorf("got %q", got)
	}
}

func TestSourceLinks(t *testing.T) {
	r := &SourceRepos{Flavor: "percona", Version: "8.4.11", Release: "11"}
	l := r.Links("/usr/sbin/mysqld", "storage/innobase/buf/buf0buf.cc", 1014)
	if len(l) != 3 || l[0].URL != "https://github.com/percona/percona-server/blob/Percona-Server-8.4.11-11/storage/innobase/buf/buf0buf.cc#L1014" ||
		l[2].URL != "https://dev.mysql.com/doc/dev/mysql-server/8.4.11/buf0buf_8cc.html" {
		t.Errorf("got %+v", l)
	}
	if r.Links("/usr/lib/x86_64-linux-gnu/libc.so.6", "malloc/malloc.c", 3294) != nil || r.Links("/usr/sbin/mysqld", "/usr/include/c++/13/bits/vector.tcc", 1) != nil {
		t.Error("links for files outside the server tree")
	}
	// MyRocks: Percona Server only; its RocksDB library is a submodule (no file page at the tag) unless -source-map says where
	if l := r.Links("/usr/lib/mysql/plugin/ha_rocksdb.so", "storage/rocksdb/ha_rocksdb.cc", 7); len(l) != 1 ||
		l[0].URL != "https://github.com/percona/percona-server/blob/Percona-Server-8.4.11-11/storage/rocksdb/ha_rocksdb.cc#L7" {
		t.Errorf("myrocks links %+v", l)
	}
	if l := r.Links("/usr/lib/mysql/plugin/ha_rocksdb.so", "storage/rocksdb/rocksdb/util/compression.h", 1226); len(l) != 1 ||
		l[0].URL != "https://github.com/percona/percona-server/tree/Percona-Server-8.4.11-11/storage/rocksdb" {
		t.Errorf("submodule links %+v", l)
	}
	m, err := ParseSourceMap("storage/rocksdb/rocksdb=https://github.com/percona/rocksdb/blob/d0e61552")
	if err != nil {
		t.Fatal(err)
	}
	rm := *r
	rm.Maps = []SourceMap{m}
	if l := rm.Links("/usr/lib/mysql/plugin/ha_rocksdb.so", "storage/rocksdb/rocksdb/util/compression.h", 1226); len(l) != 1 ||
		l[0].URL != "https://github.com/percona/rocksdb/blob/d0e61552/util/compression.h#L1226" {
		t.Errorf("mapped links %+v", l)
	}
	if _, err := ParseSourceMap("storage/rocksdb/rocksdb"); err == nil {
		t.Error("map without URL accepted")
	}
	if doxygenName("sql_parse.cc") != "sql__parse_8cc" {
		t.Error(doxygenName("sql_parse.cc"))
	}
}

func TestParseRepos(t *testing.T) {
	for _, c := range []struct{ data, want string }{
		{"x\x00MySQL 8.4.11-11\x00y\x00Percona Server (GPL), Release '11', Revision '57878ff8'\x00", "percona-8.4.11-11"},
		{"\x00MySQL 8.0.36\x00\x00MySQL Community Server - GPL\x00\x003.0.13\x00", "mysql-8.0.36"},
		{"\x00MySQL 5.7.44-48\x00Percona Server (GPL), Release 48, Revision 497f936a373\x00", "percona-5.7.44-48"},
		{"\x00MySQL 8.0.36-28\x00Percona Server (GPL), Release '27'\x00", "unknown"}, // inconsistent
		{"\x0010.11.6-MariaDB-0+deb12u1\x00\x00MySQL 5.5.5\x00", "mariadb-10.11.6"},
		{"\x003.0.13\x00\x001.2.3-4\x00", "unknown"},
	} {
		if got := ParseRepos([]byte(c.data)).String(); got != c.want {
			t.Errorf("%q: got %s, want %s", c.data, got, c.want)
		}
	}
	if r, err := DetectRepos("/usr/sbin/mysqld", ""); err == nil { // the dev VM's Percona Server 8.4.11-11
		t.Logf("/usr/sbin/mysqld: %s", r)
	}
	for in, want := range map[string]string{"8.0.36": "mysql-8.0.36", "8.4.11-11": "percona-8.4.11-11", "mariadb-10.11.6": "mariadb-10.11.6"} {
		if r, err := DetectRepos("", in); err != nil || r.String() != want {
			t.Errorf("override %s: %v %v", in, r, err)
		}
	}
	if l := (&SourceRepos{Flavor: "mariadb", Version: "10.11.6"}).Links("/usr/sbin/mariadbd", "sql/table_cache.cc", 42); len(l) != 1 ||
		l[0].URL != "https://github.com/MariaDB/server/blob/mariadb-10.11.6/sql/table_cache.cc#L42" {
		t.Errorf("mariadb links %+v", l)
	}
}

func TestReport(t *testing.T) {
	hub := live.NewHub(100)
	for i := int64(0); i < 10; i++ {
		hub.Publish(live.View{T: 1000 * i, Traced: 100 << 20, TracedPeak: 100<<20 + i<<20, Proc: map[string]int64{"rss": 200 << 20},
			BySubsys: map[string]int64{"InnoDB": 60 << 20, "AuditLog": 40 << 20}})
	}
	st := []agg.WeightedStack{{Frames: []string{"main", "audit_log_filter::notify_event", "malloc"}, Value: 64 << 20, N: 3, Max: 32 << 20, Area: "AuditLog"}}
	s := &Server{Hub: hub,
		Stacks: func(f agg.Filter) []agg.WeightedStack { return st },
		Range: func(f agg.Filter) agg.RangeTotals {
			return agg.RangeTotals{AreaTotals: agg.AreaTotals{Alloc: 64 << 20, Free: 64 << 20, PeakRise: 32 << 20},
				Areas: []agg.AreaTotals{{Area: "AuditLog", Alloc: 64 << 20, PeakRise: 32 << 20}}}
		},
		Meta: func() [][2]string {
			return [][2]string{{"Host", "db1 (Linux 7.0)"}, {"Server", "percona-8.4.11-11 <&>"}}
		},
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/report.html?from=3000&to=6000&download=1", nil))
	out := rec.Body.String()
	for _, want := range []string{"mhp-report-db1-", "Memory report", "percona-8.4.11-11 &lt;&amp;&gt;", "<svg", "By area",
		"audit_log_filter::notify_event", `<iframe class="flame"`, "Raw folded stacks", "+32.0 MiB"} {
		if !strings.Contains(out+rec.Header().Get("Content-Disposition"), want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(out, "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" width=\"1600\"") {
		t.Error("flame SVG must be escaped inside srcdoc, not inline")
	}
}
