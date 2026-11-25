package sym

import (
	"os"
	"testing"
	"time"
)

// TestLoadMysqld times symbol loading for the installed mysqld, or $MHP_MYSQLD (skipped if absent).
func TestLoadMysqld(t *testing.T) {
	bin := os.Getenv("MHP_MYSQLD")
	if bin == "" {
		bin = "/usr/sbin/mysqld"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no mysqld")
	}
	s := &Symbolizer{objs: map[string]*object{}, cache: map[uint64]string{}, DebugDirs: []string{"/usr/lib/debug"}}
	t0 := time.Now()
	o := s.load(bin)
	t.Logf("%d functions from %s in %v", len(o.syms), o.source, time.Since(t0))
	if len(o.syms) == 0 {
		t.Fatal("no symbols")
	}
}

func TestCleanSource(t *testing.T) {
	for in, want := range map[string]string{
		"./obj/sql/../storage/innobase/../../../storage/innobase/buf/buf0buf.cc": "storage/innobase/buf/buf0buf.cc",
		// Percona Server binary tarball: the source tree's own directory is in the path
		"./obj/sql/../../../percona-server-8.4.11-12/sql/sql_parse.cc":                                          "sql/sql_parse.cc",
		"./obj/storage/rocksdb/../../../../percona-server-8.4.11-12/storage/rocksdb/rocksdb/util/compression.h": "storage/rocksdb/rocksdb/util/compression.h",
		"./obj/sql/../../mysql-8.4.6/sql/handler.cc":                                                            "sql/handler.cc",
		"./mariadb-11.8.10/storage/innobase/btr/btr0cur.cc":                                                     "storage/innobase/btr/btr0cur.cc",
		// a versioned directory inside the tree stays
		"./obj/extra/zstd/zstd-1.5.5/lib/compress/zstd_compress.c": "obj/extra/zstd/zstd-1.5.5/lib/compress/zstd_compress.c",
		"extra/zstd/zstd-1.5.5/lib/common/xxhash.c":                "extra/zstd/zstd-1.5.5/lib/common/xxhash.c",
		"/usr/include/c++/13/bits/vector.tcc":                      "/usr/include/c++/13/bits/vector.tcc",
	} {
		if got := cleanSource(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
