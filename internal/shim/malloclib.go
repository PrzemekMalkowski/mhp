package shim

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// libDirs are where distributions install allocator libraries.
var libDirs = []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib64", "/usr/lib", "/lib64",
	"/usr/local/lib64", "/usr/local/lib"}

// FindMallocLib resolves the allocator to preload under libmhp (mhp run -malloc-lib): a path, or "jemalloc" /
// "tcmalloc", looked up in the usual library directories like mysqld_safe's --malloc-lib does. tcmalloc prefers
// the full library to libtcmalloc_minimal.
func FindMallocLib(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		if _, err := os.Stat(name); err != nil {
			return "", err
		}
		return filepath.Abs(name)
	}
	var stems []string
	switch name {
	case "jemalloc":
		stems = []string{"libjemalloc"}
	case "tcmalloc":
		stems = []string{"libtcmalloc", "libtcmalloc_minimal"}
	default:
		return "", fmt.Errorf("malloc library %q: give jemalloc, tcmalloc or a path", name)
	}
	for _, stem := range stems {
		for _, dir := range libDirs {
			m, _ := filepath.Glob(filepath.Join(dir, stem+".so.[0-9]*"))
			if len(m) > 0 {
				sort.Slice(m, func(i, j int) bool { return len(m[i]) < len(m[j]) || len(m[i]) == len(m[j]) && m[i] < m[j] })
				return m[0], nil // the soname link (libjemalloc.so.2) rather than a full-version file name
			}
		}
	}
	return "", fmt.Errorf("no %s library (%s.so.N) in %s", name, stems[0], strings.Join(libDirs, ", "))
}
