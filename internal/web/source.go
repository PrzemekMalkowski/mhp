package web

import (
	"debug/elf"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Link is a named URL shown next to a frame's source location.
type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// SourceRepos builds links for source files of one server build: GitHub at the release tag (file and line), and for
// MySQL/Percona the Doxygen file page on dev.mysql.com (it publishes no source browser, so no line).
type SourceRepos struct {
	Flavor  string      // "mysql", "percona" or "mariadb"
	Version string      // e.g. "8.4.11"
	Release string      // Percona release, e.g. "11" (tag Percona-Server-8.4.11-11)
	Maps    []SourceMap // -source-map: other repositories for parts of the tree, checked first
}

// SourceMap sends files under Prefix of the server tree to URL + the rest of the path + "#L<line>", e.g. Percona's
// RocksDB submodule: storage/rocksdb/rocksdb/ = https://github.com/percona/rocksdb/blob/<commit>/
type SourceMap struct{ Prefix, URL string }

// ParseSourceMap reads "PREFIX=URL".
func ParseSourceMap(s string) (SourceMap, error) {
	p, u, ok := strings.Cut(s, "=")
	if !ok || p == "" || !strings.HasPrefix(u, "http") {
		return SourceMap{}, fmt.Errorf("-source-map %q: want PREFIX=URL, e.g. storage/rocksdb/rocksdb/=https://github.com/percona/rocksdb/blob/<commit>/", s)
	}
	if !strings.HasSuffix(p, "/") {
		p += "/"
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return SourceMap{p, u}, nil
}

// perconaSubmodules are directories of the percona-server tree that are git submodules: GitHub has no file page for
// them at the release tag, only the submodule entry (with its pinned commit) in the parent directory.
var perconaSubmodules = []string{"storage/rocksdb/rocksdb/", "extra/coredumper/", "extra/libkmip/", "extra/jwt-cpp/"}

func (r *SourceRepos) String() string {
	if r == nil {
		return "unknown"
	}
	if r.Release != "" {
		return r.Flavor + "-" + r.Version + "-" + r.Release
	}
	return r.Flavor + "-" + r.Version
}

var (
	reMariaDB  = regexp.MustCompile(`\x00(\d+\.\d+\.\d+)-MariaDB`)
	rePercona  = regexp.MustCompile(`Percona Server \([^)]*\), Release '?(\d+)`)
	reMySQL    = regexp.MustCompile(`\x00MySQL (\d+\.\d+\.\d+)(?:-(\d+))?[-\x00]`)
	reOverride = regexp.MustCompile(`^(?:(mysql|percona|mariadb)-)?(\d+\.\d+\.\d+)(?:-(\d+))?$`)
)

// ParseRepos reads the server version from the constant data of a mysqld/mariadbd binary, without running it
// (so it works for containerised targets): "MySQL 8.4.11-11" next to "Percona Server (GPL), Release '11'",
// "MySQL 8.0.36" for Oracle builds, "10.11.6-MariaDB..." for MariaDB.
func ParseRepos(rodata []byte) *SourceRepos {
	if m := reMariaDB.FindSubmatch(rodata); m != nil {
		return &SourceRepos{Flavor: "mariadb", Version: string(m[1])}
	}
	m := reMySQL.FindSubmatch(rodata)
	if m == nil {
		return nil
	}
	r := &SourceRepos{Flavor: "mysql", Version: string(m[1])}
	if p := rePercona.FindSubmatch(rodata); p != nil {
		r.Flavor, r.Release = "percona", string(p[1])
		if len(m[2]) > 0 && string(m[2]) != r.Release {
			return nil // inconsistent: better no links than wrong ones
		}
	}
	return r
}

// DetectRepos reads the version from the target's executable; override ("8.4.11", "percona-8.4.11-11",
// "mariadb-10.11.6") takes precedence.
func DetectRepos(exe, override string) (*SourceRepos, error) {
	if override != "" {
		m := reOverride.FindStringSubmatch(override)
		if m == nil {
			return nil, fmt.Errorf("-source-version %q: want X.Y.Z, percona-X.Y.Z-R or mariadb-X.Y.Z", override)
		}
		r := &SourceRepos{Flavor: m[1], Version: m[2], Release: m[3]}
		if r.Flavor == "" {
			r.Flavor = "mysql"
			if r.Release != "" {
				r.Flavor = "percona"
			}
		}
		return r, nil
	}
	f, err := elf.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sec := f.Section(".rodata")
	if sec == nil {
		return nil, fmt.Errorf("%s: no .rodata", exe)
	}
	b, err := sec.Data()
	if err != nil {
		return nil, err
	}
	if r := ParseRepos(b); r != nil {
		return r, nil
	}
	return nil, fmt.Errorf("%s: no MySQL/Percona/MariaDB version string found", exe)
}

// Links returns source links for a file of the server tree (relative path) at line, for functions of the server
// binary itself or its private libraries (lib/mysql/...): glibc's malloc/malloc.c is not in the server repository.
func (r *SourceRepos) Links(object, file string, line int) []Link {
	if r == nil || file == "" || strings.HasPrefix(file, "/") || strings.HasPrefix(file, "obj/") {
		return nil // system header, or generated in the build directory
	}
	base := path.Base(object)
	if !strings.Contains(base, "mysqld") && !strings.Contains(base, "mariadbd") && !strings.Contains(object, "/mysql/") &&
		!strings.Contains(object, "/mariadb/") {
		return nil
	}
	for _, m := range r.Maps {
		if strings.HasPrefix(file, m.Prefix) {
			return []Link{{strings.TrimSuffix(m.Prefix, "/"), fmt.Sprintf("%s%s#L%d", m.URL, strings.TrimPrefix(file, m.Prefix), line)}}
		}
	}
	var out []Link
	switch r.Flavor {
	case "mariadb":
		return []Link{{"MariaDB " + r.Version,
			fmt.Sprintf("https://github.com/MariaDB/server/blob/mariadb-%s/%s#L%d", r.Version, file, line)}}
	case "percona":
		tag := "Percona-Server-" + r.Version + "-" + r.Release
		for _, sm := range perconaSubmodules {
			if strings.HasPrefix(file, sm) {
				dir := path.Dir(strings.TrimSuffix(sm, "/"))
				return []Link{{"Percona Server " + r.Version + "-" + r.Release + " (submodule " + path.Base(sm) + ": pinned commit)",
					fmt.Sprintf("https://github.com/percona/percona-server/tree/%s/%s", tag, dir)}}
			}
		}
		out = append(out, Link{"Percona Server " + r.Version + "-" + r.Release,
			fmt.Sprintf("https://github.com/percona/percona-server/blob/%s/%s#L%d", tag, file, line)})
		if strings.HasPrefix(file, "storage/rocksdb/") {
			return out // MyRocks is not in the MySQL tree
		}
	}
	out = append(out, Link{"MySQL " + r.Version,
		fmt.Sprintf("https://github.com/mysql/mysql-server/blob/mysql-%s/%s#L%d", r.Version, file, line)})
	out = append(out, Link{"MySQL docs (file)",
		fmt.Sprintf("https://dev.mysql.com/doc/dev/mysql-server/%s/%s.html", r.Version, doxygenName(file[strings.LastIndex(file, "/")+1:]))})
	return out
}

// doxygenName escapes a file name the way Doxygen names its pages (buf0buf.cc -> buf0buf_8cc).
func doxygenName(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '_':
			b.WriteString("__")
		case c == '.':
			b.WriteString("_8")
		case c == '-':
			b.WriteString("-")
		case c >= 'A' && c <= 'Z':
			b.WriteString("_" + string(c-'A'+'a'))
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

var reBanner = regexp.MustCompile(`Percona Server \([^)\x00]*\), Release '?\d+'?, Revision '?[0-9a-f]+'?|MySQL (Community|Enterprise) Server[^\x00]{0,40}|mariadb\.org binary distribution`)

// BuildInfo reads identification of a server binary for reports: its version banner (as in @@version_comment, with
// Percona's revision) and the ELF build ID, which names the exact build and its debug symbols.
func BuildInfo(exe string) (banner, buildID string) {
	f, err := elf.Open(exe)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	if sec := f.Section(".rodata"); sec != nil {
		if b, err := sec.Data(); err == nil {
			banner = string(reBanner.Find(b))
		}
	}
	if sec := f.Section(".note.gnu.build-id"); sec != nil {
		// note header: namesz, descsz, type (4 bytes each), then "GNU\0", then the ID
		if b, err := sec.Data(); err == nil && len(b) > 16 {
			buildID = fmt.Sprintf("%x", b[16:])
		}
	}
	return banner, buildID
}
