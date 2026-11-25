package pfs

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestHasTarget(t *testing.T) {
	for args, want := range map[string]bool{"": false, "-uroot": false, "-S /x.sock": true, "--socket=/x": true,
		"-h127.0.0.1": true, "--host db": true, "-P3306": true, "-pSecret": false, "--defaults-extra-file=/f": false,
		"--login-path=x": true} {
		var a []string
		for _, f := range splitArgs(args) {
			a = append(a, f)
		}
		if got := hasTarget(a); got != want {
			t.Errorf("hasTarget(%q) = %v", args, got)
		}
	}
}

func splitArgs(s string) []string {
	var out []string
	cur := ""
	for _, c := range s + " " {
		if c == ' ' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	return out
}

func TestOptionFile(t *testing.T) {
	got := string(optionFile("app", `p"a\ss`))
	want := "[client]\nuser=\"app\"\npassword=\"p\\\"a\\\\ss\"\n"
	if got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

func TestServerSocketSelf(t *testing.T) {
	if s := ServerSocket(os.Getpid()); s != "" { // the test process listens on nothing yet
		t.Fatalf("found %s in a process that listens on none", s)
	}
	dir := t.TempDir()
	x, err := net.Listen("unix", filepath.Join(dir, "mysqlx.sock")) // the X Protocol's: skipped
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if s := ServerSocket(os.Getpid()); s != "" {
		t.Errorf("took the X Protocol socket %s", s)
	}
	l, err := net.Listen("unix", filepath.Join(dir, "mysqld.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if s := ServerSocket(os.Getpid()); s != filepath.Join(dir, "mysqld.sock") {
		t.Errorf("ServerSocket = %q", s)
	}
}
