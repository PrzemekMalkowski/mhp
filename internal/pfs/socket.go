package pfs

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ServerSocket returns the Unix socket the server pid listens on for classic-protocol clients (not the X
// Protocol's mysqlx socket), as a path this process can connect to: through /proc/PID/root when the server runs
// in another mount namespace (a container). "" when there is none or pid's file descriptors are not readable.
func ServerSocket(pid int) string {
	inodes := map[string]bool{}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return ""
	}
	for _, fd := range fds {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil {
			if in, ok := strings.CutPrefix(l, "socket:["); ok {
				inodes[strings.TrimSuffix(in, "]")] = true
			}
		}
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/net/unix", pid)) // the server's network namespace
	if err != nil {
		return ""
	}
	defer f.Close()
	var found []string
	sc := bufio.NewScanner(f)
	sc.Scan() // header: Num RefCount Protocol Flags Type St Inode Path
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 8 || !inodes[fl[6]] {
			continue
		}
		flags, _ := strconv.ParseUint(fl[3], 16, 32)
		path := strings.Join(fl[7:], " ")
		if flags&0x10000 == 0 || !strings.HasPrefix(path, "/") || strings.Contains(filepath.Base(path), "mysqlx") {
			continue // not listening (__SO_ACCEPTCON), abstract, or the X Protocol's
		}
		found = append(found, path)
	}
	if len(found) == 0 {
		return ""
	}
	path := found[0]
	for _, p := range found {
		if strings.HasSuffix(p, ".sock") {
			path = p
			break
		}
	}
	// the same file seen from here? else reach it through the server's root
	if mine, err := os.Stat(path); err == nil {
		if theirs, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, path)); err == nil && os.SameFile(mine, theirs) {
			return path
		}
	}
	return fmt.Sprintf("/proc/%d/root%s", pid, path)
}

// hasTarget tells whether the mysql client args already say where to connect.
func hasTarget(args []string) bool {
	for _, a := range args {
		for _, p := range []string{"-S", "--socket", "-h", "--host", "-P", "--port", "--protocol", "--login-path"} {
			if a == p || strings.HasPrefix(a, p+"=") || (len(p) == 2 && strings.HasPrefix(a, p) && len(a) > 2) {
				return true
			}
		}
	}
	return false
}
