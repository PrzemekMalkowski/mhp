// Package pfs polls the server's own memory accounting as an optional cross-reference: Performance Schema memory
// instrumentation, or on MariaDB without it (its default) the Memory_used status variable and the per-connection
// MEMORY_USED of information_schema.PROCESSLIST. Neither is ground truth: they miss uninstrumented allocations
// (glibc overhead, many libraries, some engine paths), and PFS per-thread values can even go negative (freed by
// another thread). It uses the mysql CLI, so no driver dependency and the usual option files and auth_socket apply.
package pfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mhp/internal/model"
)

const threadsQuery = `SELECT t.THREAD_OS_ID, t.NAME, IFNULL(t.PROCESSLIST_ID,0), IFNULL(t.PROCESSLIST_USER,''),
 IFNULL(t.PROCESSLIST_COMMAND,''), IFNULL(SUM(m.CURRENT_NUMBER_OF_BYTES_USED),0)
FROM performance_schema.threads t
LEFT JOIN performance_schema.memory_summary_by_thread_by_event_name m ON m.THREAD_ID = t.THREAD_ID
WHERE t.THREAD_OS_ID IS NOT NULL GROUP BY t.THREAD_ID`

const areasQuery = `SELECT SUBSTRING_INDEX(EVENT_NAME,'/',2), SUM(CURRENT_NUMBER_OF_BYTES_USED)
FROM performance_schema.memory_summary_global_by_event_name GROUP BY 1`

// MariaDB (10.5+ has TID): what each connection's thread holds now and held at most, by its own accounting
const mariaConnQuery = `SELECT TID, ID, USER, COMMAND, MEMORY_USED, MAX_MEMORY_USED FROM information_schema.PROCESSLIST`

const mariaUsedQuery = `SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME='MEMORY_USED'`

// Ask prompts for a user and password (mhp asks on its terminal); ok false: none given.
type Ask func(ctx context.Context, why string) (user, password string, ok bool)

type Source struct {
	Args     []string // extra mysql client args (e.g. -uroot -S /path/sock)
	Interval time.Duration
	// PID is the server's: without a socket or host in Args, connect through the Unix socket it listens on.
	PID int
	// Ask is called when the server denies access (once per denial, up to 3 times; nil: never).
	Ask Ask

	creds   []byte // [client] option file content given through Ask, passed on a pipe (never on disk or argv)
	socket  string
	kind    string // "performance_schema", "mariadb" or "" (none: P_S off on MySQL)
	mariadb bool
}

// errDenied: the server refused the credentials (1045) or the authentication plugin (1698, auth_socket).
var errDenied = errors.New("access denied")

var deniedRe = regexp.MustCompile(`ERROR (1045|1698) `)

func (s *Source) args() []string {
	a := []string{}
	if s.creds != nil {
		a = append(a, "--defaults-extra-file=/dev/fd/3") // must come first
	}
	a = append(a, s.Args...)
	if s.socket != "" {
		a = append(a, "--socket="+s.socket)
	}
	return a
}

func (s *Source) query(ctx context.Context, q string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := append(s.args(), "--batch", "--skip-column-names", "--raw", "-e", q)
	var out, errb bytes.Buffer
	c := exec.CommandContext(ctx, "mysql", args...)
	c.Stdout, c.Stderr = &out, &errb
	if s.creds != nil {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		go func() { w.Write(s.creds); w.Close() }()
		c.ExtraFiles = []*os.File{r} // fd 3
		defer r.Close()
	}
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if deniedRe.MatchString(msg) {
			return nil, fmt.Errorf("%w: %s", errDenied, msg)
		}
		return nil, fmt.Errorf("mysql: %v: %s", err, msg)
	}
	var rows [][]string
	for _, l := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if l != "" {
			rows = append(rows, strings.Split(l, "\t"))
		}
	}
	return rows, nil
}

func num(s string) int64 { f, _ := strconv.ParseFloat(s, 64); return int64(f) }

func (s *Source) poll(ctx context.Context) (*model.PFSStats, error) {
	st := &model.PFSStats{Source: s.kind, ByArea: map[string]int64{}, Threads: map[int]model.PFSThread{}}
	if s.mariadb {
		rows, err := s.query(ctx, mariaUsedQuery)
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 && len(rows[0]) == 1 {
			st.MemoryUsed = num(rows[0][0])
		}
	}
	if s.kind == "mariadb" {
		rows, err := s.query(ctx, mariaConnQuery)
		if err != nil {
			return nil, err
		}
		var conns int64
		for _, r := range rows {
			if len(r) < 6 {
				continue
			}
			tid, _ := strconv.Atoi(r[0])
			conn, _ := strconv.ParseInt(r[1], 10, 64)
			b := num(r[4])
			conns += b
			if tid > 0 {
				st.Threads[tid] = model.PFSThread{Name: "connection", ConnID: conn, User: r[2], Command: r[3], Bytes: b, MaxBytes: num(r[5])}
			}
		}
		st.Total = st.MemoryUsed
		st.ByArea["connections"] = conns
		st.ByArea["not per connection"] = st.MemoryUsed - conns
		return st, nil
	}
	rows, err := s.query(ctx, areasQuery)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if len(r) == 2 {
			n := num(r[1])
			st.ByArea[strings.TrimPrefix(r[0], "memory/")] = n
			st.Total += n
		}
	}
	rows, err = s.query(ctx, threadsQuery)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if len(r) < 6 {
			continue
		}
		tid, _ := strconv.Atoi(r[0])
		conn, _ := strconv.ParseInt(r[2], 10, 64)
		st.Threads[tid] = model.PFSThread{Name: strings.TrimPrefix(r[1], "thread/"), ConnID: conn, User: r[3], Command: r[4], Bytes: num(r[5])}
	}
	return st, nil
}

// setup connects once: finds the socket, asks for credentials when denied, and picks what to read.
// done: nothing to read (P_S off on MySQL); stop polling.
func (s *Source) setup(ctx context.Context) (done bool, err error) {
	if s.socket == "" && s.PID > 0 && !hasTarget(s.Args) {
		if s.socket = ServerSocket(s.PID); s.socket != "" {
			log.Printf("server cross-check: connecting through %s (the server's socket)", s.socket)
		}
	}
	rows, err := s.query(ctx, "SELECT VERSION(), @@performance_schema")
	for tries := 0; errors.Is(err, errDenied) && s.Ask != nil && tries < 3; tries++ {
		why := strings.TrimPrefix(err.Error(), errDenied.Error()+": ")
		user, pass, ok := s.Ask(ctx, why)
		if !ok {
			s.Ask = nil
			break
		}
		s.creds = optionFile(user, pass)
		rows, err = s.query(ctx, "SELECT VERSION(), @@performance_schema")
	}
	if err != nil {
		return false, err
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return false, fmt.Errorf("unexpected answer to SELECT VERSION(): %q", rows)
	}
	s.mariadb = strings.Contains(strings.ToLower(rows[0][0]), "mariadb")
	switch {
	case rows[0][1] == "1":
		s.kind = "performance_schema"
	case s.mariadb:
		s.kind = "mariadb"
		log.Printf("server cross-check: MariaDB %s runs with performance_schema=OFF (its default): reading Memory_used and per-connection MEMORY_USED instead", rows[0][0])
	default:
		log.Print("server cross-check off: the server runs with performance_schema=OFF; restart it with --performance-schema=ON to compare")
		return true, nil
	}
	return false, nil
}

// optionFile is a [client] group for --defaults-extra-file, with values quoted the way the client reads them.
func optionFile(user, pass string) []byte {
	q := func(v string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
	}
	b := "[client]\n"
	if user != "" {
		b += "user=" + q(user) + "\n"
	}
	return []byte(b + "password=" + q(pass) + "\n")
}

func (s *Source) Run(ctx context.Context, out chan<- model.Tick) error {
	every := s.Interval
	if every == 0 {
		every = 5 * time.Second
	}
	failing, ready, denied := false, false, false
	for {
		var err error
		if !ready {
			var done bool
			if done, err = s.setup(ctx); done {
				<-ctx.Done()
				return nil
			}
			ready = err == nil
			if errors.Is(err, errDenied) && !denied {
				denied = true
				log.Printf("server cross-check: %v\n  give credentials with -mysql-args \"--defaults-extra-file=FILE\" (a [client] option file with user and password), or run mhp on a terminal to be asked", err)
			}
		}
		if ready {
			var st *model.PFSStats
			if st, err = s.poll(ctx); err == nil {
				if failing {
					log.Print("server cross-check connected")
				}
				failing = false
				select {
				case out <- model.Tick{T: time.Now(), PFS: st}:
				case <-ctx.Done():
					return nil
				}
			}
		}
		if err != nil && !errors.Is(err, errDenied) {
			if !failing {
				log.Printf("server cross-check unavailable (will retry): %v", err)
			}
			failing = true
			ready = false // connect again: a restarted server may run with other settings
			if s.PID > 0 && !hasTarget(s.Args) {
				s.socket = "" // look again: a server just started creates its socket late
			}
		}
		select {
		case <-time.After(every):
		case <-ctx.Done():
			return nil
		}
	}
}
