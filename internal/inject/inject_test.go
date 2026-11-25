package inject

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/PrzemekMalkowski/mhp/internal/shim"
)

// TestAttachDetach injects bin/libmhp.so into a small C program and undoes it (root and a C compiler needed):
//
//	sudo go test ./internal/inject -v
func TestAttachDetach(t *testing.T) {
	lib, _ := filepath.Abs("../../bin/libmhp.so")
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat(lib); err != nil {
		t.Skip("build libmhp first: make -C shim")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "t.c")
	os.WriteFile(src, []byte(`#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
static void *work(void *a) { for (;;) { free(malloc(1 << 20)); usleep(1000); } return a; }
int main(void) { pthread_t t; pthread_create(&t, 0, work, 0); for (;;) poll(0, 0, -1); }
`), 0o644)
	bin := filepath.Join(dir, "t")
	if out, err := exec.Command("cc", "-O1", "-pthread", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("no C compiler: %v %s", err, out)
	}
	cmd := exec.Command(bin)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	defer func() { cmd.Process.Kill(); cmd.Wait(); os.Remove(shim.RingPath(pid)) }()
	time.Sleep(200 * time.Millisecond)

	r, err := Attach(pid, lib, 256<<10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("attach: %+v", r)
	if !r.Loaded || r.Slots < 2 || r.TID != pid || r.Syscall != "poll" {
		t.Errorf("attach: %+v", r)
	}
	if st := shim.RingState(pid); st != shim.Injected {
		t.Errorf("ring state %d after attach", st)
	}
	time.Sleep(100 * time.Millisecond)
	d, err := Detach(pid)
	if err != nil {
		t.Fatal(err)
	}
	if d.Slots != r.Slots {
		t.Errorf("detach restored %d slots, attach redirected %d", d.Slots, r.Slots)
	}
	if st := shim.RingState(pid); st != shim.Undone {
		t.Errorf("ring state %d after detach", st)
	}
	// again: libmhp is mapped already, only the calls are redirected
	time.Sleep(50 * time.Millisecond) // the borrowed thread is back in its system call
	if r2, err := Attach(pid, lib, 256<<10, 1024); err != nil || r2.Loaded || r2.Slots != r.Slots {
		t.Errorf("re-attach: %+v %v", r2, err)
	}
	if _, err := Detach(pid); err != nil {
		t.Error(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("target died: %v", err)
	}
}
