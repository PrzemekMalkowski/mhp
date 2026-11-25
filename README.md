# mhp: Multi-dimensional Heap Profiler

A lightweight, live memory profiler for MySQL, Percona Server and MariaDB.

mhp shows, live in a browser, **where a running mysqld's memory goes**: per thread, per sub-system (InnoDB,
Performance Schema, SQL layer, TempTable, …) and down to the C++ function and call path that allocated it. It is built
for questions like "why is RSS 20 GB when the buffer pool is 12 GB?", "which part of the server is still growing?" or
"how much memory does each open table cost?".

"Multi-dimensional" because one set of samples can be cut several ways: by sub-system, thread, memory region, call
stack and time range, and each view filters the others.

It works on any native process; MySQL, Percona Server and MariaDB get extras: sub-system names, a Performance Schema
cross-check and links to the server source.

**See it without installing anything: [example recordings](https://przemekmalkowski.github.io/mhp/)** of Percona
Server 9.7 and 8.4 (InnoDB under large UPDATEs and an index build; MyRocks on glibc and jemalloc) and the overhead
benchmark. Each recording is the whole mhp UI saved as one HTML file, which opens in the browser.

## Quick start

Build (Go 1.26+, a C compiler; clang and bpftool for the BPF part):

    make -C bpf && go generate ./internal/offline && go build -o bin/mhp ./cmd/mhp && make -C shim    # -> bin/mhp, bin/libmhp.so

`go generate` compiles the offline copy's WebAssembly part (`cmd/mhpwasm`, embedded in mhp); rerun it after changing
`internal/web` or `internal/agg`.

Install debug symbols for readable function names (`percona-server-dbg`, `mysql-community-server-debug`, or your
distribution's `-dbgsym` package). Without them, stacks show only the few exported names.

Pick one way to run it (the UI is then at `http://HOST:8080`; see *Security* below):

| Situation | Command | You get |
|---|---|---|
| You can (re)start mysqld: most complete and cheapest | `sudo bin/mhp run -- /usr/sbin/mysqld --user=mysql` | every allocation since startup, ~2 % overhead |
| same, with mysqld on jemalloc or tcmalloc | `sudo bin/mhp run -malloc-lib jemalloc -- /usr/sbin/mysqld --user=mysql` | the same; `-malloc-lib` takes `jemalloc`, `tcmalloc` or a library path, like mysqld_safe's `malloc-lib` |
| mysqld already running, no restart allowed | `sudo bin/mhp watch -pid $(pidof mysqld) -inject` | heap stacks from now on at libmhp's cost, page-fault stacks, `/proc` view. Works on glibc malloc and on a preloaded jemalloc / tcmalloc |
| same, without ptrace, or with an allocator built into the binary | `sudo bin/mhp watch -pid $(pidof mysqld)` | eBPF heap stacks from now on (expensive, see below), page-fault stacks, `/proc` view |
| mysqld already running, just a cheap look | `sudo bin/mhp watch -pid $(pidof mysqld) -ebpf off` | page-fault stacks and `/proc` view, negligible cost |
| Keep the option open on a production box | start mysqld with `LD_PRELOAD=/path/libmhp.so MHP_START=0`, later `sudo bin/mhp watch -pid …` | same as `run`, but sampling is off (≈ free) until you attach |

For `mhp run` on a systemd host: stop the service first, and create `/run/mysqld` (owned by mysql), which systemd
removes on stop. mysqld then runs as a child of mhp, and stopping mhp (Ctrl-C) shuts it down cleanly.

Other modes: `bin/mhp demo` (synthetic data), `-record run.jsonl` and `bin/mhp replay run.jsonl` (record and replay a
session, e.g. to share it).

## Where the data comes from

mhp combines several sources. Each one answers a different question, and the UI says which ones are active.

### 1. `/proc`: always on, no privileges
Every second mhp reads `/proc/<pid>/status`, `/proc/<pid>/stat`, `/proc/<pid>/task/*/stat` and the cgroup memory
limit, and every 5 s `/proc/<pid>/smaps` (see `-smaps` below). That gives:
- **RSS** split into anonymous memory (heap, `malloc`), file-backed (binaries, mapped files) and shared memory;
- RSS by **region**: `heap(brk)`, `anon-mmap`, stacks, files;
- per **thread**: CPU, minor/major page faults, thread name (`ib_io_rd`, `connection`, …), like `pidstat -t`.

Linux has no per-thread RSS (threads share one address space). The per-thread *memory* columns come from the tracers
below.

### 2. Heap allocation tracing: who called `malloc`, and is it still held
This is the main source for "which function holds the memory". mhp records **a sample** of allocations with their call
stack, and their frees:
- **Sampling**: on average one allocation per 256 KiB allocated is recorded (`-sample-bytes`), and each sample is
  weighted by how likely it was to be picked. Large allocations (buffer pool, log buffer) are always recorded. Small
  ones appear statistically: totals are accurate, but a stack with only a few KiB is an estimate.
- **"Live"** means allocated and not yet freed. It is not the same as resident: memory can be allocated but never
  touched (not in RSS yet), and freed memory can stay in RSS inside glibc's free lists. The Overview's accounting
  panel shows both.
- Covers the `malloc` / `calloc` / `realloc` / `free` / `memalign` family, C++ `new`/`delete`, and anonymous
  `mmap` / `munmap` made by the server (e.g. the buffer pool). The eBPF tracer follows the allocator mysqld actually
  uses: glibc, or jemalloc / tcmalloc / mimalloc (preloaded via `malloc-lib`, linked, or built into the binary); it
  then also probes their own `operator new`/`delete` and `mallocx`-style calls.
- **Allocators with libmhp**: glibc malloc, and jemalloc or tcmalloc loaded as a library (`LD_PRELOAD`, mysqld_safe's
  `malloc-lib`), for both `mhp run` and `-inject`. libmhp sits in front of the allocator and passes every call on to
  it. jemalloc and tcmalloc bring their own `operator new`/`delete`, which mysqld then calls directly, so libmhp
  wraps those too. The allocator's own mappings (jemalloc extents, tcmalloc spans) are not recorded as `mmap`s: the
  memory in them is counted through `malloc`. The Context tab shows which allocator is in use, with its version.
  Not covered: an allocator linked statically into the mysqld binary (use the eBPF tracer), and jemalloc's own API
  (`mallocx` & co.), which mysqld does not call.
- **Reserved address space**: an inaccessible (`PROT_NONE`) mapping holds no memory and is not counted. MariaDB 11.8+
  reserves `innodb_buffer_pool_size_max` (8 TiB by default) this way, commits the buffer pool into it with `mmap`, and
  gives memory back on a shrink with `mprotect(PROT_NONE)`, which mhp counts as freed. So an online
  `SET GLOBAL innodb_buffer_pool_size` shows up in both directions. A commit through `mprotect` (MariaDB 11.8+
  commits with `mmap`) would not be seen.

**MariaDB** (tested: 11.4.14, 11.8.10, 12.3.4 from the mariadb.org binary tarballs, `mhp run`, `-inject` and eBPF):
- Sub-systems add **Aria** (page cache, `aria_pagecache_buffer_size`, 128 MiB by default), **MyISAM** (key cache,
  `key_buffer_size`, 128 MiB), **MEMORY** (also in-memory internal temporary tables), **QueryCache**, **Galera** and
  **RocksDB** (MyRocks: the RocksDB library and its handler, also in Percona Server).
  Together with the buffer pool they are allocated at startup but mostly not touched yet, so traced live is well above
  RSS (a negative gap) on an idle server.
- MariaDB before 11.8 leaves all threads named `mariadbd`; mhp then names a thread's role after its start function
  (`handle_one_connection`, `tpool::thread_pool_generic::worker_main`, `buf_flush_page_cleaner`). 11.8+ names its
  threads (`one_connection`, `ib_tpool_worker`...).
- Performance Schema is off by default in MariaDB: the cross-check says so in the log and stays off. Start the server
  with `--performance-schema=ON` to compare.
- It mallocs the whole `sort_buffer_size` (2 MiB) for every filesort and blocks for in-memory temporary tables, so
  "alloc / free rate" is in GB/s under sysbench oltp_read_write while live memory hardly moves. That is real.

Three ways to collect it:

| | **libmhp** (preload library) | **libmhp injected** | **eBPF uprobes** |
|---|---|---|---|
| Used by | `mhp run`, or mysqld started with `LD_PRELOAD=libmhp.so` | `mhp watch -inject` | `mhp watch` on a mysqld started without libmhp |
| How | a small library loaded into mysqld replaces `malloc` & co., takes the sample, and writes it to a shared-memory ring that mhp reads | mhp loads the same library into the running mysqld and redirects mysqld's calls to it (below) | the kernel puts breakpoints on `malloc` & co. of mysqld's allocator (glibc, jemalloc, tcmalloc...); a BPF program samples and passes stacks to mhp |
| Needs | restart (or preload set up earlier); no privileges for the library itself | root (ptrace), x86_64; glibc malloc, or jemalloc / tcmalloc loaded as a library; no restart | root, kernel with `uprobe_multi` links and BTF (Linux 6.6+, RHEL/Rocky 9), no restart |
| Costs | ~2 % | ~2 %, plus one thread paused for a few ms at attach and at exit | up to −67 % tps (per call) |
| Sees | everything since mysqld started | only what is allocated **after attach** | only what is allocated **after attach**; older memory (e.g. the buffer pool) is invisible to it |

**How `-inject` works.** mhp borrows one mysqld thread that is blocked in a waiting system call (the connection
listener in `poll`, usually), so it holds no lock: it stops just that thread with ptrace (the others keep running),
makes it call `dlopen("libmhp.so")` and then libmhp's `mhp_attach()`, and puts it back as it was. Loaded that way,
libmhp's `malloc` replaces nothing by itself; `mhp_attach()` rewrites the GOT slots (the per-library tables of resolved
function addresses) of every loaded library and of mysqld that point at the allocator's `malloc`, `free`, `calloc`,
`realloc`, `memalign` family and `mmap`/`munmap` (with jemalloc or tcmalloc also their `operator new`/`delete`), to
point at libmhp's wrappers, which call the allocator. That is the same set of calls
`LD_PRELOAD` would have redirected, so the data is the same as a preload's from that moment on. Libraries loaded later
(plugins, components) are redirected within a second. When mhp stops (Ctrl-C), it borrows a thread again and points
every slot back at the allocator; libmhp stays mapped but idle, and its ring stays in `/dev/shm` until mysqld exits. A later
`mhp watch -inject` reuses both. If mhp is killed before it can undo, the calls stay redirected (samples are dropped
once the ring is full, at little cost): run `mhp watch -inject` again and stop it with Ctrl-C.

### 3. Page-fault stacks: who makes RSS grow
When a process touches a page of memory for the first time, the kernel takes a *page fault* and maps a page: that is
how RSS grows. mhp counts these per call stack and per kind of memory (`[fault: anon-mmap]`, `heap(brk)`, `file`, …).
It works on any running process, with no restart. It needs root.
- Default (`-fault-src auto`): a BPF program counts faults inside the kernel at the point where they are handled. It
  sees user-mode faults, faults taken inside system calls (e.g. `read()` into a fresh buffer) and memory pre-populated
  by `mmap(MAP_POPULATE)` (the InnoDB buffer pool), and loses nothing in bursts such as server startup.
- Fallback (`-fault-src perf`, or automatically when BPF is not available): `perf` sampling. It misses faults taken
  inside system calls, and can drop samples in bursts (the UI shows "lost").
- Faults show where memory is *first touched*, not who holds it now. Memory that is freed and allocated again (e.g.
  TempTable blocks for every GROUP BY) faults again each time, so totals grow with churn. Frees are not visible here.

### 4. Server cross-check: what MySQL or MariaDB itself claims (reference only)
mhp runs the `mysql` client every 5 s and shows what the server's own accounting says *next to* mhp's numbers, never
mixed in:
- **Performance Schema** (when it is on): memory per area (`memory_summary_global_by_event_name`) and per thread
  (joined to `threads` by OS thread id), plus connection id, user and command per thread.
- **MariaDB without Performance Schema** (its default): the `Memory_used` status variable, and each connection's
  `MEMORY_USED` and `MAX_MEMORY_USED` from `information_schema.PROCESSLIST`, matched to threads by its `TID` column
  (MariaDB 10.5+). These count what MariaDB allocates through its own wrappers, resident or not, so `Memory_used` can
  exceed RSS.

Both miss memory they do not instrument (glibc overhead and fragmentation, libraries, some engine paths), and they
count from server start while `mhp watch` counts from attach.

**Connecting.** Unless `-mysql-args` already says where to connect (`-S`, `-h`, `-P`, `--protocol`,
`--login-path`), mhp connects through the Unix socket the server process listens on, found from the process itself
(`/proc/PID/fd` and `/proc/PID/net/unix`; the X Protocol socket is skipped, and a containerised server's socket is
reached through `/proc/PID/root`). It first tries the client's defaults (your option files, `auth_socket` as root).
If the server denies access and mhp runs on a terminal, mhp asks for a user and password (the password is not
echoed). Up to three tries; an empty user skips the cross-check. The credentials stay in mhp's memory and reach the
`mysql` client through a pipe (`--defaults-extra-file=/dev/fd/3`): never on its command line, in the environment or
on disk. Without a terminal mhp logs the denial; give `-mysql-args "--defaults-extra-file=FILE"` with a `[client]`
option file then.

### 5. The allocator's own statistics (with libmhp only)
Every 5 s libmhp asks the allocator inside mysqld how much memory it holds that the program is not using. This often
explains the gap between "allocated" and RSS. The Overview's accounting panel shows it:
- **glibc** (`mallinfo2()`): free chunks kept in the arenas (fragmentation), and the part `malloc_trim` could return to
  the OS. Every 30 s (`-arenas`) libmhp also takes glibc's `malloc_info()`, the same numbers **per arena**, shown in the
  Overview's **glibc arenas** panel (below).
- **jemalloc** (`mallctl` `stats.*`): allocated, active, metadata, resident, mapped and retained; "free, held by
  jemalloc" is resident minus allocated and metadata (unused space in active pages plus dirty pages). jemalloc counts
  each allocation at its size class, so its "allocated" is higher than mhp's traced bytes, which are the sizes
  requested (about 15 % higher for a freshly started Percona Server 8.4).
- **tcmalloc** (gperftools `MallocExtension` properties): allocated, heap size, free pages in the page heap (mapped,
  and returned to the OS), and free objects in the thread, central and transfer caches.

#### glibc arenas: where the free memory sits
glibc gives each thread one of up to 8 × CPUs arenas, and returns memory to the OS only from the top of an arena (and
whole sub-heaps of the non-main ones). Free chunks below a live one stay in RSS until `malloc_trim()`. `mallinfo2`
totals say how much is free; the arenas panel says **where**:
- a strip with one bar per arena, its width the arena's size, split into in use and free; clicking a bar highlights
  its row in the table (and clicking a row, its bar);
- per arena, sorted by free memory in chunks (click a column header to sort by it): size, in use, free and free %; the **top chunk** (free space at the
  arena's end, which glibc returns by itself once it exceeds the trim threshold: 128 KiB, or twice the dynamic mmap
  threshold, up to 64 MiB); free bytes in chunks by size (≥ 128 KiB, whose whole pages `malloc_trim` would release;
  1–128 KiB; < 1 KiB); the largest free chunk, the number of free chunks and the arena's high-water mark;
- the number of arenas, totals, and the allocations outside any arena (mmapped chunks);
- how much of the arenas is **resident**, from smaps: glibc maps the main arena as `[heap]` and the others as heaps
  at 64 MiB boundaries, which mhp picks out of the smaps it reads anyway. Free chunks whose pages `malloc_trim`
  released (or that were never touched) stay free in `malloc_info` but leave RSS, so arena RSS minus in-use bytes is
  the free memory that still costs RAM;
- when much of that is free and resident, a note naming the arena that holds most of it and the remedies:
  `malloc_trim(0)`, fewer arenas (`GLIBC_TUNABLES=glibc.malloc.arena_max=N`), or jemalloc / tcmalloc. When the free
  chunks are mostly not resident (after a trim), the note says so instead.

For example, a Percona Server 8.4 at its RSS peak under a blob-heavy MyRocks workload had 97 arenas holding 34 GiB,
24 GiB of it free; the one holding the most free memory, arena #67, was 3.2 GiB and 95 % free. Finding that took gdb and `malloc_info` by
hand; the panel shows it live, and keeps it in offline copies.

`malloc_info()` takes each arena's lock in turn and walks its bins, as `mallinfo2` does; it writes XML (about 3 KB per
arena) into a 4 MiB area at the end of the libmhp ring, which stays unallocated until used. mhp stretches the interval
to 200× what one call took. It runs on the target's next sampled allocation, so not while tracing is paused, and only
over glibc malloc (not jemalloc or tcmalloc, and not with the eBPF tracer). Every reading is kept for the length of the timeline (`-retention`), in offline copies too: with a
time range selected on the chart, the panel shows the reading taken at or before the end of the range, with the
smaps read nearest to it; with none selected, the latest. "refresh now" asks for
one at once, together with an smaps read so the resident figure is of the same moment; otherwise it comes from the
last periodic smaps read, whose time the panel shows. At 97 arenas and 35 GiB, one call took 12.5 ms in the target.

### 6. Symbols and source links
Return addresses are turned into function names from the binary's symbols or, much better, the debug-symbol package
(found by build id under `/usr/lib/debug`). For MySQL/Percona/MariaDB, hovering a frame in Explore shows the source
file and line where the function is defined, with links to GitHub at the exact release tag (and the dev.mysql.com
Doxygen page). The version is read from the mysqld binary. mhp uses `llvm-symbolizer` for this, started on first use. Files in a git
submodule of the server repository (Percona Server's RocksDB, under `storage/rocksdb/rocksdb/`) have no page at the
release tag, so they link to the submodule's entry, which names the pinned commit; `-source-map` turns that into file
links. Binary tarballs ship stripped; the full (non-"minimal") tarball of the same release has the same build ids, so
its `bin/mysqld` and `lib/plugin/*.so` can serve as debug files: place them as `.build-id/xx/yyyy.debug` under a
directory given to `-debug-dir`.

## What it costs

Measured on Percona Server 8.4.11 in an 8-vCPU KVM guest (Linux 7.0), sysbench `oltp_read_only`, 16 threads, unless
noted. Overhead depends mostly on how often mysqld calls `malloc`: about 140 malloc and 140 free calls per read-only
transaction here, i.e. 2.6 million per second at 9,400 tps.

| Source | Throughput cost | Memory | Notes |
|---|---|---|---|
| `/proc` polling | not measurable | – | the `smaps` read (regions view, THP) walks every resident page of mysqld: about 13 ms per GiB here. It runs every 5 s, and at most 1 % of the time: when one read takes over 50 ms the interval is stretched to 100× the read time (the Context tab shows the interval in effect). `-smaps 0` turns it off |
| **libmhp** (`mhp run` / preload / `-inject`) | **−2 % tps**, p95 latency unchanged | mysqld RSS +25 MB; 17 MB ring in `/dev/shm` | with `MHP_START=0` and nobody attached: one memory read per malloc call |
| `-inject` attach / undo | one thread paused 5–10 ms each time (mysqld's other threads keep running) | – | measured on Percona Server 8.4.11 under sysbench: no visible dip |
| libmhp allocator statistics | glibc `mallinfo2` 0.15–0.26 ms, jemalloc 0.2–0.25 ms, tcmalloc 0.02–0.04 ms, every 5 s | – | the allocator locks its arenas (tcmalloc: its thread list) while it counts, so threads allocating at that moment wait up to that long |
| **eBPF uprobes** (`watch` without libmhp) | **−67 % tps** in this VM (9,400 → 3,100) | ~96 MiB kernel memory | every malloc *and* free call traps into the kernel, ~2 µs each in this VM. Cost is per call, not per byte, so `-sample-bytes` does not reduce it. Bare metal is expected to be cheaper but is not measured yet. Use it for short sessions, or `-ebpf off` |
| **BPF page-fault counting** | +0.6 µs per page fault (a fault itself costs ~1.2 µs) | ~42 MiB kernel memory | steady-state mysqld faults rarely (about 10/s here), so the cost is negligible. Server startup (~150k faults) is about 0.1 s slower |
| perf page faults (fallback) | +0.65 µs per fault | 2 MiB per CPU | may lose samples in bursts |
| libmhp per-arena detail (`malloc_info`) | 0.07 ms for 7 arenas; grows with arenas and free chunks | up to 4 MiB of `/dev/shm`, only as written | every 30 s, stretched to 200× its cost; `-arenas 0` turns it off |
| Performance Schema / MariaDB poll | one set of queries every 5 s | – | `-pfs off` to disable, `-pfs-interval` |
| Peak copies | one offline snapshot per new RSS high: taking it is instant, finishing it (source lookups, writing) takes 1–30 s of one core in the background, more when many stacks are new | the snapshot, kept gzipped (a few MB) | `-peak off` to disable |
| mhp itself | 3–6 % of one CPU core | 80–100 MB RSS | grows with the number of distinct stacks |
| mhp history (`-retention 10m`) | – | ~15 MB per 10 min at 300 sysbench tx/s | the per-second timeline records (~400/s × 56 bytes here; none while tracing is paused) plus the chart history (~2 KB per second). Capped at 1M records (`-timeline`, ~56 MB) whatever the retention |
| Browser tab | – | a few MB | keeps its own copy of the chart history (same retention); only the last 2 minutes keep thread and stack tables |
| Tracing paused (UI button) | libmhp: one table lookup per `free` while earlier samples are still live; eBPF: the uprobes stay attached, so most of its cost remains | – | frees of earlier samples keep being recorded, so live bytes stay correct after resuming |

**Five servers on Rocky Linux 9.9** (32-vCPU KVM guest, kernel 5.14 without session uprobes; MySQL 8.4.13, 9.7.4,
26.10.0, MariaDB 12.3.4, 11.8.10; `oltp_read_only` in an 8 or 16 GB buffer pool, 1-64 threads, 450 runs). Median
throughput change against a plain start of the same server, where a second plain start moves by about ±2 %:

| Mode | MySQL 8.4 / 9.7 / 26.10 | MariaDB 12.3 / 11.8 |
|---|---|---|
| `mhp run` (glibc) | −2.0 / −2.6 / −1.7 % | −1.2 / +0.3 % |
| `mhp run -malloc-lib jemalloc` (vs jemalloc alone) | −0.3 / −0.7 / −2.0 % | −1.3 / −0.3 % |
| `LD_PRELOAD` libmhp, `MHP_START=0`, nothing attached | ≈ 0 % | ≈ 0 % |
| preloaded + `mhp watch` | −1.0 / −2.6 / −4.5 % | 0 / +0.7 % |
| `watch -inject` | −1.4 / −3.3 / −3.2 % | −1.0 / −0.1 % |
| eBPF (entry + return probes on 5.14) | −61 % (−73 % at 32+ threads) | −34 / −23 % |

mhp itself used 9–18 % of one core with libmhp (more with more threads), 20–55 % with eBPF, and 70–170 MiB RSS.
The interactive report, with these and the Percona Server 8.4.11 runs: [`docs/reports/mhp-overhead.html`](https://przemekmalkowski.github.io/mhp/reports/mhp-overhead.html).

Rules of thumb:
- For a full picture with negligible cost, **restart mysqld under `mhp run`** (or with the preload library), ideally
  in a maintenance window.
- On a busy production server you can't restart: use `mhp watch -ebpf off` (page faults plus `/proc`). Turn the eBPF
  heap tracer on only for minutes, and expect a large slowdown at high query rates, especially on VMs.
- `-sample-bytes` trades precision for cost with libmhp only: 4096 gives exact-looking small objects at noticeably
  more cost, while 1 MiB is cheaper and coarser.

## What it cannot see

- **Before attach**: `mhp watch` sees allocations and faults only from attach on. To attribute memory that already
  existed (e.g. the buffer pool), start mysqld under `mhp run`, or compare with the Performance Schema column. On a
  server at steady state, most memory allocated after attach is freed again within the same query, so traced live
  stays small (a few MiB for MariaDB under sysbench); "allocated" and the range views show the activity.
- **Re-injecting after an mhp upgrade**: a later `-inject` reuses the libmhp already mapped into mysqld, so a newer
  libmhp takes effect only after mysqld restarts.
- **Allocators built into the binary**: libmhp (`mhp run`, `-inject`) follows glibc malloc and jemalloc / tcmalloc
  loaded as libraries. A mysqld with an allocator linked in statically calls it directly: use `mhp watch` (eBPF)
  there. Other preloaded allocators (mimalloc, ...) are passed through and traced, without their statistics, but
  are not tested.
- **Preload order**: libmhp must come before the allocator in `LD_PRELOAD` (`mhp run -malloc-lib` does that). Behind
  it, libmhp stays idle and creates no ring; `mhp watch -inject` still works then.
- **`-inject` and copied function pointers**: a pointer to `free` that mysqld or a library copied into its own
  variable before the injection still calls the allocator's `free` directly. A sampled allocation freed that way stays "live"
  in mhp. mhp redirects the slots such copies are made from, so this needs a copy made before attach; none is known in
  mysqld.
- Kernel memory charged to mysqld (socket buffers, page cache for buffered I/O) is not in the stacks. The page cache is
  not in RSS either; `/proc` shows file-backed RSS.
- Transparent huge pages: a 2 MB huge-page fault is counted as one 4 KiB page.
- `mremap` is not followed.
- **File-backed mmaps** (Galera's `galera.cache` / `gcache.page.*`, TempTable mmap files with `temptable_use_mmap`) are
  page cache, not heap: they are not in the heap stacks. They show in the Overview's region view by RSS ("file: galera
  gcache", "file: deleted (temp)", "file: data"), and their page faults, with stacks, in Explore (`[fault: file]`).
  Anonymous mmaps (buffer pool, TempTable RAM chunks, Galera's in-memory store) are traced like malloc.

## Requirements and permissions

| Feature | Needs |
|---|---|
| `/proc` view | read access to `/proc/<pid>` (same user, or root) |
| libmhp | glibc as the C library; malloc from glibc, or from jemalloc / tcmalloc loaded as a library after libmhp; the library must be loaded at mysqld start; `/dev/shm` writable |
| `-inject` | root (ptrace; Yama's `ptrace_scope` up to 2 allows root), x86_64, glibc malloc or a preloaded jemalloc / tcmalloc, libmhp.so at the same path inside mysqld's mount namespace. Under an enforcing AppArmor profile (Ubuntu's `usr.sbin.mysqld`), add `/path/to/libmhp.so mr,` and `/dev/shm/mhp.* rw,` to `/etc/apparmor.d/local/usr.sbin.mysqld` and reload it |
| eBPF heap tracer | root, BTF (`/sys/kernel/btf/vmlinux`), `uprobe_multi` links (Linux 6.6+, backported in RHEL/Rocky 9). Linux 6.13+ adds session uprobes: only sampled calls take the return probe. Older kernels run an entry and a return probe on every call, which costs more (tested on 7.0 and Rocky 9.9's 5.14) |
| BPF page faults | root, Linux 5.15+ with BTF (fexit trampolines; tested on 7.0) |
| perf page faults | root or CAP_PERFMON |
| Readable stacks | mysqld built with frame pointers (verified for Percona Server 8.4 packages, MySQL and MariaDB tarballs; check other builds with `objdump -d` for `push %rbp; mov %rsp,%rbp` prologues), debug symbols. libstdc++ without frame pointers (RHEL, Rocky) is handled by libmhp's `operator new` wrappers |
| Source links | `llvm-symbolizer`, debug symbols |
| PFS cross-check | `mysql` client, Performance Schema enabled (default) |

Containers: `mhp watch -pid` with the host pid of a containerised mysqld is designed to work (mhp reads its binaries
and symbols through `/proc/<pid>/root`), but has not been tested yet.

## Security

- The UI has **no authentication**, and by default it listens on all interfaces (`-addr 0.0.0.0:8080`). On anything
  but a test box, use `-addr 127.0.0.1:8080` and an SSH tunnel (`ssh -L 8080:localhost:8080 host`).
- What is exposed: function names, call paths, memory sizes, thread names, and (with the PFS cross-check) connection
  ids, user names and current commands. No table data or query text.
- mhp runs as root for most sources. It does not modify mysqld's memory, except with `-inject`: it loads libmhp into
  mysqld and rewrites mysqld's GOT slots for the allocation functions (undone when mhp stops). libmhp runs inside
  mysqld; the eBPF and BPF programs are verified by the kernel and removed when mhp exits.

## Files and cleanup

- `/dev/shm/mhp.<pid>`: the libmhp ring (~17 MB, RAM). `mhp run` removes it when mysqld exits; after an `LD_PRELOAD` start
  without `mhp run`, delete it after mysqld has stopped. The ring is mapped into mysqld, so it shows in mysqld's RSS as `shmem`
  (filling up to 17 MB as the ring is first used) - subtract it when looking for slow RSS growth. After `-inject`, the
  ring stays until mysqld exits (a later `-inject` reuses it); `mhp watch -inject` removes rings of processes that no
  longer exist.
- `mhp run` creates a cgroup `mhp-<pid>` next to its own and removes it when mysqld exits.
- `-record FILE` writes one JSON line per second (replay with `mhp replay FILE`).

## Options

```
mhp run   [flags] -- CMD ARGS…    start CMD under libmhp (and BPF faults when root)
mhp watch -pid N [flags]          attach to a running process
mhp import [-o OUT.html] [-root DIR] FILE   explore a jemalloc / tcmalloc heap profile (see below)
mhp demo | mhp replay FILE

-addr 0.0.0.0:8080        UI listen address
-sample-bytes 262144      mean bytes between heap samples (libmhp; eBPF heap tracer)
-ebpf auto|on|off         eBPF heap tracer in watch mode (auto: when root and mysqld has no libmhp)
-shim auto|off            use the libmhp ring when the target has one (watch)
-inject                   watch: load libmhp into the running target and redirect its malloc & co. to it (root);
                          undone when mhp stops
-malloc-lib NAME|PATH     run: preload this allocator under libmhp: jemalloc, tcmalloc (looked up in the usual library
                          directories; tcmalloc prefers libtcmalloc to libtcmalloc_minimal) or a path. Default: glibc
-faults auto|on|off       page-fault stacks (auto: when root)
-fault-src auto|bpf|perf  BPF in-kernel counting, or perf sampling (auto: BPF, else perf)
-fault-period N           perf only: sample every Nth fault
-pfs auto|off             server cross-check (Performance Schema, or MariaDB's Memory_used); -mysql-args "…",
                          -pfs-interval 5s. Connects through the server's own socket and asks for credentials on
                          a terminal when access is denied
-arenas 30s               glibc per-arena detail (libmhp over glibc); stretched to 200x its cost; 0 = off
-peak on|off              keep offline copies taken at the RSS high-water mark and near the cgroup limit
-peak-dir DIR             also write them as HTML files there
-peak-cgroup 90           percent of the cgroup memory limit that triggers a copy (0 = off)
-o FILE, -root DIR        import: write the offline copy and exit; read the profile's binaries under DIR
-source-version V         for source links when it cannot be read from the binary: 8.0.36, percona-8.4.11-11, mariadb-10.11.6
-source-map PREFIX=URL    send source links for files under PREFIX elsewhere (repeatable), e.g. Percona's RocksDB
                          submodule: storage/rocksdb/rocksdb/=https://github.com/percona/rocksdb/blob/<commit>/
-debug-dir DIR[:DIR]      extra debug-symbol dirs holding .build-id/ (e.g. an unpacked -dbg package), before /usr/lib/debug
-interval 1s              /proc polling interval
-smaps 5s                 shortest interval between smaps reads (regions view, THP, swap by region); stretched
                          automatically to 100x the time one read takes; 0 = off (timeline by sub-system and
                          thread, stacks and RSS/anon/file do not need it)
-growth 60                "growth" window in seconds (Overview growers, Explore growth metric)
-retention 10m            history kept for the chart and time ranges, in mhp and in the browser
-timeline 1048576         hard cap on per-tick records for time ranges (~56 bytes each; oldest dropped first)
-rules FILE               own function -> sub-system rules (JSON array of {"match": regex, "subsystem": name},
                          optional "anywhere": true = owns any stack passing through it, like the built-in AuditLog;
                          "module": true = matches unsymbolized "lib.so+0x..." frames, which other rules never see;
                          "area": name = a sub-area rule within "subsystem", with optional "also": regex that must
                          match another frame too). A file replaces all built-in rules, sub-area ones included
-record FILE              record the session
-lib PATH                 libmhp.so for run and -inject (default: next to the mhp binary)

libmhp environment (when preloading by hand): MHP_SAMPLE_BYTES, MHP_START=0 (off until mhp attaches),
MHP_SLOTS (ring entries, default 32768), MHP_DIR (default /dev/shm)

Preloading by hand, `mhp watch` sees everything **from process start**, like `mhp run`, when libmhp sampled from the
start (default, not `MHP_START=0`) and its ring has not overflowed before the first attach: the ring keeps events
until a collector reads them, so attach early. It holds MHP_SLOTS samples (32768 ≈ 8 GiB allocated at the default
256 KiB sampling: mysqld startup plus a couple of sysbench runs); past that it drops events and mhp falls back to
"since attach". A later attach is always "since attach". The log and the Context tab say which one you got.
```

## Importing jemalloc and tcmalloc heap profiles

Heap profiles written by the allocator itself, as MariaDB's and Percona's memory troubleshooting guides ask for, open
in the mhp UI:

    mhp import jeprof.12345.0.f.heap              # UI on :8080
    mhp import -o case-1234.html prof.0042.heap   # offline copy, then exit

- **jemalloc**: `MALLOC_CONF=prof:true,prof_gdump:true,lg_prof_sample:18,prof_prefix:/path/jeprof` (add
  `prof_accum:true` for cumulative allocations). Sampled; mhp scales each stack up the way `jeprof` does, so totals
  match `jeprof --text`.
- **tcmalloc** (gperftools): `HEAPPROFILE=/path/prof` with `libtcmalloc_and_profiler`. Every allocation is
  recorded, in use and cumulative; a sampled `heap_v2` profile is scaled like jemalloc's.

The profile holds return addresses and the process's memory map, not the binaries: mhp reads `mysqld` and the
libraries at the paths the map names, so run it where the profile was taken, or give `-root DIR` with a copy of
those files (same builds: the profile does not say which build it came from, so mhp warns when the binary is newer
than the profile). Debug symbols (`-debug-dir`) and source links work as for a live server. Frames inside the
allocator are cut from the leaves. What comes out is one point in time: the live-bytes flame graph, callers, tree,
sub-systems, the allocated-total metric when the profile has cumulative counts, and the SVG, folded, pprof and
offline exports.

## The UI in brief

- **Overview**: RSS, traced and Performance Schema totals; a timeline by region, sub-system, sub-system · area or
  thread role; top growing stacks; the accounting panel (who claims what, glibc free memory). It labels whether mhp numbers are "since
  attach" or "from process start".
  - **swap** (red dotted line, when the process has any): VmSwap every tick; the hover shows it per region (smaps).
  - **pause tracing** stops sampling allocations but not the chart: RSS, regions and swap keep updating. Paused
    periods are shaded grey and the traced series (sub-system, thread role) are left out there, since only frees
    arrive while paused. Ranges and reports that include a paused period say so.
  - Click a legend item to hide or show it (the rest restacks); shift-click shows only that item, shift-click again
    shows all. Remembered per view in the browser.
  - The legend shows the latest values; click a tick on the chart for that moment's values, or drag across it for
    their averages over the range (traced peak: its highest). Clearing the range returns to the latest.
- **Engine areas**: InnoDB and RocksDB are split into what a DBA tunes or recognizes. InnoDB: buffer pool, adaptive
  hash index, redo log, doublewrite buffer, lock system, undo, purge, transactions & read views, MVCC old row
  versions, row reads, row writes, DDL & index builds, change buffer, full-text search, data dictionary cache,
  tablespaces & file I/O, crash recovery, doublewrite pages loaded at startup. RocksDB (MyRocks): block cache & block reads, index & filter blocks,
  memtables & write batches, memtable flush, compaction input, compaction output, WAL & info log, transactions,
  snapshots & locks, reads & iterators, and the MyRocks layer (row encoding, scans, transactions, handler). Context
  decides first (anything under a compaction job, a flush, an index build or purge), then the function nearest the
  allocation. They show as "InnoDB · buffer pool" in the stack tables, the chart ("sub-system · area"), the
  Explore filter, and indented under their sub-system in the accounting panel, range table and HTML reports.
- **Pause tracing** (header button): stops recording new allocations inside mysqld, so whatever happened before the
  pause stays in the timeline instead of being pushed out by later activity. Frees of earlier samples are still
  recorded.
- **Time ranges**: drag across the Overview chart, or click one tick, to select a range. The bar under the chart
  shows what was allocated and freed in it (with the number of samples and the largest single request) and the peak
  rise. "explore allocated" / "explore freed" open the flame graph, callers or call tree for just that range. This
  works even when the memory was already released: for example, select the second in which a large statement ran.
  - A range covers what happened *between* two samples of the chart. The first sample closes the first tick, which
    holds everything before it: under `mhp run` that is mysqld's whole startup (buffer pool, redo log buffer,
    Performance Schema). To include it, start the drag at the left end of the chart, or click the first sample;
    the bar then reads "range start → …". A range that starts later shows only what was allocated after it, while
    the legend and the chart show what is *live*, whenever it was allocated.
  - The purple **traced peak** line (sub-system and thread-role views) is the highest traced live total *within* each
    tick, in event order. A spike allocated and freed between two 1-second samples still shows there.
  - Under the totals, a table splits the range by **area** (sub-system), with the engine areas indented under InnoDB
    and RocksDB. Click an area to explore its stacks. For each area it shows:
    - **allocated**: bytes requested in the range, even if they were freed or reused right away. This measures churn
      (CPU and allocator work), not memory needed. Summing it overstates what was ever held at once.
    - **peak rise**: how far the area's live bytes rose above their value at the start of the range. This is "how much
      memory it needed at once". The per-area peaks may happen at different moments, so they don't add up to the total.
    - **page faults**: pages the kernel had to hand over, which is what makes RSS grow. It depends on glibc: freed
      memory that glibc keeps and reuses causes no faults, while memory it returned to the kernel (large blocks are
      mmapped and unmapped each time) faults again on the next use. The same statement can show 1 MiB or 300 MiB.
  - Area rules: an allocation belongs to the nearest recognised function above it (InnoDB, SQL, JSON, …). The
    AuditLog area is an "anywhere" rule: everything called from `audit_log_filter::` counts as AuditLog. Frames of a
    stripped library show as `module+0xoffset` and are passed over (the nearest named frame decides), except for
    "module" rules: the stripped `ha_rocksdb.so` that Percona Server and MariaDB ship counts as RocksDB.
  - Example (libmhp, Percona Server 8.4, 17.5 MiB JSON `INSERT`, 3 runs each):

    | audit setup | allocated | peak rise | AuditLog allocated / peak | time |
    |---|---|---|---|---|
    | filter `log_all` assigned to `%` | 757–782 MiB | +193–213 MiB | 411–413 / +95–143 MiB | 643–864 ms |
    | component on, no filter assigned | 340–363 MiB | +196–198 MiB | – | 536–651 ms |
    | `audit_log_filter.disable=ON` | 350–360 MiB | +193–197 MiB | – | 467–649 ms |

    Logging the statement doubles the allocation churn (+410 MiB) and adds 100–200 ms, but it barely raises the
    process's memory high-water mark. The audit formatting peaks after the JSON parse memory is already freed, so
    the two peaks do not stack. With no filter assigned, the component costs nothing measurable.
  - **export HTML report** (range bar, or Explore with filters) downloads one self-contained file for offline review.
    Scripted: `curl 'http://host:8080/report.html?from=MS&to=MS&note=what+this+case+is' > r.html` (`note` shows in the Context table;
    `tid`, `role`, `subsys` filter as in Explore).
    It contains:
    - context: host, kernel, CPUs and RAM; server version, banner and revision; binary path and ELF build ID;
      process and command line; the malloc library it uses (jemalloc/tcmalloc/... if mapped, else glibc with its
      version; LD_PRELOAD and malloc tuning variables from its environment); mhp version, binary, log; how mhp traced it;
    - the totals, and RSS and traced memory at the start and end of the range;
    - the timeline around the range;
    - the area table, top allocating and page-faulting functions (each with its heaviest stack), and per-thread
      totals;
    - interactive flame graphs (allocated, both directions; freed; page faults);
    - the raw folded stacks.

    It needs no network and no mhp to open; about 1–2 MB for a busy second. The server command line is included, so
    check it for anything sensitive before sharing.
  - The selected range and the frozen chart survive a page reload, as long as they are still within the kept
    history.
- **☾ dark / ☀ light** (header) switches the colour theme. Light is the default; the choice is kept in the browser
  (per origin, so an offline copy opened from disk remembers its own). HTML reports have the same switch.
- **save offline copy** (header) downloads the whole UI with everything mhp keeps as one HTML file: the chart
  history, the stacks, the time-range timeline, report metadata and source locations. Open it from disk on any
  machine, without mhp or a network: select ranges, explore (flame, callers, tree; every metric and filter), and
  export SVGs, folded stacks or HTML reports. It answers exactly like the live mhp did at the time of the copy,
  because it runs mhp's own query and report code, compiled to WebAssembly, on the embedded data.
  - It covers what mhp kept: `-retention` (10 minutes by default) and `-timeline` records. Raise them before the
    run you want to keep.
  - Size: about 3.4 MB of fixed code plus the gzipped data. 5 minutes of sysbench at 880 tx/s with audit logging
    (306 ticks, 172k timeline records, 5k stacks) gave a 6.2 MB file; 1M timeline records come to roughly 15 MB.
  - Making the copy takes a few seconds, mostly resolving source locations (at most 20 s; the rest go without).
  - Scripted: `curl -o copy.html http://host:8080/offline.html`.
  - Needs a current browser (WebAssembly, DecompressionStream: Chrome/Edge 80+, Firefox 113+, Safari 16.4+).
    Like the reports, it includes the server command line.
  - Precision follows sampling: a range is built from samples (one per 256 KiB on average). A 1 MiB burst has only a
    few samples, while a 100 MiB burst is accurate to a few percent.
- **Peak copies** (`-peak on`, the default): an offline copy is only useful if someone took it at the right
  moment, and memory problems peak when nobody watches. mhp takes them by itself:
  - **peak copy**: at the RSS high-water mark. Once RSS has risen 3 % (and 16 MiB) above the last copy's, mhp takes a
    new one at once, from the view that shows the new high, so a transient (a 1 GiB TempTable freed a second later,
    say) is in it with its stacks. While RSS keeps climbing, copies are at least 15 s apart, unless RSS jumped
    256 MiB or more over the last copy (then 2 s); a smaller high reached within that gap is copied when it ends (the
    reason says so). Each replaces the previous one.
  - **cgroup-limit copy**: when RSS crosses 90 % of the cgroup memory limit (`-peak-cgroup`), at once: an OOM kill
    may follow. The limit is the lowest `memory.max` of the process's cgroup and the ones above it. Again after RSS
    fell 5 points below the threshold and crossed it again.

  Each copy is taken at once with the latest `malloc_info` reading (and asks for a fresh one, for the next), then holds everything a "save offline copy" would. The header shows
  a download button per copy (with its time and reason in the tooltip), and the chart marks when each was taken. The
  copy itself marks the moment as "this copy" and says why it was taken in its Context tab. They are kept in memory
  (`/peak.html?kind=peak|cgroup`, `/peaks` lists them) and, with `-peak-dir DIR`, written there as
  `mhp-peak-HOST-pidN-TIME.html` (the previous peak file is removed) and `mhp-cgroup-…html` (all kept), so they
  survive the server, and mhp, going away.
- **export pprof** (Explore): the current metric and filters as a pprof profile (`profile.proto`, gzipped) for
  `go tool pprof`, pprof.me, Speedscope or Grafana Pyroscope. All frames are kept (alloc wrappers too), with source
  file and line where mhp knows them, and the sub-system as a `subsystem` label. Values in bytes; range metrics also
  carry the sample count. Scripted: `curl -o heap.pb.gz 'http://host:8080/pprof?metric=live'`.
- **Threads**: a pidstat-like table per thread (CPU, faults, live heap, PFS columns). Click a row to see that
  thread's stacks.
- **Explore**: flame graph, callers (bottom-up) and call tree, for live bytes, growth, allocated total or page faults,
  filtered by thread, role, sub-system or engine area.
  - Search highlights frames; in the call tree it also opens the branches leading to matches.
  - Hover a frame to see its source location; click it to pin the links.
  - "export SVG" saves a standalone, zoomable flame graph of the current view for offline review, and
    "export folded" saves the stacks for flamegraph.pl or speedscope.
- **Context**: the report metadata (host, server build and process, malloc library, mhp version, binary and log,
  how it traces) and the span of kept history; in an offline copy also when it was taken.

## License

mhp is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
version 3 as published by the Free Software Foundation. See `LICENSE`.
