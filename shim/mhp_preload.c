/* libmhp.so — LD_PRELOAD sampling allocation tracer.
 *
 * - Interposes malloc/calloc/realloc/reallocarray/free/memalign family, anonymous mmap/munmap, and
 *   mprotect(PROT_NONE) (decommit; PROT_NONE mappings are reservations and never count).
 * - Poisson byte sampling per thread (mean MHP_SAMPLE_BYTES, default 256 KiB): each sample carries
 *   weight size/(1-exp(-size/R)) so totals are unbiased estimates. mmap is always recorded.
 * - Frame-pointer unwinding, bounded by the current thread's stack (safe against garbage rbp).
 * - Sampled pointers live in a lock-free table so their frees are reported; other frees cost one probe.
 * - Events go to a shared-memory ring /dev/shm/mhp.<pid>; the collector toggles `enabled`.
 *
 * - Injected (mhp watch -inject): loaded into a running process with dlopen, where its symbols interpose nothing.
 *   mhp_attach() then creates the ring and points the GOT slots of every loaded object that hold malloc & co at the
 *   functions below; mhp_detach() points them back. See DESIGN.md.
 *
 * - The allocator underneath is whatever malloc comes next in the process: glibc's, or a preloaded jemalloc /
 *   tcmalloc (LD_PRELOAD="libmhp.so libjemalloc.so.2"). Those define operator new/delete themselves, which the
 *   program then calls without passing through malloc, so libmhp wraps the operators as well ("the allocator
 *   underneath" below).
 *
 * Env: MHP_SAMPLE_BYTES, MHP_SLOTS (ring size, default 32768), MHP_START (1 = enabled at start, default 1),
 *      MHP_DIR (default /dev/shm).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <gnu/libc-version.h>
#include <link.h>
#include <malloc.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "mhp_ring.h"

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);

enum { ALLOC_GLIBC, ALLOC_JEMALLOC, ALLOC_TCMALLOC, ALLOC_OTHER }; /* mhp_hdr.alloc_kind */

#define TLS __thread __attribute__((tls_model("initial-exec")))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define TBL_BITS 21
#define TBL_SIZE (1UL << TBL_BITS)
#define TBL_PROBE 64
#define TOMB 1ULL

static struct mhp_hdr *H;
static char *slots;
static _Atomic uint64_t *tbl;
static double R = 256 * 1024;
static uintptr_t self_lo, self_hi; /* our own text, skipped while unwinding */
static uintptr_t self_base;        /* our load address (injected: our own slots are left alone) */
static uintptr_t alloc_lo, alloc_len; /* text of a non-glibc allocator: its own mmaps (extents) are not recorded */
static uintptr_t alloc_base;       /* its load address (injected: its slots are left alone); 0 with glibc */
static int alloc_main;             /* malloc is defined by the main program: nothing to interpose or redirect */
static uint32_t alloc_kind;
static int (*je_mallctl)(const char *, void *, size_t *, void *, size_t);
static int (*tc_property)(const char *, size_t *);

static TLS int t_in;     /* recursion guard */
static TLS int t_boot;   /* resolving the allocator underneath: allocations come from boot_buf */
static TLS int t_init;
static TLS uint32_t t_tid;
static TLS int64_t t_left;
static TLS uint64_t t_rng;
static TLS uintptr_t t_stk_lo, t_stk_hi;

static inline int on(void)
{
	return H && atomic_load_explicit((_Atomic uint32_t *)&H->enabled, memory_order_relaxed);
}

/* Frees and munmaps are reported while anything was recorded in this generation, even with sampling paused:
 * otherwise memory released during a pause would stay "live" after resuming. Never armed = no cost. */
static inline int armed(void)
{
	return H && atomic_load_explicit((_Atomic uint32_t *)&H->armed, memory_order_relaxed);
}

static inline void arm(void)
{
	if (!atomic_load_explicit((_Atomic uint32_t *)&H->armed, memory_order_relaxed))
		atomic_store_explicit((_Atomic uint32_t *)&H->armed, 1, memory_order_relaxed);
}

static inline uint64_t rnd(void)
{
	t_rng ^= t_rng << 13;
	t_rng ^= t_rng >> 7;
	t_rng ^= t_rng << 17;
	return t_rng;
}

static inline int64_t draw(void)
{
	double u = ((rnd() >> 11) + 1) * (1.0 / 9007199254740993.0); /* (0,1] */
	return (int64_t)(-log(u) * R) + 1;
}

static uintptr_t hex(const char **s)
{
	uintptr_t v = 0;
	for (;; (*s)++) {
		char c = **s;
		if (c >= '0' && c <= '9')
			v = v << 4 | (uintptr_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = v << 4 | (uintptr_t)(c - 'a' + 10);
		else
			return v;
	}
}

/* Find the mapping that holds `sp` by scanning /proc/self/maps with raw syscalls only:
 * we run inside malloc, so no stdio, no malloc, no libc locks (pthread_getattr_np deadlocks here). */
static void stack_bounds(uintptr_t sp)
{
	int fd = (int)syscall(SYS_open, "/proc/self/maps", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	char buf[4096 + 128];
	size_t have = 0;
	for (;;) {
		ssize_t n = syscall(SYS_read, fd, buf + have, sizeof buf - 1 - have);
		if (n <= 0)
			break;
		have += (size_t)n;
		buf[have] = 0;
		char *line = buf, *nl;
		while ((nl = memchr(line, '\n', have - (size_t)(line - buf)))) {
			const char *p = line;
			uintptr_t lo = hex(&p);
			p++;
			uintptr_t hi = hex(&p);
			if (sp >= lo && sp < hi) {
				t_stk_lo = lo;
				t_stk_hi = hi;
				syscall(SYS_close, fd);
				return;
			}
			line = nl + 1;
		}
		have -= (size_t)(line - buf);
		memmove(buf, line, have);
		if (have >= sizeof buf - 1)
			have = 0; /* absurdly long line: drop it */
	}
	syscall(SYS_close, fd);
}

static void thread_init(void)
{
	t_tid = (uint32_t)syscall(SYS_gettid);
	t_rng = ((uint64_t)t_tid << 32) ^ (uint64_t)(uintptr_t)&t_rng ^ 0x9E3779B97F4A7C15ULL;
	t_left = draw();
	stack_bounds((uintptr_t)__builtin_frame_address(0));
	t_init = 1;
}

/* Frame of the innermost operator new wrapper that forwards to libstdc++ (0 outside one): see unwind(). */
static TLS uintptr_t t_cxx_fp;

static int unwind(uint64_t *out)
{
	uintptr_t *fp = __builtin_frame_address(0);
	int d = 0;
	while (d < MHP_DEPTH) {
		uintptr_t f = (uintptr_t)fp;
		if (f < t_stk_lo || f + 16 > t_stk_hi || (f & 7))
			break;
		uintptr_t ret = fp[1], next = fp[0];
		if (ret < 4096)
			break;
		if (ret < self_lo || ret >= self_hi)
			out[d++] = ret;
		if (next <= f || (t_cxx_fp > f && next > t_cxx_fp)) {
			/* Broken chain below one of our operator new wrappers (libstdc++ without frame pointers may
			 * use rbp as a scratch register): resume at the wrapper's frame, which the chain must pass. */
			if (t_cxx_fp <= f)
				break;
			next = t_cxx_fp;
		}
		fp = (uintptr_t *)next;
	}
	return d;
}

static void emit(uint32_t type, uintptr_t ptr, uint64_t size, uint64_t weight, int stack)
{
	_Atomic uint64_t *head = (_Atomic uint64_t *)&H->head;
	_Atomic uint64_t *tail = (_Atomic uint64_t *)&H->tail;
	uint64_t h = atomic_load_explicit(head, memory_order_relaxed);
	do {
		if (h - atomic_load_explicit(tail, memory_order_acquire) >= H->nslots) {
			atomic_fetch_add_explicit((_Atomic uint64_t *)&H->drops, 1, memory_order_relaxed);
			return;
		}
	} while (!atomic_compare_exchange_weak_explicit(head, &h, h + 1, memory_order_acq_rel, memory_order_relaxed));
	struct mhp_ev *e = (struct mhp_ev *)(slots + (h % H->nslots) * sizeof(struct mhp_ev));
	e->type = type;
	e->tid = t_tid;
	e->ptr = ptr;
	e->size = size;
	e->weight = weight;
	e->depth = stack ? (uint16_t)unwind(e->frames) : 0;
	atomic_store_explicit((_Atomic uint64_t *)&e->commit, h + 1, memory_order_release);
}

static inline uint64_t slot_of(uintptr_t p)
{
	return ((p >> 4) * 0x9E3779B97F4A7C15ULL) >> (64 - TBL_BITS);
}

static inline uint64_t cur_gen(void)
{
	return (uint64_t)(atomic_load_explicit((_Atomic uint32_t *)&H->gen, memory_order_relaxed) & 0xffff) << 48;
}

/* Track a sampled pointer. Entries from older generations count as free slots. */
static int tbl_insert(uintptr_t p)
{
	uint64_t g = cur_gen(), key = (uint64_t)p | g, i = slot_of(p);
	for (int n = 0; n < TBL_PROBE; n++, i = (i + 1) & (TBL_SIZE - 1)) {
		uint64_t v = atomic_load_explicit(&tbl[i], memory_order_relaxed);
		if (v == 0 || v == TOMB || (v & 0xffff000000000000ULL) != g) {
			if (atomic_compare_exchange_strong(&tbl[i], &v, key))
				return 1;
		}
	}
	atomic_fetch_add_explicit((_Atomic uint64_t *)&H->table_drops, 1, memory_order_relaxed);
	return 0;
}

static int tbl_remove(uintptr_t p)
{
	uint64_t key = (uint64_t)p | cur_gen(), i = slot_of(p);
	for (int n = 0; n < TBL_PROBE; n++, i = (i + 1) & (TBL_SIZE - 1)) {
		uint64_t v = atomic_load_explicit(&tbl[i], memory_order_relaxed);
		if (v == 0)
			return 0;
		if (v == key)
			return atomic_compare_exchange_strong(&tbl[i], &v, TOMB);
	}
	return 0;
}

static uint64_t je_stat(const char *name)
{
	size_t v = 0, sz = sizeof v;
	return je_mallctl(name, &v, &sz, NULL, 0) == 0 ? v : 0;
}

static uint64_t tc_stat(const char *name)
{
	size_t v = 0;
	return tc_property(name, &v) ? v : 0;
}

/* Answer a pending heap-statistics request (claimed by exactly one thread), with the allocator's own numbers.
 * glibc: mallinfo2 walks the arenas' free lists under their locks, which costs this one call a few ms on a large
 * heap. jemalloc: "epoch" refreshes its statistics (it merges the arenas under their locks). tcmalloc: reading
 * the thread-cache total walks the thread list under its lock. Other allocators: no answer. */
static void maybe_stats(void)
{
	_Atomic uint64_t *claim = (_Atomic uint64_t *)&H->stats_claim;
	uint64_t req = atomic_load_explicit((_Atomic uint64_t *)&H->stats_req, memory_order_relaxed);
	uint64_t c = atomic_load_explicit(claim, memory_order_relaxed);
	if (likely(c == req) || !atomic_compare_exchange_strong(claim, &c, req))
		return;
	uint64_t v[10] = {0};
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	if (alloc_kind == ALLOC_GLIBC) {
		struct mallinfo2 m = mallinfo2();
		uint64_t g[10] = {m.arena, m.ordblks, m.smblks, m.hblks, m.hblkhd, m.usmblks, m.fsmblks, m.uordblks, m.fordblks, m.keepcost};
		memcpy(v, g, sizeof v);
	} else if (alloc_kind == ALLOC_JEMALLOC) {
		uint64_t epoch = 1;
		size_t sz = sizeof epoch;
		je_mallctl("epoch", &epoch, &sz, &epoch, sz);
		v[0] = je_stat("stats.allocated");
		v[1] = je_stat("stats.active");
		v[2] = je_stat("stats.metadata");
		v[3] = je_stat("stats.resident");
		v[4] = je_stat("stats.mapped");
		v[5] = je_stat("stats.retained");
	} else if (alloc_kind == ALLOC_TCMALLOC) {
		v[0] = tc_stat("generic.current_allocated_bytes");
		v[1] = tc_stat("generic.heap_size");
		v[2] = tc_stat("tcmalloc.pageheap_free_bytes");
		v[3] = tc_stat("tcmalloc.pageheap_unmapped_bytes");
		v[4] = tc_stat("tcmalloc.central_cache_free_bytes");
		v[5] = tc_stat("tcmalloc.transfer_cache_free_bytes");
		v[6] = tc_stat("tcmalloc.thread_cache_free_bytes");
	} else
		return;
	clock_gettime(CLOCK_MONOTONIC, &b);
	memcpy(H->mi, v, sizeof v);
	H->stats_ns = (uint64_t)(b.tv_sec - a.tv_sec) * 1000000000ULL + (uint64_t)(b.tv_nsec - a.tv_nsec);
	atomic_store_explicit((_Atomic uint64_t *)&H->stats_seq, req, memory_order_release);
}

/* Answer a pending per-arena request (glibc only): malloc_info() writes its XML into the aux area through a
 * memory stream. It takes each arena's lock in turn and walks its bins, like mallinfo2. The FILE itself comes
 * from malloc, which passes through (t_in is set). */
static void maybe_arenas(void)
{
	_Atomic uint64_t *claim = (_Atomic uint64_t *)&H->arenas_claim;
	uint64_t req = atomic_load_explicit((_Atomic uint64_t *)&H->arenas_req, memory_order_relaxed);
	uint64_t c = atomic_load_explicit(claim, memory_order_relaxed);
	if (likely(c == req) || !atomic_compare_exchange_strong(claim, &c, req))
		return;
	uint64_t len = 0;
	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	if (alloc_kind == ALLOC_GLIBC && H->aux_cap) {
		char *aux = (char *)H + H->aux_off;
		FILE *f = fmemopen(aux, H->aux_cap, "w");
		if (f) {
			setvbuf(f, NULL, _IONBF, 0);
			malloc_info(0, f);
			long n = ftell(f);
			fclose(f);
			len = n > 0 ? (uint64_t)n : 0;
			if (len >= H->aux_cap)
				len = H->aux_cap - 1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &b);
	H->arenas_len = len;
	H->arenas_ns = (uint64_t)(b.tv_sec - a.tv_sec) * 1000000000ULL + (uint64_t)(b.tv_nsec - a.tv_nsec);
	atomic_store_explicit((_Atomic uint64_t *)&H->arenas_seq, req, memory_order_release);
}

static void maybe_rescan(void);

static inline void sample(void *p, size_t n)
{
	if (!p || !on() || t_in)
		return;
	t_in = 1;
	maybe_stats();
	maybe_arenas();
	maybe_rescan();
	if (unlikely(!t_init))
		thread_init();
	t_left -= (int64_t)n;
	if (likely(t_left > 0)) {
		t_in = 0;
		return;
	}
	t_left = draw();
	double w = (double)n / -expm1(-(double)n / R);
	if (tbl_insert((uintptr_t)p)) {
		arm();
		atomic_fetch_add_explicit((_Atomic uint64_t *)&H->sampled, 1, memory_order_relaxed);
		emit(MHP_EV_ALLOC, (uintptr_t)p, n, (uint64_t)w, 1);
	}
	t_in = 0;
}

static inline void unsample(void *p)
{
	if (!p || !armed() || t_in)
		return;
	t_in = 1;
	if (unlikely(!t_init))
		thread_init();
	if (tbl_remove((uintptr_t)p))
		emit(MHP_EV_FREE, (uintptr_t)p, 0, 0, 0);
	t_in = 0;
}

/* ---- the allocator underneath ----
 *
 * The real_* pointers lead to the next definition of each function: glibc's, or those of a preloaded jemalloc /
 * tcmalloc. They start at boot_* stubs that look the functions up on the first call, since the dynamic loader and
 * other libraries' constructors allocate before ours runs. dlsym() itself may allocate: while the lookup runs
 * (t_boot), allocations of that thread come from boot_buf, which is never freed.
 *
 * Operator new/delete: when the allocator defines them (jemalloc, tcmalloc), the program's calls bind to ours
 * instead and are sampled here (samp_*), since the allocator's operators do not pass through malloc. When they
 * come from libstdc++ they are only forwarded: libstdc++ calls malloc, which is sampled. The forwarding keeps
 * its stack frame and records it in t_cxx_fp, so the caller of operator new stays in the stack even when libstdc++
 * is built without frame pointers (RHEL, Rocky; Ubuntu 24.04 has them): its operator new would otherwise hide the
 * caller from the frame-pointer walk, by skipping the frame or (aligned new) by zeroing rbp before calling
 * aligned_alloc. unwind() resumes at the recorded frame when the chain breaks below it. If operator new throws,
 * the stale value is overwritten by the next call and at worst misplaces one stack. With no C++ runtime in
 * sight (a C program that later loads a C++ plugin) they are served by malloc; a failed throwing new aborts. */
static char boot_buf[1 << 16] __attribute__((aligned(64)));
static _Atomic size_t boot_used;

static inline int in_boot(const void *p)
{
	return (uintptr_t)p - (uintptr_t)boot_buf < sizeof boot_buf;
}

static void *boot_alloc(size_t al, size_t n)
{
	if (al < 16)
		al = 16;
	size_t cur = atomic_load(&boot_used), at;
	do {
		at = (cur + al - 1) & ~(al - 1);
		if (at + n > sizeof boot_buf || at + n < at)
			return NULL;
	} while (!atomic_compare_exchange_weak(&boot_used, &cur, at + n));
	return boot_buf + at; /* zeroed: never reused */
}

static void resolve(void);
static void *boot_malloc(size_t n);
static void *boot_calloc(size_t a, size_t b);
static void *boot_realloc(void *p, size_t n);
static void *boot_memalign(size_t al, size_t n);
static void boot_free(void *p);

static void *(*real_malloc)(size_t) = boot_malloc;
static void *(*real_calloc)(size_t, size_t) = boot_calloc;
static void *(*real_realloc)(void *, size_t) = boot_realloc;
static void *(*real_memalign)(size_t, size_t) = boot_memalign;
static void (*real_free)(void *) = boot_free;
static int (*real_posix_memalign)(void **, size_t, size_t);

static void *boot_malloc(size_t n)
{
	if (t_boot)
		return boot_alloc(16, n);
	resolve();
	return real_malloc(n);
}

static void *boot_calloc(size_t a, size_t b)
{
	size_t n;
	if (__builtin_mul_overflow(a, b, &n))
		return NULL;
	if (t_boot)
		return boot_alloc(16, n);
	resolve();
	return real_calloc(a, b);
}

static void *boot_realloc(void *p, size_t n)
{
	if (t_boot)
		return p ? NULL : boot_alloc(16, n);
	resolve();
	return real_realloc(p, n);
}

static void *boot_memalign(size_t al, size_t n)
{
	if (t_boot)
		return boot_alloc(al, n);
	resolve();
	return real_memalign(al, n);
}

static void boot_free(void *p)
{
	if (t_boot)
		return;
	resolve();
	real_free(p);
}

/* memalign for an allocator that only has posix_memalign */
static void *memalign_by_posix(size_t al, size_t n)
{
	void *p = NULL;
	if (al < sizeof(void *))
		al = sizeof(void *);
	return real_posix_memalign(&p, al, n) == 0 ? p : NULL;
}

void *malloc(size_t n)
{
	void *p = real_malloc(n);
	sample(p, n);
	return p;
}

void *calloc(size_t a, size_t b)
{
	void *p = real_calloc(a, b);
	sample(p, a * b);
	return p;
}

void free(void *p)
{
	if (unlikely(in_boot(p)))
		return;
	unsample(p);
	real_free(p);
}

void free_sized(void *p, size_t n)
{
	(void)n;
	free(p);
}

void free_aligned_sized(void *p, size_t a, size_t n)
{
	(void)a;
	(void)n;
	free(p);
}

void cfree(void *p)
{
	free(p);
}

void *realloc(void *old, size_t n)
{
	if (unlikely(in_boot(old))) { /* from before the allocator was known: its size is not, so copy what can be there */
		void *p = malloc(n);
		size_t room = (size_t)(boot_buf + sizeof boot_buf - (char *)old);
		if (p)
			memcpy(p, old, n < room ? n : room);
		return p;
	}
	unsample(old);
	void *p = real_realloc(old, n);
	sample(p, n);
	return p;
}

void *reallocarray(void *old, size_t a, size_t b)
{
	size_t n;
	if (__builtin_mul_overflow(a, b, &n)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(old, n);
}

void *memalign(size_t al, size_t n)
{
	void *p = real_memalign(al, n);
	sample(p, n);
	return p;
}

void *aligned_alloc(size_t al, size_t n)
{
	return memalign(al, n);
}

int posix_memalign(void **out, size_t al, size_t n)
{
	if (al % sizeof(void *) || (al & (al - 1)) || al == 0)
		return EINVAL;
	void *p = real_memalign(al, n);
	if (!p)
		return ENOMEM;
	sample(p, n);
	*out = p;
	return 0;
}

void *valloc(size_t n)
{
	return memalign((size_t)sysconf(_SC_PAGESIZE), n);
}

void *pvalloc(size_t n)
{
	size_t pg = (size_t)sysconf(_SC_PAGESIZE);
	return memalign(pg, (n + pg - 1) & ~(pg - 1));
}

/* operator new / delete, by mangled name. All arguments are integers or pointers, so one signature serves every
 * variant: (size | pointer, [size,] [alignment,] [const std::nothrow_t &]). X(name, alignment argument (1 = second),
 * nothrow) */
#define NEW_OPS(X) \
	X(_Znwm, 0, 0) X(_Znam, 0, 0) X(_ZnwmRKSt9nothrow_t, 0, 1) X(_ZnamRKSt9nothrow_t, 0, 1) \
	X(_ZnwmSt11align_val_t, 1, 0) X(_ZnamSt11align_val_t, 1, 0) \
	X(_ZnwmSt11align_val_tRKSt9nothrow_t, 1, 1) X(_ZnamSt11align_val_tRKSt9nothrow_t, 1, 1)
#define DEL_OPS(X) \
	X(_ZdlPv) X(_ZdaPv) X(_ZdlPvm) X(_ZdaPvm) X(_ZdlPvRKSt9nothrow_t) X(_ZdaPvRKSt9nothrow_t) \
	X(_ZdlPvSt11align_val_t) X(_ZdaPvSt11align_val_t) X(_ZdlPvmSt11align_val_t) X(_ZdaPvmSt11align_val_t) \
	X(_ZdlPvSt11align_val_tRKSt9nothrow_t) X(_ZdaPvSt11align_val_tRKSt9nothrow_t)

typedef void *(*new_fn)(size_t, uintptr_t, uintptr_t);
typedef void (*del_fn)(void *, uintptr_t, uintptr_t);

static void *plain_new(size_t n, size_t al, int nothrow)
{
	void *p = al ? memalign(al, n ? n : 1) : malloc(n ? n : 1);
	if (!p && !nothrow)
		abort(); /* no C++ runtime to throw std::bad_alloc with */
	return p;
}

#define X(name, aligned, nothrow) \
	static void *boot_##name(size_t n, uintptr_t a, uintptr_t b); \
	static new_fn real_##name = boot_##name; \
	static int samp_##name; \
	static void *plain_##name(size_t n, uintptr_t a, uintptr_t b) \
	{ \
		(void)a; \
		(void)b; \
		return plain_new(n, aligned ? a : 0, nothrow); \
	} \
	static void *boot_##name(size_t n, uintptr_t a, uintptr_t b) \
	{ \
		if (t_boot) \
			return plain_##name(n, a, b); \
		resolve(); \
		return real_##name(n, a, b); \
	} \
	void *name(size_t n, uintptr_t a, uintptr_t b) \
	{ \
		if (samp_##name) { \
			void *p = real_##name(n, a, b); \
			sample(p, n); \
			return p; \
		} \
		uintptr_t prev = t_cxx_fp; /* forwarded: keep our frame and tell unwind() where it is */ \
		t_cxx_fp = (uintptr_t)__builtin_frame_address(0); \
		void *p = real_##name(n, a, b); \
		t_cxx_fp = prev; \
		return p; \
	}
NEW_OPS(X)
#undef X

static void plain_delete(void *p, uintptr_t a, uintptr_t b)
{
	(void)a;
	(void)b;
	free(p);
}

#define X(name) \
	static void boot_##name(void *p, uintptr_t a, uintptr_t b); \
	static del_fn real_##name = boot_##name; \
	static int samp_##name; \
	static void boot_##name(void *p, uintptr_t a, uintptr_t b) \
	{ \
		if (t_boot) \
			return; \
		resolve(); \
		real_##name(p, a, b); \
	} \
	void name(void *p, uintptr_t a, uintptr_t b) \
	{ \
		if (unlikely(in_boot(p))) \
			return; \
		if (samp_##name) \
			unsample(p); \
		real_##name(p, a, b); \
	}
DEL_OPS(X)
#undef X

/* ---- finding the allocator underneath ----
 *
 * Which object defines malloc for this process, libmhp aside? The loaded objects are searched in the dynamic
 * loader's own order (the program, the preloaded libraries, then dependencies), each through its dynamic symbol
 * table. dlsym() is not used for this: in a non-PIE program that takes the address of malloc, RTLD_DEFAULT answers
 * with the program's PLT entry, which leads back to whoever is first (us); and RTLD_NEXT cannot tell that another
 * allocator was preloaded ahead of libmhp. */
struct elf_obj {
	uintptr_t base;
	const ElfW(Sym) *symtab;
	const char *strtab;
	const uint32_t *gnu_hash, *hash;
	const ElfW(Versym) *versym;
};

static int elf_open(struct dl_phdr_info *info, struct elf_obj *o)
{
	uintptr_t base = info->dlpi_addr;
	const ElfW(Dyn) *dyn = NULL;
	for (int i = 0; i < info->dlpi_phnum; i++)
		if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
			dyn = (const ElfW(Dyn) *)(base + info->dlpi_phdr[i].p_vaddr);
	memset(o, 0, sizeof *o);
	o->base = base;
	if (!dyn)
		return 0;
	/* the loader relocates these pointers in place for most objects, not for all */
#define ADDR(v) ((uintptr_t)(v) < base ? base + (uintptr_t)(v) : (uintptr_t)(v))
	for (; dyn->d_tag != DT_NULL; dyn++) {
		switch (dyn->d_tag) {
		case DT_SYMTAB: o->symtab = (const ElfW(Sym) *)ADDR(dyn->d_un.d_ptr); break;
		case DT_STRTAB: o->strtab = (const char *)ADDR(dyn->d_un.d_ptr); break;
		case DT_GNU_HASH: o->gnu_hash = (const uint32_t *)ADDR(dyn->d_un.d_ptr); break;
		case DT_HASH: o->hash = (const uint32_t *)ADDR(dyn->d_un.d_ptr); break;
		case DT_VERSYM: o->versym = (const ElfW(Versym) *)ADDR(dyn->d_un.d_ptr); break;
		}
	}
#undef ADDR
	return o->symtab && o->strtab && (o->gnu_hash || o->hash);
}

/* Is symbol i a definition of name that other objects bind to? Returns its address, 1 for an indirect
 * function (its address comes from a resolver: ask dlsym), 0 if not. */
static uintptr_t elf_match(const struct elf_obj *o, uint32_t i, const char *name)
{
	const ElfW(Sym) *sy = &o->symtab[i];
	unsigned type = ELF64_ST_TYPE(sy->st_info), bind = ELF64_ST_BIND(sy->st_info);
	if (sy->st_shndx == SHN_UNDEF || (bind != STB_GLOBAL && bind != STB_WEAK) || strcmp(o->strtab + sy->st_name, name))
		return 0;
	if (o->versym && (o->versym[i] & 0x8000)) /* an old version kept for binaries linked long ago */
		return 0;
	if (type == STT_GNU_IFUNC)
		return 1;
	return type == STT_FUNC ? o->base + sy->st_value : 0;
}

static uintptr_t elf_sym(const struct elf_obj *o, const char *name)
{
	uintptr_t a;
	if (o->gnu_hash) {
		uint32_t h = 5381;
		for (const unsigned char *c = (const unsigned char *)name; *c; c++)
			h = h * 33 + *c;
		const uint32_t *g = o->gnu_hash;
		uint32_t nbuckets = g[0], symoff = g[1], bloom = g[2];
		const uint32_t *buckets = g + 4 + bloom * (sizeof(ElfW(Addr)) / 4), *chain = buckets + nbuckets;
		uint32_t i = nbuckets ? buckets[h % nbuckets] : 0;
		if (i < symoff)
			return 0;
		for (;; i++) {
			uint32_t ch = chain[i - symoff];
			if ((ch | 1) == (h | 1) && (a = elf_match(o, i, name)))
				return a;
			if (ch & 1)
				return 0;
		}
	}
	uint32_t h = 0, g;
	for (const unsigned char *c = (const unsigned char *)name; *c; c++) {
		h = (h << 4) + *c;
		if ((g = h & 0xf0000000))
			h ^= g >> 24;
		h &= ~g;
	}
	uint32_t nbucket = o->hash[0];
	const uint32_t *bucket = o->hash + 2, *chain = bucket + nbucket;
	for (uint32_t i = nbucket ? bucket[h % nbucket] : 0; i; i = chain[i])
		if ((a = elf_match(o, i, name)))
			return a;
	return 0;
}

struct definer {
	const char *name;
	int only;                 /* search this object only (its position), -1: all */
	int idx, self_idx, at;    /* position of libmhp and of the definer in the loader's order (0 = the program) */
	uintptr_t addr, base;     /* the definition (1: an indirect function), its object's load address */
	uintptr_t lo, hi;         /* ... and the text segment it is in */
};

static int definer_cb(struct dl_phdr_info *info, size_t sz, void *arg)
{
	(void)sz;
	struct definer *d = arg;
	int idx = d->idx++;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t lo = info->dlpi_addr + ph->p_vaddr;
		if (ph->p_type == PT_LOAD && (uintptr_t)definer_cb >= lo && (uintptr_t)definer_cb < lo + ph->p_memsz) {
			d->self_idx = idx; /* libmhp itself */
			return d->addr != 0;
		}
	}
	struct elf_obj o;
	if (d->addr || (d->only >= 0 && d->only != idx) || !elf_open(info, &o) || !(d->addr = elf_sym(&o, d->name)))
		return 0;
	d->base = info->dlpi_addr;
	d->at = idx;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t lo = info->dlpi_addr + ph->p_vaddr;
		if (ph->p_type == PT_LOAD && d->addr >= lo && d->addr < lo + ph->p_memsz) {
			d->lo = lo;
			d->hi = lo + ph->p_memsz;
		}
	}
	return d->self_idx >= 0;
}

/* The first definition of name outside libmhp (in object `only` when >= 0). */
static struct definer find(const char *name, int only)
{
	struct definer d = {.name = name, .only = only, .self_idx = -1, .at = -1};
	dl_iterate_phdr(definer_cb, &d);
	if (d.addr == 1) { /* indirect function: the loader has its address */
		void *f = dlsym(d.self_idx >= 0 && d.self_idx < d.at ? RTLD_NEXT : RTLD_DEFAULT, name);
		d.addr = (uintptr_t)f;
	}
	return d;
}

static int am_first;   /* libmhp is preloaded ahead of the allocator: its functions are the ones the process calls */
static int alloc_glibc = 1;

static void resolve(void)
{
	if (t_boot)
		return;
	t_boot = 1;
	struct definer m = find("malloc", -1), c = find("calloc", -1), r = find("realloc", -1), f = find("free", -1);
	struct definer ma = find("memalign", -1), pm = find("posix_memalign", -1);
	void *vma = (void *)ma.addr;
	int glibc = 1;
	if (!m.addr || !c.addr || !r.addr || !f.addr) { /* no dynamic malloc in sight: glibc's */
		m.addr = (uintptr_t)__libc_malloc, c.addr = (uintptr_t)__libc_calloc, r.addr = (uintptr_t)__libc_realloc;
		f.addr = (uintptr_t)__libc_free, vma = __libc_memalign;
		am_first = 0;
	} else {
		am_first = m.self_idx >= 0 && m.self_idx < m.at;
		/* glibc's own malloc? Not by comparing with __libc_malloc: tcmalloc defines that name too. */
		glibc = find("gnu_get_libc_version", m.at).addr != 0;
		if (!glibc && ma.at != m.at) { /* an allocator without memalign: glibc's would mix two heaps */
			vma = pm.at == m.at ? (void *)memalign_by_posix : NULL;
			real_posix_memalign = (void *)pm.addr;
		}
	}
	if (!vma)
		vma = __libc_memalign;
	alloc_glibc = glibc;
	alloc_lo = alloc_len = alloc_base = 0;
	alloc_main = 0;
	alloc_kind = ALLOC_GLIBC;
	if (!glibc) {
		alloc_base = m.base;
		alloc_main = m.at == 0;
		alloc_kind = ALLOC_OTHER;
		struct definer s;
		if ((s = find("mallctl", m.at)).addr) {
			je_mallctl = (void *)s.addr;
			alloc_kind = ALLOC_JEMALLOC;
		} else if ((s = find("MallocExtension_GetNumericProperty", m.at)).addr) {
			tc_property = (void *)s.addr;
			alloc_kind = ALLOC_TCMALLOC;
		}
		alloc_lo = m.lo; /* last: from_alloc() reads these two without a lock */
		alloc_len = m.hi - m.lo;
	}
	/* operators: sampled here when the allocator defines them, forwarded to libstdc++'s, or served by malloc */
#define X(name, aligned, nothrow) \
	{ \
		struct definer o = find(#name, -1); \
		samp_##name = !glibc && o.addr && o.at == m.at; \
		real_##name = o.addr ? (new_fn)o.addr : plain_##name; \
	}
	NEW_OPS(X)
#undef X
#define X(name) \
	{ \
		struct definer o = find(#name, -1); \
		samp_##name = !glibc && o.addr && o.at == m.at; \
		real_##name = o.addr ? (del_fn)o.addr : plain_delete; \
	}
	DEL_OPS(X)
#undef X
	real_calloc = (void *)c.addr;
	real_realloc = (void *)r.addr;
	real_memalign = vma;
	real_free = (void *)f.addr;
	real_malloc = (void *)m.addr;
	t_boot = 0;
}

/* The allocator's own mappings (jemalloc extents, tcmalloc spans) are accounted through its malloc. */
static inline int from_alloc(void *ret)
{
	return (uintptr_t)ret - alloc_lo < alloc_len;
}

/* An inaccessible mapping or range holds no memory: a PROT_NONE mmap is an address-space reservation (MariaDB 11.8+
 * reserves innodb_buffer_pool_size_max, 8 TiB by default, and commits parts of it with MAP_FIXED mmaps), and
 * mprotect(PROT_NONE) is how it decommits. Both release whatever was recorded in the range; commits through
 * mprotect(PROT_READ|PROT_WRITE) are not seen. */
static void release(void *addr, size_t len)
{
	if (armed() && !t_in) {
		t_in = 1;
		if (unlikely(!t_init))
			thread_init();
		emit(MHP_EV_MUNMAP, (uintptr_t)addr, len, 0, 0);
		t_in = 0;
	}
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	void *p = (void *)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
	if (p != MAP_FAILED && prot == PROT_NONE) {
		if (flags & MAP_FIXED && !from_alloc(__builtin_return_address(0)))
			release(p, len);
		return p;
	}
	if (p != MAP_FAILED && (flags & MAP_ANONYMOUS) && on() && !t_in && !from_alloc(__builtin_return_address(0))) {
		t_in = 1;
		if (unlikely(!t_init))
			thread_init();
		arm();
		emit(MHP_EV_MMAP, (uintptr_t)p, len, len, 1);
		t_in = 0;
	}
	return p;
}

void *mmap64(void *addr, size_t len, int prot, int flags, int fd, off_t off) __attribute__((alias("mmap")));

int mprotect(void *addr, size_t len, int prot)
{
	int r = (int)syscall(SYS_mprotect, addr, len, prot);
	if (r == 0 && prot == PROT_NONE && !from_alloc(__builtin_return_address(0)))
		release(addr, len);
	return r;
}

int munmap(void *addr, size_t len)
{
	int r = (int)syscall(SYS_munmap, addr, len);
	if (r == 0 && armed() && !t_in && !from_alloc(__builtin_return_address(0))) {
		t_in = 1;
		if (unlikely(!t_init))
			thread_init();
		emit(MHP_EV_MUNMAP, (uintptr_t)addr, len, 0, 0);
		t_in = 0;
	}
	return r;
}

static int find_self(struct dl_phdr_info *info, size_t sz, void *arg)
{
	(void)sz;
	uintptr_t me = (uintptr_t)arg;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X))
			continue;
		uintptr_t lo = info->dlpi_addr + ph->p_vaddr, hi = lo + ph->p_memsz;
		if (me >= lo && me < hi) {
			self_lo = lo;
			self_hi = hi;
			self_base = info->dlpi_addr;
			return 1;
		}
	}
	return 0;
}

static void child_after_fork(void)
{
	H = NULL; /* the ring belongs to the parent */
}

/* Create the ring. Called once: at start (preloaded) or by mhp_attach (injected, quiet: stderr is the target's). */
static int ring_open(uint64_t nslots, int start, int quiet)
{
	const char *dir = getenv("MHP_DIR");
	char path[256];
	snprintf(path, sizeof path, "%s/mhp.%d", dir ? dir : "/dev/shm", (int)getpid());

	size_t ringsz = MHP_HDR_SIZE + nslots * sizeof(struct mhp_ev) + MHP_AUX_SIZE;
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || ftruncate(fd, (off_t)ringsz) != 0) {
		int e = errno;
		if (!quiet)
			fprintf(stderr, "libmhp: cannot create %s: %s\n", path, strerror(e));
		if (fd >= 0)
			close(fd);
		return -e;
	}
	void *m = (void *)syscall(SYS_mmap, NULL, ringsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	void *t = (void *)syscall(SYS_mmap, NULL, TBL_SIZE * 8, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (m == MAP_FAILED || t == MAP_FAILED) {
		if (!quiet)
			fprintf(stderr, "libmhp: mmap failed\n");
		return -ENOMEM;
	}
	struct mhp_hdr *h = m;
	h->version = MHP_VERSION;
	h->slot_size = sizeof(struct mhp_ev);
	h->nslots = nslots;
	h->sample_bytes = (uint64_t)R;
	h->pid = (uint64_t)getpid();
	h->gen = 1;
	h->enabled = start;
	h->alloc_kind = alloc_kind;
	h->aux_off = MHP_HDR_SIZE + nslots * sizeof(struct mhp_ev);
	h->aux_cap = MHP_AUX_SIZE;
	slots = (char *)m + MHP_HDR_SIZE;
	tbl = t;
	pthread_atfork(NULL, NULL, child_after_fork);
	atomic_store_explicit((_Atomic uint64_t *)&h->magic, MHP_MAGIC, memory_order_release);
	H = h;
	return 0;
}

/* ---- injected mode: redirect GOT slots ---- */

#if defined(__x86_64__)
#define R_SLOT R_X86_64_JUMP_SLOT
#define R_GLOB R_X86_64_GLOB_DAT
#define R_ABS R_X86_64_64
#elif defined(__aarch64__)
#define R_SLOT R_AARCH64_JUMP_SLOT
#define R_GLOB R_AARCH64_GLOB_DAT
#define R_ABS R_AARCH64_ABS64
#endif

static struct hook {
	const char *name;
	void *ours, *real;
	int release; /* redirected first: our free must be in place before our malloc samples anything */
	int *cxx;    /* operator delete: redirected only when the allocator defines it (its samp_ flag) */
	void *alt;   /* a non-PIE program that takes the function's address: the other objects' slots hold its PLT entry */
} hooks[] = {
#define C(fn, rel) {.name = #fn, .ours = fn, .release = rel},
	C(free, 1) C(cfree, 1) C(free_sized, 1) C(free_aligned_sized, 1) C(munmap, 1) C(mprotect, 1)
	C(malloc, 0) C(calloc, 0) C(realloc, 0) C(reallocarray, 0) C(memalign, 0) C(aligned_alloc, 0)
	C(posix_memalign, 0) C(valloc, 0) C(pvalloc, 0) C(mmap, 0) C(mmap64, 0)
#undef C
#define X(fn) {.name = #fn, .ours = fn, .release = 1, .cxx = &samp_##fn},
	DEL_OPS(X)
#undef X
#define X(fn, aligned, nothrow) {.name = #fn, .ours = fn}, /* always: see "Operator new/delete" above */
	NEW_OPS(X)
#undef X
};
#define NHOOKS (sizeof hooks / sizeof hooks[0])

static atomic_flag patching = ATOMIC_FLAG_INIT;
static unsigned long long last_adds;

struct pass {
	int release, undo;
	int idx; /* objects seen: the program comes first */
	uint64_t n;
};

static struct hook *hook_of(const char *name)
{
	for (size_t i = 0; i < NHOOKS; i++)
		if (hooks[i].real && !strcmp(hooks[i].name, name))
			return &hooks[i];
	return NULL;
}

/* Write one slot. GOT slots under RELRO are read-only after relocation: only the pages wholly inside the
 * PT_GNU_RELRO range were protected, so those get made writable for the store and read-only again. */
static int put(uintptr_t *slot, uintptr_t v, uintptr_t rlo, uintptr_t rhi)
{
	uintptr_t pg = (uintptr_t)slot & ~(uintptr_t)4095;
	int ro = (uintptr_t)slot >= rlo && (uintptr_t)slot < rhi;
	if (ro && syscall(SYS_mprotect, pg, 4096, PROT_READ | PROT_WRITE) != 0)
		return 0;
	atomic_store_explicit((_Atomic uintptr_t *)slot, v, memory_order_release);
	if (ro)
		syscall(SYS_mprotect, pg, 4096, PROT_READ);
	return 1;
}

static int patch_obj(struct dl_phdr_info *info, size_t sz, void *arg)
{
	(void)sz;
	struct pass *ps = arg;
	uintptr_t base = info->dlpi_addr, lo = UINTPTR_MAX, hi = 0, rlo = 0, rhi = 0;
	int prog = ps->idx++ == 0;
	last_adds = info->dlpi_adds;
	if (base == self_base || (alloc_len && base == alloc_base) || strstr(info->dlpi_name, "linux-vdso") ||
	    strstr(info->dlpi_name, "/ld-linux"))
		return 0;
	const ElfW(Dyn) *dyn = NULL;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		if (ph->p_type == PT_DYNAMIC)
			dyn = (const ElfW(Dyn) *)(base + ph->p_vaddr);
		else if (ph->p_type == PT_GNU_RELRO) {
			rlo = (base + ph->p_vaddr) & ~(uintptr_t)4095;
			rhi = (base + ph->p_vaddr + ph->p_memsz) & ~(uintptr_t)4095;
		} else if (ph->p_type == PT_LOAD) {
			if (base + ph->p_vaddr < lo)
				lo = base + ph->p_vaddr;
			if (base + ph->p_vaddr + ph->p_memsz > hi)
				hi = base + ph->p_vaddr + ph->p_memsz;
		}
	}
	if (!dyn)
		return 0;
	/* the loader relocates these pointers in place for most objects, not for all */
#define ADDR(v) ((uintptr_t)(v) < base ? base + (uintptr_t)(v) : (uintptr_t)(v))
	const ElfW(Sym) *symtab = NULL;
	const char *strtab = NULL;
	const ElfW(Rela) *rel[2] = {NULL, NULL};
	size_t relsz[2] = {0, 0};
	for (; dyn->d_tag != DT_NULL; dyn++) {
		switch (dyn->d_tag) {
		case DT_SYMTAB: symtab = (const ElfW(Sym) *)ADDR(dyn->d_un.d_ptr); break;
		case DT_STRTAB: strtab = (const char *)ADDR(dyn->d_un.d_ptr); break;
		case DT_RELA: rel[0] = (const ElfW(Rela) *)ADDR(dyn->d_un.d_ptr); break;
		case DT_RELASZ: relsz[0] = dyn->d_un.d_val; break;
		case DT_JMPREL: rel[1] = (const ElfW(Rela) *)ADDR(dyn->d_un.d_ptr); break;
		case DT_PLTRELSZ: relsz[1] = dyn->d_un.d_val; break;
		}
	}
#undef ADDR
	if (!symtab || !strtab)
		return 0;
	for (int k = 0; k < 2; k++) {
		if (!rel[k])
			continue;
		for (size_t i = 0; i < relsz[k] / sizeof(ElfW(Rela)); i++) {
			const ElfW(Rela) *r = &rel[k][i];
			unsigned type = ELF64_R_TYPE(r->r_info), si = ELF64_R_SYM(r->r_info);
			if ((type != R_SLOT && type != R_GLOB && type != R_ABS) || si == 0 || (type == R_ABS && r->r_addend))
				continue;
			struct hook *hk = hook_of(strtab + symtab[si].st_name);
			if (!hk || (!ps->undo && hk->release != ps->release))
				continue;
			uintptr_t *slot = (uintptr_t *)(base + r->r_offset), v = *slot;
			if (ps->undo) {
				if (v == (uintptr_t)hk->ours)
					ps->n += put(slot, (uintptr_t)(hk->alt && !prog ? hk->alt : hk->real), rlo, rhi);
			} else if (v == (uintptr_t)hk->ours)
				ps->n++;
			else if (v == (uintptr_t)hk->real || (hk->alt && v == (uintptr_t)hk->alt) ||
				 (type == R_SLOT && v >= lo && v < hi)) /* bound, or lazy (PLT stub) */
				ps->n += put(slot, (uintptr_t)hk->ours, rlo, rhi);
		}
	}
	return 0;
}

/* Redirect (or undo) the slots of every loaded object; returns the number of slots redirected (or restored). */
static uint64_t patch_all(int undo)
{
	struct pass ps = {.release = 1, .undo = undo};
	dl_iterate_phdr(patch_obj, &ps);
	if (!undo) {
		ps.release = 0;
		ps.idx = 0;
		dl_iterate_phdr(patch_obj, &ps);
	}
	return ps.n;
}

static int count_adds(struct dl_phdr_info *info, size_t sz, void *arg)
{
	(void)sz;
	*(unsigned long long *)arg = info->dlpi_adds;
	return 1;
}

/* Objects loaded after mhp_attach (plugins, components) are redirected on the collector's next request. */
static void maybe_rescan(void)
{
	if (likely(atomic_load_explicit((_Atomic uint32_t *)&H->inject, memory_order_relaxed) != 1))
		return;
	_Atomic uint64_t *claim = (_Atomic uint64_t *)&H->rescan_claim;
	uint64_t req = atomic_load_explicit((_Atomic uint64_t *)&H->rescan_req, memory_order_relaxed);
	uint64_t c = atomic_load_explicit(claim, memory_order_relaxed);
	if (likely(c == req) || !atomic_compare_exchange_strong(claim, &c, req))
		return;
	unsigned long long adds = 0;
	dl_iterate_phdr(count_adds, &adds);
	if (adds == last_adds || atomic_flag_test_and_set(&patching))
		return;
	atomic_store_explicit((_Atomic uint64_t *)&H->hooked, patch_all(0), memory_order_relaxed);
	atomic_flag_clear(&patching);
}

/* Called by mhp (watch -inject) through ptrace after dlopen. Returns the number of slots redirected, or
 * -1: the process's malloc is built into its executable (calls to it do not go through a GOT slot),
 * -2: libmhp is preloaded already, or -errno. */
int mhp_attach(uint64_t sample_bytes, uint64_t nslots)
{
	while (atomic_flag_test_and_set(&patching))
		;
	resolve(); /* the functions the process calls now: glibc's, jemalloc's, tcmalloc's */
	if (am_first || alloc_main) {
		atomic_flag_clear(&patching);
		return am_first ? -2 : -1;
	}
	int ret = 0;
	if (!H) {
		if (sample_bytes > 0)
			R = (double)sample_bytes;
		ret = ring_open(nslots ? nslots : 32768, 0, 1);
	}
	if (ret == 0) {
		for (size_t i = 0; i < NHOOKS; i++) {
			struct hook *hk = &hooks[i];
			hk->real = hk->alt = NULL;
			if (hk->cxx && !*hk->cxx)
				continue;
			void *seen = dlsym(RTLD_DEFAULT, hk->name); /* what the other objects were bound to */
			hk->real = (void *)find(hk->name, -1).addr;
			if (!hk->real)
				hk->real = seen == hk->ours ? NULL : seen;
			else if (seen != hk->real && seen != hk->ours)
				hk->alt = seen;
		}
		H->alloc_kind = alloc_kind;
		atomic_store((_Atomic uint32_t *)&H->inject, 1);
		uint64_t n = patch_all(0);
		atomic_store((_Atomic uint64_t *)&H->hooked, n);
		ret = (int)n;
	}
	atomic_flag_clear(&patching);
	return ret;
}

/* Points the slots back at libc's functions and stops sampling; libmhp stays mapped (a thread may be inside it).
 * Returns the number of slots restored. */
int mhp_detach(void)
{
	if (!H || atomic_load((_Atomic uint32_t *)&H->inject) == 0)
		return -2;
	while (atomic_flag_test_and_set(&patching))
		;
	atomic_store((_Atomic uint32_t *)&H->enabled, 0);
	atomic_store((_Atomic uint32_t *)&H->inject, 2);
	uint64_t n = patch_all(1);
	atomic_store((_Atomic uint32_t *)&H->armed, 0);
	atomic_store((_Atomic uint64_t *)&H->hooked, 0);
	atomic_flag_clear(&patching);
	return (int)n;
}

__attribute__((constructor)) static void mhp_init(void)
{
	t_in = 1;
	dl_iterate_phdr(find_self, (void *)(uintptr_t)&mhp_init);
	/* dlopen'ed (injected), or preloaded behind another allocator: our malloc interposes nothing; mhp_attach
	 * does the rest */
	resolve();
	if (!am_first) {
		t_in = 0;
		return;
	}
	const char *s;
	if ((s = getenv("MHP_SAMPLE_BYTES")) && atof(s) > 0)
		R = atof(s);
	uint64_t nslots = 32768;
	if ((s = getenv("MHP_SLOTS")) && atol(s) > 0)
		nslots = (uint64_t)atol(s);
	s = getenv("MHP_START");
	ring_open(nslots, !(s && *s == '0'), 0);
	t_in = 0;
}
