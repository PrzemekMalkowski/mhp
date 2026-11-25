// SPDX-License-Identifier: GPL-2.0
// eBPF heap tracer: attach to a running process without restart or LD_PRELOAD.
// Same sampling and events as libmhp: Poisson byte sampling (mean sample_bytes) of the malloc family of the
// target's allocator (glibc, or jemalloc/tcmalloc/... with their operator new/delete), all anonymous mmaps made
// outside libc and the allocator, every munmap made outside them.
//
// malloc-family probes are session uprobes (Linux 6.13+): the entry decides whether to sample, and only
// sampled calls arm the return probe, so an unsampled malloc costs one uprobe hit. free/munmap are entry-only.
// Events use the libmhp ring slot layout (shim/mhp_ring.h), so userspace shares one tracker for both.
#define BPF_NO_KFUNC_PROTOTYPES // newer bpftool emits kfunc prototypes; ours below are per kernel API
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DEPTH 62
#define EV_ALLOC 1
#define EV_FREE 2
#define EV_MMAP 3
#define EV_MUNMAP 4
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED 0x10
#define PROT_NONE 0
#define EXP_TAB 1024

#ifndef NO_SESSION
extern bool bpf_session_is_return(void *ctx) __ksym; // Linux 7.0 signatures (6.13: no ctx)
extern __u64 *bpf_session_cookie(void *ctx) __ksym;
#endif

struct event {
	__u64 commit; // unused here (ring bookkeeping in libmhp)
	__u32 type;
	__u32 tid;
	__u64 ptr;
	__u64 size;
	__u64 weight; // filled in userspace (needs floating point)
	__u16 depth;
	__u16 pad[3];
	__u64 frames[MAX_DEPTH]; // leaf-first return addresses
};

// Set before load.
const volatile __u64 sample_bytes = 256 << 10;
const volatile __u64 libc_lo, libc_hi;   // libc text: mmap/munmap called from inside libc is the allocator's own
const volatile __u64 alloc_lo, alloc_hi; // allocator library text when it is not libc (else empty), likewise
const volatile __u32 exp_tab[EXP_TAB]; // -ln(u) * 65536 for u uniform in (0,1)

// Changed at runtime from userspace.
volatile __u32 enabled = 1;

// Self-monitoring, read by userspace.
__u64 sampled, drops, table_drops;

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 16 << 20); } events SEC(".maps");
// Live sampled pointers, so that free() only reports those. Userspace keeps the details.
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1 << 20); __type(key, __u64); __type(value, __u8); } live SEC(".maps");
// Bytes left until the next sample. Per CPU: a Poisson process over bytes needs no per-thread state.
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __s64); } countdown SEC(".maps");
// posix_memalign: the cookie holds the size, this holds the out-pointer (by tid).
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, __u64); } memptr SEC(".maps");

static __always_inline __s64 draw(void)
{
	__u32 i = bpf_get_prandom_u32() & (EXP_TAB - 1);
	return (__s64)((sample_bytes * exp_tab[i]) >> 16) + 1;
}

// want reports whether an allocation of n bytes is sampled.
static __always_inline bool want(__u64 n)
{
	__u32 z = 0;
	__s64 *left = bpf_map_lookup_elem(&countdown, &z);
	if (!left || !n)
		return false;
	if (*left == 0)
		*left = draw();
	*left -= n;
	if (*left > 0)
		return false;
	*left = draw();
	return true;
}

static __always_inline void emit(void *ctx, __u32 type, __u64 ptr, __u64 size, bool stack)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&drops, 1);
		return;
	}
	e->type = type;
	e->tid = (__u32)bpf_get_current_pid_tgid();
	e->ptr = ptr;
	e->size = size;
	e->weight = 0;
	e->depth = 0;
	if (stack) {
		long n = bpf_get_stack(ctx, e->frames, sizeof(e->frames), BPF_F_USER_STACK);
		if (n > 0)
			e->depth = n / 8;
	}
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void track(void *ctx, __u64 ptr, __u64 size)
{
	__u8 one = 1;
	if (!ptr)
		return;
	if (bpf_map_update_elem(&live, &ptr, &one, BPF_ANY)) {
		__sync_fetch_and_add(&table_drops, 1);
		return;
	}
	__sync_fetch_and_add(&sampled, 1);
	emit(ctx, EV_ALLOC, ptr, size, true);
}

static __always_inline void untrack(void *ctx, __u64 ptr)
{
	if (!ptr || bpf_map_delete_elem(&live, &ptr))
		return;
	emit(ctx, EV_FREE, ptr, 0, false);
}

#ifndef NO_SESSION
// begin is the entry half of a session: return 0 to run the return half (cookie = size), 1 to skip it.
static __always_inline int begin(void *ctx, __u64 n)
{
	if (!enabled || !want(n))
		return 1;
	*bpf_session_cookie(ctx) = n;
	return 0;
}

SEC("uprobe.session")
int BPF_UPROBE(malloc_s, __u64 n)
{
	if (bpf_session_is_return(ctx)) {
		track(ctx, PT_REGS_RC(ctx), *bpf_session_cookie(ctx));
		return 0;
	}
	return begin(ctx, n);
}

SEC("uprobe.session")
int BPF_UPROBE(calloc_s, __u64 a, __u64 b)
{
	if (bpf_session_is_return(ctx)) {
		track(ctx, PT_REGS_RC(ctx), *bpf_session_cookie(ctx));
		return 0;
	}
	return begin(ctx, a * b);
}

SEC("uprobe.session")
int BPF_UPROBE(realloc_s, __u64 old, __u64 n)
{
	if (bpf_session_is_return(ctx)) {
		track(ctx, PT_REGS_RC(ctx), *bpf_session_cookie(ctx));
		return 0;
	}
	untrack(ctx, old);
	return begin(ctx, n);
}

// memalign and aligned_alloc: (alignment, size) -> ptr
SEC("uprobe.session")
int BPF_UPROBE(memalign_s, __u64 al, __u64 n)
{
	if (bpf_session_is_return(ctx)) {
		track(ctx, PT_REGS_RC(ctx), *bpf_session_cookie(ctx));
		return 0;
	}
	return begin(ctx, n);
}

SEC("uprobe.session")
int BPF_UPROBE(posix_memalign_s, __u64 out, __u64 al, __u64 n)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	if (bpf_session_is_return(ctx)) {
		__u64 *o = bpf_map_lookup_elem(&memptr, &tid);
		__u64 p = 0;
		if (o && PT_REGS_RC(ctx) == 0 && !bpf_probe_read_user(&p, sizeof(p), (void *)*o))
			track(ctx, p, *bpf_session_cookie(ctx));
		bpf_map_delete_elem(&memptr, &tid);
		return 0;
	}
	if (begin(ctx, n))
		return 1;
	bpf_map_update_elem(&memptr, &tid, &out, BPF_ANY);
	return 0;
}

#else // NO_SESSION: kernels without session uprobes (before 6.13, e.g. RHEL 9's 5.14). Every call runs the
// entry probe and a return probe; the entry leaves the size of a sampled call in a per-thread slot for the return.
struct pend { __u64 size, out; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, struct pend); } pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u32); __type(value, __u64); } pending_mmap SEC(".maps");

static __always_inline int begin(__u64 n, __u64 out)
{
	if (enabled && want(n)) {
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		struct pend p = { .size = n, .out = out };
		bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
	}
	return 0;
}

SEC("uprobe.multi")
int BPF_UPROBE(malloc_s, __u64 n) { return begin(n, 0); }

SEC("uprobe.multi")
int BPF_UPROBE(calloc_s, __u64 a, __u64 b) { return begin(a * b, 0); }

SEC("uprobe.multi")
int BPF_UPROBE(realloc_s, __u64 old, __u64 n)
{
	untrack(ctx, old);
	return begin(n, 0);
}

SEC("uprobe.multi")
int BPF_UPROBE(memalign_s, __u64 al, __u64 n) { return begin(n, 0); }

SEC("uprobe.multi")
int BPF_UPROBE(posix_memalign_s, __u64 out, __u64 al, __u64 n) { return begin(n, out); }

// Return half of all the above: posix_memalign returns 0 and the pointer through out.
SEC("uretprobe.multi")
int BPF_URETPROBE(alloc_r)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct pend *p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;
	__u64 size = p->size, out = p->out, ptr = PT_REGS_RC(ctx);
	bpf_map_delete_elem(&pending, &tid);
	if (out) {
		__u64 q = 0;
		if (ptr == 0 && !bpf_probe_read_user(&q, sizeof(q), (void *)out))
			track(ctx, q, size);
	} else {
		track(ctx, ptr, size);
	}
	return 0;
}
#endif

SEC("uprobe.multi")
int BPF_UPROBE(free_e, __u64 p)
{
	untrack(ctx, p);
	return 0;
}

static __always_inline bool from_libc(__u64 ip)
{
	return (ip >= libc_lo && ip < libc_hi) || (ip >= alloc_lo && ip < alloc_hi);
}

// mmap_entry returns 0 when the call's result is to be recorded at return, 1 to skip the return half.
static __always_inline int mmap_entry(struct pt_regs *ctx, __u64 addr, __u64 len, __u64 prot, __u64 flags)
{
	if (!(flags & MAP_ANONYMOUS))
		return 1;
	if (prot == PROT_NONE) { // a reservation holds no memory; MAP_FIXED over recorded memory releases it
		__u64 ra = 0;
		bpf_probe_read_user(&ra, sizeof(ra), (void *)PT_REGS_SP(ctx));
		if ((flags & MAP_FIXED) && !from_libc(ra))
			emit(ctx, EV_MUNMAP, addr, len, false);
		return 1;
	}
	return enabled ? 0 : 1;
}

// At return the IP is the caller's return address: skip libc's and the allocator's own mmaps (arenas, extents,
// thread stacks): their memory is accounted by the malloc probes.
static __always_inline void mmap_return(struct pt_regs *ctx, __u64 len)
{
	__u64 p = PT_REGS_RC(ctx);
	if (p != (__u64)-1 && !from_libc(PT_REGS_IP(ctx)))
		emit(ctx, EV_MMAP, p, len, true);
}

#ifndef NO_SESSION
SEC("uprobe.session")
int BPF_UPROBE(mmap_s, __u64 addr, __u64 len, __u64 prot, __u64 flags)
{
	if (bpf_session_is_return(ctx)) {
		mmap_return(ctx, *bpf_session_cookie(ctx));
		return 0;
	}
	if (mmap_entry(ctx, addr, len, prot, flags))
		return 1;
	*bpf_session_cookie(ctx) = len;
	return 0;
}
#else
SEC("uprobe.multi")
int BPF_UPROBE(mmap_s, __u64 addr, __u64 len, __u64 prot, __u64 flags)
{
	if (!mmap_entry(ctx, addr, len, prot, flags)) {
		__u32 tid = (__u32)bpf_get_current_pid_tgid();
		bpf_map_update_elem(&pending_mmap, &tid, &len, BPF_ANY);
	}
	return 0;
}

SEC("uretprobe.multi")
int BPF_URETPROBE(mmap_r)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *len = bpf_map_lookup_elem(&pending_mmap, &tid);
	if (!len)
		return 0;
	__u64 n = *len;
	bpf_map_delete_elem(&pending_mmap, &tid);
	mmap_return(ctx, n);
	return 0;
}
#endif

SEC("uprobe.multi")
int BPF_UPROBE(munmap_e, __u64 addr, __u64 len)
{
	__u64 ra = 0;
	// Reported even while paused (like frees), so mappings recorded before the pause are released.
	// At entry the return address is on top of the stack.
	bpf_probe_read_user(&ra, sizeof(ra), (void *)PT_REGS_SP(ctx));
	if (!from_libc(ra))
		emit(ctx, EV_MUNMAP, addr, len, false);
	return 0;
}

SEC("uprobe.multi")
int BPF_UPROBE(mprotect_e, __u64 addr, __u64 len, __u64 prot)
{
	__u64 ra = 0;
	if (prot != PROT_NONE) // commits through mprotect are not seen
		return 0;
	bpf_probe_read_user(&ra, sizeof(ra), (void *)PT_REGS_SP(ctx));
	if (!from_libc(ra)) // decommit (MariaDB 11.8+ buffer pool shrink): like munmap
		emit(ctx, EV_MUNMAP, addr, len, false);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
