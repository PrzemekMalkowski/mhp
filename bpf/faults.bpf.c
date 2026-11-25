// SPDX-License-Identifier: GPL-2.0
// Page-fault stack profiler with in-kernel aggregation: counts per (user stack, tid, region class) of the faulting
// mapping. Replaces per-sample perf records, so a startup burst of faults cannot overflow a ring.
// Hooked at the exit of handle_mm_fault, so it counts what the kernel accounts as min/maj faults: user-mode faults,
// kernel-mode faults on user memory (copy_to_user in read/pread...) and get_user_pages faults (e.g. O_DIRECT
// buffers), without retries, errors or uaccess with page faults disabled. The VMA comes as an argument (no lookup).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DEPTH 64
#define MAX_LEAF 1024
#define TMPFS_MAGIC 0x01021994
#define EEXIST 17
#define E2BIG 7
#define INSERTED (1ULL << 63)

#define VM_FAULT_ERROR (1 | 2 | 16 | 32 | 64 | 2048) // OOM SIGBUS HWPOISON HWPOISON_LARGE SIGSEGV FALLBACK
#define VM_FAULT_RETRY 1024
#define VM_FAULT_COMPLETED 16384 // lock was dropped: the VMA may be gone
#define FAULT_FLAG_USER 64

// Region classes; userspace names them (procfs.ClassOf names, plus unknown when the VMA could not be read).
enum { C_UNKNOWN, C_ANON, C_HEAP, C_STACK, C_FILE, C_SHMEM, C_OTHER };

const volatile __u32 tgid;
// Frameless leaf routines (glibc mem*/str*), sorted [lo, hi) ranges: the FP chain skips their caller,
// so the return address at [sp] is inserted after the IP.
const volatile __u32 nleaf;
const volatile __u64 leaf_lo[MAX_LEAF], leaf_hi[MAX_LEAF];
// libc text: a fault taken in kernel mode (syscall) leaves the user IP in a frameless syscall wrapper.
const volatile __u64 libc_lo, libc_hi;

__u64 faults, kernel_faults, count_drops, stack_drops;

struct stack { __u64 frames[MAX_DEPTH]; };
struct fkey { __u64 stack; __u32 tid; __u32 class; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 32768); __type(key, __u64); __type(value, struct stack); } stacks SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 262144); __type(key, struct fkey); __type(value, __u64); } counts SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct stack); } scratch SEC(".maps");

static __always_inline bool in_leaf(__u64 ip)
{
	__u32 lo = 0, hi = nleaf;
	if (hi > MAX_LEAF)
		hi = MAX_LEAF;
	for (int i = 0; i < 11 && lo < hi; i++) { // binary search, 2^11 > MAX_LEAF
		__u32 mid = (lo + hi) / 2;
		if (mid >= MAX_LEAF)
			return false;
		if (ip < leaf_lo[mid])
			hi = mid;
		else if (ip >= leaf_hi[mid])
			lo = mid + 1;
		else
			return true;
	}
	return false;
}

static __always_inline __u32 classify(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *f = vma->vm_file;
	if (f)
		return f->f_inode->i_sb->s_magic == TMPFS_MAGIC ? C_SHMEM : C_FILE;
	if (vma->vm_ops) // [vdso], [vvar] and other special mappings
		return C_OTHER;
	if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk)
		return C_HEAP;
	if (vma->vm_start <= mm->start_stack && vma->vm_end > mm->start_stack)
		return C_STACK;
	return C_ANON;
}

SEC("fexit/handle_mm_fault")
int BPF_PROG(pf, struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *uregs,
	     vm_fault_t ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	if ((id >> 32) != tgid || (ret & (VM_FAULT_ERROR | VM_FAULT_RETRY)))
		return 0;
	bool kernel = !(flags & FAULT_FLAG_USER);
	struct task_struct *task = bpf_get_current_task_btf();
	__sync_fetch_and_add(&faults, 1);
	if (kernel)
		__sync_fetch_and_add(&kernel_faults, 1);

	__u32 z = 0;
	struct stack *st = bpf_map_lookup_elem(&scratch, &z);
	if (!st)
		return 0;
	__builtin_memset(st, 0, sizeof(*st));
	long n = bpf_get_stack(ctx, st->frames, sizeof(st->frames), BPF_F_USER_STACK);
	int depth = n > 0 ? n / 8 : 0;
	__u64 ip = depth > 0 ? st->frames[0] : 0;
	if (depth > 0 && depth < MAX_DEPTH && ((kernel && ip >= libc_lo && ip < libc_hi) || in_leaf(ip))) {
		// Tagged with bit 63: userspace keeps it only if it is in code.
		__u64 ra = 0;
		struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
		bpf_probe_read_user(&ra, sizeof(ra), (void *)BPF_CORE_READ(regs, sp));
		if (ra && (depth < 2 || st->frames[1] != ra)) {
			for (int i = MAX_DEPTH - 1; i > 1; i--) // shift frames[1..] up by one
				st->frames[i] = st->frames[i - 1];
			st->frames[1] = ra | INSERTED;
			depth++;
		}
	}
	// FNV-1a over the frames; zeroed tail makes depth part of the hash
	__u64 h = 0xcbf29ce484222325ULL;
	for (int i = 0; i < MAX_DEPTH; i++) {
		h ^= st->frames[i];
		h *= 0x100000001b3ULL;
	}
	if (!bpf_map_lookup_elem(&stacks, &h) && bpf_map_update_elem(&stacks, &h, st, BPF_NOEXIST) == -E2BIG)
		__sync_fetch_and_add(&stack_drops, 1);

	struct fkey k = { .stack = h, .tid = (__u32)id, .class = (ret & VM_FAULT_COMPLETED) ? C_UNKNOWN : classify(vma) };
	__u64 *v = bpf_map_lookup_elem(&counts, &k);
	if (v) {
		__sync_fetch_and_add(v, 1);
	} else {
		__u64 one = 1;
		long err = bpf_map_update_elem(&counts, &k, &one, BPF_NOEXIST);
		if (err == -EEXIST && (v = bpf_map_lookup_elem(&counts, &k))) // another CPU created it
			__sync_fetch_and_add(v, 1);
		else if (err)
			__sync_fetch_and_add(&count_drops, 1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
