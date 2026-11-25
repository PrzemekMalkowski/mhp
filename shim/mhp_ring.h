/* Shared-memory ring between libmhp.so (producer, inside the target) and the
 * collector (consumer). Layout is fixed little-endian x86_64; the Go reader in
 * internal/shim mirrors the offsets below. */
#ifndef MHP_RING_H
#define MHP_RING_H

#include <stdint.h>

#define MHP_MAGIC 0x3152504d48ULL /* "HMPR1" */
#define MHP_VERSION 3
#define MHP_DEPTH 62
#define MHP_HDR_SIZE 4096
#define MHP_AUX_SIZE (4u << 20) /* after the slots: malloc_info XML (sparse in tmpfs until written) */

enum mhp_ev_type {
	MHP_EV_ALLOC = 1,  /* ptr, size, weight, stack */
	MHP_EV_FREE = 2,   /* ptr (only for sampled allocations) */
	MHP_EV_MMAP = 3,   /* ptr, size(len), stack — anonymous mappings, never sampled */
	MHP_EV_MUNMAP = 4, /* ptr, size(len) */
};

struct mhp_hdr {               /* offset */
	uint64_t magic;            /* 0 */
	uint32_t version;          /* 8 */
	uint32_t slot_size;        /* 12 */
	uint64_t nslots;           /* 16 */
	uint64_t head;             /* 24  producers reserve here (atomic) */
	uint64_t tail;             /* 32  consumer position (atomic) */
	uint64_t drops;            /* 40  events lost: ring full (atomic) */
	uint32_t enabled;          /* 48  collector toggles sampling (atomic) */
	uint32_t gen;              /* 52  bumped by collector on (re)enable (atomic) */
	uint64_t sample_bytes;     /* 56  mean sampling interval in bytes */
	uint64_t pid;              /* 64 */
	uint64_t table_drops;      /* 72  sampled allocations not tracked: table full (atomic) */
	uint64_t sampled;          /* 80  total sampled allocations (atomic) */
	uint32_t armed;            /* 88  set once something is tracked; collector clears it with a new gen (atomic) */
	uint32_t inject;           /* 92  0 = preloaded; injected (mhp watch -inject): 1 = calls redirected, 2 = undone */
	uint64_t hooked;           /* 96  GOT slots redirected to libmhp (injected) */
	uint64_t rescan_req;       /* 104 collector increments to have newly loaded objects redirected too (injected) */
	uint64_t rescan_claim;     /* 112 last request a thread took on (atomic CAS) */
	uint32_t alloc_kind;       /* 120 the allocator underneath: 0 glibc, 1 jemalloc, 2 tcmalloc, 3 other */
	uint8_t pad0[256 - 124];
	/* the allocator's heap statistics on request, on their own cache lines (the ones above are hot) */
	uint64_t stats_req;        /* 256 collector increments to request them */
	uint64_t stats_claim;      /* 264 last request a thread took on (atomic CAS) */
	uint64_t stats_seq;        /* 272 = stats_req value the fields below answer */
	uint64_t stats_ns;         /* 280 time mallinfo2() took */
	uint64_t mi[10];           /* 288 glibc mallinfo2: arena ordblks smblks hblks hblkhd usmblks fsmblks uordblks fordblks keepcost
	                            *     jemalloc stats.: allocated active metadata resident mapped retained
	                            *     tcmalloc: current_allocated heap_size pageheap_free pageheap_unmapped central_cache_free
	                            *               transfer_cache_free thread_cache_free */
	uint8_t pad1[384 - 368];
	/* glibc malloc_info() on request: per-arena XML written to the aux area (at aux_off, aux_cap bytes) */
	uint64_t arenas_req;       /* 384 collector increments to request it */
	uint64_t arenas_claim;     /* 392 last request a thread took on (atomic CAS) */
	uint64_t arenas_seq;       /* 400 = arenas_req value the aux area answers (release) */
	uint64_t arenas_ns;        /* 408 time malloc_info() took */
	uint64_t arenas_len;       /* 416 bytes of XML in the aux area; aux_cap - 1 = truncated; 0 = not glibc */
	uint64_t aux_off;          /* 424 */
	uint64_t aux_cap;          /* 432 */
};

_Static_assert(__builtin_offsetof(struct mhp_hdr, mi) == 288, "ring layout");
_Static_assert(__builtin_offsetof(struct mhp_hdr, arenas_req) == 384, "ring layout");
_Static_assert(__builtin_offsetof(struct mhp_hdr, aux_cap) == 432, "ring layout");

struct mhp_ev {                /* offset */
	uint64_t commit;           /* 0   = slot index + 1 once fully written */
	uint32_t type;             /* 8 */
	uint32_t tid;              /* 12 */
	uint64_t ptr;              /* 16 */
	uint64_t size;             /* 24 */
	uint64_t weight;           /* 32  bytes this sample represents */
	uint16_t depth;            /* 40 */
	uint16_t pad[3];
	uint64_t frames[MHP_DEPTH]; /* 48  return addresses, leaf first */
};                             /* 544 bytes */

#endif
