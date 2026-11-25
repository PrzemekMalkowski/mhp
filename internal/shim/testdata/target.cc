// Test target for libmhp (internal/shim, internal/inject): every t_* function leaves a known number of live bytes
// (or none), through a different allocation call. Large sizes, so each one is sampled with its exact weight.
// MHP_T_WAIT=1: allocate only after SIGUSR1 (injection tests attach first). Prints "done" when finished.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>
#include <malloc.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#define T extern "C" __attribute__((noinline)) void
#define MiB (1UL << 20)

static void *volatile keep[64];
static volatile int nkeep;
static void hold(void *p, size_t n)
{
	if (!p)
		abort();
	memset(p, 1, n < 4096 ? n : 4096);
	keep[nkeep++] = p;
}

// Taking malloc's address: in a non-PIE build the other objects then see the program's PLT entry as "malloc".
static void *(*volatile malloc_ptr)(size_t) = malloc;
T t_malloc() { hold(malloc_ptr(8 * MiB), 8 * MiB); }
T t_calloc() { hold(calloc(4, MiB), 4 * MiB); }
T t_realloc() { hold(realloc(malloc(MiB), 6 * MiB), 6 * MiB); }
T t_posix_memalign()
{
	void *p = 0;
	if (posix_memalign(&p, 4096, 2 * MiB))
		abort();
	hold(p, 2 * MiB);
}
T t_aligned_alloc() { hold(aligned_alloc(64, 2 * MiB), 2 * MiB); }
T t_memalign() { hold(memalign(128, 2 * MiB), 2 * MiB); }
T t_new() { hold(::operator new(3 * MiB), 3 * MiB); }
T t_new_array() { hold(new char[8 * MiB], 8 * MiB); }
T t_new_nothrow() { hold(new (std::nothrow) char[5 * MiB], 5 * MiB); }
T t_new_aligned() { hold(::operator new(5 * MiB, std::align_val_t(64)), 5 * MiB); }
T t_new_aligned_nothrow() { hold(::operator new[](2 * MiB, std::align_val_t(256), std::nothrow), 2 * MiB); }
T t_mmap() { hold(mmap(0, 32 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), 32 * MiB); }
// MariaDB 11.8+ buffer pool: reserve address space, commit with MAP_FIXED, decommit with madvise + mprotect.
T t_reserve()
{
	char *r = (char *)mmap(0, 64UL << 30, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	char *p = (char *)mmap(r, 16 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	hold(p, 16 * MiB);
	madvise(p + 12 * MiB, 4 * MiB, MADV_DONTNEED);
	mprotect(p + 12 * MiB, 4 * MiB, PROT_NONE);
}

T t_freed_malloc()
{
	void *p = malloc(16 * MiB);
	hold(p, 16 * MiB);
	free(p);
}
T t_freed_new()
{
	char *p = new char[16 * MiB];
	hold(p, 16 * MiB);
	delete[] p;
}
T t_freed_sized()
{
	void *p = ::operator new(12 * MiB);
	hold(p, 12 * MiB);
	::operator delete(p, 12 * MiB);
}
T t_freed_aligned()
{
	void *p = ::operator new(12 * MiB, std::align_val_t(4096));
	hold(p, 12 * MiB);
	::operator delete(p, 12 * MiB, std::align_val_t(4096));
}
T t_new_freed_by_free() // allowed with every allocator here: new and malloc share one heap
{
	void *p = ::operator new(4 * MiB);
	hold(p, 4 * MiB);
	free(p);
}
T t_munmap()
{
	void *p = mmap(0, 16 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	hold(p, 16 * MiB);
	munmap(p, 16 * MiB);
}
T t_bad_alloc()
{
	volatile size_t huge = ~0UL >> 2;
	try {
		hold(new char[huge], 1);
	} catch (const std::bad_alloc &) {
		puts("bad_alloc caught");
	}
}
// many small, short-lived objects: sampled statistically, nothing left
T t_small()
{
	// new[] and std::vector call operator new from this function's own (inlined) code: a std::string would
	// allocate inside libstdc++, which hides this frame where libstdc++ has no frame pointers (RHEL, Rocky).
	for (int i = 0; i < 200000; i++) {
		char *s = new char[100 + i % 900];
		std::vector<int> v(1 + i % 512);
		s[0] = 'x';
		if (v.size() == 0)
			abort();
		delete[] s;
	}
}

static void *churn(void *)
{
	for (;;) {
		std::string s(64 + rand() % 4096, 'y');
		void *p = malloc(256 + rand() % 8192);
		free(p);
		usleep(200);
	}
	return 0;
}

static volatile sig_atomic_t go;
static void on_usr1(int) { go = 1; }

int main()
{
	setvbuf(stdout, 0, _IOLBF, 0);
	signal(SIGUSR1, on_usr1);
	pthread_t th;
	pthread_create(&th, 0, churn, 0);
	if (getenv("MHP_T_WAIT")) {
		puts("waiting");
		while (!go)
			poll(0, 0, 100); // with a timeout: the signal may arrive just before poll is entered
	}
	t_malloc();
	t_calloc();
	t_realloc();
	t_posix_memalign();
	t_aligned_alloc();
	t_memalign();
	t_new();
	t_new_array();
	t_new_nothrow();
	t_new_aligned();
	t_new_aligned_nothrow();
	t_mmap();
	t_reserve();
	t_freed_malloc();
	t_freed_new();
	t_freed_sized();
	t_freed_aligned();
	t_new_freed_by_free();
	t_munmap();
	t_bad_alloc();
	t_small();
	puts("done");
	for (;;)
		poll(0, 0, -1);
}
