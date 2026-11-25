#define _GNU_SOURCE
/* Small target for libmhp: 4 threads, one leaking ~1 MiB/s, others churning. */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline)) void *leaky_cache_insert(size_t n) { void *p = malloc(n); memset(p, 1, n); return p; }
static __thread void *volatile sink;
__attribute__((noinline)) void churn_buffer(void) { sink = malloc(4096 + rand() % 65536); memset(sink, 0, 64); free(sink); }
__attribute__((noinline)) void *big_pool(void) { return mmap(0, 64 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }

static void *leaker(void *a) { (void)a; for (;;) { leaky_cache_insert(16384); usleep(16000); } }
static void *churner(void *a) { (void)a; for (;;) { for (int i = 0; i < 1000; i++) churn_buffer(); usleep(1000); } }

int main(void)
{
	pthread_t t;
	big_pool();
	pthread_create(&t, 0, leaker, 0);
	pthread_setname_np(t, "leaker");
	for (int i = 0; i < 3; i++) { pthread_create(&t, 0, churner, 0); pthread_setname_np(t, "churner"); }
	pause();
}
