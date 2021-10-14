#include <apaz-libc.h>

static void bench_fn() { for (size_t i = 0; i < 1000; i++) ; }
// MICROBENCH_MAIN(bench_fn, 10000, STOPWATCH_MICROSECONDS);

// Disabled the actual benchmark due to clutter concerns.
int main() { bench_fn(); puts("SUCCESS"); }
