#include <apaz-libc.h>

#define NITS 1000

int
popt(void) {
    Arena a = Arena_new("popt");
    for (size_t i = 0; i < 50; i++) Arena_malloc(&a, i);
    for (size_t i = 50; i-- > 0;) {
        Arena_pop(&a, i);
    }
    size_t ret = a.buf_size;
    Arena_destroy(&a, false, true);

    return (int)ret | (int)get_num_allocs();
}

int
sar(void) {
    size_t asize = ARENA_SIZE;
    Arena* a = (Arena*)malloc(sizeof(Arena));
    char buffer[asize];
    Arena_init(a, "sar", buffer, asize);

    for (size_t i = 0; i < NITS; i++) Arena_malloc(a, i);
    Arena_destroy(a, true, false);
    return (int)get_num_allocs();
}

int
har(void) {
    Arena a = Arena_new("har");

    for (size_t i = 0; i < NITS; i++) Arena_malloc(&a, i);
    Arena_destroy(&a, false, true);
    return (int)get_num_allocs();
}

int
nar(void) {
    size_t asize = 10000;
    Arena a;
    char buffer[asize];
    Arena_init(&a, "nar", buffer, asize);

    for (size_t i = 0; i < NITS; i++) Arena_malloc(&a, i);
    Arena_destroy(&a, false, false);
    return (int)get_num_allocs();
}

int
bar(void) {
    size_t asize = ARENA_SIZE;
    Arena* a = (Arena*)malloc(sizeof(Arena));
    void* buf = malloc(asize);
    Arena_init(a, "bar", buf, asize);

    for (size_t i = 0; i < NITS; i++) Arena_malloc(a, i);
    Arena_destroy(a, true, true);
    return (int)get_num_allocs();
}

int
main(void) {
    if (sar()) return 1;
    if (har()) return 2;
    if (bar()) return 3;
    if (nar()) return 4;
    if (popt()) return 5;
    puts("SUCCESS");
    return 0;
}
