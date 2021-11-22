#ifndef __STILTS_STDLIB_ALLOCATOR
#define __STILTS_STDLIB_ALLOCATOR
#include "../StiltsStdInclude.h"

/******************/
/* Error Handling */
/******************/

#define __STILTS_SRC_INFO __LINE__, __func__, __FILE__
#define __STILTS_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define __STILTS_SRC_INFO_PASS line, func, file
#define __STILTS_SRC_INFO_IGNORE() \
    (void)line;                    \
    (void)func;                    \
    (void)file;

static inline void
__Stilts_default_OOM(__STILTS_SRC_INFO_ARGS) {
    fprintf(stderr, "OUT OF MEMORY AT: %s:%zu inside %s().\n", file, line, func);
    exit(23);
}

static inline void
__Stilts_default_sanity_check_fail(__STILTS_SRC_INFO_ARGS) {
    fprintf(stderr, "FAILED SANITY CHECK AT: %s:%zu inside %s().\n", file, line, func);
    exit(24);
}

/* Decide what to do with these in the future. */
static inline void*
__Stilts_malloc(size_t size, __STILTS_SRC_INFO_ARGS) {
    __STILTS_SRC_INFO_IGNORE();
    return malloc(size);
}
static inline void*
__Stilts_realloc(void* ptr, size_t size, __STILTS_SRC_INFO_ARGS) {
    __STILTS_SRC_INFO_IGNORE();
    return realloc(ptr, size);
}
static inline void
__Stilts_free(void* ptr, __STILTS_SRC_INFO_ARGS) {
    __STILTS_SRC_INFO_IGNORE();
    free(ptr);
}

#endif /* __STILTS_STDLIB_ALLOCATOR */
