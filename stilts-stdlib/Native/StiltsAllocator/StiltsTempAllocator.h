#ifndef STILTS_STDLIB_TEMPALLOC
#define STILTS_STDLIB_TEMPALLOC
#include "../StiltsStdInclude.h"
#include "StiltsAllocator.h"

#define __STILTS_TEMP_ARENA_SIZE (__STILTS_TEMP_ARENA_PAGES * __STILTS_PAGESIZE)

static size_t __Stilts_temp_offset = 0;
static char __Stilts_temp_arena[__STILTS_TEMP_ARENA_SIZE];

static inline void*
__Stilts_temp_malloc(size_t n) {
#if __STILTS_SANITY_CHECK
    if (n > __STILTS_TEMP_ARENA_SIZE) return NULL;
#endif
    size_t next = __Stilts_temp_offset + n;
    if (next >= __STILTS_TEMP_ARENA_SIZE) {
        __Stilts_temp_offset = 0;
        return __Stilts_temp_arena;
    } else {
        void* ret = __Stilts_temp_arena + __Stilts_temp_offset;
        __Stilts_temp_offset = next;
        return ret;
    }
}

/* Reallocates on the heap with stilts_malloc(). */
static inline void*
__Stilts_temp_realize(void* ptr, size_t n, size_t line, const char* func,
                      const char* file) {
    void* buf = __Stilts_malloc(n, line, func, file);
    memcpy(buf, ptr, n);
    return buf;
}

#endif /* STILTS_STDLIB_TEMPALLOC */
