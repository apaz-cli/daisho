#ifndef STILTS_STDLIB_TEMPALLOC
#define STILTS_STDLIB_TEMPALLOC
#include "../StiltsStdInclude.h"

#include "StiltsAllocator.h"

#define __STILTS_TEMP_ARENA_PAGES 8
#define __STILTS_TEMP_ARENA_SIZE \
       (__STILTS_TEMP_ARENA_PAGES * __STILTS_PAGESIZE)


static size_t __Stilts_temp_offset = 0;
static char __Stilts_temp_arena[__STILTS_TEMP_ARENA_SIZE];

static inline void* __Stilts_temp_malloc(size_t n) {
  if (n > STILTS_TEMP_ARENA_SIZE) return NULL;

  size_t next = __Stilts_temp_offset + n;
  if (next >= STILTS_TEMP_ARENA_SIZE) {
    __Stilts_temp_offset = 0;
    return __Stilts_temp_arena;
  } else {
    void* ret = __Stilts_temp_arena + __Stilts_temp_offset;
    __Stilts_temp_offset = next;
    return ret;
  }
}

static inline void* __Stilts_temp_realloc(void* ptr, size_t n) {
  /* No realloc. */
  assert(false);
}

static inline void  __Stilts_temp_free(void* ptr) {
  /* No content */
}

/* Reallocates on the heap with stilts_malloc(). */
static inline void* __Stilts_temp_realize(void* ptr, size_t n) {

}

#endif /* STILTS_STDLIB_TEMPALLOC */
