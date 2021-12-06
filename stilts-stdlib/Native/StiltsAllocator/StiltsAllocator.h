#pragma once
#ifndef __STILTS_STDLIB_ALLOCATOR
#define __STILTS_STDLIB_ALLOCATOR
#include "../StiltsStdInclude.h"

/******************/
/* Error Handling */
/******************/



/* Decide what to do with these in the future. */
static inline void*
__Stilts_malloc(size_t size, __STILTS_SRC_INFO_ARGS) {
    if (__STILTS_SANITY_CHECK) {
        void* ret = malloc(size);
        if (!ret) __Stilts_default_OOM(__STILTS_SRC_INFO_PASS);
        return ret;
    } else {
        __STILTS_SRC_INFO_IGNORE();
        return malloc(size);
    }
}
static inline void*
__Stilts_realloc(void* ptr, size_t size, __STILTS_SRC_INFO_ARGS) {
    if (__STILTS_SANITY_CHECK) {
        void* ret = realloc(ptr, size);
        if (!ret) __Stilts_default_OOM(__STILTS_SRC_INFO_PASS);
        return ret;
    } else {
        __STILTS_SRC_INFO_IGNORE();
        return realloc(ptr, size);
    }
}
static inline void
__Stilts_free(void* ptr, __STILTS_SRC_INFO_ARGS) {
    __STILTS_SRC_INFO_IGNORE();
    free(ptr);
}

#endif /* __STILTS_STDLIB_ALLOCATOR */
