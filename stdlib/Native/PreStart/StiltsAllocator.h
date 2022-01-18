#pragma once
#ifndef __STILTS_STDLIB_ALLOCATOR
#define __STILTS_STDLIB_ALLOCATOR
#include "../PreProcessor/StiltsPreprocessor.h"
#include "StiltsError.h"

/******************/
/* Error Handling */
/******************/

#define __STILTS_KILOBYTE (1024L)
#define __STILTS_MEGABYTE (1024L * 1024L)
#define __STILTS_GIGABYTE (1024L * 1024L * 1024L)
#define __STILTS_TERABYTE (1024L * 1024L * 1024L * 1024L)

#define __STILTS_ALLOC_ALIGNMENT __STILTS_ALIGNOF(max_align_t)

/* Only works for multiples of 2 */
__STILTS_FN size_t
__Stilts_Alignment_roundUp(size_t n, size_t alignment) {
    if (__STILTS_SANITY_CHECK && ((alignment % 2) != 0)) __STILTS_SANITY_FAIL();
    return (n + alignment - 1) & -alignment;
}

__STILTS_FN size_t
__Stilts_align(size_t n) {
    return __Stilts_Alignment_roundUp(n, __STILTS_ALLOC_ALIGNMENT);
}

/* Decide what to do with these in the future. */
__STILTS_FN void*
__Stilts_malloc(size_t size, __STILTS_SRC_INFO_ARGS) {
    if (__STILTS_SANITY_CHECK) {
        /* Pass through OOM error. */
        void* ret = malloc(size);
        if (!ret) __Stilts_default_OOM(__STILTS_SRC_INFO_PASS);
        return ret;
    } else {
        __STILTS_SRC_INFO_IGNORE();
        return malloc(size);
    }
}

__STILTS_FN void*
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

__STILTS_FN void*
__Stilts_calloc(size_t num, size_t size, __STILTS_SRC_INFO_ARGS) {
#if __STILTS_SANITY_CHECK
    if (!num)
        __STILTS_ERROR((char*)"Argument \"num\" to calloc() cannot be zero.");
    else if (!size)
        __STILTS_ERROR((char*)"Argument \"size\" to calloc() cannot be zero.");
#else
    __STILTS_SRC_INFO_IGNORE();
#endif

    void* result = calloc(num, size);

#if __STILTS_SANITY_CHECK
    if (!result) __Stilts_default_OOM(__STILTS_SRC_INFO_PASS);
#endif
    return result;
}

__STILTS_FN void
__Stilts_free(void* ptr, __STILTS_SRC_INFO_ARGS) {
    __STILTS_SRC_INFO_IGNORE();
    free(ptr);
}

__STILTS_FN void*
__Stilts_originalMalloc(size_t size) {
    return malloc(size);
}
__STILTS_FN void*
__Stilts_originalRealloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}
__STILTS_FN void*
__Stilts_originalCallloc(size_t num, size_t size) {
    return calloc(num, size);
}
__STILTS_FN void
__Stilts_originalFree(void* ptr) {
    free(ptr);
}

#define __STILTS_MALLOC(size) __Stilts_malloc(size, __STILTS_SRC_INFO)
#define __STILTS_REALLOC(ptr, size) __Stilts_realloc(ptr, size, __STILTS_SRC_INFO)
#define __STILTS_CALLOC(num, size) __Stilts_calloc(num, size, __STILTS_SRC_INFO)
#define __STILTS_FREE(ptr) __Stilts_free(ptr, __STILTS_SRC_INFO)

#endif /* __STILTS_STDLIB_ALLOCATOR */
