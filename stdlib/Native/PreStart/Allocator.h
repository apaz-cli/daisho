#pragma once
#ifndef __DAI_STDLIB_ALLOCATOR
#define __DAI_STDLIB_ALLOCATOR
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

/******************/
/* Error Handling */
/******************/

#define __DAI_KILOBYTE (1024L)
#define __DAI_MEGABYTE (1024L * 1024L)
#define __DAI_GIGABYTE (1024L * 1024L * 1024L)
#define __DAI_TERABYTE (1024L * 1024L * 1024L * 1024L)

#define __DAI_ALLOC_ALIGNMENT __DAI_ALIGNOF(max_align_t)

/* Only works for multiples of 2 */
__DAI_FN size_t
__Dai_Alignment_roundUp(size_t n, size_t alignment) {
    if (__DAI_SANITY_CHECK && ((alignment % 2) != 0)) __DAI_SANITY_FAIL();
    return (n + alignment - 1) & -alignment;
}

__DAI_FN size_t
__Dai_align(size_t n) {
    return __Dai_Alignment_roundUp(n, __DAI_ALLOC_ALIGNMENT);
}

/* Decide what to do with these in the future. */
__DAI_FN void*
__Dai_malloc(size_t size, __DAI_SRC_INFO_ARGS) {
    if (__DAI_SANITY_CHECK) {
        /* Pass through OOM error. */
        void* ret = malloc(size);
        if (!ret) __Dai_default_OOM(__DAI_SRC_INFO_PASS);
        return ret;
    } else {
        __DAI_SRC_INFO_IGNORE();
        return malloc(size);
    }
}

__DAI_FN void*
__Dai_realloc(void* ptr, size_t size, __DAI_SRC_INFO_ARGS) {
    if (__DAI_SANITY_CHECK) {
        void* ret = realloc(ptr, size);
        if (!ret) __Dai_default_OOM(__DAI_SRC_INFO_PASS);
        return ret;
    } else {
        __DAI_SRC_INFO_IGNORE();
        return realloc(ptr, size);
    }
}

__DAI_FN void*
__Dai_calloc(size_t num, size_t size, __DAI_SRC_INFO_ARGS) {
#if __DAI_SANITY_CHECK
    if (!num)
        __DAI_ERROR((char*)"Argument \"num\" to calloc() cannot be zero.");
    else if (!size)
        __DAI_ERROR((char*)"Argument \"size\" to calloc() cannot be zero.");
#else
    __DAI_SRC_INFO_IGNORE();
#endif

    void* result = calloc(num, size);

#if __DAI_SANITY_CHECK
    if (!result) __Dai_default_OOM(__DAI_SRC_INFO_PASS);
#endif
    return result;
}

__DAI_FN void
__Dai_free(void* ptr, __DAI_SRC_INFO_ARGS) {
    __DAI_SRC_INFO_IGNORE();
    free(ptr);
}

__DAI_FN void*
__Dai_originalMalloc(size_t size) {
    return malloc(size);
}
__DAI_FN void*
__Dai_originalRealloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}
__DAI_FN void*
__Dai_originalCallloc(size_t num, size_t size) {
    return calloc(num, size);
}
__DAI_FN void
__Dai_originalFree(void* ptr) {
    free(ptr);
}

#define __DAI_MALLOC(size) __Dai_malloc(size, __DAI_SRC_INFO)
#define __DAI_REALLOC(ptr, size) __Dai_realloc(ptr, size, __DAI_SRC_INFO)
#define __DAI_CALLOC(num, size) __Dai_calloc(num, size, __DAI_SRC_INFO)
#define __DAI_FREE(ptr) __Dai_free(ptr, __DAI_SRC_INFO)

#endif /* __DAI_STDLIB_ALLOCATOR */
