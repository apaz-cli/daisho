#pragma once
#ifndef __DAI_STDLIB_MALLOCATOR
#define __DAI_STDLIB_MALLOCATOR
#include "../../PreProcessor/PreProcessor.h"
#include "AllocUtil.h"

/******************/
/* Error Handling */
/******************/

/* Decide what to do with these in the future. */
__DAI_FN void*
__Dai_malloc(size_t size, __DAI_SRC_INFO_ARGS) {
    if (__DAI_SANITY_CHECK) {
        /* Pass through OOM error. */
        void* ret = malloc(size);
        if (!ret) __DAI_OOM();
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
        if (!ret) __DAI_OOM();
        return ret;
    } else {
        __DAI_SRC_INFO_IGNORE();
        return realloc(ptr, size);
    }
}

__DAI_FN void*
__Dai_calloc(size_t num, size_t size, __DAI_SRC_INFO_ARGS) {
    __DAI_PEDANTIC_ASSERTMSG(num, "Argument \"num\" to calloc() cannot be zero.");
    __DAI_PEDANTIC_ASSERTMSG(size, "Argument \"size\" to calloc() cannot be zero.");

    __DAI_SRC_INFO_IGNORE();

    void* result = calloc(num, size);
    __DAI_SANE_OOMCHECK(result);
    
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

#endif /* __DAI_STDLIB_MALLOCATOR */
