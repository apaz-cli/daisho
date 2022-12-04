#pragma once
#ifndef _DAI_STDLIB_MALLOCATOR
#define _DAI_STDLIB_MALLOCATOR
#include "../../PreProcessor/PreProcessor.h"
#include "AllocUtil.h"

/******************/
/* Error Handling */
/******************/

/* Decide what to do with these in the future. */
_DAI_FN void*
_Dai_malloc(size_t size, _DAI_SRC_INFO_ARGS) {
    if (_DAI_SANE) {
        /* Pass through OOM error. */
        void* ret = malloc(size);
        if (!ret) _DAI_OOM();
        return ret;
    } else {
        _DAI_SRC_INFO_IGNORE();
        return malloc(size);
    }
}

_DAI_FN void*
_Dai_realloc(void* ptr, size_t size, _DAI_SRC_INFO_ARGS) {
    if (_DAI_SANE) {
        void* ret = realloc(ptr, size);
        if (!ret) _DAI_OOM();
        return ret;
    } else {
        _DAI_SRC_INFO_IGNORE();
        return realloc(ptr, size);
    }
}

_DAI_FN void*
_Dai_calloc(size_t num, size_t size, _DAI_SRC_INFO_ARGS) {
    _DAI_PEDANTIC_ASSERT(num, "Argument \"num\" to calloc() cannot be zero.");
    _DAI_PEDANTIC_ASSERT(size, "Argument \"size\" to calloc() cannot be zero.");

    _DAI_SRC_INFO_IGNORE();

    void* result = calloc(num, size);
    _DAI_SANE_OOMCHECK(result);

    return result;
}

_DAI_FN void
_Dai_free(void* ptr, _DAI_SRC_INFO_ARGS) {
    _DAI_SRC_INFO_IGNORE();
    free(ptr);
}

_DAI_FN void*
_Dai_originalMalloc(size_t size) {
    return malloc(size);
}
_DAI_FN void*
_Dai_originalRealloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}
_DAI_FN void*
_Dai_originalCallloc(size_t num, size_t size) {
    return calloc(num, size);
}
_DAI_FN void
_Dai_originalFree(void* ptr) {
    free(ptr);
}

#define _DAI_MALLOC(size) _Dai_malloc(size, _DAI_SRC_INFO)
#define _DAI_REALLOC(ptr, size) _Dai_realloc(ptr, size, _DAI_SRC_INFO)
#define _DAI_CALLOC(num, size) _Dai_calloc(num, size, _DAI_SRC_INFO)
#define _DAI_FREE(ptr) _Dai_free(ptr, _DAI_SRC_INFO)

#endif /* _DAI_STDLIB_MALLOCATOR */
