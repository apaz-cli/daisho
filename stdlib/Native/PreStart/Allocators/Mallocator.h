#pragma once
#ifndef _DAI_STDLIB_MALLOCATOR
#define _DAI_STDLIB_MALLOCATOR
#include "../../PreProcessor/PreProcessor.h"
#include "../Error.h"
#include "AllocUtil.h"

/******************/
/* Error Handling */
/******************/

#define _DAI_MALLOC(size) _DAI_MALLOC_SLICE(size).buf
#define _DAI_MALLOC_SLICE(size) _Dai_malloc((_Dai_Alloc_Layout){size, 1} _DAI_ALLOC_INFO_AT)
#define _DAI_MALLOC_TYPE(type) _DAI_MALLOC_TYPE_SLICE(type).buf
#define _DAI_MALLOC_TYPE_SLICE(type) _Dai_malloc(_DAI_ALLOC_ARGS(type) _DAI_ALLOC_INFO_AT)

_DAI_FN _Dai_Slice
_Dai_malloc(_Dai_Alloc_Layout req _DAI_ALLOC_INFO_ARGS) {
    size_t size = _Dai_align_max(req.min_size);
    char* ret = (char*)malloc(size);
    if (_DAI_SANE && !ret) {
        _DAI_ALLOC_OOM();
    } else {
        _DAI_ALLOC_INFO_ARGS_INNER();
    }
    return (_Dai_Slice){ret, size};
}

#define _DAI_REALLOC(ptr, size) _Dai_realloc(ptr, size _DAI_ALLOC_INFO_AT)
_DAI_FN void*
_Dai_realloc(void* ptr, size_t size _DAI_ALLOC_INFO_ARGS) {
    void* ret = realloc(ptr, size);
    if (_DAI_SANE && !ret) {
        _DAI_ALLOC_OOM();
    } else {
        _DAI_ALLOC_INFO_ARGS_INNER();
    }
    _DAI_ALLOC_INFO_ARGS_INNER();
    return ret;
}

#define _DAI_FREE(ptr) _Dai_free(ptr _DAI_ALLOC_INFO_AT)
_DAI_FN void
_Dai_free(void* ptr _DAI_ALLOC_INFO_ARGS) {
    _DAI_ALLOC_INFO_ARGS_INNER();
    free(ptr);
}

#endif /* _DAI_STDLIB_MALLOCATOR */
