#ifndef _DAI_STDLIB_ALLOCUTIL
#define _DAI_STDLIB_ALLOCUTIL
#include "../Error.h"

#define _DAI_KILOBYTE (1024L)
#define _DAI_MEGABYTE (1024L * 1024L)
#define _DAI_GIGABYTE (1024L * 1024L * 1024L)
#define _DAI_TERABYTE (1024L * 1024L * 1024L * 1024L)

/*****************/
/* Allocator API */
/*****************/

// Input
typedef struct {
    size_t min_size;
    size_t alignment;
} _Dai_Alloc_Layout;

// Output
typedef struct {
    char* buf;
    size_t size;
} _Dai_Slice;

#if _DAI_MEMDEBUG
#define _DAI_ALLOC_INFO_AT , _DAI_SRC_INFO
#define _DAI_ALLOC_INFO_PASS_AT , _DAI_SRC_INFO_PASS
#define _DAI_ALLOC_INFO_ARGS , _DAI_SRC_INFO_ARGS
#define _DAI_ALLOC_OOM() _Dai_OOM(_DAI_SRC_INFO_PASS)
#define _DAI_ALLOC_INFO_ARGS_INNER() _DAI_SRC_INFO_IGNORE()
#define _DAI_ALLOC_ARGS(type) \
    (_Dai_Alloc_Layout){sizeof(type), _DAI_ALIGNOF(type)}, (_Dai_Src_Info) { _DAI_SRC_INFO }
#else
#define _DAI_ALLOC_INFO_AT
#define _DAI_ALLOC_INFO_PASS_AT
#define _DAI_ALLOC_INFO_ARGS
#define _DAI_ALLOC_OOM() _Dai_OOM(_DAI_SRC_INFO)
#define _DAI_ALLOC_INFO_ARGS_INNER()
#define _DAI_ALLOC_ARGS(type) \
    (_Dai_Alloc_Layout) { sizeof(type), _DAI_ALIGNOF(type) }
#endif

#define _DAI_ALLOC_ALLOCATE_DEFINITION(fnname) \
    _DAI_FN _Dai_Slice fnname(void* allocator, _Dai_Alloc_Layout layout _DAI_ALLOC_INFO_ARGS)
#define _DAI_ALLOC_REALLOCATE_DEFINITION(void, fnname)                                  \
    _DAI_FN _Dai_Slice fnname(void* allocator, void* ptr, _Dai_Alloc_Layout old_layout, \
                              _Dai_Alloc_Layout new_layout _DAI_ALLOC_INFO_ARGS)
#define _DAI_ALLOC_FREE_DEFINITION(void, fnname)          \
    _DAI_FN _Dai_Slice fnname(void* allocator, void* ptr, \
                              _Dai_Alloc_Layout layout _DAI_ALLOC_INFO_ARGS)

/*************/
/* Alignment */
/*************/

#define _DAI_ALLOC_ALIGNMENT _DAI_ALIGNOF(max_align_t)

_DAI_FN size_t
_Dai_alignment_roundUp(size_t n, size_t alignment) {
    _DAI_PEDANTIC_ASSERT((alignment % 2) == 0,
                         "The alignment passed to _Dai_Alignment_roundUp() "
                         "must be a multiple of two.");

    if (alignment == 1) return n;
    if (n == 0) return alignment;
    return (n + alignment - 1) & -alignment;
}

_DAI_FN size_t
_Dai_align_max(size_t n) {
    return _Dai_alignment_roundUp(n, _DAI_ALLOC_ALIGNMENT);
}

#endif /* _DAI_STDLIB_ALLOCUTIL */
