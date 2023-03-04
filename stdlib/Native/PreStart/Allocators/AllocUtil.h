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
    _Dai_Src_Info info;
} _Dai_Alloc_Request;

// Output
typedef struct {
    char* mem;
    size_t size;
} _Dai_Slice;

#define _DAI_ALLOC_ARGS(type) \
    ((_Dai_Alloc_Request){sizeof(type), _DAI_ALIGNOF(type), (_Dai_Src_Info){_DAI_SRC_INFO}})

/*************/
/* Alignment */
/*************/

#define _DAI_ALLOC_ALIGNMENT _DAI_ALIGNOF(max_align_t)

_DAI_FN size_t
_Dai_Alignment_roundUp(size_t n, size_t alignment) {
    if (alignment == 1) return n;
    _DAI_SANE_ASSERT((alignment % 2) == 0,
                     "The alignment passed to _Dai_Alignment_roundUp() must be a multiple of two.");
    return (n + alignment - 1) & -alignment;
}

_DAI_FN size_t
_Dai_align(size_t n) {
    return _Dai_Alignment_roundUp(n, _DAI_ALLOC_ALIGNMENT);
}

#endif /* _DAI_STDLIB_ALLOCUTIL */
