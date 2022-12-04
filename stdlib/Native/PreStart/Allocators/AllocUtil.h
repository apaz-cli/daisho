#ifndef _DAI_STDLIB_ALLOCUTIL
#define _DAI_STDLIB_ALLOCUTIL
#include "../Error.h"


#define _DAI_KILOBYTE (1024L)
#define _DAI_MEGABYTE (1024L * 1024L)
#define _DAI_GIGABYTE (1024L * 1024L * 1024L)
#define _DAI_TERABYTE (1024L * 1024L * 1024L * 1024L)

#define _DAI_ALLOC_ALIGNMENT _DAI_ALIGNOF(max_align_t)

typedef struct {
    char* mem;
    size_t size;
} _Dai_Slice;

/* Only works for multiples of 2 */
_DAI_FN size_t
_Dai_Alignment_roundUp(size_t n, size_t alignment) {
    _DAI_SANE_ASSERT((alignment % 2) == 0, "The alignment passed to _Dai_Alignment_roundUp() must be a multiple of two.");
    return (n + alignment - 1) & -alignment;
}

_DAI_FN size_t
_Dai_align(size_t n) {
    return _Dai_Alignment_roundUp(n, _DAI_ALLOC_ALIGNMENT);
}

#endif /* _DAI_STDLIB_ALLOCUTIL */
