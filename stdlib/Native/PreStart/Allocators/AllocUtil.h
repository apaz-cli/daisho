#ifndef __DAI_STDLIB_ALLOCUTIL
#define __DAI_STDLIB_ALLOCUTIL
#include "../Error.h"


#define __DAI_KILOBYTE (1024L)
#define __DAI_MEGABYTE (1024L * 1024L)
#define __DAI_GIGABYTE (1024L * 1024L * 1024L)
#define __DAI_TERABYTE (1024L * 1024L * 1024L * 1024L)

#define __DAI_ALLOC_ALIGNMENT __DAI_ALIGNOF(max_align_t)

typedef struct {
    char* mem;
    size_t size;
} __Dai_Slice;

/* Only works for multiples of 2 */
__DAI_FN size_t
__Dai_Alignment_roundUp(size_t n, size_t alignment) {
    __DAI_PEDANTIC_ASSERT((alignment % 2) == 0, "The alignment passed to __Dai_Alignment_roundUp() must be a multiple of two.");
    return (n + alignment - 1) & -alignment;
}

__DAI_FN size_t
__Dai_align(size_t n) {
    return __Dai_Alignment_roundUp(n, __DAI_ALLOC_ALIGNMENT);
}

#endif /* __DAI_STDLIB_ALLOCUTIL */
