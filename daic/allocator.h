#ifndef DAIC_ALLOCATOR_INCLUDE
#define DAIC_ALLOCATOR_INCLUDE

#define _DAIC_MALLOC(n) malloc(n)
#define _DAIC_REALLOC(ptr, n) realloc(ptr, n)
#define _DAIC_FREE(n) free(n)

#endif /* DAIC_ALLOCATOR_INCLUDE */
