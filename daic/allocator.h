#ifndef DAIC_ALLOCATOR_INCLUDE
#define DAIC_ALLOCATOR_INCLUDE

#if !defined(_DAIC_LEAK_EVERYTHING)
#define _DAIC_LEAK_EVERYTHING 0
#endif

#if !_DAIC_LEAK_EVERYTHING

#define _DAIC_MALLOC(n) malloc(n)
#define _DAIC_REALLOC(p, n) realloc(p, n)
#define _DAIC_FREE(p) free(ptr)
#define _DAIC_FREE_FPTR free

#else /* _DAIC_LEAK_EVERYTHING */

static inline void
daic_nofree(void* p) {
    (void)p;
}

#define _DAIC_MALLOC(n) malloc(n)
#define _DAIC_REALLOC(p, n) realloc(p, n)
#define _DAIC_FREE(p) daic_nofree(ptr)
#define _DAIC_FREE_FPTR NULL
// Taking the address of nofree could cause it not to be optimized away

#endif /* _DAIC_LEAK_EVERYTHING */

#endif /* DAIC_ALLOCATOR_INCLUDE */
