#ifndef DAIC_ALLOCATOR_INCLUDE
#define DAIC_ALLOCATOR_INCLUDE

#if !defined(_DAIC_LEAK_EVERYTHING)
#define _DAIC_LEAK_EVERYTHING 0
#endif

#if !_DAIC_LEAK_EVERYTHING

#define _DAIC_MALLOC(n) malloc(n)
#define _DAIC_REALLOC(ptr, n) realloc(ptr, n)
#define _DAIC_FREE(n) free(n)
#define _DAIC_FREE_FPTR free

#else /* _DAIC_LEAK_EVERYTHING */

#define _DAIC_MALLOC(n) malloc(n)
#define _DAIC_REALLOC(ptr, n) realloc(ptr, n)
#define _DAIC_FREE(n) free(n)
#define _DAIC_FREE_FPTR free

#endif /* _DAIC_LEAK_EVERYTHING */

#endif /* DAIC_ALLOCATOR_INCLUDE */
