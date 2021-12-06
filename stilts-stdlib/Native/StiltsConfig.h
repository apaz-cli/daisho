/************************************************************************
 * Do not include any stdlib files inside this header. Doing so has the *
 * potential to break the Python runtime.                               *
 ************************************************************************/
#ifndef __STILTS_STDLIB_CONFIG
#define __STILTS_STDLIB_CONFIG

/*
 * 0 - No sanity checks. Difficult to debug, but very fast.
 * 1 - Default behavior. Sanity checks are performed.
 */
#define __STILTS_SANITY_CHECK 1

/*
 * 0 - Default behavior.
 * 1 - Wrap __Stilts_malloc(), __Stilts_realloc(), and __Stilts_free() for
 * additional sanity checks.
 */
#define __STILTS_MEMDEBUG 1

/*
 * Wraps malloc(), realloc(), and free() in a macro which redirects to
 * __Stilts_malloc(), __Stilts_realloc(), and __Stilts_free().
 * Everything already calls __Stilts_malloc() and friends directly,
 * so this only affects user code.
 */
#define __STILTS_WRAP_MEMALLOCS 1

#define __STILTS_PAGESIZE 4096

#define __STILTS_TEMP_ARENA_PAGES 8

#define __STILTS_IDEAL_NUM_THREADS 8

#define __STILTS_EMBED_PYTHON 0

#endif /* __STILTS_STDLIB_CONFIG */