 /************************************************************************
 * Feel free to change the constants in this file.                       *
 *                                                                       *
 * Do not include any stdlib files inside this header. Doing so has the  *
 * potential to break the Python runtime. Please only change configs.    *
 ************************************************************************/
#pragma once
#ifndef __STILTS_STDLIB_CONFIG
#define __STILTS_STDLIB_CONFIG

/*
 * Controls whether to include Python.h. Wrapped because it's usually
 * declared on the command line by stiltc.
 */
#ifndef __STILTS_EMBED_PYTHON
#define __STILTS_EMBED_PYTHON 0
#endif

/*
 * 0 - No sanity checks. Difficult to debug, but very fast.
 * 1 - Default behavior. Sanity checks are performed.
 * 2 - Pedantic sanity checks. Slow, but good for debugging.
 */
#define __STILTS_SANITY_CHECK 1

/*
 * 0 - Default behavior, __Stilts_malloc() is malloc(), etc.
 * 1 - Wrap __Stilts_malloc(), __Stilts_calloc(), __Stilts_realloc(),
 * and __Stilts_free() for additional sanity checks.
 */
#define __STILTS_MEMDEBUG 1

/*
 * The size of pages of memory returned by the operating system. Good
 * to know for optimization's sake, but an incorrect value won't break
 * anything.
 */
#define __STILTS_PAGESIZE 4096

/*
 * The number of threads that Stilts should use for your system.
 */
#define __STILTS_IDEAL_NUM_THREADS 8


/*
 * 0 - All functions are static inline
 * 1 - All functions are extern
 */
#define __STILTS_EXTERNAL_FUNCTIONS 0

#define __STILTS_TEMP_ARENA_PAGES 8

#endif /* __STILTS_STDLIB_CONFIG */
