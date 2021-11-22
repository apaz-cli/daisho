
/*
 * 0 - No sanity checks. Difficult to debug, but very fast.
 * 1 - Default behavior. Sanity checks are performed.
 */
#define __STILTS_SANITY_CHECK 1

/*
 * 0 - Default behavior.
 * 1 - Wrap __Stilts_malloc(), __Stilts_realloc(), and __Stilts_free() in a
 * macro for sanity checks.
 */
#define __STILTS_MEMDEBUG 1

/*
 * Wraps malloc(), realloc(), and free() in a macro which redirects to
 * __Stilts_malloc(), __Stilts_realloc(), and __Stilts_free().
 * Everything already calls __Stilts_malloc() and friends directly, 
 * so this only affects user code.
 */
#define __STILTS_WRAP_MEMALLOCS 1

/*
 * When sanity checks are enabled, describes what to do when 
 */
#define __STILTS_HANDLE_OOM(line, func, file) \
    __Stilts_default_OOM(__FILE__, __LINE__, __func__)

#define __STILTS_HANDLE_FAILED_SANITY_CHECK() \
    __Stilts_default_sanity_check_fail(__FILE__, __LINE__, __func__)

#define __STILTS_PAGESIZE 4096

#define __STILTS_TEMP_ARENA_PAGES 8

#define __STILTS_IDEAL_NUM_THREADS 8
