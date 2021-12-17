 /***********************************************************************\
 * Feel free to change the constants in this file. Incompatible values   *
 * will be caught at compile time.                                       *
 *                                                                       *
 * Do not include any files inside this header. Doing so has the         *
 * potential to break the Python runtime. Please only change configs.    *
 \***********************************************************************/

#pragma once
#ifndef __STILTS_STDLIB_CONFIG
#define __STILTS_STDLIB_CONFIG

/*
 * 0 - Don't embed Python
 * 1 - Embed Python (default)
 *
 * Can be declared by stiltc as a flag to the C compiler.
 * Use stiltc flags to control this. Passing neither uses
 * the default below.
 *
 * --no-python specifies 0.
 * --python    specifies 1.
 */
#ifndef __STILTS_EMBED_PYTHON
#define __STILTS_EMBED_PYTHON 0
#endif

/*
 * 0 - No sanity checks. Difficult to debug, but very fast.
 * 1 - Basic sanity checks are performed. (default)
 * 2 - Pedantic sanity checks. Slow, but good for debugging.
 *
 * Can be declared by stiltc as a flag to the C compiler.
 * Use stiltc flags to control this. Passing neither uses
 * the default below.
 *
 * --insane   specifies 0.
 * --sane     specifies 1.
 * --pedantic specifies 2.
 */
#ifndef __STILTS_SANITY_CHECK
#define __STILTS_SANITY_CHECK 1
#endif

/*
 * 0 - No memory debugging. (default)
 * 1 - Memory debugging.
 * 2 - Memory debugging, and print all allocations and frees to stderr.
 *
 * When memory debugging is turned on, __Stilts_malloc(),
 * __Stilts_calloc(), __Stilts_realloc(), and __Stilts_free()
 * are wrapped for additional sanity checks.
 *
 * For example, trying to __Stilts_realloc() or __Stilts_free()
 * a pointer not allocated by one of the other wrapped functions
 * (including by normal malloc()) causes a crash and prints debugging
 * information to stderr about exactly where the invalid free happened.
 *
 * You can also use __Stilts_heap_dump() to print a summary to stderr
 * of all tracked memory allocations and where they happened.
 *
 * Can be declared by stiltc as a flag to the C compiler.
 * Use stiltc flags to control this. Passing neither uses
 * the default below.
 *
 * --no-memdebug    specifies 0.
 * --memdebug       specifies 1.
 * --memdebug-print specifies 2.
 */
#ifndef __STILTS_MEMDEBUG
#define __STILTS_MEMDEBUG 0
#endif

/*
 * 0 - Do not replace malloc().
 * 1 - Replace malloc() (default)
 *
 * Replaces the memory allocator used by
 * __Stilts_malloc(), __Stilts_realloc(), __Stilts_calloc(), and __Stilts_free(),
 * and also wraps normal malloc(), realloc(), calloc(), and free() in a macro
 * redirecting to their __Stilts_ versions. This only works for the current
 * translation unit.
 *
 * This has multiple benefits. The custom memory allocator is faster. Also, in
 * combination with __STILTS_MEMDEBUG, this can be used to track down errors in
 * code not written by stiltc.
 *
 * When you use __STILTS_REPLACE_MEMDEBUG, be sure to always include Stilts.h
 * before including the file that provides malloc(), so that it can be wrapped
 * for the whole translation unit.
 *
 * Can be declared by stiltc as a flag to the C compiler.
 * Use stiltc flags to control this. Passing neither uses
 * the default below.
 *
 * --normal-malloc  specifies 0.
 * --replace-malloc specifies 1.
 */
#ifndef __STILTS_REPLACE_MALLOC
#define __STILTS_REPLACE_MALLOC 1
#endif

/*
 * The size of pages of memory returned by the operating system. Good
 * to know for optimization's sake, but an incorrect value won't break
 * anything. 4096 is the default on Linux.
 *
 * You can find out this number with:
 * $ getconf PAGESIZE
 */
#define __STILTS_PAGESIZE 4096

/*
 * The number of threads that Stilts should use for your system.
 * This is usually the number of logical CPUs, which is the number
 * of physical CPUs you have (Sockets), times the number of cores
 * on those physical CPUs, times the number of threads per core.
 *
 * You can find these numbers out with:
 * $ lscpu | grep -E '^Thread|^Core|^Socket|^CPU\('
 *
 * You should see something like:
 *
 * CPU(s):                8
 * Thread(s) per core:    2
 * Core(s) per socket:    4
 * Socket(s):             1
 */
#define __STILTS_IDEAL_NUM_THREADS 8

/*
 * 0 - All Stilts-managed functions are static inline.
 * 1 - All Stilts-managed functions have no modifiers.
 *
 * Be careful with ODR if you opt for no modifiers and
 * want to include Stilts.h in multiple compliation units.
 */
#define __STILTS_EXTERNAL_FUNCTIONS 0

/*
 * The maximum number of stack frames that Stilts can report in backtraces.
 */
#define __STILTS_BT_MAX_FRAMES 50

#endif /* __STILTS_STDLIB_CONFIG */
