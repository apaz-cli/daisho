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

/* Generated from the configure script. */
#include "StiltsGeneratedConfig.h"

/*
 * 0 - Don't embed Python (default if python is not configured)
 * 1 - Embed Python       (default if python is configured)
 *
 * Can be declared by stiltc as a flag to the C compiler.
 * Use stiltc flags to control this. Passing neither uses
 * the default below.
 *
 * --no-python specifies 0.
 * --python    specifies 1.
 */
#ifndef __STILTS_EMBED_PYTHON
#define __STILTS_EMBED_PYTHON __SILTS_HAS_PYTHON
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
 * __Stilts_malloc(), __Stilts_realloc(), __Stilts_calloc(), and
 * __Stilts_free(), and also wraps normal malloc(), realloc(), calloc(), and
 * free() in a macro redirecting to their __Stilts_ versions. This only works
 * for the current translation unit.
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
 * The maximum number of stack frames that can be backtraced through.
 * If backtraces are not enabled, this has no effect.
 *
 * If this number is smaller than the number of stack frames to report,
 * then the newest ones are reported.
 */
#define __STILTS_BT_MAX_FRAMES 128

/* 
 * 2 - Fully buffered
 * 1 - Line Buffered (default)
 * 0 - Unbuffered
 */
#define __STILTS_OUTPUT_BUFFERING 2

#endif /* __STILTS_STDLIB_CONFIG */