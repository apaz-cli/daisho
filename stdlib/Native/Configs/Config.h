/***********************************************************************\
* Feel free to change the default values in this file. They can be      *
* overrided in the command line.                                        *
*                                                                       *
* Do not include any files inside this header. Doing so has the         *
* potential to break the Python runtime. Please only change configs.    *
\***********************************************************************/

#pragma once
#ifndef __DAI_STDLIB_CONFIG
#define __DAI_STDLIB_CONFIG

/* Generated from the configure script. */
#include "GeneratedConfig.h"

/*
 * 0 - Don't embed Python (default if python is not configured)
 * 1 - Embed Python       (default if python is configured)
 *
 * Can be declared by daic as a flag to the C compiler.
 * Use daic flags to control this. Passing neither uses
 * the default above.
 *
 * --no-python specifies 0.
 * --python    specifies 1.
 */
#ifndef __DAI_EMBED_PYTHON
#define __DAI_EMBED_PYTHON 0
#endif

/*
 * 0 - No sanity checks. Difficult to debug, but very fast.
 * 1 - Basic sanity checks are performed. (default)
 * 2 - Pedantic sanity checks. Very slow, but good for debugging.
 *
 * Can be declared by daic as a flag to the C compiler.
 * Use daic flags to control this. Passing neither uses
 * the default above.
 *
 * --insane   specifies 0.
 * --sane     specifies 1.
 * --pedantic specifies 2.
 */
#ifndef __DAI_SANITY_CHECK
#define __DAI_SANITY_CHECK 1
#endif

/*
 * 0 - No memory debugging. (default)
 * 1 - Memory debugging.
 * 2 - Memory debugging, and print all allocations and frees to stderr.
 *
 * When memory debugging is turned on, __Dai_malloc(),
 * __Dai_calloc(), __Dai_realloc(), and __Dai_free()
 * are wrapped for additional sanity checks.
 *
 * For example, trying to __Dai_realloc() or __Dai_free()
 * a pointer not allocated by one of the other wrapped functions
 * (including by normal malloc()) causes a crash and prints debugging
 * information to stderr about exactly where the invalid free happened.
 *
 * You can also use __Dai_heap_dump() to print a summary to stderr
 * of all tracked memory allocations and where they happened.
 *
 * Can be declared by daic as a flag to the C compiler.
 * Use daic flags to control this. Passing neither uses
 * the default above.
 *
 * --no-memdebug    specifies 0.
 * --memdebug       specifies 1.
 * --memdebug-print specifies 2.
 */
#ifndef __DAI_MEMDEBUG
#define __DAI_MEMDEBUG 0
#endif

/*
 * 0 - Do not replace malloc().
 * 1 - Replace malloc() (default)
 *
 * Replaces the memory allocator used by
 * __Dai_malloc(), __Dai_realloc(), __Dai_calloc(), and
 * __Dai_free(), and also wraps normal malloc(), realloc(), calloc(), and
 * free() in a macro redirecting to their __Dai_ versions. This only works
 * for the current translation unit.
 *
 * This has multiple benefits. The custom memory allocator is faster. Also, in
 * combination with __DAI_MEMDEBUG, this can be used to track down errors in
 * code not written by daic.
 *
 * When you use __DAI_REPLACE_MALLOC, be sure to always include Daisho.h
 * before including the file that provides malloc(), so that it can be wrapped
 * for the whole translation unit.
 *
 * Can be declared by daic as a flag to the C compiler.
 * Use daic flags to control this. Passing neither uses
 * the default above.
 *
 * --normal-malloc  specifies 0.
 * --replace-malloc specifies 1.
 */
#ifndef __DAI_REPLACE_MALLOC
#define __DAI_REPLACE_MALLOC 1
#endif

/*
 * The maximum number of stack frames that can be backtraced through.
 * If backtraces are not enabled, this has no effect.
 *
 * If this number is smaller than the number of stack frames to report,
 * then the newest ones are reported.
 */
#ifndef __DAI_BT_MAX_FRAMES
#define __DAI_BT_MAX_FRAMES 128
#endif

/*
 * 2 - Fully buffered
 * 1 - Line Buffered (default)
 * 0 - Unbuffered
 *
 * Controls how stdout and stderr are flushed. Behavior is the same
 * as setvbuf() from the c stdlib.
 */
#ifndef __DAI_OUTPUT_BUFFERING
#define __DAI_OUTPUT_BUFFERING 1
#endif

/*
 * The C runtime locale for Daisho to use.
 * Default: "C.UTF-8"
 */
#ifndef __DAI_LOCALE
#define __DAI_LOCALE "C.UTF-8"
#endif

/*
 * The list of signals that trigger a backtrace and termination of the program.
 * If backtraces are not enabled, no backtrace is printed to stderr, and the
 * signal handlers are not registered. All of the default signals below will
 * still by default terminate the program however.
 *
 * At least one signal must be defined below. If you want to disable backtraces,
 * 
 *
 * See man signal.h for details and a list of signals and default actions.
 */
#ifndef __DAI_BACKTRACE_SIGNALS
#define __DAI_BACKTRACE_SIGNALS \
    SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGBUS, SIGVTALRM, SIGXCPU, SIGXFSZ, SIGSYS
#endif

/*
 * Backtraces must be both supported and enabled to work.
 */
#ifndef __DAI_BACKTRACES_ENABLED
#define __DAI_BACKTRACES_ENABLED __DAI_HAS_BACKTRACES
#endif

#endif /* __DAI_STDLIB_CONFIG */
