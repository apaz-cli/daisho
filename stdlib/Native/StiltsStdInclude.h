#pragma once
#ifndef __STILTS_STDLIB_INCLUDES
#define __STILTS_STDLIB_INCLUDES

/* Grab user configuration files. */
#include "StiltsConfig.h"

/*
 * Embed a python interpreter, because why not.
 * This has to be done before including stdlib files.
 * It can be disabled in the config files, or on the
 * stiltc command line.
 */
#if __STILTS_EMBED_PYTHON
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#endif

/* Grab all the C11 headers. */

/* Base C */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* C95 */
#include <iso646.h>
#include <wchar.h>
#include <wctype.h>

/* C99 */
#include <complex.h>
#include <fenv.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <tgmath.h>

/* C11 */
#include <stdalign.h>
// #include <stdatomic.h>
#include <stdnoreturn.h>
#include <uchar.h>
// #include <threads.h>

/************************/
/* Additional Libraries */
/************************/

/* note: pthread.h is used over C11's threads.h because
   it's better and actually more portable. */
#include "StiltsHedley/StiltsHedley.h"    /* Portable builtin macros */
#include <pthread.h>                      /* Threads, Muxtexes, RWLocks */
#include <sys/types.h>                    /* POSIX */
#include <unistd.h>    /* POSIX */

// TODO: Use GNU backtraces if possible.

/***********************/
/* Compatible Keywords */
/***********************/

#ifndef __cplusplus  // C
#define __STILTS_ALIGNOF(type) _Alignof(type)
#define __STILTS_NORETURN _Noreturn
#define __STILTS_RESTRICT restrict
#ifdef __GNUC__
#define __STILTS_LIKELY(expr) __builtin_expect(!!(expr), 1)
#define __STILTS_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else /* !__GNUC__ */
#define __STILTS_LIKELY(expr) expr
#define __STILTS_UNLIKELY(expr) expr
#endif /* __GNUC__ */

#else /* __cplusplus */

#define __STILTS_ALIGNOF(type) alignof(type)
#define __STILTS_NORETURN
#define __STILTS_RESTRICT
#if __cplusplus >= 202002L /* C++20 and up use attributes */
#define __STILTS_LIKELY(expr)                       \
    (([](bool __Stilts_expr) {                      \
        switch (__Stilts_expr) {                    \
            [[likely]] case true : return true;     \
            [[unlikely]] case false : return false; \
        }                                           \
    })((bool)expr))
#define __STILTS_UNLIKELY(expr)                   \
    (([](bool __Stilts_expr) {                    \
        switch (__Stilts_expr) {                  \
            [[unlikely]] case true : return true; \
            [[likely]] case false : return false; \
        }                                         \
    })((bool)expr))
#else /*__cplusplus >= 202002L (No C++20) */
#ifdef __GNUC__
#define __STILTS_LIKELY(expr) __builtin_expect(!!(expr), 1)
#define __STILTS_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else /* !__GNUC__ */
#define __STILTS_LIKELY(expr) expr
#define __STILTS_UNLIKELY(expr) expr
#endif /* __GNUC__ */
#endif
#endif /* __cplusplus */

/* Error handling that needs to be gloabally available, but depends on config
 * files and the stdlib. */
#include "StiltsBacktrace/StiltsBacktrace.h"
#include "StiltsColor/StiltsColor.h"
#include "StiltsError/StiltsError.h"
#include "StiltsPython/StiltsPython.h"

/* Start and end routines */
#include "StiltsStart/StiltsStart.h"

#endif /* __STILTS_STDLIB_INCLUDES */
