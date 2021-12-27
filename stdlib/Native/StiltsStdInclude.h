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
// #include <iso646.h>
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
#include <pthread.h>   /* Threads, Muxtexes, RWLocks */
#include <sys/types.h> /* POSIX */
#include <unistd.h>    /* POSIX */

// TODO: Use GNU backtraces if possible.

/***********************/
/* Compatible Keywords */
/***********************/

#ifndef __cplusplus
#define __STILTS_ALIGNOF(type) _Alignof(type)
#define __STILTS_NORETURN _Noreturn
#define __STILTS_RESTRICT restrict
#define __STILTS_STATIC_ASSERT(x, msg) _Static_assert(x, msg)
#else
#define __STILTS_ALIGNOF(type) alignof(type)
#define __STILTS_NORETURN
#define __STILTS_RESTRICT
#define __STILTS_STATIC_ASSERT(x, msg) static_assert(x, msg)
#endif

/* Error handling that needs to be gloabally available, but depends on config
 * files and the stdlib. */
#include "StiltsBacktrace/StiltsBacktrace.h"
#include "StiltsColor/StiltsColor.h"
#include "StiltsError/StiltsError.h"

#include "StiltsPython/StiltsPython.h"

/* Start and end routines */
#include "StiltsStart/StiltsStart.h"

#endif /* __STILTS_STDLIB_INCLUDES */
