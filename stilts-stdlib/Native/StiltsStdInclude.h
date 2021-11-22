#ifndef __STILTS_STDLIB_INCLUDES
#define __STILTS_STDLIB_INCLUDES

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
#include <stdatomic.h>
#include <stdnoreturn.h>
#include <threads.h>
#include <uchar.h>

/* Additional Libraries */
/* note: pthread.h is used over threads.h because it's better. */
#include <pthread.h> 
#include <sys/types.h>
#include <unistd.h>

/* Grab user configuration files. */
#include "StiltsConfig.h"

/* Grab archetecture specific assumptions like endianness. */
#include "StiltsAssumptions/StiltsAssumptions.h"

/* Embed a python interpreter, because why not. */
#if __STILTS_EMBED_PYTHON
#include <Python.h>
#endif

#endif /* __STILTS_STDLIB_INCLUDES */
