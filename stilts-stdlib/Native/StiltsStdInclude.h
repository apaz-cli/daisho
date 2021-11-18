#ifndef STILTS_STDLIB_INCLUDES
#define STILTS_STDLIB_INCLUDES

/* Grab all the C11 headers. */

/* Base Stdlib */

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
#include <wctype.h>
#include <wchar.h>

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

/* Grab user configuration files. */
#include "StiltsConfig.h"

/* Grab archetecture specific assumptions like endianness. */
#include "StiltsAssumptions/StiltsAssumptions.h"

#endif /* STILTS_STDLIB_INCLUDES */
