#ifndef __STILTS_STDLIB_LIBRARIES
#define __STILTS_STDLIB_LIBRARIES
#include "../Configs/StiltsConfigs.h"

/*
 * Embed a python interpreter, because why not.
 * This has to be done before including stdlib files.
 * It can be disabled in the config files, or on the
 * stiltc command line.
 */
#ifndef __STILTS_ASSERTING
#if __STILTS_EMBED_PYTHON
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#endif
#endif

/* Grab all the C11 headers. */
/* note: pthread.h is used over C11's threads.h because
   it's better and actually more portable. */
#ifndef __cplusplus
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
#include <stdnoreturn.h>
#include <uchar.h>
// #include <stdatomic.h>
// #include <threads.h>

#else /* __cplusplus */
#include <assert>
#include <ctype>
#include <errno>
#include <float>
#include <limits>
#include <locale>
#include <math>
#include <setjmp>
#include <signal>
#include <stdarg>
#include <stddef>
#include <stdio>
#include <stdlib>
#include <string>
#include <time>

/* C95 */
#include <iso646>
#include <wchar>
#include <wctype>

/* C99 */
#include <complex>
#include <fenv>
#include <inttypes>
#include <stdbool>
#include <stdint>
#include <tgmath>

/* C11 */
#include <stdalign>
#include <stdnoreturn>
#include <uchar>
// #include <stdatomic>
// #include <threads>

#endif /* End of stdlib includes */

/************************/
/* Additional Libraries */
/************************/

#include <pthread.h>   /* Threads, Muxtexes, RWLocks */
#include <sys/types.h> /* POSIX */
#include <unistd.h>    /* POSIX */

/* Use GNU backtraces if possible. */
#ifndef __STILTS_ASSERTING
#if __STILTS_BACKTRACES_SUPPORTED
#include <execinfo.h>
#endif
#endif

#endif /* __STILTS_STDLIB_LIBRARIES */
