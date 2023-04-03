#ifndef _DAI_STDLIB_LIBRARIES
#define _DAI_STDLIB_LIBRARIES
#include "../Configs/Configs.h"

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
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cfloat>
#include <climits>
#include <clocale>
#include <cmath>
#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

/* C95 */
#include <ciso646>
#include <cwchar>
#include <cwctype>

/* C99 */
#include <ccomplex>
#include <cfenv>
#include <cinttypes>
#include <cstdbool>
#include <cstdint>
#include <ctgmath>

/* C11 */
#include <cstdalign>
#include <cuchar>
// #include <cstdatomic>
// #include <cthreads>

#endif /* End of stdlib includes */

/************************/
/* Additional Libraries */
/************************/

/* POSIX */
// TODO deal with _GNU_SOURCE
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>

/* Use GNU backtraces if possible. */
#if _DAI_USING_BACKTRACES
#include <execinfo.h>
#endif

#endif /* _DAI_STDLIB_LIBRARIES */
