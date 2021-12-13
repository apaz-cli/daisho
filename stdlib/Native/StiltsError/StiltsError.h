#pragma once
#ifndef __STILTS_STDLIB_ERROR
#define __STILTS_STDLIB_ERROR
#include "../StiltsStdInclude.h"

#define __STILTS_SANITY_RETURN 23
#define __STILTS_OOM_RETURN 24
#define __STILTS_ERROR_RETURN 25

#define __STILTS_SRC_INFO __LINE__, __func__, __FILE__
#define __STILTS_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define __STILTS_SRC_INFO_PASS line, func, file
#define __STILTS_SRC_INFO_IGNORE() \
    (void)line;                    \
    (void)func;                    \
    (void)file;

__STILTS_FN
#if __STILTS_SANITY_CHECK
__STILTS_NORETURN
#endif
void
__Stilts_default_OOM(__STILTS_SRC_INFO_ARGS) {
#if __STILTS_SANITY_CHECK
    fprintf(stderr, "OUT OF MEMORY AT: %s:%zu inside %s().\n", file, line,
            func);
    exit(__STILTS_SANITY_RETURN);
#else
    __STILTS_SRC_INFO_IGNORE();
#endif
}

__STILTS_FN
#if __STILTS_SANITY_CHECK
__STILTS_NORETURN
#endif
void
__Stilts_default_sanity_check_fail(__STILTS_SRC_INFO_ARGS) {
#if __STILTS_SANITY_CHECK
    fprintf(stderr, "FAILED SANITY CHECK AT: %s:%zu inside %s().\n", file, line,
            func);
    exit(__STILTS_OOM_RETURN);
#else
    __STILTS_SRC_INFO_IGNORE();
#endif
}

__STILTS_FN
#if __STILTS_SANITY_CHECK
__STILTS_NORETURN
#endif
void
__Stilts_default_error(char* message, __STILTS_SRC_INFO_ARGS) {
#if __STILTS_SANITY_CHECK
    fprintf(stderr, "ERROR: %s\nAT: %s:%zu inside %s().\n", message, file, line,
            func);
    exit(__STILTS_ERROR_RETURN);
#else
    __STILTS_SRC_INFO_IGNORE();
#endif
}

/* Macro wrap for use */

#if __STILTS_SANITY_CHECK
#define __STILTS_OOM() __Stilts_default_OOM(__STILTS_SRC_INFO)
#define __STILTS_SANITY_FAIL() \
    __Stilts_default_sanity_check_fail(__STILTS_SRC_INFO)
#define __STILTS_ERROR(message) \
    __Stilts_default_error(message, __STILTS_SRC_INFO)
#else /* __STILTS_SANITY_CHECK */
#define __STILTS_OOM()
#define __STILTS_SANITY_FAIL()
#define __STILTS_ERROR(message)
#endif /* __STILTS_SANITY_CHECK */

#endif /* __STILTS_STDLIB_ERROR */
