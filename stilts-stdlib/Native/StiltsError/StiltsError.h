#pragma once
#ifndef __STILTS_STDLIB_ERROR
#define __STILTS_STDLIB_ERROR
#include "../StiltsStdInclude.h"

#define __STILTS_SRC_INFO __LINE__, __func__, __FILE__
#define __STILTS_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define __STILTS_SRC_INFO_PASS line, func, file
#define __STILTS_SRC_INFO_IGNORE() \
    (void)line;                    \
    (void)func;                    \
    (void)file;

__STILTS_FN void
__Stilts_default_OOM(__STILTS_SRC_INFO_ARGS) {
    if (__STILTS_SANITY_CHECK) {
        fprintf(stderr, "OUT OF MEMORY AT: %s:%zu inside %s().\n", file, line,
                func);
        exit(23);
    } else {
        __STILTS_SRC_INFO_IGNORE();
    }
}

__STILTS_FN void
__Stilts_default_sanity_check_fail(__STILTS_SRC_INFO_ARGS) {
    if (__STILTS_SANITY_CHECK) {
        fprintf(stderr, "FAILED SANITY CHECK AT: %s:%zu inside %s().\n", file,
                line, func);
        exit(24);
    } else {
        __STILTS_SRC_INFO_IGNORE();
    }
}

#define __STILTS_OOM(line, func, file) \
    __Stilts_default_OOM(__STILTS_SRC_INFO)

#define __STILTS_SANITY_FAIL() \
    __Stilts_default_sanity_check_fail(__STILTS_SRC_INFO)

#endif /* __STILTS_STDLIB_ERROR */
