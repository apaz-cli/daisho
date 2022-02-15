#ifndef __DAI_STDLIB_ERROR
#define __DAI_STDLIB_ERROR
#include "../PreProcessor/PreProcessor.h"

#define __DAI_SANITY_RETURN 23
#define __DAI_OOM_RETURN 24
#define __DAI_ERROR_RETURN 25

#define __DAI_SRC_INFO __LINE__, __func__, __FILE__
#define __DAI_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define __DAI_SRC_INFO_PASS line, func, file
#define __DAI_SRC_INFO_IGNORE() \
    (void)line;                    \
    (void)func;                    \
    (void)file;

__DAI_FN
#if __DAI_SANITY_CHECK
__DAI_NORETURN
#endif
void
__Dai_default_OOM(__DAI_SRC_INFO_ARGS) {
#if __DAI_SANITY_CHECK
    fprintf(stderr, "OUT OF MEMORY AT: %s:%zu inside %s().\n", file, line, func);
    exit(__DAI_SANITY_RETURN);
#else
    __DAI_SRC_INFO_IGNORE();
#endif
}

__DAI_FN
#if __DAI_SANITY_CHECK
__DAI_NORETURN
#endif
void
__Dai_default_sanity_check_fail(__DAI_SRC_INFO_ARGS) {
#if __DAI_SANITY_CHECK
    fprintf(stderr, "FAILED SANITY CHECK AT: %s:%zu inside %s().\n", file, line, func);
    exit(__DAI_OOM_RETURN);
#else
    __DAI_SRC_INFO_IGNORE();
#endif
}

__DAI_FN
#if __DAI_SANITY_CHECK
__DAI_NORETURN
#endif
void
__Dai_default_error(char* message, __DAI_SRC_INFO_ARGS) {
#if __DAI_SANITY_CHECK
    fprintf(stderr, "ERROR: %s\nAT: %s:%zu inside %s().\n", message, file, line, func);
    exit(__DAI_ERROR_RETURN);
#else
    __DAI_SRC_INFO_IGNORE();
#endif
}

/* Macro wrap for use */

#if __DAI_SANITY_CHECK
#define __DAI_OOM() __Dai_default_OOM(__DAI_SRC_INFO)
#define __DAI_SANITY_FAIL() __Dai_default_sanity_check_fail(__DAI_SRC_INFO)
#define __DAI_ERROR(message) __Dai_default_error(message, __DAI_SRC_INFO)
#else /* __DAI_SANITY_CHECK */
#define __DAI_OOM()
#define __DAI_SANITY_FAIL()
#define __DAI_ERROR(message)
#endif /* __DAI_SANITY_CHECK */

#endif /* __DAI_STDLIB_ERROR */
