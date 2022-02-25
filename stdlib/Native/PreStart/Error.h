#ifndef __DAI_STDLIB_ERROR
#define __DAI_STDLIB_ERROR
#include "../PreProcessor/PreProcessor.h"

#define __DAI_SRC_INFO __LINE__, __func__, __FILE__
#define __DAI_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define __DAI_SRC_INFO_PASS line, func, file
#define __DAI_SRC_INFO_IGNORE() \
    (void)line;                 \
    (void)func;                 \
    (void)file;

__DAI_FN __DAI_NORETURN void
__Dai_initialization_failure(int sanity, char* msg, __DAI_SRC_INFO_ARGS) {
    char errstr[32];
    const char succ[] = "Success";
    const char descerr[] = "Could not get error description.";
    const char* sanities[] = {"insane", "sane", "pedantic"};
    const char fmt[] =
        "COULD NOT INITIALIZE THE DAISHO RUNTIME.\n"
        "PLEASE CREATE AN ISSUE ON GITHUB WITH THE DAIC COMMIT HASH,\n"
        "YOUR PLATFORM, AND THE FOLLOWING INFORMATION:\n"
        "\n"
        "  ERROR AT: %s:%zu inside %s().\n"
        "  ERRNO: %i, (%s)\n"
        "  SANITY: %i, (%i required for check)\n"
        "  MESSAGE: %s\n";
    fprintf(stderr, fmt, file, line, func, errno, errno ? strerror(errno) : succ,
            __DAI_SANITY_CHECK, sanity, msg);
    exit(1);
}

__DAI_FN __DAI_NORETURN void
__Dai_OOM(__DAI_SRC_INFO_ARGS) {
    const char fmt[] =
        "OUT OF MEMORY AT: %s:%zu inside %s().\n"
        "Consider recompiling with --memdebug-print for debugging information.";
    fprintf(stderr, fmt, file, line, func);
    exit(1);
}

__DAI_FN __DAI_NORETURN void
__Dai_error(int sanity, char* msg, __DAI_SRC_INFO_ARGS) {
    const char fmt0[] = "FATAL ERROR AT: %s:%zu inside %s().\n";
    const char fmt1[] = "FAILED SANITY CHECK AT: %s:%zu inside %s().\n";
    const char fmt2[] = "FAILED PEDANTIC SANITY CHECK AT: %s:%zu inside %s().\n";
    fprintf(stderr, sanity ? sanity == 2 ? fmt2 : fmt1 : fmt0, file, line, func);
    if (msg) fprintf(stderr, "REASON: %s\n", msg);

    // TODO also provide a backtrace.
    // TODO color formatting

    exit(1);
}

/****************/
/* OOM Handling */
/****************/
#define __DAI_OOM() __Dai_OOM(__DAI_SRC_INFO)
#define __DAI_OOMCHECK(buf)                    \
    do {                                       \
        if (!(buf)) __Dai_OOM(__DAI_SRC_INFO); \
    } while (0)
#define __DAI_SANE_OOMCHECK(buf)               \
    do {                                       \
        if (!(buf)) __Dai_OOM(__DAI_SRC_INFO); \
    } while (0)
#define __DAI_PEDANTIC_OOMCHECK(buf)           \
    do {                                       \
        if (!(buf)) __Dai_OOM(__DAI_SRC_INFO); \
    } while (0)

/*******************/
/* Terminal Errors */
/*******************/
#define __DAI_ERROR(msg) __Dai_error(0, (char*)(msg), __DAI_SRC_INFO)

/**********/
/* Assert */
/**********/

/* Assert up to */

#define __DAI_ASSERT(cond, msg)           do { if (!(cond))                     __Dai_error(0, (char*)(msg), __DAI_SRC_INFO); } while (0)

#define __DAI_SANE_ASSERT(cond, msg)      do {  if ((!(cond)) & __DAI_SANE)     __Dai_error(1, (char*)(msg), __DAI_SRC_INFO); } while (0)

#define __DAI_PEDANTIC_ASSERT(cond, msg)  do {  if ((!(cond)) & __DAI_PEDANTIC) __Dai_error(2, (char*)(msg), __DAI_SRC_INFO); } while (0)

#endif /* __DAI_STDLIB_ERROR */
