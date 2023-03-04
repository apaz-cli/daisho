#ifndef _DAI_STDLIB_ERROR
#define _DAI_STDLIB_ERROR
#include "../PreProcessor/PreProcessor.h"

typedef struct {
    size_t line;
    const char* func;
    const char* file;
} _Dai_Src_Info;

#define _DAI_SRC_INFO __LINE__, __func__, __FILE__
#define _DAI_SRC_INFO_ARGS size_t line, const char *func, const char *file
#define _DAI_SRC_INFO_PASS line, func, file
#define _DAI_SRC_INFO_PACK(line, func, file) (_Dai_Src_Info){line, func, file}
#define _DAI_SRC_INFO_UNPACK(info) (info).line, (info).func, (info).file
#define _DAI_SRC_INFO_IGNORE() \
    (void)line;                 \
    (void)func;                 \
    (void)file;

#define _DAI_ERRSTR_LEN 32

/* Accepts a buffer with _DAI_ERRSTR_LEN bytes of space. */
_DAI_FN char*
_Dai_strerror(char* errstr) {
    if (errno) {
        strerror_r(errno, errstr, _DAI_ERRSTR_LEN);
    } else {
        char success[] = "Success";
        strcpy(errstr, success);
    }
    return errstr;
}

_DAI_FN _DAI_NORETURN void
_Dai_initialization_failure(int check_sanity, char* msg, _DAI_SRC_INFO_ARGS) {
    char errstr[_DAI_ERRSTR_LEN];
    _Dai_strerror(errstr);
    //const char succ[] = "Success";
    //const char descerr[] = "Could not get error description.";
    //const char* sanities[] = {"insane", "sane", "pedantic"};
    const char fmt[] =
        "COULD NOT INITIALIZE THE DAISHO RUNTIME.\n"
        "PLEASE CREATE AN ISSUE ON GITHUB WITH THE DAIC COMMIT HASH,\n"
        "YOUR PLATFORM, AND THE FOLLOWING INFORMATION:\n"
        "\n"
        "  ERROR AT: %s:%zu inside %s().\n"
        "  ERRNO: %i, (%s)\n"
        "  SANITY: %i, (%i required for check)\n"
        "  MESSAGE: %s\n";

    fprintf(stderr, fmt, file, line, func, errno, errstr, _DAI_SANITY_CHECK, check_sanity, msg);
    exit(1);

}

_DAI_FN _DAI_NORETURN void
_Dai_OOM(_DAI_SRC_INFO_ARGS) {
    const char fmt[] =
        "OUT OF MEMORY AT: %s:%zu inside %s().\n"
        "Consider recompiling with --memdebug-print for debugging information.";
    fprintf(stderr, fmt, file, line, func);
    exit(1);
}

_DAI_FN _DAI_NORETURN void
_Dai_error(int sanity, char* msg, _DAI_SRC_INFO_ARGS) {
    const char fmt0[] = "FATAL ERROR AT: %s:%zu inside %s().\n";
    const char fmt1[] = "FAILED SANITY CHECK AT: %s:%zu inside %s().\n";
    const char fmt2[] = "FAILED PEDANTIC SANITY CHECK AT: %s:%zu inside %s().\n";
    fprintf(stderr, sanity ? sanity == 2 ? fmt2 : fmt1 : fmt0, file, line, func);

    char errstr[_DAI_ERRSTR_LEN];
    if (msg) fprintf(stderr, "REASON: %s\nERRNO: %s\n", msg, _Dai_strerror(errstr));

    // TODO also provide a backtrace.
    // TODO color formatting

    exit(1);
}

/****************/
/* OOM Handling */
/****************/
#define _DAI_OOM() _Dai_OOM(_DAI_SRC_INFO)
#define _DAI_OOMCHECK(buf)                    \
    do {                                       \
        if (!(buf)) _Dai_OOM(_DAI_SRC_INFO); \
    } while (0)
#define _DAI_SANE_OOMCHECK(buf)               \
    do {                                       \
        if (!(buf)) _Dai_OOM(_DAI_SRC_INFO); \
    } while (0)
#define _DAI_PEDANTIC_OOMCHECK(buf)           \
    do {                                       \
        if (!(buf)) _Dai_OOM(_DAI_SRC_INFO); \
    } while (0)

/*******************/
/* Terminal Errors */
/*******************/
#define _DAI_ERROR(msg) _Dai_error(0, (char*)(msg), _DAI_SRC_INFO)

/**********/
/* Assert */
/**********/

/* Assert always. */
#define _DAI_ASSERT(cond, msg)                                    \
    do {                                                           \
        if (!(cond)) _Dai_error(0, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

/* Assert when not in "insane" mode. */
#define _DAI_SANE_ASSERT(cond, msg)                                              \
    do {                                                                          \
        if ((!(cond)) & _DAI_SANE) _Dai_error(1, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

/* Assert only in "pedantic" mode. */
#define _DAI_PEDANTIC_ASSERT(cond, msg)                                              \
    do {                                                                              \
        if ((!(cond)) & _DAI_PEDANTIC) _Dai_error(2, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

/**************************/
/* Initializaation Assert */
/**************************/

/* Assert always. */
#define _DAI_INIT_ASSERT(cond, msg)                                                \
    do {                                                                            \
        if (!(cond)) _Dai_initialization_failure(0, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

/* Assert when not in "insane" mode. */
#define _DAI_INIT_SANE_ASSERT(cond, msg)                                                          \
    do {                                                                                           \
        if ((!(cond)) & _DAI_SANE) _Dai_initialization_failure(1, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

/* Assert only in "pedantic" mode. */
#define _DAI_INIT_PEDANTIC_ASSERT(cond, msg)                              \
    do {                                                                   \
        if ((!(cond)) & _DAI_PEDANTIC)                                    \
            _Dai_initialization_failure(2, (char*)(msg), _DAI_SRC_INFO); \
    } while (0)

#endif /* _DAI_STDLIB_ERROR */
