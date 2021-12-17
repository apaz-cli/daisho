#ifndef __STILTS_STDLIB_BACKTRACE
#define __STILTS_STDLIB_BACKTRACE

#include "../StiltsStdInclude.h"

// TODO replace feature test macros with a configure script.

/* On compilers that support include checking (Clang and GCC), we can check if
 * we have backtraces. If we aren't able to check, or we don't, just print that
 * we can't provide one.
 */

__STILTS_FN void
__Stilts_bt_header(void) {
    fprintf(stderr, "\nStack Trace:\n");
}

__STILTS_FN void
__STILTS_bt_footer(char* sigstr) {
    char errmsg[64];
    strerror_r(errno, errmsg, 64);
    fprintf(stderr, "Errno: %s\nSignal: %s\n", errmsg, sigstr ? sigstr : "N/A");
}

#ifdef __has_include
/* If we have execinfo.h, then it's supported. */
#if __has_include(<execinfo.h>)
#include <execinfo.h>
/* Obtain a backtrace and print it to stdout. */
#define __STILTS_BACKTRACE()                                              \
    do {                                                                  \
        __Stilts_bt_header();                                             \
        const int __Stilts_max_frames = 50;                               \
        void* __Stilts_symbol_arr[__Stilts_max_frames];                   \
        char** __Stilts_symbol_strings = NULL;                            \
        int __Stilts_num_addrs, __Stilts_i;                               \
        __Stilts_num_addrs =                                              \
            backtrace(__Stilts_symbol_arr, __Stilts_max_frames);          \
        __Stilts_symbol_strings =                                         \
            backtrace_symbols(__Stilts_symbol_arr, __Stilts_num_addrs);   \
        if (__Stilts_symbol_strings) {                                    \
            fprintf(stderr, "Obtained %d stack frames.\n",                \
                    __Stilts_num_addrs);                                  \
            fflush(stderr);                                               \
            for (__Stilts_i = 0; __Stilts_i < __Stilts_num_addrs;         \
                 __Stilts_i++) {                                          \
                /* Extract the function name */                           \
                char* __Stilts_str = __Stilts_symbol_strings[__Stilts_i]; \
            /*  __Stilts_str = __Stilts_str + strlen(__Stilts_str);       \
                while (*__Stilts_str != '+') __Stilts_str--;              \
                *__Stilts_str = '\0';                                     \
                while (*__Stilts_str != '(') __Stilts_str--;              \
                __Stilts_str++;                                      */   \
                                                                          \
                fprintf(stderr, "  %s()\n", __Stilts_str);                \
                fflush(stderr);                                           \
            }                                                             \
            __Stilts_originalFree(__Stilts_symbol_strings);               \
        } else {                                                          \
            fprintf(stderr, "Backtrace failed.\n");                       \
        }                                                                 \
    } while (0);
#else /* __has_include(<execinfo.h>)*/
#define print_trace()                                                  \
    do {                                                               \
        fprintf(stderr,                                                \
                "The include file <execinfo.h> could not be found on " \
                "your system. Backtraces not supported.\n");           \
    }
#endif
#else /* No __has_include() */
#define print_trace()                                                          \
    do {                                                                       \
        fprintf(stderr,                                                        \
                "Could not look for <execinfo.h>, because __has_include() is " \
                "not supported. Backtraces not supported.\n");                 \
    }
#endif

#endif /* __STILTS_STDLIB_BACKTRACE */
