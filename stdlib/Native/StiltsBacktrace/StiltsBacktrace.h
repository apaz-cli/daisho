#pragma once
#ifndef __STILTS_STDLIB_BACKTRACE
#define __STILTS_STDLIB_BACKTRACE

#include "../StiltsColor/StiltsColor.h"
#include "../StiltsStdInclude.h"

#define __STITLS_BT_MAX_FRAMES 50

// TODO replace feature test macros with a configure script.

/*
 * On compilers that support include checking (Clang and GCC), we can check if
 * we have backtraces. If we aren't able to check, or we don't, just print that
 * we can't provide one.
 */

__STILTS_FN void
__Stilts_bt_header(void) {
    fprintf(stderr, __STILTS_COLOR_HEAD(
                        "***************\n* Stack Trace *\n***************\n"));
}

__STILTS_FN void
__STILTS_bt_footer(char* sigstr) {
    char* errmsg = errno ? strerror(errno) : (char*)"0 (Success)";
    fprintf(stderr,
            __STILTS_COLOR_MAGENTA
            "Errno: " __STILTS_COLOR_RESET " " __STILTS_COLOR_BLUE
            "%s" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_MAGENTA
            "Signal:" __STILTS_COLOR_RESET " " __STILTS_COLOR_BLUE
            "%s" __STILTS_COLOR_RESET "\n\n",
            errmsg, sigstr ? sigstr : "N/A");
}

#ifdef __has_include
/* If we have execinfo.h, then it's supported. */
#if __has_include(<execinfo.h>)
#include <execinfo.h>
/*
 * Obtain a backtrace and print it to stdout.
 * Signal handlers are hell. Therefore, this is a "best effort" scenario.
 */
typedef struct {
    char* file;
    char* name;
    char* addr;
} __Stilts_SymInfo;

__STILTS_FN __Stilts_SymInfo
__Stilts_SymInfo_parse(char* str) {
    char *file = str, *name = NULL, *addr;
    while ((*str != '[') & (*str != '(')) str++;
    if (*str == '(') {
        *str = '\0';
        str++;

        if ((*str != ')') & (*str != '+')) {
            name = str;
            while (*str != '+') str++;
            *str = '\0';
        }

        while (*str != '[') str++;
        str++;

        addr = str;
        while (*str != ']') str++;
        *str = '\0';
    } else {
        *(str - 1) = '\0';
        str++;

        addr = str;
        while (*str != ']') str++;
        *str = '\0';
    }
    __Stilts_SymInfo info = {file, name, addr};
    return info;
}

__STILTS_FN void
__Stilts_SymInfo_print(__Stilts_SymInfo info) {
    fprintf(stderr, __STILTS_COLOR_FILE("%s:") " ", info.file);
    info.name ? fprintf(stderr, __STILTS_COLOR_FUNC("%s()") " at ", info.name)
              : fprintf(stderr, __STILTS_COLOR_FUNC("%s") " at ", "UNKNOWN");
    fprintf(stderr, __STILTS_COLOR_PNTR("%s") "\n", info.addr);
    fflush(stderr);
}

__STILTS_FN void
__Stilts_backtrace(void) {
    __Stilts_bt_header();
    void* symbol_arr[__STITLS_BT_MAX_FRAMES];
    char** symbol_strings = NULL;
    int num_addrs, i;
    num_addrs = backtrace(symbol_arr, __STITLS_BT_MAX_FRAMES);
    symbol_strings = backtrace_symbols(symbol_arr, num_addrs);
    if (symbol_strings) {
        fprintf(stderr, "Obtained %d stack frames.\n", num_addrs);
        fflush(stderr);
        for (i = 0; i < num_addrs; i++) {
            __Stilts_SymInfo_print(__Stilts_SymInfo_parse(symbol_strings[i]));
        }
        __STILTS_bt_footer(NULL);
        /* Original glibc free, before allocator's inclusion or wrapping. */
        free(symbol_strings);
    } else {
        fprintf(stderr, "Backtrace failed.\n");
    }
}
#else /* __has_include(<execinfo.h>)*/
extern inline void
__Stilts_backtrace(void) {
    fprintf(stderr,
            "The include file <execinfo.h> could not be found on "
            "your system. Backtraces not supported.\n");
    fflush(stderr);
}
#endif
#else /* No __has_include() */
extern inline void
__Stilts_backtrace(void) {
    fprintf(stderr,
            "Could not look for <execinfo.h>, because __has_include() is "
            "not supported. Backtraces not supported.\n");
    fflush(stderr);
}
#endif

#endif /* __STILTS_STDLIB_BACKTRACE */
