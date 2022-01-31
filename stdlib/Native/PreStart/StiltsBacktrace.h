#ifndef __STILTS_STDLIB_BACKTRACE
#define __STILTS_STDLIB_BACKTRACE

#include "../PreProcessor/StiltsPreprocessor.h"
#include "StiltsBuffering.h"

#define __STITLS_BT_MAX_FRAMES 50

// TODO replace feature test macros with a configure script.

/*
 * On compilers that support include checking (Clang and GCC), we can check if
 * we have backtraces. If we aren't able to check, or we don't, just print that
 * we can't provide one.
 */

#if __STILTS_BACKTRACES_SUPPORTED

__STILTS_FN void
__Stilts_bt_header(void) {
    fprintf(stderr, __STILTS_COLOR_HEAD("***************\n* Stack Trace *\n***************\n"));
}

__STILTS_FN void
__STILTS_bt_footer(char* sigstr) {
    char* errmsg = errno ? strerror(errno) : (char*)"0 (Success)";
    fprintf(stderr,
            __STILTS_COLOR_MAGENTA "Errno: " __STILTS_COLOR_RESET " " __STILTS_COLOR_BLUE
                                   "%s" __STILTS_COLOR_RESET "\n" __STILTS_COLOR_MAGENTA
                                   "Signal:" __STILTS_COLOR_RESET " " __STILTS_COLOR_BLUE
                                   "%s" __STILTS_COLOR_RESET "\n\n",
            errmsg, sigstr ? sigstr : "N/A");
}

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

static void __STILTS_NEVER_INLINE
__Stilts_backtrace(void) {
    void* symbol_arr[__STITLS_BT_MAX_FRAMES];
    char** symbol_strings = NULL;
    int num_addrs, i;
    num_addrs = backtrace(symbol_arr, __STITLS_BT_MAX_FRAMES);
    symbol_strings = backtrace_symbols(symbol_arr, num_addrs);
    if (symbol_strings) {
        __Stilts_bt_header();
        const char errmsg[] = "Obtained %d stack frames.\n";
        fprintf(stderr, errmsg, num_addrs);
        fflush(stderr);
        for (i = 0; i < num_addrs; i++)
            __Stilts_SymInfo_print(__Stilts_SymInfo_parse(symbol_strings[i]));
        __STILTS_bt_footer(NULL);
        __Stilts_newline_flush(stdout);
        /* Original (glibc) free, not wrapped. */
        free(symbol_strings);
    } else {
        const char errmsg[] = "Backtrace failed.";
        puts(errmsg);
        __Stilts_newline_flush(stdout);
    }
}

static void __STILTS_NEVER_INLINE
__Stilts_low_mem_backtrace(void) {
    const char nl = '\n';
    int num_addrs;
    void* symbol_arr[__STITLS_BT_MAX_FRAMES];
    num_addrs = backtrace(symbol_arr, __STITLS_BT_MAX_FRAMES);
    backtrace_symbols_fd(symbol_arr, num_addrs, STDOUT_FILENO);
    write(STDOUT_FILENO, &nl, 1);
}

#else /* Backtraces unsupported */
static void __STILTS_NEVER_INLINE
__Stilts_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    fprintf(stdout, buf);
}

static void __STILTS_NEVER_INLINE
__Stilts_low_mem_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    write(STDERR_FILENO, buf, strlen(buf));
}
#endif

#endif /* __STILTS_STDLIB_BACKTRACE */
