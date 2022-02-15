#ifndef __DAI_STDLIB_BACKTRACE
#define __DAI_STDLIB_BACKTRACE

#include "../PreProcessor/PreProcessor.h"
#include "Buffering.h"

#define __STITLS_BT_MAX_FRAMES 50

// TODO replace feature test macros with a configure script.

/*
 * On compilers that support include checking (Clang and GCC), we can check if
 * we have backtraces. If we aren't able to check, or we don't, just print that
 * we can't provide one.
 */

#if __DAI_BACKTRACES_SUPPORTED

__DAI_FN void
__Dai_bt_header(void) {
    fprintf(stderr, __DAI_COLOR_HEAD("***************\n* Stack Trace *\n***************\n"));
}

__DAI_FN void
__DAI_bt_footer(char* sigstr) {
    char* errmsg = errno ? strerror(errno) : (char*)"0 (Success)";
    fprintf(stderr,
            __DAI_COLOR_MAGENTA "Errno: " __DAI_COLOR_RESET " " __DAI_COLOR_BLUE
                                   "%s" __DAI_COLOR_RESET "\n" __DAI_COLOR_MAGENTA
                                   "Signal:" __DAI_COLOR_RESET " " __DAI_COLOR_BLUE
                                   "%s" __DAI_COLOR_RESET "\n\n",
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
} __Dai_SymInfo;

__DAI_FN __Dai_SymInfo
__Dai_SymInfo_parse(char* str) {
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
    __Dai_SymInfo info = {file, name, addr};
    return info;
}

__DAI_FN void
__Dai_SymInfo_print(__Dai_SymInfo info) {
    fprintf(stderr, __DAI_COLOR_FILE("%s:") " ", info.file);
    info.name ? fprintf(stderr, __DAI_COLOR_FUNC("%s()") " at ", info.name)
              : fprintf(stderr, __DAI_COLOR_FUNC("%s") " at ", "UNKNOWN");
    fprintf(stderr, __DAI_COLOR_PNTR("%s") "\n", info.addr);
    fflush(stderr);
}

static void __DAI_NEVER_INLINE
__Dai_backtrace(void) {
    void* symbol_arr[__STITLS_BT_MAX_FRAMES];
    char** symbol_strings = NULL;
    int num_addrs, i;
    num_addrs = backtrace(symbol_arr, __STITLS_BT_MAX_FRAMES);
    symbol_strings = backtrace_symbols(symbol_arr, num_addrs);
    if (symbol_strings) {
        __Dai_bt_header();
        const char errmsg[] = "Obtained %d stack frames.\n";
        fprintf(stderr, errmsg, num_addrs);
        fflush(stderr);
        for (i = 0; i < num_addrs; i++)
            __Dai_SymInfo_print(__Dai_SymInfo_parse(symbol_strings[i]));
        __DAI_bt_footer(NULL);
        __Dai_newline_flush(stdout);
        /* Original (glibc) free, not wrapped. */
        free(symbol_strings);
    } else {
        const char errmsg[] = "Backtrace failed.";
        puts(errmsg);
        __Dai_newline_flush(stdout);
    }
}

static void __DAI_NEVER_INLINE
__Dai_low_mem_backtrace(void) {
    const char nl = '\n';
    int num_addrs;
    void* symbol_arr[__STITLS_BT_MAX_FRAMES];
    num_addrs = backtrace(symbol_arr, __STITLS_BT_MAX_FRAMES);
    backtrace_symbols_fd(symbol_arr, num_addrs, STDOUT_FILENO);
    write(STDOUT_FILENO, &nl, 1);
}

#else /* Backtraces unsupported */
static void __DAI_NEVER_INLINE
__Dai_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    fprintf(stdout, buf);
}

static void __DAI_NEVER_INLINE
__Dai_low_mem_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    write(STDERR_FILENO, buf, strlen(buf));
}
#endif

#endif /* __DAI_STDLIB_BACKTRACE */
