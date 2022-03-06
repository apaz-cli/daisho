#ifndef __DAI_STDLIB_BACKTRACE
#define __DAI_STDLIB_BACKTRACE

#include "../PreProcessor/PreProcessor.h"
#include "Buffering.h"
#include "Error.h"

#if __DAI_USING_BACKTRACES

#define __DAI_BT_BUF_CAP ((size_t)(__DAI_PAGESIZE * 10))

static size_t __Dai_bt_buf_size;
static char __Dai_bt_buffer[__DAI_BT_BUF_CAP];
static FILE* __Dai_bt_stream;
static int __Dai_bt_fd;

__DAI_FN void
__Dai_bt_header(void) {
    const char sthead[] =
        __DAI_COLOR_HEAD "***************\n* Stack Trace *\n***************\n" __DAI_COLOR_RESET;
    fprintf(stderr, sthead);
}

__DAI_FN void
__Dai_bt_footer(char* sigstr) {
    const char na[] = "N/A";
    const char success[] = "0 (Success)";
    const char fmt[] =
        __DAI_COLOR_MAGENTA "Errno: " __DAI_COLOR_RESET " " __DAI_COLOR_BLUE "%s" __DAI_COLOR_RESET
                            "\n" __DAI_COLOR_MAGENTA "Signal:" __DAI_COLOR_RESET
                            " " __DAI_COLOR_BLUE "%s" __DAI_COLOR_RESET "\n\n";
    char errstr[32];
    errstr[0] = '\0';
    if (errno) strerror_r(errno, errstr, 32);

    const char* errmsg = errno ? errstr : success;
    fprintf(stderr, fmt, errmsg, sigstr ? sigstr : na);
}

/*
 * Obtain a backtrace and print it to stdout.
 * Signal handlers are hell. Therefore, this is a "best effort" scenario.
 */
typedef struct {
    char* file;
    char* func;
    char* addr;
    char* source;
    long line;
    char* basename;
} __Dai_SymInfo;

/* This looks ugly, and it is. But, it null terminates
 * and returns the positions of the file, name, and
 * address a frame of a glibc backtrace.
 */
__DAI_FN __Dai_SymInfo
__Dai_SymInfo_parse(char* str) {
    char *file = str, *func = NULL, *addr;
    while ((*str != '[') & (*str != '(')) str++;
    if (*str == '(') {
        *str = '\0';
        str++;

        if ((*str != ')') & (*str != '+')) {
            func = str;
            while (*str != '+') str++;
            *str = '\0';
        }

        while (*str != '[') str++;
        str++;

        addr = str;
        while (*str != ']') str++;
        *str = '\0';
    } else {
        *str = '\0';
        str++;

        addr = str;
        while (*str != ']') str++;
        *str = '\0';
    }
    __Dai_SymInfo info = {file, func, addr, NULL, 0, NULL};
    return info;
}

__DAI_FN void
__Dai_SymInfo_print(__Dai_SymInfo info) {
    fprintf(stderr, __DAI_COLOR_FILE "%s:" __DAI_COLOR_RESET " ", info.file);
    info.func ? fprintf(stderr, __DAI_COLOR_FUNC "%s()" __DAI_COLOR_RESET " at ", info.func)
              : fprintf(stderr, __DAI_COLOR_FUNC "%s" __DAI_COLOR_RESET " at ", "UNKNOWN");
    fprintf(stderr, __DAI_COLOR_PNTR "%s" __DAI_COLOR_RESET "\n", info.addr);
    fflush(stderr);
}

static void __DAI_NEVER_INLINE
__Dai_unsafe_print_backtrace(void) {
    void* symbol_arr[__DAI_BT_MAX_FRAMES];
    char** symbol_strings = NULL;
    int num_addrs, i;
    num_addrs = backtrace(symbol_arr, __DAI_BT_MAX_FRAMES);
    symbol_strings = backtrace_symbols(symbol_arr, num_addrs);
    if (symbol_strings) {
        __Dai_bt_header();
        const char errmsg[] = "Obtained %d stack frames.\n";
        fprintf(stderr, errmsg, num_addrs);
        fflush(stderr);
        for (i = 0; i < num_addrs; i++) __Dai_SymInfo_print(__Dai_SymInfo_parse(symbol_strings[i]));
        __Dai_bt_footer(NULL);
        __Dai_newline_flush(stdout);
        /* Original (glibc) free, not wrapped. */
        free(symbol_strings);
    } else {
        const char errmsg[] = "Backtrace failed.";
        puts(errmsg);
        __Dai_newline_flush(stdout);
    }
}

static void
__Dai_print_backtrace(void) {}

static void __DAI_NEVER_INLINE
__Dai_low_mem_backtrace(void) {
    const char nl = '\n';
    int num_addrs;
    void* symbol_arr[__DAI_BT_MAX_FRAMES];
    num_addrs = backtrace(symbol_arr, __DAI_BT_MAX_FRAMES);
    backtrace_symbols_fd(symbol_arr, num_addrs, STDOUT_FILENO);
    write(STDOUT_FILENO, &nl, 1);
}

__DAI_FN void
__Dai_bt_sighandler(int sig, siginfo_t* siginfo, void* ucontext) {
    ucontext_t ctx = *(ucontext_t*)ucontext;
}

__DAI_FN void
__Dai_init_backtraces(void) {
    int sigs[] = {__DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    const char nserr[] =
        "Daisho has been misconfigured.\n"
        "In Daisho/stdlib/Native/config.h, the list\n"
        "of signals that trigger a backtrace cannot be empty.\n"
        "If you want to disable backtraces, #define __DAI_BACKTRACES_SUPPORTED to 0.";
    __DAI_ASSERT(sigs[0] != 0, nserr);

    /* Ensure backtraces' .so is loaded. */
    void* frames[50];
    int num_frames = backtrace(frames, 50);
    const char bterr[] = "Empty backtrace.";
    __DAI_SANE_ASSERT(num_frames, bterr);

    // Create a temp file buffer.
    char tmpl[] = "/tmp/Daisho Backtrace XXXXXX";
    __Dai_bt_fd = mkstemp(tmpl);
    const char tmperr[] = "Could not create temp file.";
    __DAI_SANE_ASSERT(__Dai_bt_fd != -1, tmperr);

    /* Create sa_mask. This ensures our sighandler is atomic. */
    sigset_t set;
    const char seteerr[] = "Could not empty the sigset.";
    const char seterr[] = "Could not add a signal to the set.";
    __DAI_SANE_ASSERT(sigemptyset(&set), seteerr);
    for (size_t i = 0; i < num_sigs; i++) {
        __DAI_SANE_ASSERT(sigaddset(&set, sigs[i]), seterr);
    }

    /* Install Handlers */
    const char sseterr[] = "Could not install a signal handler.";
    for (size_t i = 0; i < num_sigs; i++) {
        struct sigaction action;
        action.sa_sigaction = __Dai_bt_sighandler;
        action.sa_flags = SA_SIGINFO;
        action.sa_mask = set;
        __DAI_SANE_ASSERT(!sigaction(sigs[i], &action, NULL), sseterr);
    }
}

__DAI_FN void
__Dai_raise_test_backtrace_signal(void) {
    /*
     * Init is called before this. So, if __DAI_BACKTRACE_SYMBOLS expands to
     * nothing, we'll have already errored. However, the +0 is needed so it will
     * still compile.
     */
    int sigs[] = {__DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    raise(sigs[0]);
}

#else /* Backtraces unsupported */
static void __DAI_NEVER_INLINE
__Dai_print_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    fprintf(stderr, buf);
}

static void __DAI_NEVER_INLINE
__Dai_low_mem_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    write(STDERR_FILENO, buf, strlen(buf));
}
#endif

#endif /* __DAI_STDLIB_BACKTRACE */
