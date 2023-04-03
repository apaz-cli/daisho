#ifndef _DAI_STDLIB_BACKTRACE
#define _DAI_STDLIB_BACKTRACE

#include "../PreProcessor/PreProcessor.h"
#include "Buffering.h"
#include "Error.h"

#if _DAI_USING_BACKTRACES

#define _DAI_BT_BUF_CAP ((size_t)(_DAI_PAGESIZE * 64))

static size_t _Dai_bt_buf_size;
static char _Dai_bt_buffer[_DAI_BT_BUF_CAP];
static FILE* _Dai_bt_stream;
static int _Dai_bt_fd;

_DAI_FN void
_Dai_unsafe_bt_header(void) {
    const char sthead[] = _DAI_COLOR_HEAD
        "***************\n"
        "* Stack Trace *\n"
        "***************\n" _DAI_COLOR_RESET;
    fprintf(stderr, sthead);
}

_DAI_FN void
_Dai_unsafe_bt_footer(char* sigstr) {
    const char na[] = "N/A";
    const char success[] = "0 (Success)";
    const char fmt[] = _DAI_COLOR_MAGENTA
        "Errno: " _DAI_COLOR_RESET " " _DAI_COLOR_BLUE "%s" _DAI_COLOR_RESET "\n" _DAI_COLOR_MAGENTA
        "Signal:" _DAI_COLOR_RESET " " _DAI_COLOR_BLUE "%s" _DAI_COLOR_RESET "\n\n";
    char errstr[32];
    errstr[0] = '\0';
    if (errno) strerror_r(errno, errstr, 32);

    const char* errmsg = errno ? errstr : success;
    fprintf(stderr, fmt, errmsg, sigstr ? sigstr : na);
}

/* Obtain a backtrace and print it to stdout.
 * Signal handlers are hell. Therefore, this is a "best effort" scenario.
 */
typedef struct {
    char* file;
    char* func;
    char* addr;
    char* source;
    char* line;
    char* basename;
} _Dai_SymInfo;

/* This looks ugly, and it is. But, it null terminates
 * and returns the positions of the file, name, and
 * address a frame of a glibc backtrace.
 */
_DAI_FN _Dai_SymInfo
_Dai_SymInfo_parse(char* str) {
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
    _Dai_SymInfo info = {file, func, addr, NULL, 0, NULL};
    return info;
}

_DAI_FN char*
_Dai_simplifyPath(char* path) {
    char state = 1;
    char c;
    int ri = 1;
    int wi = 1;
    while ((c = path[ri]) != '\0') {
        if (state == 0) {
            if (c == '/') {
                state = 1;
            }
            path[wi] = path[ri];
            ri++;
            wi++;
            continue;
        } else if (state == 1) {
            if (c == '/') {
                ri++;
                continue;
            }
            if (c == '.') {
                state = 2;
                ri++;
                continue;
            }
            state = 0;
            path[wi] = path[ri];
            ri++;
            wi++;
            continue;
        }
        if (c == '/') {
            state = 1;
            ri++;
            continue;
        }
        if (c == '.') {
            if (path[ri + 1] != '/' && path[ri + 1] != '\0') {
                state = 0;
                ri -= 1;
                continue;
            }
            int slashes = 2;
            while (slashes > 0 && wi != 0) {
                wi--;
                if (path[wi] == '/') {
                    slashes--;
                }
            }
            state = 1;
            ri++;
            wi++;
            continue;
        }
        state = 0;
        path[wi++] = '.';
        path[wi] = path[ri];
        ri++;
        wi++;
        continue;
    }
    wi -= wi > 1 && path[wi - 1] == '/';
    path[wi] = '\0';
    return path;
}

_DAI_FN void
_Dai_SymInfo_print(_Dai_SymInfo info) {
    fprintf(stderr, _DAI_COLOR_FILE "%s:" _DAI_COLOR_RESET " ", info.file);
    info.func ? fprintf(stderr, _DAI_COLOR_FUNC "%s()" _DAI_COLOR_RESET " at ", info.func)
              : fprintf(stderr, _DAI_COLOR_FUNC "%s" _DAI_COLOR_RESET " at ", "UNKNOWN");
    fprintf(stderr, _DAI_COLOR_PNTR "%s" _DAI_COLOR_RESET "\n", info.addr);
    fflush(stderr);
}

static void _DAI_NEVER_INLINE
_Dai_unsafe_print_backtrace(void) {
    void* symbol_arr[_DAI_BT_MAX_FRAMES];
    char** symbol_strings = NULL;
    int num_addrs, i;
    num_addrs = backtrace(symbol_arr, _DAI_BT_MAX_FRAMES);
    symbol_strings = backtrace_symbols(symbol_arr, num_addrs);
    if (symbol_strings) {
        _Dai_unsafe_bt_header();
        const char errmsg[] = "Obtained %d stack frames.\n";
        fprintf(stderr, errmsg, num_addrs);
        fflush(stderr);
        for (i = 0; i < num_addrs; i++) _Dai_SymInfo_print(_Dai_SymInfo_parse(symbol_strings[i]));
        _Dai_unsafe_bt_footer(NULL);
        _Dai_newline_flush(stdout);
        free /*no expand*/ (symbol_strings);
    } else {
        const char errmsg[] = "Backtrace failed.\n";
        fputs(errmsg, stderr);
        _Dai_newline_flush(stdout);
    }
}

static void _DAI_NEVER_INLINE
_Dai_low_mem_backtrace(void) {
    const char nl = '\n';
    int num_addrs;
    void* symbol_arr[_DAI_BT_MAX_FRAMES];
    num_addrs = backtrace(symbol_arr, _DAI_BT_MAX_FRAMES);
    backtrace_symbols_fd(symbol_arr, num_addrs, STDERR_FILENO);
    write(STDERR_FILENO, &nl, 1);
}

_DAI_FN void
_Dai_bt_sighandler(int sig, siginfo_t* siginfo, void* ucontext) {
    ucontext_t ctx = *(ucontext_t*)ucontext;
    (void)ctx;
    (void)siginfo;
    fprintf(stderr, "Handled backtrace signal: %s\n", strsignal(sig));
    _Dai_low_mem_backtrace();
    _exit(0);
}

_DAI_FN void
_Dai_init_backtraces(void) {
    int sigs[] = {_DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    const char nserr[] =
        "Daisho has been misconfigured.\n"
        "In Daisho/stdlib/Native/config.h, the list\n"
        "of signals that trigger a backtrace cannot be empty.\n"
        "If you want to disable backtraces, #define _DAI_BACKTRACES_SUPPORTED to 0.";
    _DAI_INIT_SANE_ASSERT(sigs[0] != 0, nserr);

    /* Ensure backtraces' .so is loaded. */
    void* frames[50];
    int num_frames = backtrace(frames, 50);
    const char bterr[] = "Empty backtrace.";
    _DAI_INIT_SANE_ASSERT(num_frames, bterr);

    // Create a temp file buffer.
    char tmpl[] = "/tmp/Daisho Backtrace XXXXXX";
    _Dai_bt_fd = mkstemp(tmpl);
    const char tmperr[] = "Could not create temp file.";
    _DAI_INIT_SANE_ASSERT(_Dai_bt_fd != -1, tmperr);

    /* Create sa_mask. This ensures our sighandler is atomic. */
    sigset_t set;
    const char seteerr[] = "Could not empty the sigset.";
    const char seterr[] = "Could not add a signal to the set.";
    _DAI_INIT_SANE_ASSERT(sigemptyset(&set) == 0, seteerr);
    for (size_t i = 0; i < num_sigs; i++) {
        _DAI_INIT_SANE_ASSERT(sigaddset(&set, sigs[i]) == 0, seterr);
    }

    /* Install Handlers */
    const char sseterr[] = "Could not install a signal handler.";
    for (size_t i = 0; i < num_sigs; i++) {
        struct sigaction action;
        action.sa_sigaction = _Dai_bt_sighandler;
        action.sa_flags = SA_SIGINFO;
        action.sa_mask = set;
        _DAI_INIT_SANE_ASSERT(!sigaction(sigs[i], &action, NULL), sseterr);
    }
}

_DAI_FN void
_Dai_raise_test_backtrace_signal(void) {
    /*
     * Init is called before this. So, if _DAI_BACKTRACE_SYMBOLS expands to
     * nothing, we'll have already errored. However, the +0 is needed so it will
     * still compile.
     */
    int sigs[] = {_DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    const char nserr[] =
        "Daisho has been misconfigured.\n"
        "In Daisho/stdlib/Native/config.h, the list\n"
        "of signals that trigger a backtrace cannot be empty.\n"
        "If you want to disable backtraces, #define _DAI_BACKTRACES_SUPPORTED to 0.\n"
        "Also, call _Dai_init_backtraces before this function.";
    _DAI_ASSERT(num_sigs == 0 || sigs[0] != 0, nserr);

    raise(sigs[0]);
}

#else /* Backtraces unsupported */
static void _DAI_NEVER_INLINE
_Dai_print_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    fprintf(stderr, buf);
}

static void _DAI_NEVER_INLINE
_Dai_low_mem_backtrace(void) {
    const char buf[] = "Backtraces are not supported on this system.\n";
    write(STDERR_FILENO, buf, strlen(buf));
}
#endif

#endif /* _DAI_STDLIB_BACKTRACE */
