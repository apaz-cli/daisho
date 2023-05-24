#ifndef _DAI_STDLIB_BACKTRACE
#define _DAI_STDLIB_BACKTRACE

#include "../PreProcessor/PreProcessor.h"
#include "Buffering.h"
#include "Error.h"
#include "Signals.h"
#include "Wrappers.h"

#define _DAI_BT_BUF_CAP ((size_t)(_DAI_PAGESIZE * 64))

#define _DAI_BT_ERR_NOTENABLED -1
#define _DAI_BT_ERR_BTFAIL -2
#define _DAI_BT_ERR_BTTOOLONG -3
#define _DAI_BT_ERR_LSEEKF -4
#define _DAI_BT_ERR_LSEEKS -5
#define _DAI_BT_ERR_READ -6
#define _DAI_BT_ERR_WRITE -7
#define _DAI_BT_ERR_PIPE -8
#define _DAI_BT_ERR_FORK -9
#define _DAI_BT_ERR_CLOSEPIPE -10
#define _DAI_BT_ERR_DUP2 -11
#define _DAI_BT_ERR_EXECV -12
#define _DAI_BT_ERR_WAITPID -13
#define _DAI_BT_ERR_SUBPFAIL -14
#define _DAI_BT_ERR_SUBPREAD -15
#define _DAI_BT_ERR_BUFTOOSMALL -16
#define _DAI_BT_ERR_CLOSERPIPE -17
#define _DAI_BT_ERR_NOCOLON -18
#define _DAI_BT_ERR_NOSPACE -19

_DAI_FN long _Dai_write_backtrace(int, char*, size_t, int, int, int);
_DAI_FN void _Dai_init_backtrace(void);
_DAI_FN void _Dai_raise_backtrace(void);
_DAI_FN int _Dai_scratch_fd_create(void);

#if _DAI_USING_BACKTRACES
static int _Dai_backtrace_fd;
static int _Dai_backtrace_sighandlers_installed = 0;
#endif

_DAI_FN void
_Dai_raise_backtrace(void) {
#define _DAI_BT_EXIT(msg)                                                     \
    do {                                                                      \
        int werr = 0;                                                         \
        const char exit_msg[] = msg "\n";                                     \
        _Dai_write_wrapper(STDERR_FILENO, exit_msg, sizeof(exit_msg), &werr); \
        _exit(0);                                                             \
    } while (0)
#if !_DAI_HAS_BACKTRACES
    _DAI_BT_EXIT("When Daisho was configured, glibc backtraces were not detected as supported.");
#endif
#if !_DAI_BACKTRACES_ENABLED
    _DAI_BT_EXIT("When Daisho was configured, backtraces were not enabled.");
#endif
#if _DAI_USING_BACKTRACES
    if (!_Dai_backtrace_sighandlers_installed) _Dai_init_backtrace();
#endif

    int sigs[] = {_DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    if (!sigs[0])
        _DAI_BT_EXIT(
            "No signals have been set up to cause a backtrace. To change this, \n"
            "#define _DAI_BACKTRACE_SIGNALS to a comma-separated list of signals.");

#if _DAI_USING_BACKTRACES
    if (raise(sigs[0])) _DAI_BT_EXIT("Could not raise() the test signal.");
#else
#endif
}

#if !_DAI_USING_BACKTRACES
/* Backtraces unsupported */
_DAI_FN long
_Dai_write_backtrace(int scratch_fd, char* buf, size_t n, int err_no, int signal_no, int color) {
    (void)scratch_fd;
    (void)buf;
    (void)n;
    (void)err_no;
    (void)signal_no;
    (void)color;
    return _DAI_BT_ERR_NOTENABLED;
}

_DAI_FN void
_Dai_init_backtrace(void) {}

#else /* _DAI_USING_BACKTRACES */

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

// Call addr2line, write path to the source file to the buffer, write the number of characters
// written (including null terminator) to num_written, and return the line number for the info.
// Returns < 0 on a syscall or addr2line failure. Keeps errno set to indicate the error, and
// returns an error code. Otherwise, returns the number of characters written to space,
// including the null terminator, and writes the source file name to info->sourcefile.
_DAI_FN long
_Dai_SymInfo_addr2line(_Dai_SymInfo* info, char* space, size_t n) {
    // Create a file descriptor for addr2line to pipe to.
    errno = 0;
    int pipes[2];
    if (pipe(pipes) == -1) return _DAI_BT_ERR_PIPE;

    // Fork
    int status, ret;
    int pid = fork();
    if (pid == -1) return _DAI_BT_ERR_FORK;
    if (!pid) {
        // Child

        // Redirect stdout to pipe.
        ret = close(pipes[0]);
        if (ret == -1) return _DAI_BT_ERR_CLOSEPIPE;
        ret = dup2(pipes[1], STDOUT_FILENO);
        if (ret == -1) return _DAI_BT_ERR_DUP2;

        // Replace execution image with addr2line or fail.
        char addrpath[] = "/usr/bin/addr2line";
        char addrname[] = "addr2line";
        char opt1[] = "-e";
        char opt2[] = "-Cpi";
        char* addr2lineargs[] = {addrname, opt1, info->file, opt2, info->addr, NULL};
        execv(addrpath, addr2lineargs);
        return _DAI_BT_ERR_EXECV;
    }

    // Wait for addr2line to write to pipe.
    ret = close(pipes[1]);
    if (ret == -1) return _DAI_BT_ERR_CLOSEPIPE;
    ret = waitpid(pid, &status, 1);
    if (ret == -1) return _DAI_BT_ERR_WAITPID;
    if (WIFEXITED(status) && WEXITSTATUS(status)) {
        if (WEXITSTATUS(status) == _DAI_BT_ERR_EXECV) return _DAI_BT_ERR_EXECV;
        errno = ENOENT;
        return _DAI_BT_ERR_SUBPFAIL;
    }

    // Read from the pipe (addr2line child stdout), and null terminate.
    char tmp[_DAI_BT_BUF_CAP];
    int read_err = 0;
    ssize_t bytes_read = _Dai_read_wrapper(pipes[0], tmp, _DAI_BT_BUF_CAP, &read_err);
    if (bytes_read <= 0 || read_err) return _DAI_BT_ERR_SUBPREAD;
    if (bytes_read >= (ssize_t)_DAI_BT_BUF_CAP) {
        /* Large return probably doesn't matter. It shouldn't come up.
           We can do multiple reads instead of erroring if it becomes a problem. */
        return _DAI_BT_ERR_BUFTOOSMALL;
    }
    ret = close(pipes[0]);
    if (ret == -1) return _DAI_BT_ERR_CLOSERPIPE;
    tmp[bytes_read] = '\0';

    // We need to return two different things. The line number and the source file.
    // Either could fail independently, resulting in unique return < -1 and no write into info.
    // However, we should still track the errors seperately.
    int line_failed = 0;
    int source_failed = 0;

    // Parse line, write to buf. Examples of format:
    // ??:7
    // /path/to/file.c:0
    // /path/to/file.c:??
    // /path/to/file.c:?
    // /home/apaz/git/Daisho/tests/scripts/backtrace_test.c:8

    // There's a solid chance that the following parsing is more robust than it has to be.
    // Oh well.

    // Seek to the end, then backtrack to the last colon. Save the position of the colon.
    // Then step forward one character. This is the start of the line number.
    size_t pos = 0;
    bool hascolon = 0;
    while (tmp[pos] != '\0') (tmp[pos] == ':' ? (hascolon = 1) : 0), pos++;
    if (!hascolon) return _DAI_BT_ERR_NOCOLON;
    while (tmp[pos] != ':') pos--;
    size_t colonpos = pos;
    tmp[colonpos] = '\0';
    pos++;
    size_t written = 0;

    // Make sure we have enough space to store the source.
    if (n < written) {
        source_failed = 1;
    }

    // Check if we got a ??: for the file.
    if ((colonpos == 2) & (tmp[colonpos - 2] == '?') & (tmp[colonpos - 1] == '?'))
        source_failed = 1;

    // Check if we got a ? or a zero for the line number.
    if ((tmp[pos] == '?') | (tmp[pos] == '0')) line_failed = 1;

    // Copy the line number and source file from the return of addr2line into the space
    // provided.
    if (!source_failed) {
        // Copy, null terminate over the colon or end, and add to info.
        _Dai_simplifyPath(tmp);
        written = strlen(tmp) + 1;
        if (n <= written) {
            info->source = NULL;
            info->basename = NULL;
            return _DAI_BT_ERR_NOSPACE;
        }
        for (size_t i = 0; i < written; i++) space[i] = tmp[i];

        // Grab base name from the end of the path as well.
        size_t end = written;
        while (space[end] != '/') end--;
        info->source = space;
        info->basename = space + end + 1;
    } else {
        info->source = NULL;
        info->basename = NULL;
    }

    // Parse line number from addr2line to long, or error for line number.
    if (!line_failed) {
        size_t copied = 0;
        char* line = tmp + colonpos + 1;
        char* into = space + written;
        while ((line[copied] != '\n') & (line[copied] != '\0')) {
            into[copied] = line[copied];
            copied++;
        }
        into[copied] = '\0';
        written += copied + 1;
        info->line = into;

    } else {
        info->line = 0;
    }

    // Return the number of characters written to space.
    return written;
}

_DAI_FN long
_Dai_bt_append(char* s, size_t n, char* append) {
    if (append) {
        size_t sn = strlen(append);
        if (sn > n) return _DAI_BT_ERR_NOSPACE;
        for (size_t i = 0; i < sn; i++) s[i] = append[i];
        return (long)sn;
    } else {
        return _Dai_bt_append(s, n, "(null)");
    }
}

#define _DAI_BT_APPEND(append)                      \
    do {                                            \
        tmpret = _Dai_bt_append(s, n, (append));    \
        if (tmpret < 0) return _DAI_BT_ERR_NOSPACE; \
        num_written += (long)tmpret;                \
        s += (size_t)tmpret;                        \
        n -= (size_t)tmpret;                        \
    } while (0)

_DAI_FN long
_Dai_bt_header(char* s, size_t n, int color) {
    long tmpret;
    long num_written = 0;
    char sthead[] =
        "***************\n"
        "* Stack Trace *\n"
        "***************\n";
    if (color) _DAI_BT_APPEND(_DAI_COLOR_HEAD);
    _DAI_BT_APPEND(sthead);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    return num_written;
}

_DAI_FN long
_Dai_bt_footer(char* s, size_t n, int err_no, int signal, int color) {
    long tmpret;
    long num_written = 0;

    char err_string[256];
    char* errno_string = NULL;
    if (!err_no) errno_string = "0 (Success)";
    if (err_no) errno_string = _Dai_strerror_r(err_no, err_string, 256);
    if (!errno_string) errno_string = "FAILED TO GET ERRNO STRING";

    char* signal_string = NULL;
    if (!signal) signal_string = "N/A";
    if (signal) signal_string = (char*)_Dai_signal_to_str(signal);
    if (!signal_string) signal_string = "FAILED TO GET SIGNAL STRING";

    if (color) _DAI_BT_APPEND(_DAI_COLOR_MAGENTA);
    _DAI_BT_APPEND("Errno:");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("  ");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_BLUE);
    _DAI_BT_APPEND(errno_string);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");

    if (color) _DAI_BT_APPEND(_DAI_COLOR_MAGENTA);
    _DAI_BT_APPEND("Signal:");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND(" ");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_BLUE);
    _DAI_BT_APPEND(signal_string);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n\n");

    return num_written;
}

_DAI_FN long
_Dai_SymInfo_snwrite(char* s, size_t n, _Dai_SymInfo info, int color) {
    long tmpret = 0;
    long num_written = 0;
    _DAI_BT_APPEND("file: ");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_FILE);
    _DAI_BT_APPEND(info.file);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");
    _DAI_BT_APPEND("func: ");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_FUNC);
    _DAI_BT_APPEND(info.func);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");
    _DAI_BT_APPEND("addr: ");
    _DAI_BT_APPEND(info.addr);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");
    _DAI_BT_APPEND("source: ");
    _DAI_BT_APPEND(info.source);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");
    _DAI_BT_APPEND("line: ");
    if (color) _DAI_BT_APPEND(_DAI_COLOR_LINE);
    _DAI_BT_APPEND(info.line);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n");
    _DAI_BT_APPEND("basename: ");
    _DAI_BT_APPEND(info.basename);
    if (color) _DAI_BT_APPEND(_DAI_COLOR_RESET);
    _DAI_BT_APPEND("\n\n");
    return num_written;
}
#undef _DAI_BT_APPEND

// Call backtrace(), then backtrace_symbols_fd() into the backtrace file.
// Rewind the file, read it back into stack memory, reset the file for next time.
// Parse the backtrace, decode with addr2line
// write() a pretty-printed result to print_fd
// Important note: For scratch_fd, pass _Dai_backtrace_fd iff being installed as a signal
// handler below. Otherwise, make your own scratch file buffer.
_DAI_FN long
_Dai_write_backtrace(int scratch_fd, char* buf, size_t n, int err_no, int signal_no, int color) {
    // Call backtrace.
    void* frames[_DAI_BT_MAX_FRAMES];
    int num_frames = backtrace(frames, _DAI_BT_MAX_FRAMES);
    if (num_frames <= 0) return _DAI_BT_ERR_BTFAIL;                     // No backtrace
    if (num_frames > _DAI_BT_MAX_FRAMES) return _DAI_BT_ERR_BTTOOLONG;  // Backtrace too long

    // Write the backtrace to the temp file dedicated for it during initialization.
    // Unfortunately, redirecting a write() into memory is barely doable and not portable.
    backtrace_symbols_fd(frames, num_frames, scratch_fd);

    // Rewind the file
    int ret = lseek(scratch_fd, 0, SEEK_SET);
    if (ret == (off_t)-1) return _DAI_BT_ERR_LSEEKF;

    // Read back the file into memory.
    char pages[_DAI_BT_BUF_CAP];
    int read_err = 0;
    ssize_t num_read = _Dai_read_wrapper(scratch_fd, pages, _DAI_BT_BUF_CAP - 1, &read_err);
    if (read_err) return _DAI_BT_ERR_READ;

    char* space = pages + num_read;
    size_t remaining = _DAI_BT_BUF_CAP - num_read;

    // Reset the file offset for the next time we backtrace.
    lseek(scratch_fd, 0, SEEK_SET);
    if (ret == (off_t)-1) return _DAI_BT_ERR_LSEEKS;

    // Parse the exename, func, addr from the backtrace.
    // The _Dai_SymInfo structs point into data in `pages` before `space`.
    char* str = pages;
    _Dai_SymInfo frameinfo[_DAI_BT_MAX_FRAMES];
    for (int n = 0; n < num_frames; n++) {
        // We know that backtrace_symbols_fd() writes each frame, followed by a newline.
        // We're about to mess up the buffer, so figure out where to resume parsing
        // after this frame by advancing to just after the \n.
        char* next = str;
        while ((*next != '\n')) next++;
        next++;

        frameinfo[n] = _Dai_SymInfo_parse(str);

        // If we know we've hit main(), stop early.
        // No reason to unwind through libc start stuff.
        if (frameinfo[n].func) {
            if (strcmp(frameinfo[n].func, "main") == 0) {
                num_frames = n + 1;  // Keep this frame.
            } else if (strcmp(frameinfo[n].func, "__libc_start_main") == 0) {
                num_frames = n;  // Cut off this frame.
            }
        }

        str = next;
    }

    // For each frame (which we now have info for), get the line number.
    for (int n = 0; n < num_frames; n++) {
        // Call addr2line
        long written = _Dai_SymInfo_addr2line(frameinfo + n, space, remaining);

        // If a syscall failed, error out.
        if (written < 0) return written;

        // Advance through the space
        space += written;
        remaining -= written;
    }

    // char* display = space;
    // size_t display_remaining = remaining;
    char* display_save = buf;
    size_t display_written = 0;

    long written = _Dai_bt_header(buf, n, color);
    if (written < 0) return written;
    buf += written;
    n -= written;
    display_written += written;

    for (int i = 0; i < num_frames; i++) {
        long written = _Dai_SymInfo_snwrite(buf, n, frameinfo[i], color);
        if (written < 0) return written;

        // Advance
        buf += written;
        n -= written;
        display_written += written;
    }

    written = _Dai_bt_footer(buf, n, err_no, signal_no, color);
    if (written < 0) return written;
    buf += written;
    n -= written;
    display_written += written;

    buf[display_written++] = '\0';
    n--;

    // TODO actual bounds checking on appending to pages/space/display.

    return display_written;
}

_DAI_FN void
_Dai_bt_sighandler(int sig, siginfo_t* siginfo, void* ucontext) {
    (void)ucontext;
    (void)siginfo;

    int saved_e = errno;

    char pages[_DAI_BT_BUF_CAP];
    long written = _Dai_write_backtrace(_Dai_backtrace_fd, pages, _DAI_BT_BUF_CAP, saved_e, sig,
                                        _DAI_BT_COLORS);
    if (written < 0) {
        // For now do nothing on failure
    } else {
        int err_ret = 0;
        size_t have_written = _Dai_write_wrapper(STDERR_FILENO, pages, (size_t)written, &err_ret);
        if (err_ret) {
            // Nothing on failure again
        }
    }

    _exit(0);
}

_DAI_FN void
_Dai_init_backtrace(void) {
    /* Ensure backtraces' .so is loaded. */
    void* frame;
    int num_frames = backtrace(&frame, 1);
    const char bterr[] = "Empty backtrace.";
    _DAI_INIT_SANE_ASSERT(num_frames, bterr);

    // Create a temp file buffer.
    int btfd = _Dai_scratch_fd_create();
    const char tmperr[] = "Could not create scratch file descriptor.";
    _DAI_INIT_SANE_ASSERT(btfd != -1, tmperr);
    _Dai_backtrace_fd = btfd;

    // Don't install signal handlers if there are none to install.
    int sigs[] = {_DAI_BACKTRACE_SIGNALS + 0};
    size_t num_sigs = sizeof(sigs) / sizeof(int);
    if (!sigs[0]) return;

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

    _Dai_backtrace_sighandlers_installed = 1;
}

#endif /* _DAI_USING_BACKTRACES */

_DAI_FN int
_Dai_scratch_fd_create(void) {
    int ret = -1;
#ifdef __USE_GNU
    // Don't touch disk unless we have to.
    if (ret == -1) {
        char memfd_name[] = "Daisho_Backtrace";
        ret = memfd_create(memfd_name, 0);
    }
#endif
    if (ret == -1) {
        char tmp_template[] = "/tmp/Daisho_Backtrace_XXXXXX";
        ret = mkstemp(tmp_template);
    }
    return ret;
}

#endif /* _DAI_STDLIB_BACKTRACE */
