#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define _DAI_TESTING_BACKTRACES
#include "stdlib/Daisho.h"

_DAI_FN char*
_Dai_simplifyPath(char* path) {
    /* https://leetcode.com/problems/simplify-path/discuss/266774/S-100-speed-(4-ms)-100-memory-(7-mb)
     */
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
// Returns < 0 on a syscall or addr2line failure. Keeps errno set to indicate the error, and returns
// an error code. Otherwise, returns the number of characters written to space, including the null
// terminator, and writes the source file name to info->sourcefile.
_DAI_FN long
_Dai_SymInfo_addr2line(_Dai_SymInfo* info, char* space, size_t n) {
    // Create a file descriptor for addr2line to pipe to.
    errno = 0;
    int pipes[2];
    if (pipe(pipes) == -1) return -1;

    // Fork
    int status, ret;
    int pid = fork();
    if (pid == -1) return -2;
    if (!pid) {
        // Child

        // Redirect stdout to pipe.
        ret = close(pipes[0]);
        if (ret == -1) return -3;
        ret = dup2(pipes[1], STDOUT_FILENO);
        if (ret == -1) return -4;

        // Replace execution image with addr2line or fail.
        char addrpath[] = "/usr/bin/addr2line";
        char addrname[] = "addr2line";
        char* addr2lineargs[] = {addrname, "-e", info->file, "-Cpi", info->addr, NULL};
        execv(addrpath, addr2lineargs);
        return -5;
    }

    // Wait for addr2line to write to pipe.
    ret = close(pipes[1]);
    if (ret == -1) return -6;
    ret = waitpid(pid, &status, 1);
    if (ret == -1) return -7;
    if (WIFEXITED(status) && WEXITSTATUS(status)) {
        if (WEXITSTATUS(status) == -5) return -8;
        errno = ENOENT;
        return -9;
    }

    // Read from the pipe (addr2line child stdout), and null terminate.
    char tmp[_DAI_BT_BUF_CAP];
    ssize_t bytes_read = read(pipes[0], tmp, _DAI_BT_BUF_CAP);
    if (bytes_read <= 0) return -10;
    if (bytes_read == _DAI_BT_BUF_CAP) {
        /* Large return probably doesn't matter. It shouldn't come up.
           We can do multiple reads instead of erroring if it becomes a problem. */
        return -11;
    }
    ret = close(pipes[0]);
    if (ret == -1) return -12;
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
    while (tmp[pos] != '\0') pos++;
    while (tmp[pos] != ':') pos--;
    size_t colonpos = pos;
    tmp[colonpos] = '\0';
    pos++;
    long written = 0;

    // Make sure we have enough space to store the source.
    if (n < written) {
        source_failed = 1;
    }

    // Check if we got a ??: for the file.
    if ((colonpos == 2) & (tmp[colonpos - 2] == '?') & (tmp[colonpos - 1] == '?'))
        source_failed = 1;

    // Check if we got a ? or a zero for the line number.
    if ((tmp[pos] == '?') | (tmp[pos] == '0')) line_failed = 1;

    // Copy the line number and source file from the return of addr2line into the space provided.
    if (!source_failed) {
        // Copy, null terminate over the colon or end, and add to info.
        _Dai_simplifyPath(tmp);
        written = strlen(tmp) + 1;
        if (n <= written) {
            info->source = NULL;
            info->basename = NULL;
            return -13;
        }
        for (size_t i = 0; i < written; i++) space[i] = tmp[i];
        info->source = space;

        // Grab base name from the end of the path as well.
        size_t end = written;
        while (space[end] != '/') end--;
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
_Dai_SymInfo_snwrite(char* s, size_t n, _Dai_SymInfo info, size_t width) {
    long num_written = 0;

#if _DAI_BT_COLORS
    // "" if !_DAI_ANSI_TERMINAL
    const char func_color[] = _DAI_COLOR_FUNC;
    const char file_color[] = _DAI_COLOR_FILE;
    const char line_color[] = _DAI_COLOR_LINE;
    const char reset_color[] = _DAI_COLOR_RESET;
    const char head_color[] = _DAI_COLOR_HEAD;
#else
    const char func_color[] = "";
    const char file_color[] = "";
    const char line_color[] = "";
    const char reset_color[] = "";
    const char head_color[] "";
#endif
    char unk[] = "UNKNOWN";

    size_t unk_size = sizeof(unk) - 1;
    size_t func_size = sizeof(func_color) - 1;
    size_t file_size = sizeof(file_color) - 1;
    size_t line_size = sizeof(line_color) - 1;
    size_t reset_size = sizeof(reset_color) - 1;
    size_t head_size = sizeof(head_color) - 1;

    size_t total_size = 0;
    // Box
    // color|reset <information> color|reset
    total_size += (2 * head_size) + 2 + (2 * reset_size);

    if (info.func) {
        // Function
        total_size += func_size + (info.func ? strlen(info.func) + 2 : unk_size) + reset_size;
        // line
        if (info.line) total_size += line_size + strlen(info.line) + reset_size;
        printf("file: %s\nfunc: %s\naddr: %s\nsource: %s\nline: %s\nbasename: %s\n\n", info.file,
               info.func, info.addr, info.source, info.line, info.basename);
    } else {
        // Binary
        total_size += file_size + strlen(info.file) + reset_size;
        //        printf("file: %s\naddr: %s\n\n", info.file, info.addr);
        printf("file: %s\nfunc: %s\naddr: %s\nsource: %s\nline: %s\nbasename: %s\n\n", info.file,
               info.func, info.addr, info.source, info.line, info.basename);
    }

    return 0;
}

// Global. This is necessary, because opening a temp file is not possible in a signal handler.
static int fd;

int
init() {
    // Call backtrace once to load the
    // library so dlopen(), which calls malloc(),
    // is not called inside the signal handler.
    void* frames[_DAI_BT_MAX_FRAMES];
    int num_frames = backtrace(frames, _DAI_BT_MAX_FRAMES);
    if (!num_frames) return 1;

    // Create a temp file buffer.
    char template[] = "/tmp/Daisho Backtrace XXXXXX";
    fd = mkstemp(template);
    if (fd == -1) return 2;

    return 0;
}

long print_trace(void) {
    // Call backtrace.
    _Dai_SymInfo frameinfo[_DAI_BT_MAX_FRAMES];
    void* frames[_DAI_BT_MAX_FRAMES];
    int num_frames = backtrace(frames, _DAI_BT_MAX_FRAMES);
    if (!num_frames) return 1;                       // No backtrace
    if (num_frames > _DAI_BT_MAX_FRAMES) return 2;  // Backtrace too long

    // Write the backtrace to the temp file dedicated for it during initialization.
    // Unfortunately, redirecting a write() into memory is barely doable and not portable.
    backtrace_symbols_fd(frames, num_frames, fd);

    // Rewind the file
    int ret = lseek(fd, 0, SEEK_SET);
    if (ret == (off_t)-1) {
        close(fd);
        backtrace_symbols_fd(frames, num_frames, STDERR_FILENO);
        return 3;
    }

    // Read back the file into memory.
    char pages[_DAI_BT_BUF_CAP];
    ssize_t num_read = read(fd, pages, _DAI_BT_BUF_CAP - 1);

    // Reset the file offset for the next time we backtrace.
    lseek(fd, 0, SEEK_SET);
    if (ret == (off_t)-1) {
        close(fd);
        backtrace_symbols_fd(frames, num_frames, STDERR_FILENO);
        return 4;
    }

    // Parse the exename, func, addr from the backtrace.
    char* str = pages;
    for (int n = 0; n < num_frames; n++) {
        // We know that backtrace_symbols_fd() writes each frame, followed by a newline.
        // We're about to mess up the buffer, so figure out where to resume parsing
        // after this frame by advancing to just after the \n.
        char* next = str;
        while ((*next != '\n')) next++;
        next++;

        frameinfo[n] = _Dai_SymInfo_parse(str);
        // fprintf(stderr, "%s %s %s\n", frameinfo[n].file, frameinfo[n].func, frameinfo[n].addr);

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
    char* space = pages + num_read;
    size_t remaining = _DAI_BT_BUF_CAP - num_read;
    for (int n = 0; n < num_frames; n++) {
        // Call addr2line
        long written = _Dai_SymInfo_addr2line(frameinfo + n, space, remaining);

        // If a syscall failed, error out.
        if (written <= -1) {
            // TODO use write() here.
            backtrace_symbols_fd(frames, num_frames, STDERR_FILENO);
            return written;
        }

        // Advance through the space
        space += written;
        remaining -= written;
    }

    for (size_t i = 0; i < num_frames; i++) {
        long written = _Dai_SymInfo_snwrite(space, remaining, frameinfo[i], 80);
        if (written < 0) {
            backtrace_symbols_fd(frames, num_frames, STDERR_FILENO);
            return 5;
        }

        // Advance
        space += written;
        remaining -= written;
    }

    return 0;
}

int
main() {
    if (init()) puts("Failed to initialize.");
    return print_trace();
}
