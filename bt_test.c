#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bt_head.h"
#include "stdlib/Daisho.h"

// Call addr2line, write path to the source file to the buffer, write the number of characters
// written (including null terminator) to num_written, and return the line number for the info.
// Returns < 0 on a syscall or addr2line failure. Keeps errno set to indicate the error, and returns
// an error code. Otherwise, returns the number of characters written to space, including the null
// terminator, and writes the source file name to info->sourcefile.
__DAI_FN long
__Dai_SymInfo_linenum(__Dai_SymInfo* info, char* space, size_t n) {
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
    char tmp[__DAI_BT_BUF_CAP];
    ssize_t bytes_read = read(pipes[0], tmp, __DAI_BT_BUF_CAP);
    if (bytes_read <= 0) return -10;
    if (bytes_read == __DAI_BT_BUF_CAP) {
        /* Large return probably doesn't matter. It shouldn't come up.
           We can do multiple reads instead of erroring if it becomes a problem. */
        return -11;
    }
    tmp[bytes_read] = '\0';

    // TODO remove when done testing.
    // Print the output of addr2line.
    printf("%s", tmp);

    // We need to return two different things. The line number and the source file.
    // Either could fail independently, resulting in unique return < -1 and no write into info.
    // However, we should still track the errors seperately.
    int lnum_failed = 0;
    int source_failed = 0;

    // Parse line, write to buf. Examples of format:
    // ??:7
    // /path/to/file.c:0
    // /path/to/file.c:??
    // /home/apaz/git/Daisho/tests/scripts/backtrace_test.c:8

    // Seek to the end, then backtrack to the last colon. Save the position of the colon.
    // Then step forward one character. This is the start of the line number.
    size_t pos = 0;
    while (tmp[pos] != '\0') pos++;
    while (tmp[pos] != ':') pos--;
    size_t colonpos = pos;
    pos++;
    long written = pos;

    // Make sure we have enough space to store the source.
    if (n < written) source_failed = 1;

    // Check if we got a ??: for the file.
    if ((colonpos == 2) & (tmp[colonpos - 2] == '?') & (tmp[colonpos - 1] == '?'))
        source_failed = 1;

    // Check if we got a ?? or a zero for the line number.
    if ((tmp[pos] == '?') & (tmp[pos + 1] == '?') | (tmp[pos] == '0')) lnum_failed = 1;

    // Copy the source file from the return of addr2line into the space provided.
    if (!source_failed) {
        for (size_t i = 0; i < colonpos; i++) {
            space[i] = tmp[i];
        }
        space[colonpos] = '\0';

        info->sourcefile = space;
    }

    // Parse line number from addr2line to long, or error for line number.
    if (!lnum_failed) {
        long l = atol(tmp + pos);
        if ((l == LONG_MAX) | (l == LONG_MIN)) return -11;
        info->linenum = l;
    }

    // If ran out of space, return an error.
    if (source_failed) return -12;

    // Return the number of characters written to space.
    return written;
}

__DAI_FN long
__Dai_SymInfo_snwrite(char* s, size_t n, __Dai_SymInfo info) {
    long num_written = 0;

#if __DAI_BT_COLORS
    // "" if !__DAI_ANSI_TERMINAL
    const char func_color[] = __DAI_COLOR_FUNC;
    const char file_color[] = __DAI_COLOR_FILE;
    const char line_color[] = __DAI_COLOR_LINE;
    const char reset_color[] = __DAI_COLOR_RESET;
#else
    const char func_color[] = "";
    const char file_color[] = "";
    const char line_color[] = "";
    const char reset_color[] = "";
#endif
    size_t func_size = sizeof(func_color) - 1;
    size_t file_size = sizeof(file_color) - 1;
    size_t line_size = sizeof(line_color) - 1;
    size_t reset_size = sizeof(reset_color) - 1;

    return 0;
}

// Global. This is necessary, because opening a temp file is not possible in a signal handler.
static int fd;

int
init() {
    // Call backtrace once to load the
    // library so dlopen(), which calls malloc(),
    // is not called inside the signal handler.
    void* frames[__DAI_BT_MAX_FRAMES];
    int num_frames = backtrace(frames, __DAI_BT_MAX_FRAMES);
    if (!num_frames) return 0;

    // Create a temp file buffer.
    char template[] = "/tmp/Daisho Backtrace XXXXXX";
    fd = mkstemp(template);
    if (fd == -1) return 0;

    return 1;
}

// Print the
void
print_trace(void) {
    // Call backtrace.
    __Dai_SymInfo frameinfo[__DAI_BT_MAX_FRAMES];
    void* frames[__DAI_BT_MAX_FRAMES];
    int num_frames = backtrace(frames, __DAI_BT_MAX_FRAMES);
    if (!num_frames) puts("No backtrace.");
    if (num_frames > __DAI_BT_MAX_FRAMES) puts("too long.");

    // Write the backtrace to the temp file dedicated for it during initialization.
    // Unfortunately, redirecting a write() into memory is barely doable and not portable.
    backtrace_symbols_fd(frames, num_frames, fd);

    // Rewind the file
    int ret = lseek(fd, 0, SEEK_SET);
    if (ret == (off_t)-1) {
        close(fd);
        backtrace_symbols_fd(frames, num_frames, STDERR_FILENO);
        return;
    }

    // Read back the file into memory.
    char pages[__DAI_BT_BUF_CAP];
    ssize_t num_read = read(fd, pages, __DAI_BT_BUF_CAP - 1);
    close(fd);

    // TODO remove when done testing.
    write(STDERR_FILENO, pages, num_read);
    puts("");

    // Parse the exename, func, addr from the backtrace.
    char* str = pages;
    for (int n = 0; n < num_frames; n++) {
        // We know that backtrace_symbols_fd() writes each frame, followed by a newline.
        // We're about to mess up the buffer, so figure out where to resume parsing
        // after this frame by advancing to just after the \n.
        char* next = str;
        while ((*next != '\n')) next++;
        next++;

        frameinfo[n] = __Dai_SymInfo_parse(str);
        // fprintf(stderr, "%s %s %s\n", frameinfo[n].file, frameinfo[n].func, frameinfo[n].addr);

        // If we know we've hit main(), stop early.
        // No reason to unwind through libc start stuff.
        if (frameinfo[n].func) {
            if (strcmp(frameinfo[n].func, "main") == 0) {
                num_frames = n + 1;  // idx -> count
            }
        }

        str = next;
    }

    // For each frame (which we now have info for), get the line number.
    char* space = pages + num_read;
    size_t remaining = __DAI_BT_BUF_CAP - num_read;
    for (int n = 0; n < num_frames; n++) {
        // Call addr2line
        long written = __Dai_SymInfo_linenum(frameinfo + n, space, remaining);

        // If a syscall failed, error out.
        if (written < -1) {
            // TODO use write() here.
            backtrace_symbols_fd(frames, num_frames, fd);
            fflush(stderr);
            fprintf(stderr, "Backtrace failed with error %ld.\nErrno: %i\n", written, errno);
            return;
        }

        space += written;
        remaining -= written;
    }
}

int
main() {
    if (!init()) puts("Failed to initialize.");
    indir1();
}
