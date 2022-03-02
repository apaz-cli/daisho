
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "stdlib/Daisho.h"

// Call addr2line, write path to the source file to the buffer, write the number of characters written 
// (including null terminator) to num_written, and return the line number for the info.
// Returns < -1 on a syscall failure. Keeps errno set to indicate the error.
// Returns -1 when addr2line returns ?? as the file or line number.
// Otherwise, returns the line number.
__DAI_FN long
__Dai_SymInfo_linenum(__Dai_SymInfo info, char* buf, size_t* num_written) {
    // Create a file descriptor for addr2line to pipe to.
    errno = 0;
    int pipes[2];
    if (pipe(pipes) == -1) return -2;

    // Fork
    int status, ret;
    int pid = fork();
    if (pid == -1) return -3;
    if (!pid) {
        // Child

        // Redirect stdout to pipe.
        ret = close(pipes[0]);
        if (ret == -1) return -4;
        ret = dup2(pipes[1], STDOUT_FILENO);
        if (ret == -1) return -5;

        // Replace execution image with addr2line or fail.
        char addrpath[] = "/usr/bin/addr2line";
        char addrname[] = "addr2line";
        char* addr2lineargs[] = {addrname, "-e", info.file, "-Cfpi", info.addr, NULL};
        execv(addrpath, addr2lineargs);
        return -6;
    }
    // Parent

    // Wait for addr2line to write to pipe.
    ret = close(pipes[1]);
    if (ret == -1) return -7;
    ret = waitpid(pid, &status, 1);
    if (ret == -1) return -8;
    if (WIFEXITED(status) && WEXITSTATUS(status)) return -9;

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
    printf("%s", tmp);

    // Parse line, write to buf. Example of format:
    // /home/apaz/git/Daisho/tests/scripts/backtrace_test.c:8

    // Check if we got a ??: for the file.
    size_t pos = 0;
    if ((tmp[pos] == '?') & (tmp[pos + 1] == '?') & (tmp[pos + 2] == ':')) return -1;

    // Seek to the end.
    while (tmp[pos] != '\0') pos++;

    // Backtrack to the character past the last colon.
    while (tmp[pos] != ':') pos--;
    pos++;

    // Check if we got a ?? for the line number.
    if ((tmp[pos] == '?') & (tmp[pos + 1] == '?')) return -1;

    // Parse line number from addr2line to long.
    errno = 0;
    long l = strtol(tmp + pos, NULL, 10);
    return errno ? -12 : l;
}

__DAI_FN long
__Dai_SymInfo_snwrite(char* s, size_t n, __Dai_SymInfo info) {
    long num_written = 0;
#if __DAI_BT_COLORS
    char func_color[] = __DAI_COLOR_FUNC;
    char file_color[] = __DAI_COLOR_FILE;
    char line_color[] = __DAI_COLOR_LINE;
#endif
    
    


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

    // Rewind and read back the file into memory.
    lseek(fd, 0, SEEK_SET);
    char pages[__DAI_BT_BUF_CAP];
    ssize_t num_read = read(fd, pages, __DAI_BT_BUF_CAP - 1);
    close(fd);

    // Print the original backtrace.
    // TODO remove.
    write(STDOUT_FILENO, pages, num_read);
    puts("");

    // Parse the exename, func, addr from the backtrace.
    char* str = pages;
    for (int n = 0; n < num_frames; n++) {
        char* next = str;
        while ((*next != '\n')) next++;
        next++;

        frameinfo[n] = __Dai_SymInfo_parse(str);
        // fprintf(stderr, "%s %s %s\n", frameinfo[n].file, frameinfo[n].func, frameinfo[n].addr);

        // If we know we've hit, main(), stop early.
        // No reason to unwind through libc start stuff.
        if (frameinfo[n].func) {
            if (strcmp(frameinfo[n].func, "main") == 0) {
                num_frames = n + 1;
            }
        }

        str = next;
    }

    // For each frame (which we now have info for), get the line number.
    int failed = 0;
    for (int n = 0; n < num_frames; n++) {
        long res = __Dai_SymInfo_linenum(frameinfo[n]);
        if (res < -1) {
            failed = true;
            perror("error: ");
            exit(1);
        }
        frameinfo[n].linenum = res;

        fprintf(stderr, "%s %s() %s, %ld\n", frameinfo[n].file, frameinfo[n].func,
                frameinfo[n].addr, frameinfo[n].linenum);
    }
}

int
main() {
    if (!init()) puts("Failed to initialize.");
    print_trace();
}
