#define _GNU_SOURCE
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "stdlib/Daisho.h"

// Call addr2line, and returns the line number for the info.
// Returns -1 on fork, pipe, close, dup2, execv, wait. Keeps errno set to indicate the error.
// Returns -2 when addr2line returns ?? as the file or line number.
// Otherwise, returns the line number.
__DAI_FN long
__Dai_SymInfo_linenum(__Dai_SymInfo info) {

    // Create a file descriptor for addr2line to pipe to.
    errno = 0;
    int pipes[2];
    if (pipe(pipes) == -1) {
        return -1;
    }

    // Fork
    int status, ret;
    int pid = fork();
    if (pid == -1) return -1;
    if (!pid) {
        // Child

        // Redirect stdout to pipe.
        ret = close(pipes[0]);
        if (ret == -1) return -1;
        ret = dup2(pipes[1], STDOUT_FILENO);
        if (ret == -1) return -1;

        // Replace execution image with addr2line or fail.
        char addrpath[] = "/usr/bin/addr2line";
        char addrname[] = "addr2line";
        char* addr2lineargs[] = {addrname, "-e", info.file, "-Cpi", info.addr, NULL};
        execv(addrpath, addr2lineargs);
        return -1;
    }
    // Parent

    // Wait for addr2line to write to pipe.
    ret = close(pipes[1]);
    if (ret == -1) return -1;
    ret = waitpid(pid, &status, 1);
    if (ret == -1) return -1;
    ret = (WIFEXITED(status) && WEXITSTATUS(status)) | WIFSIGNALED(status);
    if (ret) return -1;

    // Read from the pipe (addr2line child stdout), and null terminate.
    char tmp[__DAI_BT_BUF_CAP];
    ssize_t bytes_read = read(pipes[0], tmp, __DAI_BT_BUF_CAP);
    if (bytes_read <= 0) return -1;
    if (bytes_read == __DAI_BT_BUF_CAP) {
        /* Large return probably doesn't matter. It shouldn't come up.
           We can do multiple reads instead of erroring if it becomes a problem. */
        return -1;
    }
    tmp[bytes_read] = '\0';

    // Parse line, write to buf. Example of format:
    // /home/apaz/git/Daisho/tests/scripts/backtrace_test.c:8

    // Check if we got a ??: for the file.
    size_t pos = 0;
    if ((tmp[pos] == '?') & (tmp[pos+1] == '?') & (tmp[pos+2] == ':')) return -2;

    // Seek to the end.
    while (tmp[pos] != '\0') pos++;

    // Backtrack to the character past the last colon.
    while (tmp[pos] != ':') pos--;
    pos++;

    // Check if we got a ?? for the line number.
    if ((tmp[pos] == '?') & (tmp[pos+1] == '?')) return -2;

    // Parse line number from addr2line to long.
    errno = 0;
    long l = strtol(tmp + pos, NULL, 10);
    return errno ? -1 : l;
}

__DAI_FN size_t
__Dai_SymInfo_snwrite(char* s, size_t n, __Dai_SymInfo info, int use_color) {

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

int
main() {
    if (!init()) puts("Failed to initialize.");

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

        str = next;
    }

    // Write some colors to the stack.
    char fn_color[] = __DAI_BT_COLOR_FUNC;
    char file_color[] = __DAI_BT_COLOR_FILE;
    char reset_color[] = __DAI_BT_COLOR_FUNC;
    char ptr_color[] = __DAI_BT_COLOR_PNTR;
    char line_color[] = __DAI_BT_COLOR_LINE;


    // For each frame (which we now have info for), get the line number.
    int failed = 0;
    for (int n = 0; n < num_frames; n++) {
        long res = __Dai_SymInfo_linenum(frameinfo[n]);
        if (res == -1) failed = true;
        frameinfo[n].linenum = res;
        printf("%ld\n", res);
    }

    //

    close(fd);
    puts("");
}
