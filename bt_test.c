#define _GNU_SOURCE
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
    char* file;
    char* name;
    char* addr;
} __Dai_SymInfo;

typedef struct {
    void* frames;
    int size;
    int fd;
} __Dai_fallback_args;

__Dai_SymInfo
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
        *str = '\0';
        str++;

        addr = str;
        while (*str != ']') str++;
        *str = '\0';
    }
    __Dai_SymInfo info = {file, name, addr};
    return info;
}

// Handle failure in addr2line translation.
void backtrace_fallback(__Dai_fallback_args args) {
    backtrace_symbols_fd(args.frames, args.size, args.fd);
    const char msg[] = "Failed to translate addresses to lines.";
}

// Returns 0 on failure, otherwise num written.
// Call addr2line, format the results, and append to buf.
size_t translate_append(char* buf, __Dai_fallback_args args, __Dai_SymInfo info) {
    pid_t addrpid;
    int status;

    int pipes[2];
    if (pipe(pipes) == -1) {
        backtrace_fallback(args);
        return 0;
    }

    pid = fork();
    if (!pid) {
        // Child

        // Redirect stdout to pipe.
        close(pipes[0]);
        dup2(pipes[1], STDOUT_FILENO);

	// Replace execution image or fail.
        const char addrpath[] = "/usr/bin/addr2line";
        const char addrname[] = "addr2line";
        const char* addr2lineargs[] = { addrname, "-e", info.file, "-Cfpi", addr, NULL };
        execv(addrpath, addr2lineargs);

        backtrace_fallback(args);
        return 0;
    } else {
        // Parent

        // Wait for addr2line to write to pipe.
        close(pipes[1]);
        wait(&status);
        int failure = (WIFEXITED(status) && WEXITSTATUS(status)) | WIFSIGNALED(status);
        if (failure) {
            backtrace_fallback(args);
            return 0;
        }

        // Read from the pipe (addr2line child stdout).
        char tmp[__DAI_BT_BUF_CAP];
        ssize_t bytes_read = read(pipes[0], tmp, __DAI_BT_BUF_CAP);
        if (bytes_read <= 0) {
            backtrace_fallback(args);
            return 0;
        }
        if (bytes_read == __DAI_BT_BUF_CAP) {
            /* Large return probably doesn't matter. It shouldn't come up.
               We can do multiple reads instead of erroring if it becomes a problem. */
            backtrace_fallback(args);
            return 0;
        }

        // Parse line, write to buf. Example of format:
        // f1 at /home/apaz/git/Daisho/tests/scripts/backtrace_test.c:8
        char* t = tmp;
        
    }

    return 0;
}

#define __DAI_BT_MAX_FRAMES 50
#define __DAI_BT_BUF_CAP (4096 * 4)
static int fd;

int init() {
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

    // Take a backtrace, write it to the buffer.
    backtrace_symbols_fd(frames, num_frames, fd);

    // Rewind and read back the file.
    lseek(fd, 0, SEEK_SET);
    char pages[__DAI_BT_BUF_CAP];
    ssize_t num_read = read(fd, pages, __DAI_BT_BUF_CAP - 1);

    // Print the original backtrace.
    write(STDOUT_FILENO, pages, num_read);
    puts("");

    // Parse the backtrace.
    char* str = pages;
    for (int n = 0; n < num_frames; n++) {
        char* next = str;
        while ((*next != '\n')) next++;
        next++;

        frameinfo[n] = __Dai_SymInfo_parse(str);
        fprintf(stderr, "%s %s %s\n", frameinfo[n].file, frameinfo[n].name, frameinfo[n].addr);

        str = next;
    }

    close(fd);
    puts("");

}
