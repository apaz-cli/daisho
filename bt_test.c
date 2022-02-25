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

#define __DAI_BT_BUF_CAP (4096 * 4)
static int fd;

int
init() {
    // Call backtrace once to load the
    // library so dlopen(), which calls malloc(),
    // is not called inside the signal handler.
    void* frames[50];
    int num_frames = backtrace(frames, 50);
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
    void* frames[50];
    int num_frames = backtrace(frames, 50);
    if (!num_frames) puts("No backtrace.");
    if (num_frames > 50) puts("too long.");

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

        __Dai_SymInfo info = __Dai_SymInfo_parse(str);
        fprintf(stderr, "%s %s %s\n", info.file, info.name, info.addr);

        str = next;
    }

    close(fd);
    puts("");
}
