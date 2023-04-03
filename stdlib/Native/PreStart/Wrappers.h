#pragma once
#ifndef _DAI_STDLIB_WRAPPERS
#define _DAI_STDLIB_WRAPPERS
#include "../PreProcessor/PreProcessor.h"

_DAI_FN size_t
_Dai_write_wrapper(int fd, const void* mem, size_t bytes, int* err) {
    size_t written_sofar = 0;
    while (bytes) {
        ssize_t bytes_written = write(fd, (char*)mem + written_sofar, bytes);
        if (bytes_written == -1 && errno == EINTR) continue;
        if (bytes_written == -1 && errno != EINTR) return *err = errno, written_sofar;
        bytes -= bytes_written;
        written_sofar += bytes_written;
    }
    return written_sofar;
}

_DAI_FN size_t
_Dai_read_wrapper(int fd, void* buf, size_t bytes, int* err) {
    size_t have_read = 0;
    while (1) {
        ssize_t n = read(fd, (char*)buf + have_read, bytes - have_read);
        if (n == -1) {
            int e = errno;
            if (e == EINTR)
                continue;
            else {
                *err = e;
                return have_read;
            }
        } else {
            have_read += (size_t)n;
            if ((have_read >= bytes) | (n == 0)) break;
        }
    }

    *err = 0;
    return have_read;
}

#endif /* _DAI_STDLIB_WRAPPERS */
