#pragma once
#ifndef _DAI_STDLIB_OSTREAM
#define _DAI_STDLIB_OSTREAM
#include "String.h"
#include "UTF8.h"

typedef struct {
    char* buf;
    int fd;
    uint32_t len;
    uint32_t cap;
    _Dai_Mutex mtx;
} _Dai_OStream;

#ifndef _DAI_STDOUT_BUFSIZ
#define _DAI_STDOUT_BUFSIZ _DAI_PAGESIZE * 16
_Static_assert(_DAI_STDOUT_BUFSIZ <= UINT32_MAX, "");
#endif

#ifndef _DAI_STDERR_BUFSIZ
#define _DAI_STDERR_BUFSIZ _DAI_PAGESIZE * 2
_Static_assert(_DAI_STDERR_BUFSIZ <= UINT32_MAX, "");
#endif

static char _Dai_stdout_buf[_DAI_STDOUT_BUFSIZ];
static char _Dai_stderr_buf[_DAI_STDERR_BUFSIZ];

static _Dai_OStream _Dai_stdout_ =
    (_Dai_OStream){_Dai_stdout_buf, STDOUT_FILENO, 0, _DAI_STDOUT_BUFSIZ, _DAI_MUTEX_INITIALIZER};
static _Dai_OStream _Dai_stderr_ =
    (_Dai_OStream){_Dai_stderr_buf, STDERR_FILENO, 0, _DAI_STDERR_BUFSIZ, _DAI_MUTEX_INITIALIZER};

static const _Dai_OStream* _Dai_stdout = &_Dai_stdout_;
static const _Dai_OStream* _Dai_stderr = &_Dai_stderr_;

_DAI_FN size_t
_Dai_write_wrapper(int fd, void* mem, size_t bytes) {
    size_t written_sofar = 0;
    while (bytes) {
        ssize_t bytes_written = write(fd, (char*)mem + written_sofar, bytes);
        if (bytes_written == -1 && errno == EINTR) continue;
        _DAI_SANE_ASSERT(bytes_written != -1, "Write error");
        bytes -= bytes_written;
        written_sofar += bytes_written;
    }
    return written_sofar;
}

_DAI_FN int
_Dai_OStream_flush(_Dai_OStream* os, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    ssize_t written = _Dai_write_wrapper(os->fd, os->buf, os->len);
    _DAI_ASSERT(written == os->len, "The entire message was not written.");
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return 0;
}

_DAI_FN ssize_t
_Dai_OStream_write(_Dai_OStream* os, void* mem, size_t bytes, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    if (bytes > os->cap) {
        _Dai_OStream_flush(os, unlocked);
        _Dai_write_wrapper(os->fd, mem, bytes);
        if (!unlocked) _Dai_mutex_unlock(&os->mtx);
        return bytes;
    }

    size_t bufspace = os->cap - os->len;
    size_t cpy = bytes <= bufspace ? bytes : bufspace;
    memcpy(os->buf + os->len, mem, cpy);
    os->len += cpy;
    if (bytes > bufspace) {
        _Dai_OStream_flush(os, unlocked);
        memcpy(os->buf, mem, bytes - bufspace);
        os->len = bytes - bufspace;
    }
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return bytes;
}

_DAI_FN int
_Dai_OStream_close(_Dai_OStream* os, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    int c = close(os->fd);
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return c;
}

#endif /* _DAI_STDLIB_OSTREAM */