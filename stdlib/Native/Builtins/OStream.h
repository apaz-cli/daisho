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

static char _Dai_stdout_buf[_DAI_STDOUT_BUFSIZ];
static char _Dai_stderr_buf[_DAI_STDERR_BUFSIZ];

static _Dai_OStream _Dai_stdout_ =
    {NULL, STDOUT_FILENO, 0, _DAI_STDOUT_BUFSIZ, _DAI_MUTEX_INITIALIZER};
static _Dai_OStream _Dai_stderr_ =
    {NULL, STDERR_FILENO, 0, _DAI_STDERR_BUFSIZ, _DAI_MUTEX_INITIALIZER};

static const _Dai_OStream* _Dai_stdout = &_Dai_stdout_;
static const _Dai_OStream* _Dai_stderr = &_Dai_stderr_;

_DAI_FN void
_Dai_init_std_ostreams(void) {
    _Dai_stdout_.buf = _Dai_stdout_buf;
    _Dai_stderr_.buf = _Dai_stderr_buf;
}

_DAI_FN int
_Dai_OStream_flush(_Dai_OStream* os, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    int err;  // TODO use
    ssize_t written = _Dai_write_wrapper(os->fd, os->buf, os->len, &err);
    _DAI_ASSERT(written == os->len, "The entire message was not written.");
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return 0;
}

_DAI_FN ssize_t
_Dai_OStream_write(_Dai_OStream* os, const void* mem, size_t bytes, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    if (bytes > os->cap) {
        int err;  // TODO use
        _Dai_OStream_flush(os, 1);
        _Dai_write_wrapper(os->fd, mem, bytes, &err);
    } else {
        size_t bufspace = os->cap - os->len;
        size_t cpy = bytes <= bufspace ? bytes : bufspace;
        memcpy(os->buf + os->len, mem, cpy);
        os->len += cpy;
        if (bytes > bufspace) {
            _Dai_OStream_flush(os, 1);
            memcpy(os->buf, mem, bytes - bufspace);
            os->len = bytes - bufspace;
        }
    }
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return bytes;
}

_DAI_FN void
_Dai_OStream_fprintf(_Dai_OStream* os, int unlocked, const char* fmt, ...) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    _Dai_OStream_flush(os, 1);
    va_list va;
    va_start(va, fmt);
    vdprintf(os->fd, fmt, va);
    va_end(va);
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
}

_DAI_FN void
_Dai_OStream_write_cstr(_Dai_OStream* os, const char* cstr, int unlocked) {
    size_t len = strlen(cstr);
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    _Dai_OStream_write(os, cstr, len, 1);
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
}

_DAI_FN int
_Dai_OStream_close(_Dai_OStream* os, int unlocked) {
    if (!unlocked) _Dai_mutex_lock(&os->mtx);
    int c = close(os->fd);
    if (!unlocked) _Dai_mutex_unlock(&os->mtx);
    return c;
}

#endif /* _DAI_STDLIB_OSTREAM */
