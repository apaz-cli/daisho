#ifndef DAIC_UTILS_INCLUDE
#define DAIC_UTILS_INCLUDE
#include "../stdlib/Daisho.h"
#include "list.h"


// Takes a pointer to a malloced or null pointer.
// Returns the number written or -1 on error.
static inline int
daic_cstring_appendf(char** buf, size_t* len, size_t* cap, const char* fmt, ...) {
    if (!buf | !len | !cap) return -1;
    if (!fmt) return -1;
    if (!*buf || !*cap) {
        size_t initialcap = 4096;
        *buf = (char*)realloc(*buf, initialcap);
        *len = 0;
        *cap = initialcap;
        if (!*buf) return -1;
    }

    va_list va;
    va_start(va, fmt);
    int written = vsprintf(*buf + *len, fmt, va);
    va_end(va);
    if (written < 0) {
        free(*buf);
        *buf = NULL;
        return -1;
    }

    size_t need_cap = (size_t)written + 1;
    if (*cap <= need_cap) {
        size_t new_cap = need_cap * 2;
        *buf = (char*)realloc(*buf, new_cap);
        *cap = new_cap;
        if (!*buf) return -1;

        va_start(va, fmt);
        written = vsprintf(*buf + *len, fmt, va);
        va_end(va);
        if (written < 0) {
            free(*buf);
            *buf = NULL;
            return -1;
        }
    }

    *len += written;
    return written;
}

#endif /* DAIC_UTILS_INCLUDE */
