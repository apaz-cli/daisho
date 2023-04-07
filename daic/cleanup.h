#ifndef DAIC_CLEANUP_INCLUDE
#define DAIC_CLEANUP_INCLUDE
#include <stdlib.h>

#include "list.h"

typedef struct {
    void (*f)(void*);
    void* a;
} DaicCleanupEntry;

_DAIC_LIST_DECLARE(DaicCleanupEntry)
_DAIC_LIST_DEFINE(DaicCleanupEntry)
typedef _Daic_List_DaicCleanupEntry DaicCleanupContext;

static inline DaicCleanupContext
daic_cleanup_init(void) {
    return _Daic_List_DaicCleanupEntry_new();
}

static inline void
daic_cleanup_add(DaicCleanupContext* cleanup, void (*fn)(void*), void* arg) {
#if !_DAIC_LEAK_EVERYTHING
    _Daic_List_DaicCleanupEntry_add(cleanup, (DaicCleanupEntry){fn, arg});
#else
    (void)cleanup;
    (void)fn;
    (void)arg;
#endif
}

static inline void
daic_cleanup(DaicCleanupContext* cleanup) {
#if !_DAIC_LEAK_EVERYTHING
    // Reverse the list
    size_t j = cleanup->len - 1;
    for (size_t i = 0; i < (cleanup->len / 2); i++) {
        DaicCleanupEntry tmp = cleanup->buf[i];
        cleanup->buf[i] = cleanup->buf[j];
        cleanup->buf[j] = tmp;
        j--;
    }

    // Call functions in the reversed order, ignoring duplicates.
    for (size_t i = 0; i < cleanup->len; i++) {
        int dup = 0;
        for (size_t z = 0; z < i; z++) {
            if ((cleanup->buf[i].a == cleanup->buf[z].a) &&
                (cleanup->buf[i].f == cleanup->buf[z].f)) {
                dup = 1;
                break;
            }
        }
        if (!dup) cleanup->buf[i].f(cleanup->buf[i].a);
    }

    // Delete self
    _Daic_List_DaicCleanupEntry_clear(cleanup);
#else
    (void)cleanup;
#endif
}

#else

#endif /* DAIC_CLEANUP_INCLUDE */
