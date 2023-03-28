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
daic_cleanup(_Daic_List_DaicCleanupEntry* cleanup) {
#if !_DAIC_LEAK_EVERYTHING
    for (size_t i = cleanup->len; i-- > 0;) cleanup->buf[i].f(cleanup->buf[i].a);
    _Daic_List_DaicCleanupEntry_clear(cleanup);
#else
    (void)cleanup;
#endif
}

#else

#endif /* DAIC_CLEANUP_INCLUDE */
