#ifndef DAIC_CLEANUP_INCLUDE
#define DAIC_CLEANUP_INCLUDE
#include <stdlib.h>

#include "daic_context.h"
#include "list.h"
#include "staticerr.h"

// If we call _Daic_List_type_new(), there will be trouble. This sets the buffer
// to NULL, which when we call add() will call cleanup_add() on itself, causing
// infinite recursion and overflow the call stack. So we initialize it manually here.
static inline _Daic_List_DaicCleanupEntry
daic_cleanup_entries_new(char** panic_msg_loc) {
    _Daic_List_DaicCleanupEntry self;
    self.len = 0;
    self.cap = 256;
    self.buf = (DaicCleanupEntry*)malloc(sizeof(DaicCleanupEntry) * self.cap);
    if (!_DAIC_LEAK_EVERYTHING && !self.buf) {
        if (panic_msg_loc) *panic_msg_loc = daic_oom_err;
    }
    return self;
}


static inline void
daic_cleanup_add(DaicContext* ctx, void (*fn)(void*), void* arg) {
#if !_DAIC_LEAK_EVERYTHING
    if (!fn || !arg) return;
    _Daic_List_DaicCleanupEntry_add(&ctx->cleanup, (DaicCleanupEntry){fn, arg});
#else
    (void)cleanup;
    (void)fn;
    (void)arg;
#endif
}

// Error Cleanly
static inline void
daic_cleanup(DaicContext* ctx) {
    _Daic_List_DaicCleanupEntry* cleanup = &ctx->cleanup;
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
        if (!dup) {
            cleanup->buf[i].f(cleanup->buf[i].a);
        }
    }

    // Delete self
    _Daic_List_DaicCleanupEntry_clear(cleanup);
}

#endif /* DAIC_CLEANUP_INCLUDE */
