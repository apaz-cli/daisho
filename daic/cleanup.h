#ifndef DAIC_CLEANUP_INCLUDE
#define DAIC_CLEANUP_INCLUDE
#include <stdlib.h>

#include "types.h"
#include "staticerr.h"
#include "argparse.h"

// If we call _Daic_List_type_new(), there will be trouble. This sets the buffer
// to NULL, which when we call add() will call cleanup_add() on itself, causing
// infinite recursion and overflow the call stack. So we initialize it manually here.
static inline void
daic_cleanup_init(DaicContext* ctx) {
    _Daic_List_DaicCleanupEntry self;
    self.len = 1;
    self.cap = 256;
    self.buf = (DaicCleanupEntry*)malloc(sizeof(DaicCleanupEntry) * self.cap);
    self.ctx = ctx;
    ctx->cleanup = self;
    if (!self.buf)
        ctx->panic_err_message = daic_oom_err;
    else
        // Have the cleanup object clean itself up too. Since cleanup
        // happens in reverse order, we know this is called last.
        self.buf[0] = (DaicCleanupEntry){free, self.buf};
}

static inline void
daic_cleanup_add_always(DaicContext* ctx, void (*fn)(void*), void* arg) {
    _Daic_List_DaicCleanupEntry_add(&ctx->cleanup, (DaicCleanupEntry){fn, arg});
}

static inline void
daic_cleanup_add(DaicContext* ctx, void (*fn)(void*), void* arg) {
#if !_DAIC_LEAK_EVERYTHING
    daic_cleanup_add_always(ctx, fn, arg);
#else
    (void)ctx;
    (void)fn;
    (void)arg;
#endif
}

static inline void
daic_cleanup_claim(DaicContext* ctx, void* ptr) {
#if !_DAIC_LEAK_EVERYTHING
    if (!ptr) return;
    daic_cleanup_add(ctx, free, ptr);
#else
    (void)ctx;
    (void)ptr;
#endif
}

static inline void*
daic_cleanup_malloc(DaicContext* ctx, size_t size) {
    if (_DAI_SANE && !size) daic_panic(ctx, "Tried to malloc() size zero.");
    void* ptr = malloc(size);
    if (_DAI_SANE && !ptr) daic_panic(ctx, "malloc() returned NULL.");

#if !_DAIC_LEAK_EVERYTHING
    _Daic_List_DaicCleanupEntry_add(&ctx->cleanup, (DaicCleanupEntry){free, ptr});
#endif
    return ptr;
}

static inline void*
daic_cleanup_realloc(DaicContext* ctx, void* ptr, size_t size) {
    // null ptr is valid for realloc
    if (_DAI_SANE && !size) daic_panic(ctx, "Tried to realloc() size zero.");
    void* rptr = realloc(ptr, size);
    if (_DAI_SANE && !rptr) daic_panic(ctx, daic_oom_err);

#if !_DAIC_LEAK_EVERYTHING
    int inserted = 0;
    if (ptr)
        for (size_t i = 0; i < ctx->cleanup.len; i++)
            if (ctx->cleanup.buf[i].a == ptr && ctx->cleanup.buf[i].f == free)
                ctx->cleanup.buf[i].a = rptr, inserted = 1;
    if (!inserted) _Daic_List_DaicCleanupEntry_add(&ctx->cleanup, (DaicCleanupEntry){free, rptr});
#endif
    return rptr;
}

static inline void*
daic_cleanup_strdup(DaicContext* ctx, char* s) {
    if (_DAI_SANE && !s) daic_panic(ctx, "Tried to strdup() NULL.");
    size_t slen = strlen(s);
    return slen ? strcpy(daic_cleanup_malloc(ctx, slen + 1), s) : "";
}

// Destroy all memory, open files, and resources used by DaicContext.
static inline void
daic_cleanup(DaicContext* ctx) {
    // Cleanup is still called even with _DAIC_LEAK_EVERYTHING.
    // We do this to do things like close files. The list of
    // things to do will just be a lot smaller.
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
    daic_argdestroy(&ctx->args);
}

#endif /* DAIC_CLEANUP_INCLUDE */
