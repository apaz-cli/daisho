#ifndef _DAI_STDLIB_LIST
#define _DAI_STDLIB_LIST

#include "../stdlib/Daisho.h"
#include "allocator.h"
#include "staticerr.h"

struct DaicContext;
typedef struct DaicContext DaicContext;

/********/
/* List */
/********/

#define _DAIC_LIST_DECLARE(type) \
    typedef struct {             \
        type* buf;               \
        size_t len;              \
        size_t cap;              \
        DaicContext* ctx;        \
    } _Daic_List_##type;

#define _DAIC_LIST_DEFINE(type)                                                             \
    static inline _Daic_List_##type _Daic_List_##type##_new(DaicContext* ctx) {             \
        _Daic_List_##type nl;                                                               \
        nl.buf = NULL;                                                                      \
        nl.len = 0;                                                                         \
        nl.cap = 0;                                                                         \
        nl.ctx = ctx;                                                                       \
        return nl;                                                                          \
    }                                                                                       \
    static inline void _Daic_List_##type##_clear(_Daic_List_##type* self) {                 \
        self->buf = NULL;                                                                   \
        self->len = 0;                                                                      \
        self->cap = 0;                                                                      \
        self->ctx = NULL;                                                                   \
    }                                                                                       \
    static inline int _Daic_List_##type##_add(_Daic_List_##type* self, type item) {         \
        size_t next_len = self->len + 1;                                                    \
        /* Grow the buffer if there's not enough space. */                                  \
        if (self->cap <= next_len) {                                                        \
            size_t next_cap = next_len * 2 + 8;                                             \
            type* reall =                                                                   \
                (type*)daic_cleanup_realloc(self->ctx, self->buf, sizeof(type) * next_cap); \
            self->cap = next_cap;                                                           \
            self->buf = reall;                                                              \
        }                                                                                   \
        /* Insert */                                                                        \
        self->buf[self->len] = item;                                                        \
        self->len = next_len;                                                               \
        return 0;                                                                           \
    }                                                                                       \
    static inline type _Daic_List_##type##_get(_Daic_List_##type* self, size_t idx) {       \
        _DAI_SANE_ASSERT(self, "List is null.");                                            \
        _DAI_SANE_ASSERT(idx < self->len, "List index out of range.");                      \
        return self->buf[idx];                                                              \
    }                                                                                       \
    static inline type _Daic_List_##type##_remove(_Daic_List_##type* self, size_t idx) {    \
        _DAI_SANE_ASSERT(self, "List is null.");                                            \
        _DAI_SANE_ASSERT(idx < self->len, "List index out of range.");                      \
        type ret = self->buf[idx];                                                          \
        size_t nlen = self->len ? self->len - 1 : 0;                                        \
        for (size_t i = idx; i < nlen; i++) self->buf[i] = self->buf[i + 1];                \
        self->len = nlen;                                                                   \
        return ret;                                                                         \
    }                                                                                       \
    static inline bool _Daic_List_##type##_isEmpty(_Daic_List_##type* self) {               \
        return self->len == 0;                                                              \
    }

#endif /* _DAI_STDLIB_LIST */
