#include <cstddef>

#include "LSPTypes.h"

/////////////////////////
// MY USEFUL ADDITIONS //
/////////////////////////

#define LSP_TRANSPORTKIND_STDIO 0
#define LSP_TRANSPORTKIND_PIPE 1
#define LSP_TRANSPORTKIND_SOCKET 2

// Memory allocator //

#define LSP_ALLOCATOR_MAXALIGN
#define LSP_ALLOCATOR_NUM_ARENAS 256

typedef struct {
    char* buf;
    void (*free_fn)(void*);
    size_t cap;
} LSP_Arena;

typedef struct {
    size_t current_arena;
    size_t current_offset;
    LSP_Arena arenas[LSP_ALLOCATOR_NUM_ARENAS];
} LSP_Allocator;

static inline LSP_Allocator
lsp_allocator_new(void) {
    LSP_Allocator a;
    memset(&a, 0, sizeof(LSP_Allocator));
    return a;
}

static inline int
lsp_allocator_yoink(LSP_Allocator* allocator, LSP_Arena memory_to_steal) {
    for (size_t i = 0; i < LSP_ALLOCATOR_NUM_ARENAS; i++) {
        if (!allocator->arenas[i].buf) {
            allocator->arenas[i] = memory_to_steal;
            return 1;
        }
    }
    return 0;
}

static inline char*
lsp_allocator_allocate(LSP_Allocator* allocator, size_t size) {
    return NULL;
}

static inline void
lsp_allocator_destroy(LSP_Allocator* allocator) {
    for (size_t i = 0; i < LSP_ALLOCATOR_NUM_ARENAS; i++) {
        if (allocator->arenas[i].buf) {
            allocator->arenas[i].free_fn(allocator->arenas[i].buf);
        } else {
            break;
        }
    }
}

#define LSP_ALLOCATE(allocator, type) (type*)lsp_allocator_allocate(allocator, sizeof(type))

#define _LSP_ALIGNOF(type) \
    ((size_t)(offsetof(    \
        struct {           \
            char c;        \
            type d;        \
        },                 \
        d)))