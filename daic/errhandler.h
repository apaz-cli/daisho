#ifndef DAIC_ERRHANDLER_INCLUDE
#define DAIC_ERRHANDLER_INCLUDE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../stdlib/Daisho.h"
#include "allocator.h"
#include "cleanup.h"
#include "list.h"
#include "types.h"

struct DaicError;
typedef struct DaicError DaicError;
struct DaicError {
    DaicError* next;
    char* msg;  // If it must be freed, add to the cleanup context.
    char* file;
    size_t line;
    size_t col;
    DaicStage stage;
    bool show_file_line;
};

_DAIC_LIST_DECLARE(DaicError)
_DAIC_LIST_DEFINE(DaicError)

static inline DaicError*
daic_tokenize_error(DaicCleanupContext* cleanup, DaicStage stage, char* msg, char* file, size_t line, size_t col,
                    bool show_file_line) {
    DaicError* e = (DaicError*)_DAIC_MALLOC(sizeof(DaicError));
    daic_cleanup_add(cleanup, _DAIC_FREE_FPTR, e);
    e->next = NULL;
    e->msg = msg;
    e->file = file;
    e->line = line;
    e->col = col;
    e->stage = stage;
    e->stage = e->show_file_line = show_file_line;
    return e;
}

static inline void
daic_tokenizer_error_destroy(DaicError* e) {
    if (!e) return;
    _DAIC_FREE(e);
}

static inline void
daic_tokenizer_error_print(DaicError* e) {
    fprintf(stderr, "%s:%zu:%zu: " _DAI_COLOR_RED "error:" _DAI_COLOR_RESET, e->file, e->line,
            e->col);
    if (e->next) daic_tokenizer_error_print(e->next);
}

#endif /* DAIC_ERRHANDLER_INCLUDE */
