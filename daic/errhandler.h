#ifndef DAIC_ERRHANDLER_INCLUDE
#define DAIC_ERRHANDLER_INCLUDE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../stdlib/Daisho.h"
#include "cleanup.h"
#include "enums.h"
#include "list.h"
#include "responses.h"

struct DaicError;
typedef struct DaicError DaicError;
struct DaicError {
    DaicError* next;
    char* msg;  // If it must be freed, add to the cleanup context first.
    char* file;
    size_t line;
    size_t col;
    DaicSeverity severity;
    DaicStage stage;
    bool trace_frame;
};
typedef DaicError* DaicErrorPtr;

_DAIC_LIST_DECLARE(DaicErrorPtr)
_DAIC_LIST_DEFINE(DaicErrorPtr)

static inline DaicError*
daic_error_new(DaicContext* ctx, DaicStage stage, char* msg, char* file, size_t line,
               size_t col, DaicSeverity severity, bool trace_frame) {
    DaicError* e = (DaicError*)malloc(sizeof(DaicError));
    if (!e) daic_panic(ctx, daic_oom_err);
    daic_cleanup_add(ctx, free, e);
    e->next = NULL;
    e->msg = msg;
    e->file = file;
    e->line = line;
    e->col = col;
    e->severity = severity;
    e->stage = stage;
    e->trace_frame = trace_frame;
    return e;
}

static inline void
daic_error_destroy(DaicError* e) {
    if (!e) return;
    free(e);
}

static inline void
daic_error_print_sourceinfo(FILE* f, DaicError* e, int color) {
    char* fcolor = color ? _DAI_COLOR_FILE : "";
    char* lcolor = color ? _DAI_COLOR_LINE : "";
    char* ccolor = color ? _DAI_COLOR_LINE : "";
    char* colorreset = color ? _DAI_COLOR_RESET : "";
    if (!e->file)
        fprintf(f, "%sunknown file%s:", fcolor, colorreset);
    else if (!e->line)
        fprintf(f, "%s%s%s:", fcolor, e->file, colorreset);
    else if (!e->col)
        fprintf(f, "%s%s%s:%s%zu%s:", fcolor, e->file, colorreset, lcolor, e->line, colorreset);
    else
        fprintf(f, "%s%s%s:%s%zu%s:%s%zu%s:", fcolor, e->file, colorreset, lcolor, e->line,
                colorreset, ccolor, e->col, colorreset);
}

static inline void
daic_error_print_info(FILE* f, DaicError* e, int color) {
    char* sevcolor = color ? daic_sevstr_color[e->severity] : "";
    char* severity = color ? daic_sevstr_capital[e->severity] : "";
    char* stage = color ? daic_stagedisplay[e->stage] : "";
    char* stagecolor = color ? daic_stagecolor[e->stage] : "";
    char* colorreset = color ? _DAI_COLOR_RESET : "";
    fprintf(f, "%s%s%s in %s%s%s:", sevcolor, severity, colorreset, stagecolor, stage, colorreset);
}

static inline void
daic_error_print(FILE* f, DaicError* e, int color) {
    if (!e) return;
    if (e->trace_frame) {
        daic_error_print_sourceinfo(f, e, color);
        fprintf(f, "\n");
    } else {
        daic_error_print_sourceinfo(f, e, color);
        fprintf(f, " ");
        daic_error_print_info(f, e, color);
        if (e->next) daic_error_print(f, e->next, color);
    }
}

static inline int
daic_error_cmpstage(const void* a, const void* b) {
    _DAI_PEDANTIC_ASSERT(a && b, "Cannot compare null errors.");
    DaicError* ae = (DaicError*)a;
    DaicError* be = (DaicError*)b;
    while (ae->next) ae = ae->next;
    while (be->next) be = be->next;
    return ((DaicError*)ae)->stage - ((DaicError*)b)->stage;
}

// Bubble sort b/c qsort is unstable
static inline void
daic_error_sort(_Daic_List_DaicErrorPtr* errlist) {
    size_t n = errlist->len;
    for (size_t i = 0; i < n - 1; i++) {
        for (size_t j = 0; j < n - i - 1; j++) {
            if (daic_error_cmpstage(errlist->buf[j], errlist->buf[j + 1]) > 0) {
                DaicError* tmp = errlist->buf[j];
                errlist->buf[j] = errlist->buf[j + 1];
                errlist->buf[j + 1] = tmp;
            }
        }
    }
}

static inline void
daic_print_errlist(FILE* f, _Daic_List_DaicErrorPtr* errlist, int color) {
    // Stable sort such that the highest severity errors are printed first.
    daic_error_sort(errlist);
    for (size_t i = 0; i < errlist->len; i++) {
        daic_error_print(f, errlist->buf[i], color);
    }
}

// Explode
static inline void
daic_panic(DaicContext* ctx, const char* panic_msg) {
#if !_DAIC_LEAK_EVERYTHING
    daic_cleanup(ctx);
    ctx->panic_err_message = (char*)panic_msg;
    longjmp(ctx->panic_handler, 1);
#else
    (void)ctx;
    (void)panic_msg;
#endif
}

static inline void
daic_print_panic(DaicContext* ctx, char* panic_err_message) {
    if (!panic_err_message) panic_err_message = "Unknown Error.";
    fputs("Daic panic: ", ctx->daic_stderr);
    fputs(panic_err_message, ctx->daic_stderr);
}

#endif /* DAIC_ERRHANDLER_INCLUDE */
