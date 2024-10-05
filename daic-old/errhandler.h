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

static inline DaicError*
daic_error_new(DaicContext* ctx, DaicStage stage, char* msg, char* file, size_t line, size_t col,
               DaicSeverity severity, bool trace_frame) {
    DaicError* e = (DaicError*)daic_cleanup_malloc(ctx, sizeof(DaicError));
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
daic_error_add(DaicContext* ctx, DaicError* e) {
    _Daic_List_DaicErrorPtr_add(&ctx->errors, e);
}

static inline void
daic_type_error_global(DaicContext* ctx, char* msg) {
    DaicError* e =
        daic_error_new(ctx, DAIC_ERROR_STAGE_TYPING, msg, NULL, 0, 0, _DAIC_ERROR_SEV_ERROR, 0);
    daic_error_add(ctx, e);
}

static inline void
daic_error_print_sourceinfo(FILE* f, DaicError* e, int color) {
    char* fcolor = color ? _DAI_COLOR_FILE : "";
    char* lcolor = color ? _DAI_COLOR_LINE : "";
    char* ccolor = color ? _DAI_COLOR_LINE : "";
    char* reset = color ? _DAI_COLOR_RESET : "";
    if (!e->file)
        return;
    else if (!e->line)
        fprintf(f, "%s%s%s:", fcolor, e->file, reset);
    else if (!e->col)
        fprintf(f, "%s%s%s:%s%zu%s:", fcolor, e->file, reset, lcolor, e->line, reset);
    else
        fprintf(f, "%s%s%s:%s%zu%s:%s%zu%s:", fcolor, e->file, reset, lcolor, e->line, reset,
                ccolor, e->col, reset);
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

// TODO: For large numbers of errors this is prohibitively slow.
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
    // Stable sort such that the earliest errors are printed first.
    daic_error_sort(errlist);
    for (size_t i = 0; i < errlist->len; i++) {
        daic_error_print(f, errlist->buf[i], color);
    }
}

// Explode
static inline void
daic_panic(DaicContext* ctx, const char* panic_msg) {
    daic_cleanup(ctx);
    ctx->panic_err_message = (char*)panic_msg;
    longjmp(ctx->panic_handler, 1);
}

static inline void
_daic_print_panic(DaicContext* ctx, char* panic_err_message) {
    if (!panic_err_message) panic_err_message = "Unknown Error.";
    char errbuf[4096];
    const char* errfmt = _DAI_COLOR_RED "Daic panic:" _DAI_COLOR_RESET " %s\n";
    snprintf(errbuf, 4095, errfmt, panic_err_message);
    errbuf[4095] = '\0';
    fputs(errbuf, ctx->daic_stderr);
}

#endif /* DAIC_ERRHANDLER_INCLUDE */
