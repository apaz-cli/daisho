#ifndef DAIC_CONTEXT_INCLUDE
#define DAIC_CONTEXT_INCLUDE

#include "argparse.h"
#include "daisho.peg.h"
#include "list.h"

struct DaicContext;
typedef struct DaicContext DaicContext;

typedef struct {
    void (*f)(void*);
    void* a;
} DaicCleanupEntry;

_DAIC_LIST_DECLARE(DaicCleanupEntry)
typedef _Daic_List_DaicCleanupEntry DaicCleanupContext;
static inline void daic_cleanup_add(DaicContext* c, void (*fn)(void*), void* arg);
static inline void daic_cleanup(DaicContext* c);
_DAIC_LIST_DEFINE(DaicCleanupEntry)

struct DaicContext {
    Daic_Args args;
    FILE* daic_stdout;
    FILE* daic_stderr;
    char* panic_err_message;
    jmp_buf panic_handler;
    pgen_allocator allocator;
    DaicCleanupContext cleanup;
    daisho_tokenizer tokenizer;
    daisho_parser_ctx parser;
    daisho_astnode_t* ast;
    _Daic_List_NamespaceDecl namespaces;
};

#endif /* DAIC_CONTEXT_INCLUDE */
