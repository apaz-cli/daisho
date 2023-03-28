#ifndef DAIC_CONTEXT_INCLUDE
#define DAIC_CONTEXT_INCLUDE

#include "argparse.h"
#include "cleanup.h"
#include "daisho_peg.h"
#include "errhandler.h"

typedef struct {
    Daic_Args args;
    pgen_allocator allocator;
    DaicCleanupContext cleanup;
    daisho_tokenizer tokenizer;
    daisho_parser_ctx parser;
    daisho_astnode_t* ast;
    _Daic_List_NamespaceDecl namespaces;
} DaicContext;

#endif /* DAIC_CONTEXT_INCLUDE */
