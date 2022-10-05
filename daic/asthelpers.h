#ifndef DAIC_ASTHELPERS_INCLUDE
#define DAIC_ASTHELPERS_INCLUDE
#include <stdint.h>
#include <stdlib.h>

#ifndef PGEN_UTF8_INCLUDED
#include "grammar/daisho_tokenizer_parser.h"
#endif

#include "types.h"

// This file is meant to include only the bare minimum for building the AST.
// Doing stuff with the AST goes elsewhere.

static TypeDecl voidtypedecl = {NULL, 0};
static ExprType voidExprType = {0, 0, 0};

static inline ExprType*
ExprType_init(daisho_parser_ctx* ctx, ExprType* info) {
    if (!info) info = PGEN_ALLOC_OF(ctx->alloc, ExprType);
    info->declared_at = NULL;
    info->pointer_depth = 0;
    info->concrete = 0;
    return info;
}

#define set_depth(node, depth) _set_depth(ctx, node, depth)
static inline daisho_astnode_t*
_set_depth(daisho_parser_ctx* ctx, daisho_astnode_t* node, uint8_t depth) {
    ExprType* info = ExprType_init(ctx, NULL);
    info->pointer_depth = depth;
    node->type = info;
    return node;
}

#endif /* DAIC_ASTHELPERS_INCLUDE */
