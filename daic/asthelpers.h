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

static inline ExprType*
ExprType_symtab_init(daisho_parser_ctx* ctx, ExprType* info) {
  if (!info) info = PGEN_ALLOC_OF(ctx->alloc, ExprType);
  info->decl = NULL;
  info->pointer_depth = 0;
  info->kind = SYMTAB_EXPRTYPE;
  return info;
}

static inline ExprType*
ExprType_function_init(daisho_parser_ctx* ctx, ExprType* info) {
  if (!info) info = PGEN_ALLOC_OF(ctx->alloc, ExprType);
  info->decl = NULL;
  info->pointer_depth = 0;
  info->kind = SYMTAB_EXPRTYPE;
  return info;
}


#define set_depth(node, depth) _set_depth(ctx, node, depth)
static inline daisho_astnode_t*
_set_depth(daisho_parser_ctx* ctx, ExprType* type, uint8_t depth) {
  type->pointer_depth = depth;
  return node;
}

static inline size_t
get_depth(ExprType* type) {
  size_t depth = type->pointer_depth;
  while (type->is_concrete == 0) {
    type = type->generic;
    depth += type->pointer_depth;
  }
  return depth;
}

#endif /* DAIC_ASTHELPERS_INCLUDE */
