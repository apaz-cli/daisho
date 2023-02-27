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
  if (!info) info = PGEN_ALLOC(ctx->alloc, ExprType);
  info->decl = NULL;
  info->kind = SYMTAB_EXPRTYPE;
  return info;
}

static inline ExprType*
ExprType_function_init(daisho_parser_ctx* ctx, ExprType* info) {
  if (!info) info = PGEN_ALLOC(ctx->alloc, ExprType);
  info->decl = NULL;
  info->kind = FUNCTION_EXPRTYPE;
  return info;
}

#endif /* DAIC_ASTHELPERS_INCLUDE */
