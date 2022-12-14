#ifndef DAIC_SYMTAB_INCLUDE
#define DAIC_SYMTAB_INCLUDE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef PGEN_UTF8_INCLUDED
#include "grammar/daisho_tokenizer_parser.h"
#endif

static inline size_t
roundUpToNextMultiple(size_t num, size_t of) {
  return ((num / of) + 1) * of;
}

static inline Symtab*
Symtab_init(daisho_parser_ctx* ctx) {
  const size_t initial_entries = 64;
  Symtab* symtab = PGEN_ALLOC_OF(ctx->alloc, Symtab);
  symtab->decls = (Declaration*)malloc(sizeof(Declaration*) * initial_entries);
  symtab->num_decls = 0;
  symtab->cap_decls = initial_entries;
  symtab->alloc = ctx->alloc;
  pgen_defer(ctx->alloc, free, symtab->decls, ctx->alloc->rew);
  return symtab;
}

static inline Declaration*
Symtab_get(Symtab* symtab, Identifier id) {
  for (size_t i = 0; i < symtab->num_decls; i++)
    if (ident_eq(symtab->decls[i].id, id))
      return symtab->decls[i];
  return NULL;
}

static inline int
Symtab_add(Symtab* symtab, Declaration* decl) {
  if (symtab->num_decls >= symtab->cap_decls) {
    Declaration* old_arr = symtab->decls;
    symtab->cap_entries = roundUpToNextMultiple(symtab->cap_entries, 4096)
    symtab->entries = (SymtabEntry*)realloc(symtab->decls, symtab->cap_decls);
    assert(symtab->entries != NULL);
    pgen_allocator_realloced(symtab->alloc, old_arr, symtab->entries, free);
  }

  symtab->decls[symtab->num_entries++] = decl;
}

static inline void
Symtab_verifyNoShadowing(daisho_astnode_t* ast) {}

#endif /* DAIC_SYMTAB_INCLUDE */
