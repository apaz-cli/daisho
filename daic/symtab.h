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

static inline int
key_equals(SymtabKey key1, SymtabKey key2) {
    return !strcmp(key1, key2);
}

static inline Symtab*
Symtab_init(daisho_parser_ctx* ctx) {
    Symtab* symtab = PGEN_ALLOC_OF(ctx->alloc, Symtab);
    symtab->entries = (SymtabEntry*)malloc(sizeof(SymtabEntry*) * 64);
    symtab->num_entries = 0;
    symtab->cap_entries = 64;
    symtab->alloc = ctx->alloc;
    pgen_defer(ctx->alloc, free, symtab->entries, ctx->alloc->rew);
    return symtab;
}

static inline int
Symtab_get(Symtab* symtab, SymtabKey key, SymtabValue* result) {
    for (size_t i = 0; i < symtab->num_entries; i++)
        if (key_equals(symtab->entries[i].key, key)) return *result = symtab->entries[i].value, 1;
    return 0;
}

static inline void
Symtab_add(Symtab* symtab, SymtabKey key, SymtabValue value) {
    if (symtab->num_entries >= symtab->cap_entries) {
        SymtabEntry* old_arr = symtab->entries;
        symtab->entries = (SymtabEntry*)realloc(
            symtab->entries,
            (symtab->cap_entries = roundUpToNextMultiple(symtab->cap_entries, 4096)));
        assert(symtab->entries != NULL);
        pgen_allocator_realloced(symtab->alloc, old_arr, symtab->entries, free);
    }

    symtab->entries[symtab->num_entries++] = (SymtabEntry){key, value};
}

static inline void
Symtab_verifyNoShadowing(daisho_astnode_t* ast) {}

#endif /* DAIC_SYMTAB_INCLUDE */