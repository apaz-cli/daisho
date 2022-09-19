#ifndef DAIC_ASTHELPERS_INCLUDE
#define DAIC_ASTHELPERS_INCLUDE
#include <stdint.h>
#include <stdlib.h>

#ifndef PGEN_UTF8_INCLUDED
#include "grammar/daisho_tokenizer_parser.h"
#endif

typedef struct {
    uint8_t pointer_depth;
    struct {
        bool resolved : 1;
        bool unresolved : 1;
    };
} TypeInfo;

daisho_astnode_t*
type_node(daisho_parser_ctx* ctx, daisho_astnode_t* node, uint8_t depth) {
    TypeInfo* info = PGEN_ALLOC_OF(ctx->alloc, TypeInfo);
    info->pointer_depth = depth;
    node->extra = info;
    return node;
}

#endif /* DAIC_ASTHELPERS_INCLUDE */