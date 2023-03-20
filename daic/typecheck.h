#ifndef DAIC_TYPECHECK_INCLUDE
#define DAIC_TYPECHECK_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho_peg.h"
#endif

static inline Identifier
nodeIdentifier(daisho_astnode_t* node) {
    return (Identifier){node->tok_repr, node->repr_len};
}

static inline void
mainReturnsInt(daisho_astnode_t* ast) {}

static inline _Dai_List_NamespaceDecl
extractTLDs(daisho_astnode_t* root) {
    _Dai_List_NamespaceDecl nsdlist = _Dai_List_NamespaceDecl_new();

    daisho_astnode_t* nslist = root->children[0];
    for (size_t nsnum = 0; nsnum < nslist->num_children; nsnum++) {
        NamespaceDecl nsd;
        nsd.symtab.decls = _Dai_List_Declaration_new();
        nsd.symtab.parent = NULL;
        nsd.nsnode = nslist->children[nsnum];
        nsd.id = nodeIdentifier(nsd.nsnode->children[0]);
        _Dai_List_NamespaceDecl_add(&nsdlist, nsd);

        daisho_astnode_t** items = nsd.nsnode->children + 1;
    }

    return nsdlist;
}

static inline void
exprTypeVisit(daisho_astnode_t* n, daisho_astnode_t* ns) {
    printf("Visiting kind: %s\n", daisho_nodekind_name[n->kind]);
    daisho_astnode_kind kind = n->kind;
    if (kind == DAISHO_NODE_PROGRAM) {
        for (size_t i = 0; i < n->children[0]->num_children; i++)
            exprTypeVisit(n->children[0]->children[i], NULL);
    } else if (kind == DAISHO_NODE_NAMESPACE) {
        for (size_t i = 0; i < n->children[1]->num_children; i++)
            exprTypeVisit(n->children[1]->children[i], n->children[0]);
    } else {
        printf("Error in type checking: Unknown astnode kind: %s\n", daisho_nodekind_name[n->kind]);
    }
}

/*
static inline void
postorderIterative(daisho_astnode_t* ast) {
    daisho_astnode_t* stack1[5000];
    size_t stack_size1 = 1;
    stack1[0] = ast;
    daisho_astnode_t* stack2[5000];
    size_t stack_size2 = 0;
    while (stack_size1) {
        daisho_astnode_t* n = stack1[--stack_size1];
        stack2[stack_size2++] = n;
        for (size_t i = 0; i < n->num_children; i++) stack2[stack_size2++] = n->children[i];
    }

    while (stack_size2) exprTypeVisit(stack2[--stack_size2]);
}

static inline void
postorderRecursive(daisho_astnode_t* n) {
    for (size_t i = 0; i < n->num_children; i++) postorderRecursive(n->children[i]);
    exprTypeVisit(n);
}

static inline void
typeAST(daisho_astnode_t* ast) {
    postorderRecursive(ast);
    // postorderIterative(ast);
}
*/
#endif /* DAIC_TYPECHECK_INCLUDE */
