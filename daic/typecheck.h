#ifndef DAIC_TYPECHECK_INCLUDE
#define DAIC_TYPECHECK_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho.peg.h"
#endif

#include "types.h"

static inline Identifier
nodeIdentifier(daisho_astnode_t* node) {
    return (Identifier){node->tok_repr, node->repr_len};
}

static inline void
mainReturnsInt(daisho_astnode_t* ast) {}

static inline _Daic_List_NamespaceDecl
extractNamespacesAndTLDs(DaicContext* ctx, daisho_astnode_t* root) {
    _Daic_List_NamespaceDecl nsdlist = _Daic_List_NamespaceDecl_new(ctx);

    daisho_astnode_t* nslist = root->children[0];
    for (size_t nsnum = 0; nsnum < nslist->num_children; nsnum++) {
        NamespaceDecl nsd;
        nsd.symtab.decls = _Daic_List_Declaration_new(ctx);
        nsd.symtab.parent = NULL;
        nsd.nsnode = nslist->children[nsnum];
        nsd.id = nodeIdentifier(nsd.nsnode->children[0]);
        _Daic_List_NamespaceDecl_add(&nsdlist, nsd);

        _Daic_List_Declaration* decls = &nsd.symtab.decls;
        daisho_astnode_t** nsdecl_items = nsd.nsnode->children[1]->children;
        size_t num_nsdecl_items = nsd.nsnode->children[1]->num_children;
        for (size_t i = 0; i < num_nsdecl_items; i++) {
            daisho_astnode_t* tld = nsdecl_items[i];
            if (tld->kind == DAISHO_NODE_FNDECL) {
                Identifier id = nodeIdentifier(tld->children[1]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = FN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CTYPE) {
                Identifier id = nodeIdentifier(tld->children[1]);
                CTypeDecl ct = {0};
                Declaration d;
                d.ctypedecl = ct;
                d.source = tld;
                d.id = id;
                d.kind = CTYPE_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CFN) {
                Identifier id = nodeIdentifier(tld->children[1]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = FN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else {
                printf("Cannot extract TLD of kind: %s\n", daisho_nodekind_name[tld->kind]);
                exit(1);
            }
        }
    }

    return nsdlist;
}

static inline void
cleanup_namespaces_tlds(void* nstld) {
    _Daic_List_NamespaceDecl* nsdlist = (_Daic_List_NamespaceDecl*)nstld;

    for (size_t i = 0; i < nsdlist->len; i++) {
        PreMonoSymtab pms = nsdlist->buf[0].symtab;
        _Daic_List_Declaration* decls = &pms.decls;
        _Daic_List_Declaration_cleanup(decls);
    }
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
