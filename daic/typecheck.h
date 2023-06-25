#ifndef DAIC_TYPECHECK_INCLUDE
#define DAIC_TYPECHECK_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho.peg.h"
#endif

#include "errhandler.h"
#include "types.h"

static inline Identifier
nodeIdentifier(daisho_astnode_t* node) {
    // TODO: remove or rethink eventually.
    if (!node) _DAI_ERROR("Cannot get the identifier of null.");
    if (!node->tok_repr) _DAI_ERROR("The Identifier representation has not been set.");
    return (Identifier){node->tok_repr, node->repr_len};
}

// returns a malloced cstr
static inline char*
identString(Identifier* id) {
    char* name = NULL;
    size_t namelen = 0;
    if (!UTF8_encode(id->name, id->len, &name, &namelen))
        _DAI_ERROR("Couldn't encode the identifier as UTF-8.");
    char* mname = strdup(name);
    UTF8_FREE(name);
    return mname;
}

static inline NamespaceDecl*
nslookup(DaicContext* ctx, Identifier* id) {
    if (!id) return ctx->global_namespace;
    for (size_t i = 0; i < ctx->namespaces.len; i++) {
        NamespaceDecl* ns = &(ctx->namespaces.buf[i]);
        if (ident_eq(ns->id, *id)) return ns;
    }
    daic_panic(ctx, "Cannot find the namespace of an identifier.");
    return NULL;
}

static inline ResolvedIdentifier
nodeResolvedIdentifier(DaicContext* ctx, daisho_astnode_t* node, Identifier* ns) {
    return (ResolvedIdentifier){nodeIdentifier(node), nslookup(ctx, ns)};
}

static codepoint_t _global_nsid_name[] = {'G', 'L', 'O', 'B', 'A', 'L', '\0'};

static inline void
findAndValidateMain(DaicContext* ctx, daisho_astnode_t* ast) {
    Identifier global_nsid = (Identifier){_global_nsid_name, 6};

    ast = ast->children[0];

    // Look fpr the GLOBAL namespace.
    daisho_astnode_t* global_tlds = NULL;
    for (size_t i = 0; i < ast->num_children; i++) {
        daisho_astnode_t* nsdecl = ast->children[i];
        daisho_astnode_t* nsname = nsdecl->children[0];
        Identifier nsid = nodeIdentifier(nsname);
        if (ident_eq(nsid, global_nsid)) global_tlds = nsdecl->children[1];
    }

    if (!global_tlds) {
        daic_type_error_global(ctx, "Couldn't find the GLOBAL namespace. This shouldn't happen.");
        return;
    }

    Identifier main_id = (Identifier){(codepoint_t[]){'m', 'a', 'i', 'n', '\0'}, 4};

    // Look for a main function.
    daisho_astnode_t* main_rettype = NULL;
    daisho_astnode_t* main_tmplexpand = NULL;
    daisho_astnode_t* main_arglist = NULL;

    for (size_t i = 0; i < global_tlds->num_children; i++) {
        daisho_astnode_t* tld = global_tlds->children[i];
        if (tld->kind == DAISHO_NODE_FN) {
            daisho_astnode_t* fnname = tld->children[0];
            Identifier fn_id = nodeIdentifier(fnname);
            if (ident_eq(fn_id, main_id)) {
                main_rettype = tld->children[0];
                main_tmplexpand = tld->children[3];
                main_arglist = tld->children[4];
                break;
            }
        }
    }

    if (!main_rettype) {
        daic_type_error_global(ctx, "Couldn't find the main() function.");
        return;
    }

    if (main_tmplexpand->kind != DAISHO_NODE_NOEXPAND) {
        daic_type_error_global(ctx, "The main() function cannot be templated.");
        return;
    }

    int valid_type = 0;
    if (main_rettype->kind == DAISHO_NODE_VOIDTYPE)
        valid_type = 1;
    else if (main_rettype->tok_repr && main_rettype->kind == DAISHO_NODE_TYPEIDENT) {
        Identifier rettype_id = nodeIdentifier(main_rettype);
        Identifier int_id = (Identifier){(codepoint_t[]){'I', 'n', 't', '\0'}, 3};
        if (ident_eq(rettype_id, int_id)) valid_type = 1;
    }
    if (!valid_type) {
        daic_type_error_global(
            ctx, "The main() function's return type must be Void, Int, or directly inferrable.");
        return;
    }

    if (main_arglist->num_children != 0) {
        daic_type_error_global(ctx, "The main() function must not take any arguments.");
        return;
    }
}

static inline void
prependSelfToMethod(DaicContext* ctx, daisho_astnode_t* methodArglist, int methodIsStub) {
    daisho_astnode_t* self = daisho_astnode_leaf(&ctx->allocator, DAISHO_NODE_SELFTYPE);
}

static inline void
hoistMethodDeclarations(DaicContext* ctx, daisho_astnode_t* sudecl) {}

// Constructs a namespace (symbol table) out of each
// namespace declaration in the AST.
static inline void
extractNamespacesAndTLDs(DaicContext* ctx, daisho_astnode_t* root) {
    ctx->namespaces = _Daic_List_NamespaceDecl_new(ctx);

    daisho_astnode_t* nslist = root->children[0];
    for (size_t nsnum = 0; nsnum < nslist->num_children; nsnum++) {
        NamespaceDecl nsd;
        nsd.symtab.decls = _Daic_List_Declaration_new(ctx);
        nsd.symtab.parent = NULL;
        nsd.nsnode = nslist->children[nsnum];
        nsd.id = nodeIdentifier(nsd.nsnode->children[0]);
        _Daic_List_NamespaceDecl_add(&ctx->namespaces, nsd);

        _Daic_List_Declaration* decls = &nsd.symtab.decls;
        daisho_astnode_t** nsdecl_items = nsd.nsnode->children[1]->children;
        size_t num_nsdecl_items = nsd.nsnode->children[1]->num_children;
        for (size_t i = 0; i < num_nsdecl_items; i++) {
            daisho_astnode_t* tld = nsdecl_items[i];

            if (tld->kind == DAISHO_NODE_STRUCT) {
                Identifier id = nodeIdentifier(tld->children[0]);
                StructDecl sd = {0};
                sd.id = id;
                Declaration d;
                d.structdecl = sd;
                d.source = tld;
                d.id = id;
                d.kind = STRUCT_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_UNION) {
                Identifier id = nodeIdentifier(tld->children[0]);
                UnionDecl ud = {0};
                ud.id = id;
                Declaration d;
                d.uniondecl = ud;
                d.source = tld;
                d.id = id;
                d.kind = UNION_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_TRAIT) {
                Identifier id = nodeIdentifier(tld->children[0]);
                TraitDecl td = {0};
                td.id = id;
                Declaration d;
                d.traitdecl = td;
                d.source = tld;
                d.id = id;
                d.kind = TRAIT_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_IMPL) {
                Identifier id = nodeIdentifier(tld->children[0]);
                ImplDecl idl = {0};
                idl.trait = nodeIdentifier(tld->children[1]);
                idl.for_type = nodeIdentifier(tld->children[2]);
                Declaration d;
                d.impldecl = idl;
                d.source = tld;
                d.id = id;
                d.kind = IMPL_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CFN) {
                Identifier id = nodeIdentifier(tld->children[1]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = CFN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_FNDECL) {
                Identifier id = nodeIdentifier(tld->children[1]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = FN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CTYPE) {
                Identifier id = nodeIdentifier(tld->children[0]);
                CTypeDecl ct = {0};
                ct.from = nodeIdentifier(tld->children[1]);
                ct.to = nodeIdentifier(tld->children[2]);
                Declaration d;
                d.ctypedecl = ct;
                d.source = tld;
                d.id = id;
                d.kind = CTYPE_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else {
                printf("Cannot extract TLD of kind: %s\n", daisho_nodekind_name[tld->kind]);
                exit(1);
            }
        }
    }
}

static inline void
exprTypeVisit(DaicContext* ctx, daisho_astnode_t* n, daisho_astnode_t* ns) {
    printf("Visiting kind: %s\n", daisho_nodekind_name[n->kind]);
    daisho_astnode_kind kind = n->kind;
    if (kind == DAISHO_NODE_PROGRAM) {
        // For each namespace in the nslist (skip the shebang)
        for (size_t i = 0; i < n->children[0]->num_children; i++)
            exprTypeVisit(ctx, n->children[0]->children[i], NULL);
    } else if (kind == DAISHO_NODE_NAMESPACE) {
        // For each nsdecl in the nsdecl list, pass the identifier as ns.
        for (size_t i = 0; i < n->children[1]->num_children; i++)
            exprTypeVisit(ctx, n->children[1]->children[i], n->children[0]);
    } else if (kind == DAISHO_NODE_FNDECL) {
        daisho_astnode_t* rettype = n->children[0];
        daisho_astnode_t* name = n->children[1];
        daisho_astnode_t* expand = n->children[2];
        daisho_astnode_t* arglist = n->children[3];
        daisho_astnode_t* expression = n->children[4];
        exprTypeVisit(ctx, expression, ns);
    } else if (kind == DAISHO_NODE_CALL) {
        daisho_astnode_t* function = n->children[0];
        daisho_astnode_t* expand = n->children[1];
        daisho_astnode_t* exprlist = n->children[2];
        for (size_t i = 0; i < exprlist->num_children; i++)
            exprTypeVisit(ctx, exprlist->children[i], ns);
    } else if (kind == DAISHO_NODE_INTLIT) {
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
