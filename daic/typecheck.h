#ifndef DAIC_TYPECHECK_INCLUDE
#define DAIC_TYPECHECK_INCLUDE
#include "list.h"
#ifndef PGEN_UTF8_INCLUDED
#include "daisho.peg.h"
#endif

#include "errhandler.h"
#include "types.h"

static inline Identifier
nodeIdentifier(DaicContext* ctx, daisho_astnode_t* node) {
    if (!node) daic_panic(ctx, "Cannot get the identifier of null.");
    if (!node->tok_repr) daic_panic(ctx, "The Identifier representation has not been set.");
    return (Identifier){node->tok_repr, node->repr_len};
}

static inline Identifier
stringIdentifier(DaicContext* ctx, char* str) {
    if (!str) daic_panic(ctx, "Cannot get the identifier of null.");
    size_t len = strlen(str);
    codepoint_t* m = (codepoint_t*)daic_cleanup_malloc(ctx, sizeof(codepoint_t) * len);
    for (size_t i = 0; i < len; i++) m[i] = str[i];
    return (Identifier){m, len};
}

// Returns the UTF-8 encoded identifier.
static inline char*
identifierString(DaicContext* ctx, Identifier* id) {
    if (!id->name | !id->len) return "";
    char* name = NULL;
    size_t namelen = 0;
    if (!UTF8_encode(id->name, id->len, &name, &namelen))
        daic_panic(ctx, "Couldn't encode the identifier as UTF-8.");
    char* mname = daic_cleanup_strdup(ctx, name);
    UTF8_FREE(name);
    return mname;
}

static inline PreMonoSymtab* findPreSymtab(daisho_astnode_t* n) {
    return n->presymtab ? n->presymtab : findPreSymtab(n->parent);
}

static inline bool
startsWith(char* str, const char* prefix) {
    return strncmp(prefix, str, strlen(prefix)) == 0;
}

static inline NumberLiteral
parse_numberliteral(DaicContext* ctx, daisho_astnode_t* node) {
    // Numbers don't contain any arbitrary utf8,
    // so treating them as cstring is fine.
    Identifier id = nodeIdentifier(ctx, node);
    char* il = identifierString(ctx, &id);
    NumberLiteral ret = {0, 0, 0, NULL, 0, 0};

    // Parse sign
    ret.sign = *il == '-';
    il += ret.sign;

    // Parse first part of number
    char* spn = NULL;
    int base = 0;
    char* spn2 = "01";
    char* spn10 = "0123456789";
    char* spn16 = "0123456789aAbBcCdDeEfF";
    if (startsWith(il, "0x") || startsWith(il, "0X")) {
        il += 2;
        base = 16;
        spn = spn16;
    } else if (startsWith(il, "0b") || startsWith(il, "0B")) {
        il += 2;
        base = 2;
        spn = spn2;
    } else {
        base = 10;
        spn = spn10;
    }
    size_t len = strspn(il, spn);
    char tmp = il[len];
    il[len] = '\0';
    errno = 0;
    char* endptr = NULL;
    ret.content = strtoull(il, &endptr, base);
    il[len] = tmp;
    il += len;
    if (errno || (endptr != il)) {
        ret.err = 1;
        return ret;
    }

    if (*il == '.') {
        il++;

        // Parse [0-9]*
        len = strspn(il, spn10);
        ret.floating = 1;
        ret.decimals = !!len;
        if (len) {
            tmp = il[len];
            il[len] = '\0';
            errno = 0;
            endptr = NULL;
            ret.decimals = strtoull(il, &endptr, 10);
            il[len] = tmp;
            il += len;
            if (errno || (endptr != il)) {
                ret.err = 1;
                return ret;
            }
        }
    }

    // If there's no postfix letters, we're done.
    if (*il == '\0') return ret;

    // Parse the postfix.
    char* postfixes[] = {"i", "i8", "i16", "i32", "i64", "u8",  "u16", "u32", "u64",
                         "l", "ll", "s",   "ss",  "f",   "f32", "f64", "d"};
    size_t postfixes_len = _DAI_ARRAY_SIZE(postfixes);

    for (size_t i = 0; i < postfixes_len; i++) {
        if (!strcmp(il, postfixes[i])) {
            ret.postfix = postfixes[i];
            break;
        }
    }

    if (!ret.postfix) daic_panic(ctx, "Unknown number literal postfix.");

    return ret;
}

// Given the name of a namespace, find it in the context.
// Converts the namespace identifier to the registered NamespaceDecl.
// Does not look up the namespace for identifiers.
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
    return (ResolvedIdentifier){nodeIdentifier(ctx, node), nslookup(ctx, ns)};
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
        Identifier nsid = nodeIdentifier(ctx, nsname);
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
            Identifier fn_id = nodeIdentifier(ctx, fnname);
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
        Identifier rettype_id = nodeIdentifier(ctx, main_rettype);
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
    (void)methodArglist, (void)methodIsStub;
}

static inline void
hoistMethodDeclarations(DaicContext* ctx, daisho_astnode_t* sudecl) {
    (void)ctx, (void)sudecl;
}

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
        nsd.id = nodeIdentifier(ctx, nsd.nsnode->children[0]);

        _Daic_List_Declaration* decls = &nsd.symtab.decls;
        daisho_astnode_t** nsdecl_items = nsd.nsnode->children[1]->children;
        size_t num_nsdecl_items = nsd.nsnode->children[1]->num_children;
        for (size_t i = 0; i < num_nsdecl_items; i++) {
            daisho_astnode_t* tld = nsdecl_items[i];
            if (tld->kind == DAISHO_NODE_STRUCT) {
                Identifier id = nodeIdentifier(ctx, tld->children[0]);
                StructDecl sd = {0};
                sd.id = id;
                Declaration d;
                d.structdecl = sd;
                d.source = tld;
                d.id = id;
                d.kind = STRUCT_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_UNION) {
                Identifier id = nodeIdentifier(ctx, tld->children[0]);
                UnionDecl ud = {0};
                ud.id = id;
                Declaration d;
                d.uniondecl = ud;
                d.source = tld;
                d.id = id;
                d.kind = UNION_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_TRAIT) {
                Identifier id = nodeIdentifier(ctx, tld->children[0]);
                TraitDecl td = {0};
                td.id = id;
                Declaration d;
                d.traitdecl = td;
                d.source = tld;
                d.id = id;
                d.kind = TRAIT_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_IMPL) {
                Identifier id = nodeIdentifier(ctx, tld->children[0]);
                ImplDecl idl = {0};
                idl.trait = nodeIdentifier(ctx, tld->children[1]);
                idl.for_type = nodeIdentifier(ctx, tld->children[2]);
                Declaration d;
                d.impldecl = idl;
                d.source = tld;
                d.id = id;
                d.kind = IMPL_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CFN) {
                Identifier id = nodeIdentifier(ctx, tld->children[1]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = CFN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_FNDECL) {
                Identifier id = nodeIdentifier(ctx, tld->children[2]);
                FunctionDecl fd = {0};
                Declaration d;
                d.fndecl = fd;
                d.source = tld;
                d.id = id;
                d.kind = FN_DECLKIND;
                _Daic_List_Declaration_add(decls, d);
            } else if (tld->kind == DAISHO_NODE_CTYPE) {
                Identifier id = nodeIdentifier(ctx, tld->children[0]);
                CTypeDecl ct = {0};
                ct.from = nodeIdentifier(ctx, tld->children[1]);
                ct.to = nodeIdentifier(ctx, tld->children[2]);
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
        _Daic_List_NamespaceDecl_add(&ctx->namespaces, nsd);
    }
}

static inline void
printNamespaceTLDs(DaicContext* ctx) {
    for (size_t i = 0; i < ctx->namespaces.len; i++) {
        NamespaceDecl* nsd = &(ctx->namespaces.buf[i]);
        fprintf(ctx->daic_stderr, "Namespace: %s\n", identifierString(ctx, &nsd->id));
        for (size_t j = 0; j < nsd->symtab.decls.len; j++) {
            Declaration* d = &(nsd->symtab.decls.buf[j]);
            fprintf(ctx->daic_stderr, "    TLD: %s\n", identifierString(ctx, &d->id));
        }
        fprintf(ctx->daic_stderr, "\n");
    }
}

static inline void
exprTypeVisitPostMono(DaicContext* ctx, daisho_astnode_t* n, daisho_astnode_t* ns) {
    printf("Visiting kind: %s\n", daisho_nodekind_name[n->kind]);
    daisho_astnode_kind kind = n->kind;
    if (kind == DAISHO_NODE_PROGRAM) {
        // For each namespace in the nslist (skip the shebang)
        for (size_t i = 0; i < n->children[0]->num_children; i++)
            exprTypeVisitPostMono(ctx, n->children[0]->children[i], NULL);
    } else if (kind == DAISHO_NODE_NAMESPACE) {
        // For each nsdecl in the nsdecl list, pass the identifier as ns.
        for (size_t i = 0; i < n->children[1]->num_children; i++)
            exprTypeVisitPostMono(ctx, n->children[1]->children[i], n->children[0]);
    } else if (kind == DAISHO_NODE_FNDECL) {
        daisho_astnode_t* fntype = n->children[0];
        daisho_astnode_t* rettype = n->children[1];
        daisho_astnode_t* name = n->children[2];
        daisho_astnode_t* expand = n->children[3];
        daisho_astnode_t* arglist = n->children[4];
        daisho_astnode_t* expression = n->children[5];
        exprTypeVisitPostMono(ctx, expression, ns);
    } else if (kind == DAISHO_NODE_CALL) {
        daisho_astnode_t* function = n->children[0];
        daisho_astnode_t* expand = n->children[1];
        daisho_astnode_t* exprlist = n->children[2];
        for (size_t i = 0; i < exprlist->num_children; i++)
            exprTypeVisitPostMono(ctx, exprlist->children[i], ns);
    } else if (kind == DAISHO_NODE_CTYPE) {
        // Leaf
    } else if (kind == DAISHO_NODE_INTLIT || kind == DAISHO_NODE_TINTLIT ||
               kind == DAISHO_NODE_FLOATLIT || kind == DAISHO_NODE_TFLOATLIT) {
        Identifier id = nodeIdentifier(ctx, n);
        char* idutf8 = identifierString(ctx, &id);
        printf("Found number literal: %s\n", idutf8);

        NumberLiteral num = parse_numberliteral(ctx, n);
        if (num.err) {
            // TODO: Figure out propogating source information.
            DaicError* err =
                daic_error_new(ctx, DAIC_ERROR_STAGE_TYPING, "Could not parse the number literal.",
                               NULL, 0, 0, _DAIC_ERROR_SEV_ERROR, 0);
            _Daic_List_DaicErrorPtr_add(&ctx->errors, err);
        }

    } else if (kind == DAISHO_NODE_THEN) {
        daisho_astnode_t* first = n->children[0];
        daisho_astnode_t* second = n->children[1];
        
    } else if (kind == DAISHO_NODE_ALSO) {
        daisho_astnode_t* first = n->children[0];
        daisho_astnode_t* second = n->children[1];
    }
    
    // Node kinds that have nothing to do with expressions
    else if (kind == DAISHO_NODE_CFN) {

    }
    else {
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
