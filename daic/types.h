#ifndef DAIC_TYPES_INCLUDE
#define DAIC_TYPES_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "grammar/daisho_tokenizer_parser.h"
#endif

// This file should contain only type definitions.

//////////////////////////////
// SYMTABS AND DECLARATIONS //
//////////////////////////////

typedef struct {
    codepoint_t* name;
    size_t len;
} Identifier;

static inline int
ident_eq(Identifier i1, Identifier i2) {
    if (i1.len != i2.len) return 0;
    for (size_t i = 0; i < i1.len; i++)
        if (i1.name[i] != i2.name[i]) return 0;
    return 1;
}

struct Declaration;
typedef struct Declaration Declaration;
typedef struct {
    Declaration* type;
    codepoint_t* name;
    size_t size;
} Field;

typedef struct {
} NamespaceDecl;
typedef struct {
} StructDecl;
typedef struct {
} UnionDecl;
typedef struct {
} TraitDecl;
typedef struct {
    Identifier trait;
    Identifier for_type;
} ImplDecl;
typedef struct {
    Identifier from;
    Identifier to;
} CTypeDecl;
typedef struct {
    Identifier from;
    Declaration* to;
} AliasDecl;
typedef struct {
    void* ret_type;
    void* arg_types;
    daisho_astnode_t* body;
} FunctionDecl;

struct Declaration {
#define FIELD_DECLKIND 0
#define NAMESPACE_DECLKIND 1
#define STRUCT_DECLKIND 2
#define UNION_DECLKIND 3
#define TRAIT_DECLKIND 4
#define IMPL_DECLKIND 5
#define CTYPE_DECLKIND 6
#define ALIAS_DECLKIND 7
#define FN_DECLKIND 8
    union {
        NamespaceDecl ns;
        StructDecl s;
        UnionDecl u;
        TraitDecl t;
        ImplDecl i;
        CTypeDecl c;
        AliasDecl a;
        FunctionDecl f;
    };
    daisho_astnode_t* source;
    Identifier id;
    uint8_t kind;
};

struct Symtab;
typedef struct Symtab Symtab;
struct Symtab {
    Declaration** decls;
    pgen_allocator* alloc;
    size_t num_decls;
    size_t cap_decls;
};

//////////////////////
// TYPES IN THE AST //
//////////////////////

// The type of an expression in the AST.
struct ExprType;
typedef struct ExprType ExprType;
struct ExprType {
#define SYMTAB_EXPRTYPE 0
#define FUNCTION_EXPRTYPE 1
#define VOID_EXPRTYPE 2
#define TRAIT_EXPRTYPE 3
    union {
        ExprType* generic;
        Declaration* decl;
    };
    uint8_t kind : 2;
    // List_MonoParams mono;
};

////////////////////////
// FUNCTIONS ON TYPES //
////////////////////////

static inline ExprType*
typeFromDecl(Declaration* decl) {
    return NULL;
}

static inline char*
mangle_decl(Declaration* decl) {
    return NULL;
}

static inline char*
mangle_expr(ExprType* type) {
    return NULL;
}

//////////////
// BUILTINS //
//////////////

// static Declaration voidTypeDecl;
// static ExprType* voidType;

#endif /* DAIC_TYPES_INCLUDE */
