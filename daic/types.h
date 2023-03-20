#ifndef DAIC_TYPES_INCLUDE
#define DAIC_TYPES_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho_peg.h"
#endif

#include <daisho/Daisho.h>

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
    if (i1.name == i2.name) return 1;
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
#define STRUCT_DECLKIND 1
#define UNION_DECLKIND 2
#define TRAIT_DECLKIND 3
#define IMPL_DECLKIND 4
#define CTYPE_DECLKIND 5
#define ALIAS_DECLKIND 6
#define FN_DECLKIND 7
#define CFN_DECLKIND 8
    union {
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

_DAI_LIST_DECLARE(Declaration)
_DAI_LIST_DEFINE(Declaration)

struct PreMonoSymtab;
typedef struct PreMonoSymtab PreMonoSymtab;
struct PreMonoSymtab {
    PreMonoSymtab* parent;
    _Dai_List_Declaration decls;
};

typedef struct {
    Identifier id;
    PreMonoSymtab symtab;
    daisho_astnode_t* nsnode;
} NamespaceDecl;

_DAI_LIST_DECLARE(NamespaceDecl)
_DAI_LIST_DEFINE(NamespaceDecl)

//////////////////////
// TYPES IN THE AST //
//////////////////////

// The type of an expression in the AST.
struct PreMonoType;
typedef struct PreMonoType PreMonoType;
_DAI_LIST_DECLARE(PreMonoType)
struct PreMonoExpand;
typedef struct PreMonoExpand PreMonoExpand;
struct PreMonoType {
#define SYMTAB_PREMONOTYPE 0   /* A ctype or struct type in a symtab. */
#define FUNCTION_PREMONOTYPE 1 /* A type of the form Type -> Type.    */
#define VOID_PREMONOTYPE 2     /* The type Void.                      */
#define VOIDPTR_PREMONOTYPE 3  /* The type Void*.                     */
#define PTR_PREMONOTYPE 4      /* A type of the form Type*.           */
#define TRAIT_PREMONOTYPE 5    /* A trait type.                       */
#define DYNTRAIT_PREMONOTYPE 6 /* A dynamic trait type.               */
#define GENERIC_PREMONOTYPE 7  /* A type given by a generic.          */
    union {
        struct {
            Declaration* decl;
        } st;
        struct {
            PreMonoType* rett;
            _Dai_List_PreMonoType argt;
        } fn;
        // No repr for Void. Use the global declaration.
        // No repr for Void*. Use the global declaration.
        struct {
            PreMonoType* to;
        } ptr;
        struct {
            Declaration* decl;
        } trait;
        struct {
            Declaration* decl;
        } dyntrait;
        struct {
            Declaration* decl;
        } generic;
    };
    uint8_t kind;
};

static PreMonoType _voidpretype = {.kind = VOID_PREMONOTYPE};
static PreMonoType* voidpretype = &_voidpretype;
static PreMonoType _voidptrpretype = {.kind = VOIDPTR_PREMONOTYPE};
static PreMonoType* voidptrpretype = &_voidptrpretype;

_DAI_LIST_DEFINE(PreMonoType)

struct PostMonoType;
typedef struct PostMonoType PostMonoType;
struct PostMonoType {};

#endif /* DAIC_TYPES_INCLUDE */
