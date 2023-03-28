#ifndef DAIC_TYPES_INCLUDE
#define DAIC_TYPES_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho_peg.h"
#endif

#include "list.h"

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

struct InputFile {
    char* fname;
    ino_t inode;
    char* content;
    size_t contentlen;
    codepoint_t* cps;
    size_t* cps_map;
    size_t cpslen;
};
typedef struct InputFile InputFile;

_DAIC_LIST_DECLARE(InputFile)
_DAIC_LIST_DEFINE(InputFile)

static inline void
InputFile_free(InputFile of) {
    if (of.fname) free(of.fname);
    if (of.content) free(of.content);
    if (of.cps) free(of.cps);
    if (of.cps_map) free(of.cps_map);
}

static inline void
InputFile_cleanup(void* ifs) {
    _Daic_List_InputFile* ipfs = (_Daic_List_InputFile*)ifs;
    for (size_t i = 0; i < ipfs->len; i++) InputFile_free(ipfs->buf[i]);
    _Daic_List_InputFile_clear(ipfs);
}

typedef int UNIMPL;

struct Declaration;
typedef struct Declaration Declaration;
typedef struct {
    Declaration* type;
    Identifier name;
    size_t size;
} Field;

struct NamespaceDecl;
typedef struct NamespaceDecl NamespaceDecl;

typedef struct {
    UNIMPL ui;
} StructDecl;
typedef struct {
    UNIMPL ui;
} UnionDecl;
typedef struct {
    UNIMPL ui;
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
    NamespaceDecl* ns;
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
        StructDecl structdecl;
        UnionDecl uniondecl;
        TraitDecl traitdecl;
        ImplDecl impldecl;
        CTypeDecl ctypedecl;
        AliasDecl aliasdecl;
        FunctionDecl fndecl;
    };
    daisho_astnode_t* source;
    Identifier id;
    uint8_t kind;
};

_DAIC_LIST_DECLARE(Declaration)
_DAIC_LIST_DEFINE(Declaration)

struct PreMonoSymtab;
typedef struct PreMonoSymtab PreMonoSymtab;
struct PreMonoSymtab {
    PreMonoSymtab* parent;
    _Daic_List_Declaration decls;
};

struct NamespaceDecl {
    Identifier id;
    PreMonoSymtab symtab;
    daisho_astnode_t* nsnode;
};

_DAIC_LIST_DECLARE(NamespaceDecl)
_DAIC_LIST_DEFINE(NamespaceDecl)

//////////////////////
// TYPES IN THE AST //
//////////////////////

// The type of an expression in the AST.
struct PreMonoType;
typedef struct PreMonoType PreMonoType;
_DAIC_LIST_DECLARE(PreMonoType)
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
            _Daic_List_PreMonoType argt;
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

_DAIC_LIST_DEFINE(PreMonoType)

struct PostMonoType;
typedef struct PostMonoType PostMonoType;
struct PostMonoType {
    UNIMPL ui;
};

_DAIC_LIST_DECLARE(PostMonoType)
_DAIC_LIST_DEFINE(PostMonoType)

#endif /* DAIC_TYPES_INCLUDE */
