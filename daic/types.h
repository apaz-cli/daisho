#ifndef DAIC_TYPES_INCLUDE
#define DAIC_TYPES_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "daisho.peg.h"
#endif

#include "enums.h"
#include "list.h"

// This file should contain only type definitions.

typedef struct {
    char* target;
    char* outputfile;
    char* errstr;
    size_t errstrlen;
    size_t errstrcap;
    bool errfail : 1;
    bool h : 1;  // Help
    bool v : 1;  // Version
    bool t : 1;  // Tokens
    bool a : 1;  // AST
    bool c : 1;  // Color
} Daic_Args;

_DAIC_LIST_DECLARE(codepoint_t)
_DAIC_LIST_DECLARE(daisho_token)

//////////////////////////////
// SYMTABS AND DECLARATIONS //
//////////////////////////////

typedef struct {
    codepoint_t* name;
    size_t len;
} Identifier;

struct NamespaceDecl;
typedef struct NamespaceDecl NamespaceDecl;
typedef struct {
    Identifier id;
    NamespaceDecl* ns;
} ResolvedIdentifier;

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

typedef int UNIMPL;

struct Declaration;
typedef struct Declaration Declaration;

typedef struct {
    Declaration* type;
    Identifier name;
    size_t size;
} Field;

typedef struct {
    Identifier name;
} TraitRequirement;

typedef struct {
    Identifier name;
} TraitRequirementImpl;

typedef struct {
    Identifier id;
} StructDecl;
typedef struct {
    Identifier id;
} UnionDecl;
typedef struct {
    Identifier id;
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
typedef struct {
    void* ret_type;
    void* arg_types;
    daisho_astnode_t* body;
} CFunctionDecl;

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
        CFunctionDecl cfndecl;
    };
    daisho_astnode_t* source;
    Identifier id;
    uint8_t kind;
};
_DAIC_LIST_DECLARE(Declaration)

struct PreMonoSymtab;
typedef struct PreMonoSymtab PreMonoSymtab;
struct PreMonoSymtab {
    PreMonoSymtab* parent;
    _Daic_List_Declaration decls;
};
_DAIC_LIST_DECLARE(PreMonoSymtab)

struct NamespaceDecl {
    Identifier id;
    PreMonoSymtab symtab;
    daisho_astnode_t* nsnode;
};
_DAIC_LIST_DECLARE(NamespaceDecl)

typedef struct {
    bool err;                     // 1 if error, 0 if the rest is valid.
    bool sign;                    // 1 if negative, 0 if positive
    bool floating;                // 1 if number is fp
    char* postfix;                // Nullable, ((i|u)(8|16|32|64)?|f(32|64)?|d|l|ll|s|ss)
    unsigned long long content;   // [0-9]+
    unsigned long long decimals;  // \.[0-9]*
} NumberLiteral;

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

struct PostMonoType;
typedef struct PostMonoType PostMonoType;
struct PostMonoType {
    UNIMPL ui;
};
_DAIC_LIST_DECLARE(PostMonoType)

typedef struct {
    void (*f)(void*);
    void* a;
} DaicCleanupEntry;
_DAIC_LIST_DECLARE(DaicCleanupEntry)
typedef _Daic_List_DaicCleanupEntry DaicCleanupContext;

struct DaicError;
typedef struct DaicError DaicError;
struct DaicError {
    DaicError* next;
    char* msg;  // Non-owning.
    char* file;
    size_t line;
    size_t col;
    DaicSeverity severity;
    DaicStage stage;
    bool trace_frame;
};
typedef DaicError* DaicErrorPtr;
_DAIC_LIST_DECLARE(DaicErrorPtr)

struct DaicContext {
    Daic_Args args;
    FILE* daic_stdout;
    FILE* daic_stderr;
    char* panic_err_message;
    jmp_buf panic_handler;
    _Daic_List_DaicErrorPtr errors;
    pgen_allocator allocator;
    DaicCleanupContext cleanup;
    daisho_tokenizer tokenizer;
    daisho_parser_ctx parser;
    daisho_astnode_t* ast;
    NamespaceDecl* global_namespace;
    _Daic_List_NamespaceDecl namespaces;
};

///////////////////////////////
// IMPORTANT PREDECLARATIONS //
///////////////////////////////
#if __clang__
_Pragma("clang diagnostic push")
_Pragma("clang diagnostic ignored \"-Wundefined-internal\"")
#endif

static inline void daic_panic(DaicContext* ctx, const char* panic_msg);
static inline void* daic_cleanup_realloc(DaicContext* ctx, void* ptr, size_t size);

#if __clang__
_Pragma("clang diagnostic pop")
#endif


// Expand lists

_DAIC_LIST_DEFINE(codepoint_t)
_DAIC_LIST_DEFINE(daisho_token)
_DAIC_LIST_DEFINE(Declaration)
_DAIC_LIST_DEFINE(NamespaceDecl)
_DAIC_LIST_DEFINE(PreMonoType)
_DAIC_LIST_DEFINE(PostMonoType)
_DAIC_LIST_DEFINE(DaicCleanupEntry)
_DAIC_LIST_DEFINE(InputFile)
_DAIC_LIST_DEFINE(DaicErrorPtr)

#endif /* DAIC_TYPES_INCLUDE */
