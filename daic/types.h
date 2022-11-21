#ifndef DAIC_TYPES_INCLUDE
#define DAIC_TYPES_INCLUDE
#ifndef PGEN_UTF8_INCLUDED
#include "grammar/daisho_tokenizer_parser.h"
#endif

// This file should contain only type definitions.

typedef char* SymtabKey;
typedef char* SymtabValue;

typedef struct {
    SymtabKey key;
    SymtabValue value;
} SymtabEntry;

typedef struct {
    SymtabEntry* entries;
    size_t num_entries;
    size_t cap_entries;
    pgen_allocator* alloc;
} Symtab;

/*

typedef struct {
  ASTNode* belongsTo;
  List<BoundType> backedges;
} BindableType;

typedef struct {
  UniverseType from;
  List<Void*> as;
} BoundType;

// A type unification context
typedef struct {
  List<>
} Universe;

typedef struct {} NamespaceDecl;
typedef struct {
  
} StructDecl;
typedef struct {} UnionDecl;
typedef struct {} TraitDecl;
typedef struct {} ImplDecl;
typedef struct {} CTypeDecl;
typedef struct {} AliasDecl;
typedef struct {} FunctionDecl;

typedef struct {
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
} Declaration;
*/

// Constructed post-monomorphization.
// Goes into the symbol table that is attached to each lexical scope in the AST. 
typedef struct {
    daisho_astnode_t* source;
    size_t size;
} TypeDecl;

// The type of an expression in the AST.
typedef struct {
    TypeDecl* declared_at;
    uint8_t pointer_depth;
    bool concrete : 1;
} ExprType;


#endif /* DAIC_TYPES_INCLUDE */