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
    pgen_allocator* alloc;
    size_t num_entries;
    size_t cap_entries;
} Symtab;

/*

typedef struct {
  daisho_astnode_t* belongsTo;
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

typedef enum {
  SYMTAB_TYPE,
  FUNCTION_TYPE,
  VOID_TYPE,
  VOIDPTR_TYPE,
} TypeKind;

struct ConcreteType;
typedef struct ConcreteType ConcreteType;
struct ConcreteType {
  union {
    SymtabEntry* entry;
  };
  TypeKind kind;
  size_t size;
};

// The type of an expression in the AST.
struct ExprType;
typedef struct ExprType ExprType;
struct ExprType {
  union {
    ExprType* generic;
    SymtabEntry* declared_at;
  };
  uint8_t is_concrete : 1;
  uint8_t pointer_depth : 7;
};


#endif /* DAIC_TYPES_INCLUDE */