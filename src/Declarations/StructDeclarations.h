#ifndef STRUCT_DECLARATIONS
#define STRUCT_DECLARATIONS

#include "TokType.h"
#include <apaz-libc.h>
#include <list.h/list.h>

/***************************/
/*    TYPE DECLARATIONS    */
/***************************/

/*************/
/* Tokenizer */
/*************/

// Defined in the "Compiler" section.
struct Target;
typedef struct Target Target;

struct Token {
  TokType type;
  String content;

  Target* source;
  size_t line;
  size_t pos;
};
typedef struct Token Token;
LIST_DEFINE(Token);
typedef List_Token TokenStream;

struct StiltsTokenizer {
  size_t current_position;
  List_Token outstream;
  List_Token ignorestream;
};
typedef struct StiltsTokenizer StiltsTokenizer;

/*******/
/* AST */
/*******/

struct ASTNode;
#include "ASTNodeType.h"
typedef struct ASTNode ASTNode;
typedef ASTNode AST;
struct ASTNode {
  // Information format specified by node type.
  ASTNodeType type;
  void* typed_info;

  Token* corresponding_tokens;
  size_t num_corresponding;

  ASTNode* children;
  size_t num_children;
};
LIST_DEFINE(ASTNode);
LIST_DEFINE(AST);

/**********/
/* Parser */
/**********/

#define STILTS_PARSER_MAX_STACK_FRAMES 500
struct ParserStackFrame {
  TokType currently_parsing;
  size_t token_num;
};
typedef struct ParserStackFrame ParserStackFrame;
struct ParserCallStack {
  ParserStackFrame frames[STILTS_PARSER_MAX_STACK_FRAMES];
  size_t height;
};
typedef struct ParserCallStack ParserCallStack;
struct StiltsParser {
  Token* sym;
  size_t current_token;
  List_Token token_stream;
  ParserCallStack call_stack;
};
typedef struct StiltsParser StiltsParser;

/*************/
/* ASTWalker */
/*************/

enum TraversalOrder { PREORDER, POSTORDER, PREORDER_BACKWARD, POSTORDER_BACKWARD };
typedef enum TraversalOrder TraversalOrder;

typedef void (*walk_fn)(ASTNode* , void*);
struct ASTWalker {
  TraversalOrder order;
  AST root;
  List_ASTNode stack;
  walk_fn onwalk;
};
typedef struct ASTWalker ASTWalker;

/*********************/
/* Semantic Analysis */
/*********************/

struct MethodArg;
typedef struct MethodArg MethodArg;
typedef MethodArg* MethodArgPtr;

struct Method;
typedef struct Method Method;
typedef Method* MethodPtr;

struct Trait;
typedef struct Trait Trait;
typedef Trait* TraitPtr;

struct Type;
typedef struct Type Type;
typedef Type* TypePtr;

struct Expr;
typedef struct Expr Expr;
typedef Expr* ExprPtr;

// As in a type signature, not an expr.
struct MethodArg {
  Type* type;
  Token* tok;
};
LIST_DEFINE(MethodArg);
LIST_DEFINE(MethodArgPtr);

// Information about type signature.
struct Method {
  Token* tok;
  Type* return_type;
  List_MethodArg args;
  ASTNode* implementation;
};
LIST_DEFINE(Method);
LIST_DEFINE(MethodPtr);

struct Trait {
  // Implementation is null
  List_Method abstract_methods;
  // Implementation not null
  List_Method default_methods;
  // Actually a List_Trait
  TraitPtr subtraits;
};
LIST_DEFINE(Trait);
LIST_DEFINE(TraitPtr);

struct Type {
  Token* source_name; // Null if not inferred
  String runtime_name; // Null if not inferred
  List_TraitPtr implements;
  List_Method methods;
};
LIST_DEFINE(Type);
LIST_DEFINE(TypePtr);

struct Expr {
  TypePtr own_type;
  bool compile;
  void* other;
};
LIST_DEFINE(Expr);
LIST_DEFINE(ExprPtr);

/* Validate, in order: */
typedef List_Trait TraitTable;
typedef List_Type  TypeTable;
typedef List_Expr  ExprTable;


/************/
/* Compiler */
/************/

struct Target {
    char* file_name;
    String content;
    TokenStream tokens;
    AST ast;
};
LIST_DEFINE(Target);

struct CMDLineFlags {
  /* Compilation steps */
  bool parse;
  bool check;
  bool codegen;
  bool compileC;

  /* C codegen options */
  char* CC;
  List_String cflags;
  char* temp_folder;

  /* Target files to compile */
  List_Target targets;
};
typedef struct CMDLineFlags CMDLineFlags;


#endif // STRUCT_DECLARATIONS