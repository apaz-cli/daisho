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
struct Token {
  TokType type;
  size_t pos;
  size_t line;
  String file;
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
struct ASTNode {
  // Information format specified by node type.
  ASTNodeType type;
  void *typed_info;

  Token* corresponding_tokens;
  size_t num_corresponding;

  ASTNode *children;
  size_t num_children;
};

LIST_DEFINE(ASTNode);
typedef ASTNode AST;


/**********/
/* Parser */
/**********/

#define STILTS_PARSER_MAX_STACK_FRAMES 150
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
  Token sym;
  size_t current_token;
  List_Token token_stream;
  ParserCallStack call_stack;
};
typedef struct StiltsParser StiltsParser;


/*************/
/* ASTWalker */
/*************/
enum TraversalOrder {

};
typedef enum TraversalOrder TraversalOrder;


typedef void (walk_fn*)(ASTNode*, void*);
struct ASTWalker {
  TraversalOrder order;
  AST root;
  List_ASTNode stack;
  walk_fn onwalk;
};
typedef struct ASTWalker ASTWalker;

/**********/
/* Tables */
/**********/

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
  Type type;
  Token* tok;
};
LIST_DEFINE(MethodArg);
LIST_DEFINE(MethodPtr);

// Information about type signature.
struct Method {
  Token* tok;
  Type return_type;
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
}
LIST_DEFINE(Trait);
LIST_DEFINE(TraitPtr);

struct Type {
  Token* source_name; // Null if not inferred
  char* runtime_name; // Null if not inferred
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
typedef TraitTable List_TraitPtr;
typedef TypeTable  List_TypePtr;
typedef ExprTable  List_ExprPtr;



#endif // STRUCT_DECLARATIONS