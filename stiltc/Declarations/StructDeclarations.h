#ifndef STRUCT_DECLARATIONS
#define STRUCT_DECLARATIONS

#include "Generated/TokType.h"
#include <apaz-libc.h>

/***************************/
/*    TYPE DECLARATIONS    */
/***************************/

/*************/
/* Tokenizer */
/*************/

TYPE_DECLARE(Optional);
struct Optional {
  void* item; // const char* with error if error, otherwise value.
  bool error;
};

TYPE_DECLARE(Target);
TYPE_DECLARE(Token);
struct Token {
  TokType type;
  String content;

  Target* source;
  size_t line;
  size_t pos;
};
LIST_DEFINE(Token);
typedef List_Token TokenStream;

#include "Generated/Automata.h"

TYPE_DECLARE(StiltsTokenizer);
struct StiltsTokenizer {
  // NUM_DFAS is a generated macro.
  DFA* DFAs;
  Target* target;
  size_t current_pos;
  size_t next_pos;
};

/*******/
/* AST */
/*******/

TYPE_DECLARE(ASTNode);
#include "Generated/ASTNodeType.h"
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
  ASTNodeType frames[STILTS_PARSER_MAX_STACK_FRAMES];
  size_t height;
};
typedef struct ParserCallStack ParserCallStack;
struct StiltsParser {
  Arena* arena;
  ParserCallStack call_stack;

  size_t current_token_pos;
  Token current_token;
  TokenStream token_stream;
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

TYPE_DECLARE(MethodArg);
TYPE_DECLARE(Method);
TYPE_DECLARE(Trait)
TYPE_DECLARE(Type);
TYPE_DECLARE(Expr);

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

LIST_DECLARE(Trait);
struct Trait {
  // Implementation is null
  List_Method abstract_methods;
  // Implementation not null
  List_Method default_methods;

  List_Trait subtraits;
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
    UTF8FileContent fileInfo;
    TokenStream token_stream;
    AST ast;
};
LIST_DEFINE(Target);

#define SANITY_INSANE   0
#define SANITY_SANE     1
#define SANITY_PEDANTIC 2

struct CMDLineFlags {
  /* Compilation steps */
  bool parse;
  bool check;
  bool codegen;
  bool compileC;
  bool python;
  char sanity;

  /* C codegen options */
  char* CC;
  size_t num_threads;
  List_String cflags;
  char* temp_folder;

  /* Target files to compile */
  List_Target targets;
};
typedef struct CMDLineFlags CMDLineFlags;


#endif // STRUCT_DECLARATIONS
