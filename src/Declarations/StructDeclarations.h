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

#endif // STRUCT_DECLARATIONS