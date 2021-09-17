#ifndef STRUCT_DECLARATIONS
#define STRUCT_DECLARATIONS

#include <apaz-libc.h>
#include "Tokens.h"


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

/**********/
/* Parser */
/**********/

#define STILTS_PARSER_MAX_STACK_FRAMES 150
struct ParserStackFrame {
  TokType currently_parsing;
  Token *startingFrom;
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


#endif // STRUCT_DECLARATIONS