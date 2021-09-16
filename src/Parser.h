#include "stilts-common.h"
#include "Tokenizer.h"

#ifndef PARSER_INCLUDE
#define PARSER_INCLUDE

#include <apaz-libc.h>

/*********************/
/* Type Declarations */
/*********************/

struct ParserStackFrame {
    TokType currently_parsing;
    Token* startingFrom;
};
typedef struct ParserStackFrame ParserStackFrame;
struct ParserCallStack {
    ParserStackFrame frames[50];
    size_t height;
};
typedef struct ParserCallStack ParserCallStack;
struct StiltsParser {
    Token sym;
    TokenStream* toks;
    ParserCallStack call_stack;
};
typedef struct StiltsParser StiltsParser;

/*************************/
/* Function Declarations */
/*************************/

void StiltsParser_init(StiltsParser *parser);
void nextsym(StiltsParser *parser);
void error(StiltsParser *parser, const char *message);
void accept(StiltsParser *parser, TokType s);
void expect(StiltsParser *parser, TokType s);


/****************************/
/* Function Implementations */
/****************************/

void StiltsParser_init(StiltsParser* parser) {

}

void nextsym(StiltsParser* parser) {
    parser->TokenStream;
}
void error(StiltsParser* parser,  const char* message);

bool accept(StiltsParser* parser, TokType s) {
    if (parser->sym.type == s) {
        nextsym(parser);
        return 1;
    }
    return 0;
}

bool expect(StiltsParser* parser, TokType s) {
    if (accept(parser, s))
        return 1;
    error(parser, "expect: unexpected symbol");
    return 0;
}




#endif // PARSER_INCLUDE