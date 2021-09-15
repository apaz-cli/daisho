#ifndef PARSER_INCLUDE
#define PARSER_INCLUDE

#include <apaz-libc.h>
#include "stilts-common.h"
#include "Tokenizer.h"

/*********************/
/* Type Declarations */
/*********************/

struct ParserStackFrame {
    TokType currently_parsing;
    Token* startingFrom;
};
typedef struct ParserStackFrame ParserStackFrame;
struct ParserCallStack {
    ParserStackFrame frames[];
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


/****************************/
/* Function Implementations */
/****************************/

void StiltsParser_init(StiltsParser* parser) {

}

void nextsym(StiltsParser* parser) {
    parser->TokenStream
}
void error(StiltsParser* const char* message);

bool accept(StiltsParser* parser, TokType s) {
    if (sym == s) {
        nextsym();
        return 1;
    }
    return 0;
}

bool expect(TokType s) {
    if (accept(s))
        return 1;
    error("expect: unexpected symbol");
    return 0;
}




#endif // PARSER_INCLUDE