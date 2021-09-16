#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "Tokens.h"
#include "stilts-common.h"
#include <apaz-libc.h>

/*********************/
/* Type Declarations */
/*********************/

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

/***********/
/* Methods */
/***********/

StiltsTokenizer *Tokenizer_init(StiltsTokenizer *tokenizer) {
    tokenizer->outstream = List_Token_new_cap(1000);
    tokenizer->ignorestream = List_Token_new_cap(1000);
    tokenizer->current_position = 0;
}

Token Tokenizer_nextToken(StiltsTokenizer *tokenizer) {
}

StiltsTokenizer *Tokenizer_parse(StiltsTokenizer *tokenizer, String input, String source_file) {
    size_t input_len = 0;
    List_Token outstream = tokenizer->outstream;
    List_Token ignorestream = tokenizer->ignorestream;
    for (size_t i = 0; i < input_len; i++) {
      
    }
}

StiltsTokenizer *Tokenizer_destroy(StiltsTokenizer *tokenizer) {
    List_Token_destroy(tokenizer->outstream);
    List_Token_destroy(tokenizer->ignorestream);
}

#endif // TOKENIZER_INCLUDE