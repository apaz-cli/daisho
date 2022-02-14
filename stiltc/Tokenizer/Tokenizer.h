#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include <apaz-utf8.h/apaz-utf8.h>

#include "../Declarations/Declarations.h"

static inline Target*
Target_readFile(Target* target) {
#define TOKENSTREAM_INITIAL_CAPACITY 1000
    target->token_stream = List_Token_new_cap(TOKENSTREAM_INITIAL_CAPACITY);

    return target;
}

static inline DaishoTokenizer*
Tokenizer_init(DaishoTokenizer* tokenizer, Target* target) {
    tokenizer->DFAs = all_DFAs;
    tokenizer->target = target;
    tokenizer->current_pos = 0;
    tokenizer->next_pos = 0;
    return tokenizer;
}

static inline bool
Tokenizer_nextToken(DaishoTokenizer* tokenizer, TokenStream stream) {
    utf8_t* current = tokenizer->target->fileInfo.content + tokenizer->current_pos;
    for (size_t i = 0; i < NUM_TOKTYPES; i++) {
        utf8_t c = *(current + i);
    }

    return false;
}

static inline TokenStream
Tokenizer_tokenize(DaishoTokenizer* tokenizer) {
    // Tokenize the content
    TokenStream stream = List_Token_new_cap(10000);
    while (Tokenizer_nextToken(tokenizer, stream))
        ;
    return stream;
}

static inline void
Tokenizer_destroy(DaishoTokenizer* tokenizer) {}

#endif  // TOKENIZER_INCLUDE