#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "Declarations/Declarations.h"

static inline Target *Target_readFile(Target *target) {
#define TOKENSTREAM_INITIAL_CAPACITY 1000
  target->token_stream = List_Token_new_cap(TOKENSTREAM_INITIAL_CAPACITY);

  target->content = String_new_fromFile(target->file_name);
  if (!target->content) {
    // TODO error check
    printf("Could not open file: %s\n", target->file_name);
    exit(1);
  }

  return target;
}

static inline StiltsTokenizer *Tokenizer_init(StiltsTokenizer *tokenizer) {
  return tokenizer;
}

static inline bool Tokenizer_nextToken(StiltsTokenizer *tokenizer,
                                       TokenStream stream) {

  char *current = tokenizer->target->content + tokenizer->current_pos;
  for (size_t i = 0; i < NUM_TOKTYPES; i++) {
    char c = *(current + i);
  }
  
  return false;
}

static inline StiltsTokenizer *Tokenizer_tokenize(StiltsTokenizer *tokenizer,
                                                  TokenStream stream) {
  // Tokenize the content
  while (Tokenizer_nextToken(tokenizer, stream)) ;
  return tokenizer;
}

static inline void Tokenizer_destroy(StiltsTokenizer *tokenizer) {}

#endif // TOKENIZER_INCLUDE