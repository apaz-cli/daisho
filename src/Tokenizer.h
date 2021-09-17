#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "Declarations/Declarations.h"

static inline StiltsTokenizer *Tokenizer_init(StiltsTokenizer *tokenizer) {
  const size_t initial_capacity = 1000;
  tokenizer->outstream = List_Token_new_cap(initial_capacity);
  tokenizer->ignorestream = List_Token_new_cap(initial_capacity);
  tokenizer->current_position = 0;
}

static inline Token Tokenizer_nextToken(StiltsTokenizer *tokenizer) {}

static inline StiltsTokenizer *
Tokenizer_tokenize(StiltsTokenizer *tokenizer, String input, String source_file) {
  size_t input_len = 0;
  List_Token outstream = tokenizer->outstream;
  List_Token ignorestream = tokenizer->ignorestream;
  for (size_t i = 0; i < input_len; i++) {
  }

  return tokenizer;
}

static inline void Tokenizer_destroy(StiltsTokenizer *tokenizer) {
  List_Token_destroy(tokenizer->outstream);
  List_Token_destroy(tokenizer->ignorestream);
}

#endif // TOKENIZER_INCLUDE