#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "Tokens.h"
#include "stilts-common.h"

#include <apaz-libc.h>

struct Token {
  TokType type;
  size_t pos;
  size_t line;
  String file;
};

typedef unsigned char DFAState;
LIST_DEFINE(DFAState);

struct DFATransition {
  DFAState start_state;
  DFAState end_state;
  char range_start;
  char range_end;
};
LIST_DEFINE(DFATransition);

struct TokenizerDFA {
  List_DFATransition range_map;
  List_DFAState accepting_states;
  DFAState current_state;
  bool active;
};
LIST_DEFINE(TokenizerDFA);

struct StiltsTokenizer {
  size_t current_input_position;
  size_t next_input_position;
  String input;
  List_TokenizerDFA DFAs;
};
static inline void Tokenizer_init(StiltsTokenizer *tokenizer) {


}
static inline void Tokenizer_transition(StiltsTokenizer *tokenizer,
                                        char next_character) {
  size_t num_tokenizers = List_TokenizerDFA_len(tokenizer->DFAs);
  for (size_t i = 0; i < num_tokenizers; i++) {
    TokenizerDFA dfa = tokenizer->DFAs[i];
    if (!dfa.active)
      continue;
    // DFAState next_state = dfa.statemap;
    // DFAState current_state = current_states[i].second();
    // DFAState next_state = statemaps[i][pair<DFAState,
    // char>(current_state, next_character)];
  }
};
static inline Token Tokenizer_nextToken(StiltsTokenizer *tokenizer) {

  // Consume a maximal munch of the input string by running the DFAs, and
  Token tok;
  while (true) {
    Tokenizer_transition(tokenizer,
                         tokenizer->input[tokenizer->next_input_position]);
    // If only one of the tokens are valid, break.
    // If no tokens are valid, return.
  }

  tokenizer->current_input_position = tokenizer->next_input_position;
  return tok;
};

#endif // TOKENIZER_INCLUDE