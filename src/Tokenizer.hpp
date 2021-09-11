#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "stilts-common.hpp"
#include "Tokens.h"

class Token {
  TokType type;
  size_t pos;
  size_t line;
  string file;
};

typedef unsigned char DFAState;

struct DFATransition {
  DFAState start_state;
  DFAState end_state;
  char range_start;
  char range_end;
  constexpr DFATransition(DFAState start_state, DFAState end_state,
                          char range_start, char range_end)
      : start_state(start_state), end_state(end_state),
        range_start(range_start), range_end(range_end){};
};

class RangeMap {
  vector<DFATransition> transitions;
  RangeMap(vector<DFATransition> transitions) : transitions(transitions) {
    sort(transitions.begin(), transitions.end(),
         [](DFATransition a, DFATransition b) {
           return a.range_start < b.range_start;
         });
  };
};

struct TokenizerDFA {
  RangeMap statemap;
  vector<DFAState> accepting_states;
  DFAState current_state;
  bool active = true;
};

class StiltsTokenizer {

  size_t current_input_position;
  size_t next_input_position;

  string input;
  vector<TokenizerDFA> DFAs;

  StiltsTokenizer(string input, vector<TokenizerDFA> DFAs)
      : input(input), DFAs(DFAs){};

  Token nextToken() {

    // Consume a maximal munch of the input string by running the DFAs, and 
    Token tok;
    while (true) {
      transition(input[next_input_position]);
      // If only one of the tokens are valid, break.
      // If no tokens are valid, return.
    }

    this->current_input_position = this->next_input_position;
    return tok;
  };

  void transition(char next_character) {
    for (TokenizerDFA dfa : this->DFAs) {
      if (!dfa.active)
        continue;
      // DFAState next_state = dfa.statemap;
      // DFAState current_state = current_states[i].second();
      // DFAState next_state = statemaps[i][pair<DFAState,
      // char>(current_state, next_character)];
    }
  };
};

#endif // TOKENIZER_INCLUDE