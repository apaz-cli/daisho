#ifndef PARSER_INCLUDE
#define PARSER_INCLUDE

#include "Declarations/Declarations.h"

/****************************/
/* Function Implementations */
/****************************/

static inline void StiltsParser_init(StiltsParser *parser,
                                     List_Token token_stream) {
  parser->token_stream = token_stream;
  parser->current_token = 0;
  parser->call_stack.height = 0;
  nextsym(parser);
}

static inline void nextsym(StiltsParser *parser) {
  parser->sym = parser->token_stream[parser->current_token++];
}

static inline void parser_stack_trace(StiltsParser *parser) {}

static inline void parse_error(StiltsParser *parser, const char *message) {}

static inline bool accept(StiltsParser *parser, TokType s) {
  if (parser->sym.type == s) {
    nextsym(parser);
    return 1;
  }
  return 0;
}

static inline bool expect(StiltsParser *parser, TokType s) {
  if (accept(parser, s))
    return 1;

  char *err_msg;
  sprintf(err_msg, "Parsing error:\nExpected %s, but got: %s.");
  parse_error(parser, err_msg);
  return 0;
}

#endif // PARSER_INCLUDE