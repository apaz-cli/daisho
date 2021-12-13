#ifndef PARSER_INCLUDE
#define PARSER_INCLUDE

#include "../Declarations/Declarations.h"
#include <apaz-libc.h>

/***************************/
/* Stack Management Macros */
/***************************/
#define FRAGMENT_ENTER(name) {};
#define FRAGMENT_EXIT(name) {};

// TODO move this into generated code
static inline void ASTNode_CompilationUnit_destroy(Arena *arena) {
  Arena_pop(arena, sizeof(ASTNode) + sizeof(CompilationUnit_Info));
}

#define RULE_ENTER(node_type)                                                  \
  ASTNode *new_node = ASTNode_##node_type##_new(parser->arena);                \
  parser->call_stack.frames[parser->call_stack.height++] = node_type;
#define RULE_EXIT(ret)                                                         \
  parser->call_stack.height--;                                                 \
  if (!ret) {                                                                  \
    ASTNode_CompilationUnit_destroy(parser->arena);                            \
    new_node = NULL;                                                           \
  }                                                                            \
  return new_node;

/****************************/
/* Function Implementations */
/****************************/

static inline void StiltsParser_init(StiltsParser *parser,
                                     List_Token token_stream) {
  parser->token_stream = token_stream;
  parser->current_token_pos = 0;
  parser->call_stack.height = 0;
  next_token(parser);
}

static inline void next_token(StiltsParser *parser) {
  parser->current_token = parser->token_stream[parser->current_token_pos++];
}

static inline void parser_stack_trace(StiltsParser *parser) {}

static inline void parse_error(StiltsParser *parser, const char *message) {
  parser_stack_trace(parser);
}

static inline bool accept(StiltsParser *parser, TokType s) {
  if (parser->current_token.type == s) {
    next_token(parser);
    return 1;
  }
  return 0;
}

static inline bool expect(StiltsParser *parser, TokType s) {
  if (accept(parser, s))
    return 1;

  fprintf(stderr, "Parsing error:\nExpected %s, but got: %s.\n", TokNameMap[s],
          TokNameMap[parser->current_token.type]);

  return 0;
}

static inline ASTNode *parse_CompilationUnit(StiltsParser *parser) {
  RULE_ENTER(CompilationUnit);
  
  RULE_EXIT(new_node);
}

#endif // PARSER_INCLUDE