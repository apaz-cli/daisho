#ifndef METHOD_DECLARATIONS
#define METHOD_DECLARATIONS
#include "StructDeclarations.h"
#include "TokType.h"

/*****************************/
/*    METHOD DECLARATIONS    */
/*****************************/

/* The compiler is self-contained right now. */

/*************/
/* Tokenizer */
/*************/
static inline StiltsTokenizer *Tokenizer_init(StiltsTokenizer *tokenizer);
static inline Token Tokenizer_nextToken(StiltsTokenizer *tokenizer);
static inline TokenStream Tokenizer_tokenize(StiltsTokenizer *tokenizer, String input, char* source_file);
static inline void Tokenizer_destroy(StiltsTokenizer *tokenizer);

/*******/
/* AST */
/*******/
// Created by GenNodeTypes.py
#include "ASTNodeMethods.h"

/**********/
/* Parser */
/**********/
static inline void StiltsParser_init(StiltsParser *parser);
static inline void StiltsParser_destroy(StiltsParser *parser);
static inline AST  StiltsParser_parse(StiltsParser* parser, TokenStream tokens);
static inline void nextsym(StiltsParser *parser);
static inline void parser_stack_trace(StiltsParser *parser);
static inline void parse_error(StiltsParser *parser, char *message);
static inline bool accept(StiltsParser *parser, TokType s);
static inline bool expect(StiltsParser *parser, TokType s);

#endif // METHOD_DECLARATIONS