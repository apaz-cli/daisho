#ifndef AST_INCLUDE
#define AST_INCLUDE
#include "../Declarations/Declarations.h"
#include <assert.h>

#define TREE_PADDING_WIDTH 4
#define TREE_MAX_DEPTH 150

static inline void ASTNode_toString(ASTNode node, char *into, size_t *len) {}

static inline void printAST_(ASTNode current, size_t depth) {
  // Indent
  size_t padding_len = 0;
  char padding[TREE_PADDING_WIDTH * TREE_MAX_DEPTH];
  for (size_t i = 0; i < depth; i++) {
    for (size_t j = 0; j < TREE_PADDING_WIDTH; j++) {
      assert(padding_len != TREE_PADDING_WIDTH * TREE_MAX_DEPTH);
      padding[padding_len++] = ' ';
    }
  }

  // Print self
  padding[padding_len] = '\0';
  puts(padding);

  // Print children
  for (size_t i = 0; i < current.num_children; i++)
    printAST_(current.children[i], depth + 1);
}

static inline void printAST(AST ast) { printAST_(ast, 0); }

#endif // AST_INCLUDE