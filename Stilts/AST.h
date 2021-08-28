#ifndef AST_INCLUDE
#define AST_INCLUDE
#include "Utils/Common.h"

struct ASTNode;
typedef struct ASTNode ASTNode;

enum ASTNodeType {

};

struct ASTNode {
    size_t line_num;
    size_t line_position;

    ASTNodeType type;
    union ASTNodeVariety {

    };
};


#endif // AST_INCLUDE