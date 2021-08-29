#ifndef AST_INCLUDE
#define AST_INCLUDE
#include "apaz-libc/apaz-libc.h"


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
    ASTNode* nodeList; // Is a List_ASTNode
};

LIST_DEFINE(ASTNode);

int a() {
    List_ASTNode a;
}

#endif // AST_INCLUDE