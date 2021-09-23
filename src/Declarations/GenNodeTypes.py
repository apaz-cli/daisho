#!/bin/python

# [name, [[type, key], [type, key], ...]]

node_types = [
    ['CompilationUnit', [['char*', 'fname']]],
    ['TopLevelDecl',    [['char*', 'name']]],
    ['EnumDecl',        [['char*', 'name']]],
    ['TraitDecl',       [['char*', 'name']]],
    ['ClassDecl',       [['char*', 'name']]],
    ['FunctionDecl',    [['char*', 'name']]],
    ['CTypeDecl',       [['char*', 'name'], ['char*', 'cname']]],
    ['GlobalVarDecl',   [['char*', 'name'], ['char*', 'type']]],
]

def flowerbox(f, str):
    tb = "/" + ("*"*(len(str)+4)) + "/\n"
    f.write(tb)
    f.write("/* " + str + " */\n")
    f.write(tb)


def makeStruct(f):
    flowerbox(f, "Info Structs")
    for t in node_types:
        f.write(f'struct {t[0]}_Info {{\n')
        for tup in t[1]:
            f.write(f'  {tup[0]} {tup[1]};\n')
        f.write(f'}};\ntypedef struct {t[0]}_Info {t[0]}_Info;\n\n')
    f.write('\n\n')


def makeGetInfo(f):
    flowerbox(f, "Struct Getters")
    for t in node_types:
        f.write(f'static inline {t[0]}_Info* ASTNode_{t[0]}_getInfo(ASTNode* node) {{ return ({t[0]}_Info*)node->typed_info; }}\n')
    f.write('\n\n')

def makeNew(f):
    flowerbox(f, "Constructors")
    for t in node_types:
        signature = ''.join([f', {tup[0]} {tup[1]}' for tup in t[1]])
        sizesum = '+'.join([f'sizeof({tup[0]})' for tup in t[1]])
        f.write(
            f"static inline ASTNode* ASTNode_{t[0]}_new(Arena* arena{signature}) {{ ASTNode* node = (ASTNode*)Arena_malloc(arena, sizeof(ASTNode)+sizeof({t[0]}_Info)); {t[0]}_Info* info = ({t[0]}_Info*)(((char*)node) + sizeof(ASTNode)); node->typed_info = (void*)info; return node;}}\n")
    f.write('\n\n')


def makeGetMember(f):
    flowerbox(f, "Getters")
    for t in node_types:
        for tup in t[1]:
            f.write(
                f"static inline {tup[0]} ASTNode_{t[0]}_get_{tup[1]}(ASTNode* node) {{ return ASTNode_{t[0]}_getInfo(node)->{tup[1]}; }}\n")
    f.write('\n\n')


def makeSet(f):
    flowerbox(f, "Setters")
    for t in node_types:
        for tup in t[1]:
            f.write(
                f"static inline void ASTNode_{t[0]}_set_{tup[1]}(ASTNode* node, {tup[0]} {tup[1]}) {{ ASTNode_{t[0]}_getInfo(node)->{tup[1]} = {tup[1]}; }}\n")
    f.write('\n\n')


def makePrint(f):
    flowerbox(f, "Print Node")
    
    for t in node_types:
        printcontents = " ".join(f'printf("");')
        f.write(
            f"static inline void ASTNode_{t[0]}_print(ASTNode* node) {{ }}\n")

    cases = "".join([f"    case {t[0]}: return ASTNode_{t[0]}_print;\n" for t in node_types])
    cases += '    default: return (ASTNodePrintFn)NULL;\n'
    contents = f'  switch(type) {{\n{cases}  }}\n'
    f.write('\n')

    f.write('typedef void (*ASTNodePrintFn)(ASTNode*);\n')
    f.write(f'static inline ASTNodePrintFn AST_dispatch_print(ASTNodeType type) {{\n{contents}}}\n\n')

    f.write(f'enum PrintOrder {{ PREORDER, POSTORDER, PREORDER_BACKWARD, POSTORDER_BACKWARD }};\n')
    f.write(f'typedef enum PrintOrder PrintOrder;\n\n')

    f.write(f'static inline void AST_print(AST* ast, PrintOrder order) {{\n')
    f.write(f'  if (order == POSTORDER)\n')
    f.write(f'    for (size_t i = 0; i < ast->num_children; i++)\n')
    f.write(f'      AST_print(ast->children + i, order);\n')
    f.write(f'  if (order == POSTORDER_BACKWARD)\n')
    f.write(f'    for (int i = ast->num_children; i --> 0;)\n')
    f.write(f'      AST_print(ast->children + i, order);\n')
    f.write(f'  AST_dispatch_print(ast->type)(ast);\n')
    f.write(f'  if (order == PREORDER)\n')
    f.write(f'    for (size_t i = 0; i < ast->num_children; i++)\n')
    f.write(f'      AST_print(ast->children + i, order);  \n')
    f.write(f'  if (order == PREORDER_BACKWARD)\n')
    f.write(f'    for (int i = ast->num_children; i --> 0;)\n')
    f.write(f'      AST_print(ast->children + i, order);\n')
    f.write(f'}}\n\n')
      

def makeEnum(f):
    f.write('enum ASTNodeType {\n')
    [f.write(f'  {t[0]},\n') for t in node_types]
    f.write('};\ntypedef enum ASTNodeType ASTNodeType;\n')
    

with open('ASTNodeType.h', 'w') as f:
    f.write('// THIS FILE GENERATED BY GenNodeTypes.py. DO NOT EDIT.\n')
    f.write('#ifndef INCLUDE_ASTNODETYPE\n')
    f.write('#define INCLUDE_ASTNODETYPE\n')
    f.write('#include <apaz-libc.h>\n\n')

    makeEnum(f)

    f.write('#endif // INCLUDE_ASTNODETYPE')

with open('ASTNodeMethods.h', 'w') as f:
    f.write('// THIS FILE GENERATED BY GenNodeTypes.py. DO NOT EDIT.\n')
    f.write('#ifndef INCLUDE_ASTNODEMETHODS\n')
    f.write('#define INCLUDE_ASTNODEMETHODS\n')
    f.write('#include "StructDeclarations.h"\n')
    f.write('#include "ASTNodeType.h"\n')
    f.write('#include <apaz-libc.h>\n\n')

    makeStruct(f)
    makeGetInfo(f)
    makeNew(f)
    makeGetMember(f)
    makeSet(f)
    makePrint(f)

    f.write('#endif // INCLUDE_ASTNODEMETHODS')