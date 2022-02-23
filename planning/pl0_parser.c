#ifndef PL0_PARSER_INCLUDE
#define PL0_PARSER_INCLUDE
#include <stdio.h>
#include <stdlib.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-label-as-value"


/********************/
/* Tokens / Symbols */
/********************/

typedef enum {
    IDENTSYM,
    NUMBERSYM,
    LPARENSYM,
    RPARENSYM,
    TIMESSYM,
    SLASHSYM,
    PLUSSYM,
    MINUSSYM,
    EQLSYM,
    NEQSYM,
    LSSSYM,
    LEQSYM,
    GTRSYM,
    GEQSYM,
    CALLSYM,
    BEGINSYM,
    SEMISYM,
    ENDSYM,
    IFSYM,
    WHILESYM,
    BECOMES,
    THENSYM,
    DOSYM,
    CONSTSYM,
    COMMASYM,
    VARSYM,
    PROCSYM,
    PERIODSYM,
    ODDSYM
} Symbol;


/**********************/
/* AST Implementation */
/**********************/

/* This AST Node implementation is not efficient,
   the API is what's important. The daic implementation
   will use a custom memory allocator and handle
   fragmentation. This is the dumbest example possible. */
struct ASTNode;
typedef struct ASTNode ASTNode;
struct ASTNode {
    char* name;
    ASTNode* parent;
    ASTNode** children;
    size_t num_children;
};

static inline ASTNode*
ASTNode_new(char* name) {
    ASTNode* node = (ASTNode*)malloc(sizeof(ASTNode));
    node->name = name;
    node->parent = NULL;
    node->children = NULL; // realloc() as children are added
    node->num_children = 0;
    return node;
}

static inline void
ASTNode_addChild(ASTNode* parent, ASTNode* child) {
    if (!parent || !child) {
        // TODO: Remove
        fprintf(stderr, "PANIC!\n");
        exit(1);
    }

    parent->num_children++;
    parent->children = (ASTNode**)realloc(parent->children, sizeof(ASTNode*) * parent->num_children);
    parent->children[parent->num_children - 1] = node;
}

static inline void
ASTNode_destroy(ASTNode* self) {
    for (size_t i = 0; i < self->num_children; i++)
        ASTNode_destroy(self);
    free(self->children);
    free(self);
}

static inline void
AST_print_helper(ASTNode* current, size_t depth) {
    for (size_t i = 0; i < depth; i++) printf("  ");
    puts(current->name);
}

static inline void
AST_print(ASTNode* root) {
    AST_print_helper(root, 0);
}


/***********************/
/* Call Stack Emulator */
/***********************/


/* GCC has an extension called "Labels as Values." It's also been adopted by
   Clang and the Intel C compiler. It greatly simplifies the code, and also
   makes it considerably more efficient. However, it's not available in standard
   C, so for compatibility's sake I'm defining it both ways. */

/* If we're forced to use standard C, create an xmacro enum jump table. */
/* If we have labels as values, identify labels with void .*/
#define HAS_LABEL_VALUES
#ifndef HAS_LABEL_VALUES
#define LOCATIONS   \
    X(program)      \
    X(block)        \
    X(statement)    \
    X(condition)    \
    X(expression)   \
    X(term)         \
    X(factor)       \
    X(end)


typedef enum {
#define X(label) label##_loc,
    LOCATIONS
#undef X
} goto_t;
#else /* HAS_LABEL_VALUES */
typedef void* goto_t;
#endif

/* Define GOTO(label_val). It will be use to define CALL() and RETURN(). */
#ifndef HAS_LABEL_VALUES
#define X(label) case label##_loc: goto label;
#define GOTO(label_val)                                                             \
    do {                                                                            \
        switch (label_val) { LOCATIONS default : fprintf(stderr, "Error: %s\n", msg), exit(1); } \
    } while (0)
#else /* HAS_LABEL_VALUES */
#define GOTO(label_val)  \
    do {                 \
        goto* label_val; \
    } while (0)
#endif

/* Use the __LINE__ trick to generate an IDENTSYMifier with a
   unique name. Note that inside the expansion of a single
   macro, all the expansions of UNIQUE will be the same,
   since it expands into a single line.  */
#define __CAT(a, b) a##b
#define __LBL(b, l) __CAT(b, l)
#define UNIQUE(base) __LBL(base, __LINE__)

/* Now for the good part, "Functions." */

#define FUNCTION(name) name:; node = ASTNode_new(parent, #name);

#define CALL(to_val)                                        \
    do {                                                    \
        /* Push a frame with the address and stream         \
           position we want to return to. */                \
        stack[stack_height].stream_pos = stream_pos;        \
        stack[stack_height].parent = node;                  \
        stack[stack_height].return_address =                \
                                       &&UNIQUE(__label_);  \
        stack_height++;                                     \
        if (stack_height >= stack_max_height) {             \
            fprintf(stderr, "Stack Overflow.\n");           \
            exit(1);                                        \
        }                                                   \
                                                            \
        /* Jump to what we're calling. */                   \
        puts("Calling "#to_val"().");                       \
        goto to_val;                                        \
                                                            \
        puts("Returned from "#to_val"().");                 \
        UNIQUE(__label_):;                                  \
    } while (0)

/* Return an AST node to add as a child to the calling function's node. */
#define RETURN(ret)                                         \
    do {                                                    \
        /* When we return, check the return value.          \
         *                                                  \
         * If it was a failure, clean up. Free all the      \
         * nodes, rewind the token stream and pop the       \
         * stack frame.                                     \
         *                                                  \
         * If it was a success, add the node to the AST.    \
         */                                                 \
        stack_height--;                                     \
        if (!retval) {                                      \
            ASTNode_destroy(node);                          \
            stream_pos = stack[stack_height].stream_pos;    \
                                                            \
        } else {                                            \
            // don't rewind symbol stream (stream_pos)      \
        }                                                   \
        stack_height--;                                     \
        retval = ret;                                       \
        goto_t __retaddr = stack[stack_height].retaddr;     \
        GOTO(stack[stack_height].retaddr);                  \
    } while (0)


/*************************/
/* Parser Implementation */
/*************************/

typedef struct {
    size_t stream_pos;
    goto_t retaddr;
    ASTNode* parent;
} ParserStackFrame;

#define accept(s)   (stream[stream_pos] == (s) ? stream_pos++, puts("Accepted: " #s), 1 : puts("Rejected: " #s), 0)
#define expect(s)   (accept(s) ? 1 : fprintf(stderr, "Unexpected symbol. Expected "#s".\n", sym), exit(1), 1))

#define PARSER_STACK_SIZE 10000

int main(void) {

    /* Symbol stream and position */
    Symbol program[] = {VARSYM,    IDENTSYM,     COMMASYM,     IDENTSYM,  SEMISYM, BEGINSYM, IDENTSYM, EQLSYM,
                        NUMBERSYM,    SEMISYM, WHILESYM,  IDENTSYM,  BEGINSYM,  IDENTSYM,    EQLSYM,   IDENTSYM,
                        PLUSSYM,      NUMBERSYM,    SEMISYM, IDENTSYM,  EQLSYM,       IDENTSYM,    TIMESSYM, NUMBERSYM,
                        SEMISYM, ENDSYM,    SEMISYM, ENDSYM, PERIODSYM, ENDSYM};
    Symbol* stream = program;
    size_t num_symbols = sizeof(program) / sizeof(Symbol);
    size_t stream_pos = 0;

    /* Call stack */
    ParserStackFrame stack[PARSER_STACK_SIZE];
    size_t stack_height = 0;
    size_t stack_max_height = PARSER_STACK_SIZE - 1;

    /* AST variables */
    ASTNode* node;
    ASTNode* retval = NULL;


    /* Start the parser */
    CALL(program);
    goto end;

    /****************/
    /* Parser rules */
    /****************/

FUNCTION(program) {
    CALL(block);
    expect(PERIODSYM);
    RETURN();
}
FUNCTION(block) {
    if (accept(CONSTSYM)) {
        do {
            expect(IDENTSYM);
            expect(EQLSYM);
            expect(NUMBERSYM);
        } while (accept(COMMASYM));
        expect(SEMISYM);
    }

    if (accept(VARSYM)) {
        do {
            expect(IDENTSYM);
        } while (accept(COMMASYM));
        expect(SEMISYM);
    }
    while (accept(PROCSYM)) {
        expect(IDENTSYM);
        expect(SEMISYM);
        CALL(block);
        expect(SEMISYM);
    }
    CALL(statement);
    RETURN();
}
FUNCTION(statement) {
    if (accept(IDENTSYM)) {
        expect(EQLSYM);
        CALL(expression);
    } else if (accept(CALLSYM)) {
        expect(IDENTSYM);
    } else if (accept(BEGINSYM)) {
        CALL(statement);
        while (accept(SEMISYM)) {
            CALL(statement);
        }
        expect(ENDSYM);
    }
    RETURN();
}
FUNCTION(condition) {
    if (accept(ODDSYM)) {
        CALL(expression);
    } else {
        CALL(expression);
        (accept(EQLSYM) || accept(NEQSYM) || accept(LSSSYM) ||
           accept(LEQSYM) || accept(GTRSYM) || expect(GEQSYM));
    }
    RETURN();
}
FUNCTION(expression) {
    (accept(PLUSSYM) || accept(MINUSSYM));
    CALL(term);
    while (accept(PLUSSYM) || accept(MINUSSYM)) {
        CALL(term);
    }
    RETURN();
}
FUNCTION(term) {
    // TODO function returns.
    CALL(factor);
    while(accept(TIMESSYM) || accept(SLASHSYM)) {
        CALL(factor);
    }
    RETURN();
}
FUNCTION(factor) {
    if (accept(IDENTSYM)) {
    } else if (accept (NUMBERSYM)) {
    } else {
        expect(LPARENSYM);
        CALL(expression);
        expect(RPARENSYM);
    }
    RETURN();
}

end:;
    return 0;
}

#undef X
#endif
