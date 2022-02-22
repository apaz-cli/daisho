#ifndef PL0_PARSER_INCLUDE
#define PL0_PARSER_INCLUDE
#include <stdio.h>
#include <stdlib.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-label-as-value"


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
    X(blockretproc) \
    X(factretterm1) \
    X(factretterm2) \
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
        switch (label_val) { LOCATIONS default : error("Invalid GOTO variable!"); } \
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
#define ERR(str) do { fprintf(stderr, "%s\n" str); exit(1); } while(0)
#define CALL(to_val)                                        \
    do {                                                    \
        /* Push a frame with the address and stream         \
           position we want to return to. */                \
        current_frame++;                                    \
        if (current_frame == stack_end)                     \
            ERR("Stack Overflow.");                         \
        current_frame->return_address = &&UNIQUE(__label_); \
        current_frame->stream_pos = spos->pos;              \
        current_frame->parent = node;                       \
                                                            \
        /* Jump to what we're calling. */                   \
        puts("Calling "#to_val"().");                       \
        goto to_val;                                        \
                                                            \
        UNIQUE(__label_):;                                  \
        puts("Returned from "#to_val"().");                 \
        /* Now that we've returned, rewind the token stream \
           and pop the stack frame. */                      \
        spos->pos = current_frame->stream_pos;              \
        current_frame--;                                    \
    } while (0)

#define RETURN()                                          \
    do {                                                  \
        goto_t __retaddr = current_frame->return_address; \
        GOTO(__retaddr);                                  \
    } while (0)


/***********/
/* Symbols */
/***********/

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

typedef Symbol* SymbolStream;

typedef struct {
    SymbolStream stream;
    size_t pos;
} StreamPosition;


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
    ASTNode* parent;
    ASTNode** children;
    size_t num_children;
    char* name;
};

static inline ASTNode*
ASTNode_new(ASTNode* parent, char* rule_name) {
    ASTNode* node = (ASTNode*)malloc(sizeof(ASTNode));
    node->parent = parent;
    node->children = NULL; // realloc() below
    node->num_children = 0;
    node->name = rule_name;

    if (parent != NULL) {
        parent->children = (ASTNode**)realloc(parent->children, sizeof(ASTNode*) * (parent->num_children + 1));
        parent->children[parent->num_children++] = node;
    }

    return node;
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
    for (size_t i = 0; i < depth; i++)
        printf("  ");
    puts(current->name);
}

static inline void
AST_print(ASTNode* root) {
    AST_print_helper(root, 0);
}

/*************************/
/* Parser Implementation */
/*************************/

typedef struct {
    size_t stream_pos;
    goto_t return_address;
    ASTNode* parent;
} ParserStackFrame;

static inline Symbol
sym_at(StreamPosition* spos) {
    return spos->stream[spos->pos];
}

static inline _Noreturn void
error(const char* msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(1);
}

#define accept(s) (sym_at(spos) == (s) ? spos->pos++, puts("Accepted " #s), 1 : 0)
#define expect(s) (accept(s) ? 1 : (error("unexpected symbol."), 1))


#define PARSER_STACK_SIZE 10000

int
main(void) {
    Symbol program[] = {VARSYM,    IDENTSYM,     COMMASYM,     IDENTSYM,  SEMISYM, BEGINSYM, IDENTSYM, EQLSYM,
                        NUMBERSYM,    SEMISYM, WHILESYM,  IDENTSYM,  BEGINSYM,  IDENTSYM,    EQLSYM,   IDENTSYM,
                        PLUSSYM,      NUMBERSYM,    SEMISYM, IDENTSYM,  EQLSYM,       IDENTSYM,    TIMESSYM, NUMBERSYM,
                        SEMISYM, ENDSYM,    SEMISYM, ENDSYM, PERIODSYM};
    size_t num_symbols = sizeof(program) / sizeof(Symbol);
    StreamPosition p = {program, 0};
    StreamPosition* spos = &p;

    ParserStackFrame stack_space[PARSER_STACK_SIZE];
    ParserStackFrame* stack_end = stack_space + PARSER_STACK_SIZE;
    ParserStackFrame* current_frame = stack_space;
    stack_space->stream_pos = 0;
    stack_space->return_address = &&end;

    ASTNode* node = (ASTNode*)malloc(sizeof(ASTNode*));

program:;
    CALL(block);
    expect(PERIODSYM);
    RETURN();
block:;
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
statement:;
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
condition:;
    if (accept(ODDSYM)) {
        CALL(expression);
    } else {
        CALL(expression);
        (accept(EQLSYM) || accept(NEQSYM) || accept(LSSSYM) ||
           accept(LEQSYM) || accept(GTRSYM) || expect(GEQSYM));
    }
    RETURN();
expression:;
    (accept(PLUSSYM) || accept(MINUSSYM));
    CALL(term);
    while (accept(PLUSSYM) || accept(MINUSSYM)) {
        CALL(term);
    }
    RETURN();
term:;
    // TODO function returns.
    CALL(factor);
    // or
    accept(NUMBERSYM);
    // else
    expect(RPARENSYM);
    CALL(expression);
    expect(LPARENSYM);
factor:;
end:;
    return 0;
}

#undef X
#endif
