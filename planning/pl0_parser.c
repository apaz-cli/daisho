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
    node->children = NULL;  // realloc() as children are added
    node->num_children = 0;
    return node;
}

static inline void
ASTNode_addChild(ASTNode* parent, ASTNode* child) {
    if (!child) return;
    if (!parent) {
        // TODO: Remove
        fprintf(stderr, "PANIC!\n");
        exit(1);
    }

    parent->num_children++;
    parent->children =
        (ASTNode**)realloc(parent->children, sizeof(ASTNode*) * parent->num_children);
    parent->children[parent->num_children - 1] = child;
}

static inline void
ASTNode_destroy(ASTNode* self) {
    for (size_t i = 0; i < self->num_children; i++) ASTNode_destroy(self->children[i]);
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
#define LOCATIONS \
    X(program)    \
    X(block)      \
    X(statement)  \
    X(condition)  \
    X(expression) \
    X(term)       \
    X(factor)     \
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
#define X(label)      \
    case label##_loc: \
        goto label;
#define GOTO(label_val)                                                                          \
    do {                                                                                         \
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

#define FUNCTION(name) \
    name:;             \
    node = ASTNode_new(#name);

#define CALL(to_val)                                      \
    do {                                                  \
        /* Push a frame with the address and stream       \
           position we want to return to. */              \
        stack[stack_height].stream_pos = stream_pos;      \
        stack[stack_height].parent = node;                \
        stack[stack_height].retaddr = &&UNIQUE(__label_); \
        stack_height++;                                   \
        if (stack_height >= stack_max_height) {           \
            fprintf(stderr, "Stack Overflow.\n");         \
            exit(1);                                      \
        }                                                 \
                                                          \
        /* Jump to what we're calling. It will            \
          RETURN() to the label immediately after. */     \
        puts("Calling " #to_val "().");                   \
        goto to_val;                                      \
        /* After some code is run, we return here: */     \
        UNIQUE(__label_) :;                               \
        /* puts("Returned from " #to_val "()."); */       \
    } while (0)

/* Return an AST node to add as a child to the calling function's node. */
#define RETURN(ret)                                             \
    do {                                                        \
        stack_height--;                                         \
        retval = ret;                                           \
        if (!retval) {                                          \
            ASTNode_destroy(node);                              \
            stream_pos = stack[stack_height].stream_pos;        \
        } else {                                                \
            ASTNode_addChild(stack[stack_height].parent, node); \
        }                                                       \
        goto_t __retaddr = stack[stack_height].retaddr;         \
        GOTO(__retaddr);                                        \
    } while (0)

/*************************/
/* Parser Implementation */
/*************************/

typedef struct {
    size_t stream_pos;
    goto_t retaddr;
    ASTNode* parent;
} ParserStackFrame;

#define ACCEPT(s) \
    (stream[stream_pos] == (s) ? stream_pos++, puts("Accepted: " #s), 1 : puts("Rejected: " #s), 0)

#define PARSER_STACK_SIZE 10000

int
main(void) {
    /* Symbol stream and position */
    Symbol stream[] = {VARSYM,   IDENTSYM, COMMASYM,  IDENTSYM, SEMISYM,   BEGINSYM,
                       IDENTSYM, EQLSYM,   NUMBERSYM, SEMISYM,  WHILESYM,  IDENTSYM,
                       BEGINSYM, IDENTSYM, EQLSYM,    IDENTSYM, PLUSSYM,   NUMBERSYM,
                       SEMISYM,  IDENTSYM, EQLSYM,    IDENTSYM, TIMESSYM,  NUMBERSYM,
                       SEMISYM,  ENDSYM,   SEMISYM,   ENDSYM,   PERIODSYM, ENDSYM};
    size_t num_symbols = sizeof(stream) / sizeof(Symbol);
    size_t stream_pos = 0;

    /* Call stack */
    ParserStackFrame stack[PARSER_STACK_SIZE];
    size_t stack_height = 0;
    size_t stack_max_height = PARSER_STACK_SIZE - 1;

    /* AST variables */
    ASTNode* node = ASTNode_new("root");
    ASTNode* retval = NULL;

    /* Start the parser */
    CALL(program);
    goto end;

    /****************/
    /* Parser rules */
    /****************/

    FUNCTION(program) {
        CALL(block);
        ACCEPT(PERIODSYM);
        ACCEPT(ENDSYM);
        RETURN(node);
    }

    FUNCTION(block) {
        if (ACCEPT(CONSTSYM)) {
            int i, j, k, l;
            i = ACCEPT(IDENTSYM);
            j = ACCEPT(EQLSYM);
            k = ACCEPT(NUMBERSYM);
            if (!(i & j & k)) RETURN(NULL);
            do {
                i = ACCEPT(COMMASYM);
                j = ACCEPT(IDENTSYM);
                k = ACCEPT(EQLSYM);
                l = ACCEPT(NUMBERSYM);
            } while (i & j & k & l);
            RETURN(ACCEPT(SEMISYM) ? node : NULL);
        }

        if (ACCEPT(VARSYM)) {
            do {
                if (ACCEPT(IDENTSYM)) RETURN(NULL);
            } while (ACCEPT(COMMASYM));
            RETURN(ACCEPT(SEMISYM) ? node : NULL);
        }

        while (ACCEPT(PROCSYM)) {
            ACCEPT(IDENTSYM);
            ACCEPT(SEMISYM);
            CALL(block);
            ACCEPT(SEMISYM);
        }
        CALL(statement);
        RETURN(node);
    }

    FUNCTION(statement) {
        if (ACCEPT(IDENTSYM)) {
            ACCEPT(EQLSYM);
            CALL(expression);
        } else if (ACCEPT(CALLSYM)) {
            ACCEPT(IDENTSYM);
        } else if (ACCEPT(BEGINSYM)) {
            CALL(statement);
            while (ACCEPT(SEMISYM)) {
                CALL(statement);
            }
            ACCEPT(ENDSYM);
        }
        RETURN(node);
    }

    FUNCTION(condition) {
        if (ACCEPT(ODDSYM)) {
            CALL(expression);
        } else {
            CALL(expression);
            (ACCEPT(EQLSYM) || ACCEPT(NEQSYM) || ACCEPT(LSSSYM) ||
             ACCEPT(LEQSYM) || ACCEPT(GTRSYM) || ACCEPT(GEQSYM));
        }
        RETURN(node);
    }

    FUNCTION(expression) {
        (ACCEPT(PLUSSYM) || ACCEPT(MINUSSYM));
        CALL(term);
        while (ACCEPT(PLUSSYM) || ACCEPT(MINUSSYM)) {
            CALL(term);
        }
        RETURN(node);
    }

    FUNCTION(term) {
        CALL(factor);
        while (ACCEPT(TIMESSYM) || ACCEPT(SLASHSYM)) {
            CALL(factor);
        }
        RETURN(node);
    }

    FUNCTION(factor) {
        if (ACCEPT(IDENTSYM)) {
        } else if (ACCEPT(NUMBERSYM)) {
        } else {
            ACCEPT(LPARENSYM);
            CALL(expression);
            ACCEPT(RPARENSYM);
        }
        RETURN(node);
    }

end:;
    AST_print(node);
    return 0;
}

#undef X
#endif
