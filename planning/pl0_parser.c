#ifndef PL0_PARSER_INCLUDE
#define PL0_PARSER_INCLUDE
#include <stdio.h>
#include <stdlib.h>

/* GCC has an extension called "Labels as Values." It's also been adopted by
   Clang and the Intel C compiler. It greatly simplifies the code, and also
   makes it considerably more efficient. However, it's not available in standard
   C, so for compatibility's sake I'm defining it both ways. */


/* If we're forced to use standard C, create an xmacro enum of locations we can go to, and fill an enum. */
/* If we have labels as values, identify labels with void*. Otherwise, use the enum values.*/
#define HAS_LABEL_VALUES
#ifndef HAS_LABEL_VALUES
#define LOCATIONS                 \
    X(program)           \
    X(block)               \
    X(statement)       \
    X(condition)       \
    X(expression)     \
    X(term)                 \
    X(factor)             \
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
#define GOTO(label_val) do { switch (label_val) { LOCATIONS default : error("Invalid GOTO variable!"); } } while(0)
#else /* HAS_LABEL_VALUES */
#define GOTO(label_val) do { goto *label_val; } while(0)
#endif


#define __CAT(a,b) a##b
#define __LBL(b,l) __CAT(b, l)
#define UNIQUE(base) __LBL(base, __LINE__)

#define CALL(to_val)                                                \
    do {                                                            \
        puts("Saving info for call.");\
        /* Push a frame with the address and state that we want to \
           return to. */ \
        current_frame++;                                            \
        puts("Pushed frame.");\
        printf("%p\n", &&UNIQUE(__label_));\
        current_frame->return_address = &&UNIQUE(__label_);         \
        puts("Saved address.");\
        current_frame->stream_pos = spos->pos;                      \
        current_frame->parent = node;                               \
                                                                    \
        /* Jump to what we're calling. */                           \
        puts("jumping");\
        goto to_val;                                           \
                                                                    \
        /* Use the __LINE__ trick to generate a label with a        \
           unique name. We can reference it above because a         \
           macro only expands into one line. */                     \
        UNIQUE(__label_):;                                          \
        puts("Loading info for call.");                                                            \
        /* Now that we've returned, rewind the token stream         \
           and pop the stack frame. */                              \
        spos->pos = current_frame->stream_pos;                      \
        current_frame--;                                            \
    } while (0)

#define RETURN() do { goto_t __retaddr = current_frame->return_address; GOTO(__retaddr); } while(0)


/************/
/* Typedefs */
/************/
typedef enum {
    IDENT,
    NUMBER,
    LPAREN,
    RPAREN,
    TIMES,
    SLASH,
    PLUS,
    MINUS,
    EQL,
    NEQ,
    LSS,
    LEQ,
    GTR,
    GEQ,
    CALLSYM,
    BEGINSYM,
    SEMICOLON,
    ENDSYM,
    IFSYM,
    WHILESYM,
    BECOMES,
    THENSYM,
    DOSYM,
    CONSTSYM,
    COMMA,
    VARSYM,
    PROCSYM,
    PERIOD,
    ODDSYM
} Symbol;

typedef Symbol* SymbolStream;

typedef struct {
    SymbolStream stream;
    size_t pos;
} StreamPosition;

struct ASTNode;
typedef struct ASTNode ASTNode;
struct ASTNode {
    ASTNode* parent;
};

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

static inline int
accept(StreamPosition* spos, Symbol s) {
    return sym_at(spos++) == s;
}

static inline int
expect(StreamPosition* spos, Symbol s) {
    if (accept(spos, s)) return 1;
    error("unexpected symbol.");
}

/*************************/
/* Parser Implementation */
/*************************/

#define PARSER_STACK_SIZE 10000

int
main(void) {
    Symbol program[] = {VARSYM,    IDENT,     COMMA,     IDENT,  SEMICOLON, BEGINSYM, IDENT, EQL,
                        NUMBER,    SEMICOLON, WHILESYM,  IDENT,  BEGINSYM,  IDENT,    EQL,   IDENT,
                        PLUS,      NUMBER,    SEMICOLON, IDENT,  EQL,       IDENT,    TIMES, NUMBER,
                        SEMICOLON, ENDSYM,    SEMICOLON, ENDSYM, PERIOD};
    size_t num_symbols = sizeof(program) / sizeof(Symbol);
    StreamPosition p = {program, 0};
    StreamPosition* spos = &p;

    ParserStackFrame stack_space[PARSER_STACK_SIZE];
    ParserStackFrame* stack_end = stack_space + PARSER_STACK_SIZE;
    ParserStackFrame* current_frame = current_frame;
    stack_space->stream_pos = 0;
    stack_space->return_address = &&end;

    ASTNode* node = (ASTNode*)malloc(sizeof(ASTNode*));

program:;
    puts("program");
    CALL(block);
    puts("Called block.");
    expect(spos, PERIOD);
    RETURN();
block:;
    puts("block");
    if (accept(spos, CONSTSYM)) {
        do {
            expect(spos, IDENT);
            expect(spos, EQL);
            expect(spos, NUMBER);
        } while (accept(spos, COMMA));
        expect(spos, SEMICOLON);
    }
    if (accept(spos, VARSYM)) {
        do {
            expect(spos, IDENT);
        } while (accept(spos, COMMA));
        expect(spos, SEMICOLON);
    }
    while (accept(spos, PROCSYM)) {
        expect(spos, IDENT);
        expect(spos, SEMICOLON);
        CALL(block);
        expect(spos, SEMICOLON);
    }
    CALL(statement);
    RETURN();
statement:;
    puts("statement");
condition:;
    puts("condition");
expression:;
    puts("expression");
term:;
    puts("term");
factor:;
    puts("factor");
end:;
    puts("end");
}

#undef X
#endif
