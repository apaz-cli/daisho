#include <apaz-libc.h>

/*************************/
/* Start of GOTO xmacros */
/*************************/

#define LOCATIONS             \
    X(program, PROGRAM)       \
    X(block, BLOCK)           \
    X(statement, STATEMENT)   \
    X(condition, CONDITION)   \
    X(expression, EXPRESSION) \
    X(term, TERM)             \
    X(factor, FACTOR)         \
    X(end, END)

typedef enum {
#define X(label, num) num,
    LOCATIONS
#undef X
} goto_t;

#define X(label, num) \
    case num:         \
        goto label;
#define GOTO(number) \
    switch (number) { LOCATIONS default : error("AAAAAAAAH!"); }

#define CALL(from, to, on)                           \
    do {                                             \
        current_frame++;                             \
        current_frame->return_address = from;        \
        current_frame->stream_start_pos = spos->pos; \
        current_frame->parent = on;                  \
        GOTO(to);                                    \
    } while (0)

#define RETURN()                                           \
    do {                                                   \
        goto_t __ret_addr = current_frame->return_address; \
        current_frame--;                                   \
        GOTO(__ret_addr);                                  \
    } while (0)

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
    size_t stream_start_pos;
    goto_t return_address;
    ASTNode parent;
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
main(int argc, char** argv) {
    (void)argc;
    char* input = argv[1];
    if (!input) error("Please provide input.\n");

    ParserStackFrame stack_space[PARSER_STACK_SIZE];
    ParserStackFrame* stack_end = stack_space + PARSER_STACK_SIZE;
    ParserStackFrame* current_frame = current_frame;
    stack_space->stream_start_pos = 0;
    stack_space->return_address = END;

    SymbolStream stream = NULL;
    StreamPosition p = {stream, 0};
    StreamPosition* spos = &p;

program:;
    puts("program");
    GOTO(BLOCK);
block:;
    puts("block");
    GOTO(STATEMENT);
statement:;
    puts("statement");
    GOTO(PROGRAM);
condition:;
expression:;
term:;
factor:;
end:;
}
