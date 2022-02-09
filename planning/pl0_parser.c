#include <apaz-libc.h>

/*************************/
/* Start of GOTO xmacros */
/*************************/

#define LOCATIONS                 \
    X(program, PROGRAM)           \
    X(block, BLOCK)               \
    X(statement, STATEMENT)       \
    X(condition, CONDITION)       \
    X(expression, EXPRESSION)     \
    X(term, TERM)                 \
    X(factor, FACTOR)             \
    X(blockretproc, BLOCKRETPROC) \
    X(factretterm1, FACTRETTERM1) \
    X(factretterm2, FACTRETTERM2) \
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

#define CALL(from, to)                               \
    do {                                             \
        current_frame++;                             \
        current_frame->return_address = from;        \
        current_frame->stream_start_pos = spos->pos; \
        current_frame->parent = node;                \
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
    StreamPosition p = {(SymbolStream)program, 0};
    StreamPosition* spos = &p;

    ParserStackFrame stack_space[PARSER_STACK_SIZE];
    ParserStackFrame* stack_end = stack_space + PARSER_STACK_SIZE;
    ParserStackFrame* current_frame = current_frame;
    stack_space->stream_start_pos = 0;
    stack_space->return_address = END;

    ASTNode* node = (ASTNode*)malloc(sizeof(ASTNode*));

program:;
    puts("program");
    GOTO(BLOCK);
block:;
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
        CALL(BLOCKRETPROC, PROCSYM);
    blockretproc:;
        expect(spos, SEMICOLON);
    }
    GOTO(STATEMENT);
statement:;
    puts("statement");
    GOTO(PROGRAM);
condition:;
expression:;
term:;
    {
        factor();
    factretterm1:;
        while (sym_at(spos) == TIMES || sym_at(spos) == SLASH) {
            spos->pos++;
            factor();
        factretterm2:;
        }
    }
factor:;
end:;
}
