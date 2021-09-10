#pragma once
#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

typedef unsigned int uint32_t;
typedef char *string;

template <typename t>
class vector {};

template <typename t1, typename t2>
class pair {};

template <typename t1, typename t2>
class map {};

/*
using std::string;
using std::pair;
using std::map;
using std::tuple;
*/

enum TokType {
    // Pragma
    IMPORT,
    NATIVE,
    CTYPE,

    // Types
    BOOL,
    CHAR,
    UCHAR,
    SHORT,
    USHORT,
    INT,
    UINT,
    LONG,
    ULONG,
    FLOAT,
    DOUBLE,
    VOID,

    // Control
    IF,
    ELIF,
    ELSE,

    // Loops
    FOR,
    WHILE,
    CONTINUE,
    BREAK,

    // Classes
    CLASS,
    THIS,
    OPERATOR,
    EXTENDS,

    // Interfaces
    INTERFACE,
    IMPLEMENTS,
    ABSTRACT,
    DEFAULT,
    DEFAULTSTO,

    // Other containers
    ENUM,

    // Access modifiers
    PRIVATE,
    PROTECTED,
    PUBLIC,

    // Builtin functions
    SUPER,
    INSTANCEOF,
    SIZEOF,
    ASSERT,

    // Literals
    INTEGERLITERAL,
    FLOATLITERAL,
    BOOLEANLITERAL,
    NULLLITERAL,
    STRINGLITERAL,

    // Separators
    LPAREN,
    RPAREN,
    LBRACE,
    RBRACE,
    LBRACK,
    RBRACK,
    LARROW,
    RARROW,
    SEMI,
    COMMA,
    DOT,
    STAR,
    EQUALS,

    // Operators
    BANG,
    TILDE,
    QUESTION,
    COLON,
    EQUAL,
    LE,
    GE,
    NOTEQUAL,
    AND,
    OR,
    INC,
    DEC,
    ADD,
    SUB,
    MUL,
    DIV,
    AMP,
    BITOR,
    CARET,
    MOD,
    ARROW,
    // Handled by grammar
    // LSHIFT,
    // RSHIFT,
    // URSHIFT

    ADD_ASSIGN,
    SUB_ASSIGN,
    MUL_ASSIGN,
    DIV_ASSIGN,
    AND_ASSIGN,
    OR_ASSIGN,
    XOR_ASSIGN,
    MOD_ASSIGN,
    // Handled by grammar
    //LSHIFT_ASSIGN,
    //RSHIFT_ASSIGN,
    //URSHIFT_ASSIGN,

    // Identifiers
    IDENT,

    // Ignored sections
    WS,
    COMMENT,
    LINE_COMMENT
};

class Token {
    TokType type;
    uint32_t pos;
    uint32_t line;
    string file;
};

typedef unsigned char DFAState;

struct TokenizerDFA {
    map<pair<wchar_t, DFAState>, DFAState> statemap;
    vector<DFAState> accepting_states;
    DFAState current_state;
    bool active = true;
};

class StiltsTokenizer {

    string input;
    vector<TokenizerDFA> DFAs;

    StiltsTokenizer(string input) : input(input), DFAs(){

    };

    Token nextToken() {
        Token tok;
        bool cont = true;
        while (cont) {
        }
    };

    void transition(wchar_t next_character) {
        for (TokenizerDFA dfa : this->DFAs) {
            if (!dfa.active)
                continue;
            DFAState next_state = dfa.statemap[]
            //DFAState current_state = current_states[i].second();
            //DFAState next_state = statemaps[i][pair<DFAState, wchar_t>(current_state, next_character)];
        }
    };
};

#endif // TOKENIZER_INCLUDE