// THIS FILE GENERATED BY GenTokType.py. DO NOT EDIT.
#ifndef INCLUDE_TOKENS
#define INCLUDE_TOKENS
#include <apaz-libc.h>

#define NUM_TOKTYPES 80
#define MAX_TOKTYPE_NAME_LEN 11
enum TokType {
  INVALID,
  END_OF_FILE,
  IMPORT,
  COMMENT,
  IDENT,
  NATIVE,
  CTYPE,
  BOOL,
  CHAR,
  UCHAR,
  SHORT,
  USHORT,
  INT,
  UINT,
  LONG,
  FLOAT,
  DOUBLE,
  VOID,
  IF,
  ELSE,
  FOR,
  WHILE,
  CONTINUE,
  BREAK,
  IN,
  CLASS,
  THIS,
  OPERATOR,
  EXTENDS,
  TRAIT,
  IMPL,
  ENUM,
  PRIVATE,
  PROTECTED,
  PUBLIC,
  SUPER,
  INSTANCEOF,
  SIZEOF,
  ASSERT,
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
  DIV,
  AMP,
  BITOR,
  CARET,
  MOD,
  ARROW,
  ADD_ASSIGN,
  SUB_ASSIGN,
  MUL_ASSIGN,
  DIV_ASSIGN,
  AND_ASSIGN,
  OR_ASSIGN,
  XOR_ASSIGN,
  MOD_ASSIGN,
};
typedef enum TokType TokType;
static const char* TokNameMap[] = {
  "INVALID", 
  "END_OF_FILE", 
  "IMPORT", 
  "COMMENT", 
  "IDENT", 
  "NATIVE", 
  "CTYPE", 
  "BOOL", 
  "CHAR", 
  "UCHAR", 
  "SHORT", 
  "USHORT", 
  "INT", 
  "UINT", 
  "LONG", 
  "FLOAT", 
  "DOUBLE", 
  "VOID", 
  "IF", 
  "ELSE", 
  "FOR", 
  "WHILE", 
  "CONTINUE", 
  "BREAK", 
  "IN", 
  "CLASS", 
  "THIS", 
  "OPERATOR", 
  "EXTENDS", 
  "TRAIT", 
  "IMPL", 
  "ENUM", 
  "PRIVATE", 
  "PROTECTED", 
  "PUBLIC", 
  "SUPER", 
  "INSTANCEOF", 
  "SIZEOF", 
  "ASSERT", 
  "LPAREN", 
  "RPAREN", 
  "LBRACE", 
  "RBRACE", 
  "LBRACK", 
  "RBRACK", 
  "LARROW", 
  "RARROW", 
  "SEMI", 
  "COMMA", 
  "DOT", 
  "STAR", 
  "EQUALS", 
  "BANG", 
  "TILDE", 
  "QUESTION", 
  "COLON", 
  "EQUAL", 
  "LE", 
  "GE", 
  "NOTEQUAL", 
  "AND", 
  "OR", 
  "INC", 
  "DEC", 
  "ADD", 
  "SUB", 
  "DIV", 
  "AMP", 
  "BITOR", 
  "CARET", 
  "MOD", 
  "ARROW", 
  "ADD_ASSIGN", 
  "SUB_ASSIGN", 
  "MUL_ASSIGN", 
  "DIV_ASSIGN", 
  "AND_ASSIGN", 
  "OR_ASSIGN", 
  "XOR_ASSIGN", 
  "MOD_ASSIGN"
};

static inline TokType valid_NATIVE(char* str) { static const char* tok = "native"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return NATIVE; }
static inline TokType valid_CTYPE(char* str) { static const char* tok = "ctype"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return CTYPE; }
static inline TokType valid_BOOL(char* str) { static const char* tok = "Bool"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return BOOL; }
static inline TokType valid_CHAR(char* str) { static const char* tok = "Char"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return CHAR; }
static inline TokType valid_UCHAR(char* str) { static const char* tok = "UChar"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return UCHAR; }
static inline TokType valid_SHORT(char* str) { static const char* tok = "Short"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SHORT; }
static inline TokType valid_USHORT(char* str) { static const char* tok = "UShort"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return USHORT; }
static inline TokType valid_INT(char* str) { static const char* tok = "Int"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return INT; }
static inline TokType valid_UINT(char* str) { static const char* tok = "UInt"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return UINT; }
static inline TokType valid_LONG(char* str) { static const char* tok = "Long"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LONG; }
static inline TokType valid_FLOAT(char* str) { static const char* tok = "Float"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return FLOAT; }
static inline TokType valid_DOUBLE(char* str) { static const char* tok = "Double"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return DOUBLE; }
static inline TokType valid_VOID(char* str) { static const char* tok = "Void"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return VOID; }
static inline TokType valid_IF(char* str) { static const char* tok = "if"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return IF; }
static inline TokType valid_ELSE(char* str) { static const char* tok = "else"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ELSE; }
static inline TokType valid_FOR(char* str) { static const char* tok = "for"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return FOR; }
static inline TokType valid_WHILE(char* str) { static const char* tok = "while"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return WHILE; }
static inline TokType valid_CONTINUE(char* str) { static const char* tok = "continue"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return CONTINUE; }
static inline TokType valid_BREAK(char* str) { static const char* tok = "break"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return BREAK; }
static inline TokType valid_IN(char* str) { static const char* tok = "in"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return IN; }
static inline TokType valid_CLASS(char* str) { static const char* tok = "class"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return CLASS; }
static inline TokType valid_THIS(char* str) { static const char* tok = "this"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return THIS; }
static inline TokType valid_OPERATOR(char* str) { static const char* tok = "operator"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return OPERATOR; }
static inline TokType valid_EXTENDS(char* str) { static const char* tok = "extends"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return EXTENDS; }
static inline TokType valid_TRAIT(char* str) { static const char* tok = "trait"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return TRAIT; }
static inline TokType valid_IMPL(char* str) { static const char* tok = "impl"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return IMPL; }
static inline TokType valid_ENUM(char* str) { static const char* tok = "enum"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ENUM; }
static inline TokType valid_PRIVATE(char* str) { static const char* tok = "private"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return PRIVATE; }
static inline TokType valid_PROTECTED(char* str) { static const char* tok = "protected"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return PROTECTED; }
static inline TokType valid_PUBLIC(char* str) { static const char* tok = "public"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return PUBLIC; }
static inline TokType valid_SUPER(char* str) { static const char* tok = "super"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SUPER; }
static inline TokType valid_INSTANCEOF(char* str) { static const char* tok = "instanceof"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return INSTANCEOF; }
static inline TokType valid_SIZEOF(char* str) { static const char* tok = "sizeof"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SIZEOF; }
static inline TokType valid_ASSERT(char* str) { static const char* tok = "assert"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ASSERT; }
static inline TokType valid_LPAREN(char* str) { static const char* tok = "("; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LPAREN; }
static inline TokType valid_RPAREN(char* str) { static const char* tok = ")"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return RPAREN; }
static inline TokType valid_LBRACE(char* str) { static const char* tok = "{"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LBRACE; }
static inline TokType valid_RBRACE(char* str) { static const char* tok = "}"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return RBRACE; }
static inline TokType valid_LBRACK(char* str) { static const char* tok = "["; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LBRACK; }
static inline TokType valid_RBRACK(char* str) { static const char* tok = "]"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return RBRACK; }
static inline TokType valid_LARROW(char* str) { static const char* tok = "<"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LARROW; }
static inline TokType valid_RARROW(char* str) { static const char* tok = ">"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return RARROW; }
static inline TokType valid_SEMI(char* str) { static const char* tok = ";"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SEMI; }
static inline TokType valid_COMMA(char* str) { static const char* tok = ","; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return COMMA; }
static inline TokType valid_DOT(char* str) { static const char* tok = "."; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return DOT; }
static inline TokType valid_STAR(char* str) { static const char* tok = "*"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return STAR; }
static inline TokType valid_EQUALS(char* str) { static const char* tok = "="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return EQUALS; }
static inline TokType valid_BANG(char* str) { static const char* tok = "!"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return BANG; }
static inline TokType valid_TILDE(char* str) { static const char* tok = "~"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return TILDE; }
static inline TokType valid_QUESTION(char* str) { static const char* tok = "?"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return QUESTION; }
static inline TokType valid_COLON(char* str) { static const char* tok = ":"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return COLON; }
static inline TokType valid_EQUAL(char* str) { static const char* tok = "=="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return EQUAL; }
static inline TokType valid_LE(char* str) { static const char* tok = "<="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return LE; }
static inline TokType valid_GE(char* str) { static const char* tok = ">="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return GE; }
static inline TokType valid_NOTEQUAL(char* str) { static const char* tok = "!="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return NOTEQUAL; }
static inline TokType valid_AND(char* str) { static const char* tok = "&&"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return AND; }
static inline TokType valid_OR(char* str) { static const char* tok = "||"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return OR; }
static inline TokType valid_INC(char* str) { static const char* tok = "++"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return INC; }
static inline TokType valid_DEC(char* str) { static const char* tok = "--"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return DEC; }
static inline TokType valid_ADD(char* str) { static const char* tok = "+"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ADD; }
static inline TokType valid_SUB(char* str) { static const char* tok = "-"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SUB; }
static inline TokType valid_DIV(char* str) { static const char* tok = "/"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return DIV; }
static inline TokType valid_AMP(char* str) { static const char* tok = "&"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return AMP; }
static inline TokType valid_BITOR(char* str) { static const char* tok = "|"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return BITOR; }
static inline TokType valid_CARET(char* str) { static const char* tok = "^"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return CARET; }
static inline TokType valid_MOD(char* str) { static const char* tok = "%"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return MOD; }
static inline TokType valid_ARROW(char* str) { static const char* tok = "->"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ARROW; }
static inline TokType valid_ADD_ASSIGN(char* str) { static const char* tok = "+="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return ADD_ASSIGN; }
static inline TokType valid_SUB_ASSIGN(char* str) { static const char* tok = "-="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return SUB_ASSIGN; }
static inline TokType valid_MUL_ASSIGN(char* str) { static const char* tok = "*="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return MUL_ASSIGN; }
static inline TokType valid_DIV_ASSIGN(char* str) { static const char* tok = "/="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return DIV_ASSIGN; }
static inline TokType valid_AND_ASSIGN(char* str) { static const char* tok = "&="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return AND_ASSIGN; }
static inline TokType valid_OR_ASSIGN(char* str) { static const char* tok = "|="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return OR_ASSIGN; }
static inline TokType valid_XOR_ASSIGN(char* str) { static const char* tok = "^="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return XOR_ASSIGN; }
static inline TokType valid_MOD_ASSIGN(char* str) { static const char* tok = "%="; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return MOD_ASSIGN; }
static inline bool potential_NATIVE(char* str) { static const char* tok = "native"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_CTYPE(char* str) { static const char* tok = "ctype"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_BOOL(char* str) { static const char* tok = "Bool"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_CHAR(char* str) { static const char* tok = "Char"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_UCHAR(char* str) { static const char* tok = "UChar"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SHORT(char* str) { static const char* tok = "Short"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_USHORT(char* str) { static const char* tok = "UShort"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_INT(char* str) { static const char* tok = "Int"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_UINT(char* str) { static const char* tok = "UInt"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LONG(char* str) { static const char* tok = "Long"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_FLOAT(char* str) { static const char* tok = "Float"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_DOUBLE(char* str) { static const char* tok = "Double"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_VOID(char* str) { static const char* tok = "Void"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_IF(char* str) { static const char* tok = "if"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ELSE(char* str) { static const char* tok = "else"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_FOR(char* str) { static const char* tok = "for"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_WHILE(char* str) { static const char* tok = "while"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_CONTINUE(char* str) { static const char* tok = "continue"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_BREAK(char* str) { static const char* tok = "break"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_IN(char* str) { static const char* tok = "in"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_CLASS(char* str) { static const char* tok = "class"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_THIS(char* str) { static const char* tok = "this"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_OPERATOR(char* str) { static const char* tok = "operator"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_EXTENDS(char* str) { static const char* tok = "extends"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_TRAIT(char* str) { static const char* tok = "trait"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_IMPL(char* str) { static const char* tok = "impl"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ENUM(char* str) { static const char* tok = "enum"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_PRIVATE(char* str) { static const char* tok = "private"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_PROTECTED(char* str) { static const char* tok = "protected"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_PUBLIC(char* str) { static const char* tok = "public"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SUPER(char* str) { static const char* tok = "super"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_INSTANCEOF(char* str) { static const char* tok = "instanceof"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SIZEOF(char* str) { static const char* tok = "sizeof"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ASSERT(char* str) { static const char* tok = "assert"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LPAREN(char* str) { static const char* tok = "("; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_RPAREN(char* str) { static const char* tok = ")"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LBRACE(char* str) { static const char* tok = "{"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_RBRACE(char* str) { static const char* tok = "}"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LBRACK(char* str) { static const char* tok = "["; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_RBRACK(char* str) { static const char* tok = "]"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LARROW(char* str) { static const char* tok = "<"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_RARROW(char* str) { static const char* tok = ">"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SEMI(char* str) { static const char* tok = ";"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_COMMA(char* str) { static const char* tok = ","; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_DOT(char* str) { static const char* tok = "."; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_STAR(char* str) { static const char* tok = "*"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_EQUALS(char* str) { static const char* tok = "="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_BANG(char* str) { static const char* tok = "!"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_TILDE(char* str) { static const char* tok = "~"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_QUESTION(char* str) { static const char* tok = "?"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_COLON(char* str) { static const char* tok = ":"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_EQUAL(char* str) { static const char* tok = "=="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_LE(char* str) { static const char* tok = "<="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_GE(char* str) { static const char* tok = ">="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_NOTEQUAL(char* str) { static const char* tok = "!="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_AND(char* str) { static const char* tok = "&&"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_OR(char* str) { static const char* tok = "||"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_INC(char* str) { static const char* tok = "++"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_DEC(char* str) { static const char* tok = "--"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ADD(char* str) { static const char* tok = "+"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SUB(char* str) { static const char* tok = "-"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_DIV(char* str) { static const char* tok = "/"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_AMP(char* str) { static const char* tok = "&"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_BITOR(char* str) { static const char* tok = "|"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_CARET(char* str) { static const char* tok = "^"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_MOD(char* str) { static const char* tok = "%"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ARROW(char* str) { static const char* tok = "->"; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_ADD_ASSIGN(char* str) { static const char* tok = "+="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_SUB_ASSIGN(char* str) { static const char* tok = "-="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_MUL_ASSIGN(char* str) { static const char* tok = "*="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_DIV_ASSIGN(char* str) { static const char* tok = "/="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_AND_ASSIGN(char* str) { static const char* tok = "&="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_OR_ASSIGN(char* str) { static const char* tok = "|="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_XOR_ASSIGN(char* str) { static const char* tok = "^="; while (*str) if (*str++ != *tok++) return false; return true; }
static inline bool potential_MOD_ASSIGN(char* str) { static const char* tok = "%="; while (*str) if (*str++ != *tok++) return false; return true; }

/**********/
/* Custom */
/**********/


static inline TokType validImport(char *str) {
  return String_equals(str, "include") || String_equals(str, "import")
             ? IMPORT
             : INVALID;
}

static inline bool potentialImport(char *str) {
  return apaz_str_startsWith("import", str) ||
         apaz_str_startsWith("include", str);
}

static inline TokType validIdent(char *str) {
  for (size_t i = 0; i < String_len(str); i++) {
    if ((str[i] != ' ') &
        (str[i] != '\t') &
        (str[i] != '\r') &
        (str[i] != '\n'))
      return INVALID;
  }
  return IDENT;
}

static inline bool potentialIdent(char *str) { }

static inline TokType validComment(char *str) {
  if (apaz_strlen(str) < 3)
    return INVALID;
  else if (String_startsWith(str, "/*") && String_endsWith(str, "*/")) {
    size_t search_end = apaz_strlen(str) - 4; // Prefix/suffix
    str = str + 2;
    for (size_t i = 0; i < search_end; i++)
      if (str[i] == '*' & str[i + 1] == '/')
        return INVALID;
    return COMMENT;
  } else if (String_startsWith(str, "//") && String_endsWith(str, "\n")) {
    size_t search_end = apaz_strlen(str) - 3; // -3 for prefix/suffix
    str = str + 2;
    for (size_t i = 0; i < search_end; i++)
      if (str[i] == '\n')
        return INVALID;
    return COMMENT;
  }
  return INVALID;
}

static inline bool potentialComment(char *str) {
  bool sl = apaz_str_startsWith(str, "//");
  bool ml = apaz_str_startsWith(str, "/*");
  if (!(sl | ml))
    return false;

  size_t len = apaz_strlen(str);
  if (sl) {
    for (size_t i = 2; i < len - 1; i++)
      if (str[i] == '\n')
        return false;
    return true;
  } else {
    for (size_t i = 2; i < len - 2; i++)
      if (str[i] == '*' & str[i + 1] == '/')
        return false;
    return true;
  }
}


#endif // INCLUDE_TOKENS