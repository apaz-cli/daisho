#pragma once
#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "stilts-common.hpp"
#include <string>

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
  INTERFACE,
  IMPLEMENTS,
  ABSTRACT,
  DEFAULT,

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
  EQUALS

  // Operators
};

class Token {
  u16string text;
  string file;
  uint32_t line;
};

class StiltsTokenizer {
  u16string current;
};

#endif // TOKENIZER_INCLUDE