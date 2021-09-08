#pragma once
#ifndef TOKENIZER_INCLUDE
#define TOKENIZER_INCLUDE

#include "stilts-common.hpp"
#include <string>

enum TokType {
  IMPORT,
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
  ULONG,
  FLOAT,
  DOUBLE,
  VOID,
  IF,
  ELIF,
  ELSE,
  FOR,
  WHILE,
  CONTINUE,
  BREAK,
  CLASS,
  THIS,
  OPERATOR,
  EXTENDS,
  INTERFACE,
  IMPLEMENTS,
  ABSTRACT,
  DEFAULT,
  ENUM,
  PRIVATE,
  PROTECTED,
  PUBLIC,
  SUPER,
  INSTANCEOF,
  SIZEOF,
  ASSERT
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