
write_to = "src/Tokens.h"

# [TokType, literal]

def makeCap(s):
	return [s.upper(), s.capitalize()]

def makeLower(s):
	return [s.upper(), s.lower()]


entries = [
	# Pragma
	makeLower("native"),
	makeLower("ctype"),

	# Types
	["BOOL", "Bool"],
	["CHAR", "Char"],
	["UCHAR", "UChar"],
	["SHORT", "Short"],
	["USHORT", "UShort"],
	["INT", "Int"],
	["UINT", "UInt"],
	["LONG", "Long"],
	["FLOAT", "Float"],
	["DOUBLE", "Double"],
	["VOID", "Void"],

	# Control
	makeLower('if'),
	makeLower('else'),

	# Loops
	makeLower('for'),
	makeLower('while'),
	makeLower('continue'),
	makeLower('break'),

	# Exceptions
	#makeLower('try'),
	#makeLower('catch'),
	#makeLower('finally'),

	# Classes
	makeLower('class'),
	makeLower('this'),
	makeLower('operator'),
	makeLower('extends'),

	# Interfaces
	makeLower('interface'),
	makeLower('implements'),
	makeLower('abstract'),
	makeLower('default'),
	makeLower('defaultsto'),

	# Other containers
	makeLower('enum'),

	# Access Modifiers
	makeLower('private'),
	makeLower('protected'),
	makeLower('public'),

	# Builtin functions
	makeLower('super'),
	makeLower('instanceof'),
	makeLower('sizeof'),
	makeLower('assert'),

	# Separators
	["LPAREN", "("],
	["RPAREN", ")"],
	["LBRACE", "{"],
	["RBRACE", "}"],
	["LBRACK", "["],
	["RBRACK", "]"],
	["LARROW", "<"],
	["RARROW", ">"],
	["SEMI", ";"],
	["COMMA", ","],
	["DOT", "."],
	["STAR", "*"],
	["EQUALS", "="],

	# Operators
	["BANG", "!"],
	["TILDE", "~"],
	["QUESTION", "?"],
	["COLON", ":"],
	["EQUAL", "=="],
	["LE", "<="],
	["GE", ">="],
	["NOTEQUAL", "!="],
	["AND", "&&"],
	["OR", "||"],
	["INC", "++"],
	["DEC", "--"],
	["ADD", "+"],
	["SUB", "-"],
	["DIV", "/"],
	["AMP", "&"],
	["BITOR", "|"],
	["CARET", "^"],
	["MOD", "%"],
	["ARROW", "->"],

	["ADD_ASSIGN", "+="],
	["SUB_ASSIGN", "-="],
	["MUL_ASSIGN", "*="],
	["DIV_ASSIGN", "/="],
	["AND_ASSIGN", "&="],
	["OR_ASSIGN", "|="],
	["XOR_ASSIGN", "^="],
	["MOD_ASSIGN", "%="],

]

tok_enum = """
enum TokType {
  // Invalid
  INVALID = 0,
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
  // MUL, (STAR)
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
  // LSHIFT_ASSIGN,
  // RSHIFT_ASSIGN,
  // URSHIFT_ASSIGN,

  // Identifiers
  IDENT,

  // Ignored sections
  WS,
  COMMENT
};
"""

custom_functions = """
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
        (str[i] != '\\t') & 
        (str[i] != '\\r') &
        (str[i] != '\\n'))
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
  } else if (String_startsWith(str, "//") && String_endsWith(str, "\\n")) {
    size_t search_end = apaz_strlen(str) - 3; // -3 for prefix/suffix
    str = str + 2;
    for (size_t i = 0; i < search_end; i++)
      if (str[i] == '\\n')
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
      if (str[i] == '\\n')
        return false;
    return true;
  } else {
    for (size_t i = 2; i < len - 2; i++)
      if (str[i] == '*' & str[i + 1] == '/')
        return false;
    return true;
  }
}

"""

def writeValid(name, literal):
	f.write(f"static inline TokType valid{name.capitalize()}(char* str) {{ return apaz_str_equals(str, \"{literal}\") ? {name} : INVALID; }}\n")
def writePotential(name, literal):
	f.write(f"static inline bool potential{name.capitalize()}(char* str) {{ return apaz_str_startsWith(\"{literal}\", str); }}\n")

with open(write_to, 'w') as f:
	f.write('// THIS FILE GENERATED BY GenTokType.py. DO NOT EDIT.\n')
	f.write('#ifndef INCLUDE_TOKENS\n')
	f.write('#define INCLUDE_TOKENS\n\n')
	f.write('#include <apaz-libc.h>\n')
	f.write(tok_enum)
	f.write('typedef enum TokType TokType;\n')
	f.write('\n\n')

	for e in entries:
		writeValid(e[0], e[1])
	for e in entries:
		writePotential(e[0], e[1])
	
	f.write(custom_functions)

	f.write("\n#endif // INCLUDE_TOKENS")
