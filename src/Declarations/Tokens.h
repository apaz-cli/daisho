// THIS FILE GENERATED BY GenTokType.py. DO NOT EDIT.
#ifndef INCLUDE_TOKENS
#define INCLUDE_TOKENS

#include <apaz-libc.h>

enum TokType {
  // Special Token Types
  INVALID = 0,
  END_OF_FILE,
  
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
typedef enum TokType TokType;


static inline TokType validNative(char* str) { return apaz_str_equals(str, "native") ? NATIVE : INVALID; }
static inline TokType validCtype(char* str) { return apaz_str_equals(str, "ctype") ? CTYPE : INVALID; }
static inline TokType validBool(char* str) { return apaz_str_equals(str, "Bool") ? BOOL : INVALID; }
static inline TokType validChar(char* str) { return apaz_str_equals(str, "Char") ? CHAR : INVALID; }
static inline TokType validUchar(char* str) { return apaz_str_equals(str, "UChar") ? UCHAR : INVALID; }
static inline TokType validShort(char* str) { return apaz_str_equals(str, "Short") ? SHORT : INVALID; }
static inline TokType validUshort(char* str) { return apaz_str_equals(str, "UShort") ? USHORT : INVALID; }
static inline TokType validInt(char* str) { return apaz_str_equals(str, "Int") ? INT : INVALID; }
static inline TokType validUint(char* str) { return apaz_str_equals(str, "UInt") ? UINT : INVALID; }
static inline TokType validLong(char* str) { return apaz_str_equals(str, "Long") ? LONG : INVALID; }
static inline TokType validFloat(char* str) { return apaz_str_equals(str, "Float") ? FLOAT : INVALID; }
static inline TokType validDouble(char* str) { return apaz_str_equals(str, "Double") ? DOUBLE : INVALID; }
static inline TokType validVoid(char* str) { return apaz_str_equals(str, "Void") ? VOID : INVALID; }
static inline TokType validIf(char* str) { return apaz_str_equals(str, "if") ? IF : INVALID; }
static inline TokType validElse(char* str) { return apaz_str_equals(str, "else") ? ELSE : INVALID; }
static inline TokType validFor(char* str) { return apaz_str_equals(str, "for") ? FOR : INVALID; }
static inline TokType validWhile(char* str) { return apaz_str_equals(str, "while") ? WHILE : INVALID; }
static inline TokType validContinue(char* str) { return apaz_str_equals(str, "continue") ? CONTINUE : INVALID; }
static inline TokType validBreak(char* str) { return apaz_str_equals(str, "break") ? BREAK : INVALID; }
static inline TokType validClass(char* str) { return apaz_str_equals(str, "class") ? CLASS : INVALID; }
static inline TokType validThis(char* str) { return apaz_str_equals(str, "this") ? THIS : INVALID; }
static inline TokType validOperator(char* str) { return apaz_str_equals(str, "operator") ? OPERATOR : INVALID; }
static inline TokType validExtends(char* str) { return apaz_str_equals(str, "extends") ? EXTENDS : INVALID; }
static inline TokType validInterface(char* str) { return apaz_str_equals(str, "interface") ? INTERFACE : INVALID; }
static inline TokType validImplements(char* str) { return apaz_str_equals(str, "implements") ? IMPLEMENTS : INVALID; }
static inline TokType validAbstract(char* str) { return apaz_str_equals(str, "abstract") ? ABSTRACT : INVALID; }
static inline TokType validDefault(char* str) { return apaz_str_equals(str, "default") ? DEFAULT : INVALID; }
static inline TokType validDefaultsto(char* str) { return apaz_str_equals(str, "defaultsto") ? DEFAULTSTO : INVALID; }
static inline TokType validEnum(char* str) { return apaz_str_equals(str, "enum") ? ENUM : INVALID; }
static inline TokType validPrivate(char* str) { return apaz_str_equals(str, "private") ? PRIVATE : INVALID; }
static inline TokType validProtected(char* str) { return apaz_str_equals(str, "protected") ? PROTECTED : INVALID; }
static inline TokType validPublic(char* str) { return apaz_str_equals(str, "public") ? PUBLIC : INVALID; }
static inline TokType validSuper(char* str) { return apaz_str_equals(str, "super") ? SUPER : INVALID; }
static inline TokType validInstanceof(char* str) { return apaz_str_equals(str, "instanceof") ? INSTANCEOF : INVALID; }
static inline TokType validSizeof(char* str) { return apaz_str_equals(str, "sizeof") ? SIZEOF : INVALID; }
static inline TokType validAssert(char* str) { return apaz_str_equals(str, "assert") ? ASSERT : INVALID; }
static inline TokType validLparen(char* str) { return apaz_str_equals(str, "(") ? LPAREN : INVALID; }
static inline TokType validRparen(char* str) { return apaz_str_equals(str, ")") ? RPAREN : INVALID; }
static inline TokType validLbrace(char* str) { return apaz_str_equals(str, "{") ? LBRACE : INVALID; }
static inline TokType validRbrace(char* str) { return apaz_str_equals(str, "}") ? RBRACE : INVALID; }
static inline TokType validLbrack(char* str) { return apaz_str_equals(str, "[") ? LBRACK : INVALID; }
static inline TokType validRbrack(char* str) { return apaz_str_equals(str, "]") ? RBRACK : INVALID; }
static inline TokType validLarrow(char* str) { return apaz_str_equals(str, "<") ? LARROW : INVALID; }
static inline TokType validRarrow(char* str) { return apaz_str_equals(str, ">") ? RARROW : INVALID; }
static inline TokType validSemi(char* str) { return apaz_str_equals(str, ";") ? SEMI : INVALID; }
static inline TokType validComma(char* str) { return apaz_str_equals(str, ",") ? COMMA : INVALID; }
static inline TokType validDot(char* str) { return apaz_str_equals(str, ".") ? DOT : INVALID; }
static inline TokType validStar(char* str) { return apaz_str_equals(str, "*") ? STAR : INVALID; }
static inline TokType validEquals(char* str) { return apaz_str_equals(str, "=") ? EQUALS : INVALID; }
static inline TokType validBang(char* str) { return apaz_str_equals(str, "!") ? BANG : INVALID; }
static inline TokType validTilde(char* str) { return apaz_str_equals(str, "~") ? TILDE : INVALID; }
static inline TokType validQuestion(char* str) { return apaz_str_equals(str, "?") ? QUESTION : INVALID; }
static inline TokType validColon(char* str) { return apaz_str_equals(str, ":") ? COLON : INVALID; }
static inline TokType validEqual(char* str) { return apaz_str_equals(str, "==") ? EQUAL : INVALID; }
static inline TokType validLe(char* str) { return apaz_str_equals(str, "<=") ? LE : INVALID; }
static inline TokType validGe(char* str) { return apaz_str_equals(str, ">=") ? GE : INVALID; }
static inline TokType validNotequal(char* str) { return apaz_str_equals(str, "!=") ? NOTEQUAL : INVALID; }
static inline TokType validAnd(char* str) { return apaz_str_equals(str, "&&") ? AND : INVALID; }
static inline TokType validOr(char* str) { return apaz_str_equals(str, "||") ? OR : INVALID; }
static inline TokType validInc(char* str) { return apaz_str_equals(str, "++") ? INC : INVALID; }
static inline TokType validDec(char* str) { return apaz_str_equals(str, "--") ? DEC : INVALID; }
static inline TokType validAdd(char* str) { return apaz_str_equals(str, "+") ? ADD : INVALID; }
static inline TokType validSub(char* str) { return apaz_str_equals(str, "-") ? SUB : INVALID; }
static inline TokType validDiv(char* str) { return apaz_str_equals(str, "/") ? DIV : INVALID; }
static inline TokType validAmp(char* str) { return apaz_str_equals(str, "&") ? AMP : INVALID; }
static inline TokType validBitor(char* str) { return apaz_str_equals(str, "|") ? BITOR : INVALID; }
static inline TokType validCaret(char* str) { return apaz_str_equals(str, "^") ? CARET : INVALID; }
static inline TokType validMod(char* str) { return apaz_str_equals(str, "%") ? MOD : INVALID; }
static inline TokType validArrow(char* str) { return apaz_str_equals(str, "->") ? ARROW : INVALID; }
static inline TokType validAdd_assign(char* str) { return apaz_str_equals(str, "+=") ? ADD_ASSIGN : INVALID; }
static inline TokType validSub_assign(char* str) { return apaz_str_equals(str, "-=") ? SUB_ASSIGN : INVALID; }
static inline TokType validMul_assign(char* str) { return apaz_str_equals(str, "*=") ? MUL_ASSIGN : INVALID; }
static inline TokType validDiv_assign(char* str) { return apaz_str_equals(str, "/=") ? DIV_ASSIGN : INVALID; }
static inline TokType validAnd_assign(char* str) { return apaz_str_equals(str, "&=") ? AND_ASSIGN : INVALID; }
static inline TokType validOr_assign(char* str) { return apaz_str_equals(str, "|=") ? OR_ASSIGN : INVALID; }
static inline TokType validXor_assign(char* str) { return apaz_str_equals(str, "^=") ? XOR_ASSIGN : INVALID; }
static inline TokType validMod_assign(char* str) { return apaz_str_equals(str, "%=") ? MOD_ASSIGN : INVALID; }
static inline bool potentialNative(char* str) { return apaz_str_startsWith("native", str); }
static inline bool potentialCtype(char* str) { return apaz_str_startsWith("ctype", str); }
static inline bool potentialBool(char* str) { return apaz_str_startsWith("Bool", str); }
static inline bool potentialChar(char* str) { return apaz_str_startsWith("Char", str); }
static inline bool potentialUchar(char* str) { return apaz_str_startsWith("UChar", str); }
static inline bool potentialShort(char* str) { return apaz_str_startsWith("Short", str); }
static inline bool potentialUshort(char* str) { return apaz_str_startsWith("UShort", str); }
static inline bool potentialInt(char* str) { return apaz_str_startsWith("Int", str); }
static inline bool potentialUint(char* str) { return apaz_str_startsWith("UInt", str); }
static inline bool potentialLong(char* str) { return apaz_str_startsWith("Long", str); }
static inline bool potentialFloat(char* str) { return apaz_str_startsWith("Float", str); }
static inline bool potentialDouble(char* str) { return apaz_str_startsWith("Double", str); }
static inline bool potentialVoid(char* str) { return apaz_str_startsWith("Void", str); }
static inline bool potentialIf(char* str) { return apaz_str_startsWith("if", str); }
static inline bool potentialElse(char* str) { return apaz_str_startsWith("else", str); }
static inline bool potentialFor(char* str) { return apaz_str_startsWith("for", str); }
static inline bool potentialWhile(char* str) { return apaz_str_startsWith("while", str); }
static inline bool potentialContinue(char* str) { return apaz_str_startsWith("continue", str); }
static inline bool potentialBreak(char* str) { return apaz_str_startsWith("break", str); }
static inline bool potentialClass(char* str) { return apaz_str_startsWith("class", str); }
static inline bool potentialThis(char* str) { return apaz_str_startsWith("this", str); }
static inline bool potentialOperator(char* str) { return apaz_str_startsWith("operator", str); }
static inline bool potentialExtends(char* str) { return apaz_str_startsWith("extends", str); }
static inline bool potentialInterface(char* str) { return apaz_str_startsWith("interface", str); }
static inline bool potentialImplements(char* str) { return apaz_str_startsWith("implements", str); }
static inline bool potentialAbstract(char* str) { return apaz_str_startsWith("abstract", str); }
static inline bool potentialDefault(char* str) { return apaz_str_startsWith("default", str); }
static inline bool potentialDefaultsto(char* str) { return apaz_str_startsWith("defaultsto", str); }
static inline bool potentialEnum(char* str) { return apaz_str_startsWith("enum", str); }
static inline bool potentialPrivate(char* str) { return apaz_str_startsWith("private", str); }
static inline bool potentialProtected(char* str) { return apaz_str_startsWith("protected", str); }
static inline bool potentialPublic(char* str) { return apaz_str_startsWith("public", str); }
static inline bool potentialSuper(char* str) { return apaz_str_startsWith("super", str); }
static inline bool potentialInstanceof(char* str) { return apaz_str_startsWith("instanceof", str); }
static inline bool potentialSizeof(char* str) { return apaz_str_startsWith("sizeof", str); }
static inline bool potentialAssert(char* str) { return apaz_str_startsWith("assert", str); }
static inline bool potentialLparen(char* str) { return apaz_str_startsWith("(", str); }
static inline bool potentialRparen(char* str) { return apaz_str_startsWith(")", str); }
static inline bool potentialLbrace(char* str) { return apaz_str_startsWith("{", str); }
static inline bool potentialRbrace(char* str) { return apaz_str_startsWith("}", str); }
static inline bool potentialLbrack(char* str) { return apaz_str_startsWith("[", str); }
static inline bool potentialRbrack(char* str) { return apaz_str_startsWith("]", str); }
static inline bool potentialLarrow(char* str) { return apaz_str_startsWith("<", str); }
static inline bool potentialRarrow(char* str) { return apaz_str_startsWith(">", str); }
static inline bool potentialSemi(char* str) { return apaz_str_startsWith(";", str); }
static inline bool potentialComma(char* str) { return apaz_str_startsWith(",", str); }
static inline bool potentialDot(char* str) { return apaz_str_startsWith(".", str); }
static inline bool potentialStar(char* str) { return apaz_str_startsWith("*", str); }
static inline bool potentialEquals(char* str) { return apaz_str_startsWith("=", str); }
static inline bool potentialBang(char* str) { return apaz_str_startsWith("!", str); }
static inline bool potentialTilde(char* str) { return apaz_str_startsWith("~", str); }
static inline bool potentialQuestion(char* str) { return apaz_str_startsWith("?", str); }
static inline bool potentialColon(char* str) { return apaz_str_startsWith(":", str); }
static inline bool potentialEqual(char* str) { return apaz_str_startsWith("==", str); }
static inline bool potentialLe(char* str) { return apaz_str_startsWith("<=", str); }
static inline bool potentialGe(char* str) { return apaz_str_startsWith(">=", str); }
static inline bool potentialNotequal(char* str) { return apaz_str_startsWith("!=", str); }
static inline bool potentialAnd(char* str) { return apaz_str_startsWith("&&", str); }
static inline bool potentialOr(char* str) { return apaz_str_startsWith("||", str); }
static inline bool potentialInc(char* str) { return apaz_str_startsWith("++", str); }
static inline bool potentialDec(char* str) { return apaz_str_startsWith("--", str); }
static inline bool potentialAdd(char* str) { return apaz_str_startsWith("+", str); }
static inline bool potentialSub(char* str) { return apaz_str_startsWith("-", str); }
static inline bool potentialDiv(char* str) { return apaz_str_startsWith("/", str); }
static inline bool potentialAmp(char* str) { return apaz_str_startsWith("&", str); }
static inline bool potentialBitor(char* str) { return apaz_str_startsWith("|", str); }
static inline bool potentialCaret(char* str) { return apaz_str_startsWith("^", str); }
static inline bool potentialMod(char* str) { return apaz_str_startsWith("%", str); }
static inline bool potentialArrow(char* str) { return apaz_str_startsWith("->", str); }
static inline bool potentialAdd_assign(char* str) { return apaz_str_startsWith("+=", str); }
static inline bool potentialSub_assign(char* str) { return apaz_str_startsWith("-=", str); }
static inline bool potentialMul_assign(char* str) { return apaz_str_startsWith("*=", str); }
static inline bool potentialDiv_assign(char* str) { return apaz_str_startsWith("/=", str); }
static inline bool potentialAnd_assign(char* str) { return apaz_str_startsWith("&=", str); }
static inline bool potentialOr_assign(char* str) { return apaz_str_startsWith("|=", str); }
static inline bool potentialXor_assign(char* str) { return apaz_str_startsWith("^=", str); }
static inline bool potentialMod_assign(char* str) { return apaz_str_startsWith("%=", str); }

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