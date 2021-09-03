lexer grammar StiltsLexer;

/************/
/* KEYWORDS */
/************/

// Pragma
IMPORT: 'import';
INCLUDE: 'include';
NATIVE: 'native';

// Types
BOOL: 'Bool';
CHAR: 'Char';
UCHAR: 'UChar';
SHORT: 'Short';
USHORT: 'UShort';
INT: 'Int';
UINT: 'UInt';
LONG: 'Long';
ULONG: 'ULong';
FLOAT: 'Float';
DOUBLE: 'Double';
VOID: 'Void';

// Control
IF: 'if';
ELIF: 'elif';
ELSE: 'else';

// Loops
FOR: 'for';
WHILE: 'while';
CONTINUE: 'continue';
BREAK: 'break';

// Exceptions
TRY: 'try';
CATCH: 'catch';
FINALLY: 'finally';

// Classes
CLASS: 'class';
THIS: 'this';
OPERATOR: 'operator';
EXTENDS: 'extends';
SUPER: 'super';

// Interfaces
INTERFACE: 'interface';
IMPLEMENTS: 'implements';
ABSTRACT: 'abstract';
DEFAULT: 'default';

// Access Modifiers
PRIVATE: 'private';
PROTECTED: 'protected';
PUBLIC: 'public';

// Builtin functions
INSTANCEOF: 'instanceof';
SIZEOF: 'sizeof';
ASSERT: 'assert';

/************/
/* LITERALS */
/************/

IntegerLiteral: DecimalNumeral | HexNumeral;

fragment DecimalNumeral:
	Sign? UnderscoreDigits DecimalTypeSuffix?;
fragment Sign: [+-];
fragment DecimalTypeSuffix: [Ll];
fragment UnderscoreDigits: Digits '_' UnderscoreDigits | Digits;
fragment Digits: Digit+;
fragment Digit: [0-9];

fragment HexNumeral: '0x' UnderscoreHexDigits;
fragment UnderscoreHexDigits: HexDigits '_' UnderscoreHexDigits | HexDigits;
fragment HexDigits: HexDigit+;
fragment HexDigit: [0-9A-F];

FloatLiteral: IntegerLiteral | Sign? Digits '.' Digits?;

BooleanLiteral: 'true' | 'false';

NullLiteral: 'NULL';

/**************/
/* Separators */
/**************/

LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';
LBRACK: '[';
RBRACK: ']';
SEMI: ';';
COMMA: ',';
DOT: '.';

/*************/
/* Operators */
/*************/

// Ignored Sections (Whitespace and Comments)
WS: [ \t\r\n\u000C]+ -> skip;
COMMENT: '/*' .*? '*/' -> skip;
LINE_COMMENT: '//' ~[\n]* -> skip;
