lexer grammar StiltsLexer;

/************/
/* KEYWORDS */
/************/

// Pragma
IMPORT: 'import' | 'include';
NATIVE: 'native';
CTYPE: 'ctype';

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
SUPER: 'super';
INSTANCEOF: 'instanceof';
SIZEOF: 'sizeof';
ASSERT: 'assert';

/************/
/* LITERALS */
/************/

// Number fragments
fragment DecimalNumeral:
	Sign? UnderscoreDigits DecimalTypeSuffix?;
fragment Sign: [+-];
fragment DecimalTypeSuffix: [Ll];
fragment UnderscoreDigits: Digits '_' UnderscoreDigits | Digits;
fragment Digits: Digit+;
fragment Digit: [0-9];
fragment Nondigit: [a-zA-Zα-ωΑ-Ω_];

// Hex fragments
fragment HexNumeral: '0x' UnderscoreHexDigits;
fragment UnderscoreHexDigits:
	HexDigits '_' UnderscoreHexDigits
	| HexDigits;
fragment HexDigits: HexDigit+;
fragment HexDigit: [0-9A-F];

// String fragments
// TODO: refine ~["\\\r\n]
fragment SCharFrag: '"' SChar+ '"';
fragment SCharSeq: SChar+;
fragment SChar: ~["\\\r\n] | EscapeSequence | '\\\n' | '\\\r\n';
fragment EscapeSequence: '\\' ['"?abfnrtv\\] | '\\x' HexDigit+;

// Literal definitions
IntegerLiteral: DecimalNumeral | HexNumeral;
FloatLiteral:
	IntegerLiteral
	| Sign? DecimalNumeral '.' DecimalNumeral?;
BooleanLiteral: 'true' | 'false';
NullLiteral: 'NULL';
StringLiteral: SCharFrag+;

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
STAR: '*';

/*************/
/* Operators */
/*************/

// Ignored Sections (Whitespace and Comments)
WS: [ \t\r\n\u000C]+ -> skip;
COMMENT: '/*' .*? '*/' -> skip;
LINE_COMMENT: '//' ~[\n]* -> skip;
