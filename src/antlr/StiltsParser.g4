parser grammar StiltsParser;

options {
	tokenVocab = StiltsLexer;
}

compilationUnit: topLevelDeclaration+;

topLevelDeclaration:
	globalVariableDeclaration
	| functionDeclaration
	| classDeclaration
	| interfaceDeclaration
	| enumDeclaration
	| ctypeDeclaration;

functionDeclaration: typeIdent;
classDeclaration: CLASS;
interfaceDeclaration: INTERFACE IDENT;

// Enum
enumDeclaration: ENUM LBRACE enumMember* RBRACE;
enumMember: varIdent EQUALS enumValue SEMI;
enumValue: NullLiteral | IntegerLiteral | BooleanLiteral;

// ctype
ctypeDeclaration: CTYPE IDENT SEMI;

globalVariableDeclaration: // Disallow tuple unpacking
	typeIdent varIdent SEMI
	| typeIdent varIdent EQUALS expr SEMI;

genericTypes: LARROW RARROW;

/***************/
/* Identifiers */
/***************/
// Normal letters, underscores, etc.
varIdent: IDENT;

// With generic types and pointers
typeIdent: IDENT genericTypes? | typeIdent STAR;

/***************/
/* Expressions */
/***************/
expr:;

/**************/
/* Statements */
/**************/
statement:;