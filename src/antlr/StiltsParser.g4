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
	| typeIdent varIdent EQUALS expr SEMI; // must be a compile expr

genericTypeDecl: LARROW genTypeDecList RARROW;
genTypeDecList: genDeclType genTypeDecList |;
genDeclType:
	varIdent // For type generics (<T>)s
	| typeIdent; // For value-type generics

/***************/
/* Identifiers */
/***************/
// Normal letters, underscores, etc.
varIdent: IDENT;
fnIdent: IDENT;
enumIdent: IDENT;

// With generic types and pointers
typeIdent: IDENT genericTypeDecl? | typeIdent STAR;

/***************/
/* Expressions */
/***************/
expr:
	IDENT
	| literal
	| lambdaExpr
	| functionCall
	| LPAREN expr RPAREN;

lambdaExpr: LPAREN lambdaArgList RPAREN ARROW statement;
lambdaArgList: varIdent lambdaArgList |;
// or empty

/**************/
/* Statements */
/**************/
statement:
	SEMI
	| blockStatement
	| ifStatement
	| forStatement
	| whileStatement
	| varDeclStatement;

varDeclStatement:
	typeIdent? varIdent EQUALS expr SEMI
	| typeIdent varIdent SEMI;

// If / Else If / Else
ifStatement:
	IF LPAREN expr RPAREN statement elseStatement?
	| IF expr statement elseStatement?;
elseStatement: ELSE statement;

forStatement:
	FOR LPAREN forCondition RPAREN statement
	| FOR forCondition statement;
whileStatement: // typecheck expr as bool or int type
	WHILE LPAREN expr RPAREN statement
	| WHILE expr statement;
blockStatement: LBRACE statement* RBRACE;
exprStatement: expr SEMI;

forCondition: forDeclarations SEMI forExpr? SEMI forExpr? |;
forDeclarations:;
forExpr:;

/*************/
/* Functions */
/*************/

// declaration
functionDeclaration:
	typeIdent? fnIdent LPAREN fnDeclarationArgList RPAREN statement;
fnDeclarationArgList: fnDeclarationArg fnDeclarationArgList |;
fnDeclarationArg: typeIdent varIdent defaultArg?;
defaultArg: EQUALS literal;

// call
functionCall: fnIdent LPAREN callArgList RPAREN;
callArgList: expr COMMA callArgList | expr |;

/**************/
/* Misc Rules */
/**************/
literal:
	NullLiteral
	| IntegerLiteral
	| FloatLiteral
	| StringLiteral
	| BooleanLiteral;