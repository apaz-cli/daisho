# Tokenization

A tokenizer is created for and consumes each source file, each returning a list of tokens. For definitions of tokens, see `daisho.tok`.

# Parsing

For the implementation grammar, see `daisho.peg`.

## Precedence (Lowest to Highest)
* Definitions
  * Struct Declaration
  * Trait Declaration
  * Impl Declaration
  * Function Declaration
  * CType Declaration
    * Binds a C type to a Daisho type. Only supports normal type names and pointers, not full C typing, for example function pointers.
  * CFunc Declaration
    * Arguments and return are daisho types, but should be verifiable against their C types manually. This might be a further extension. Perhaps clangd can help?
* Control Flow
  * for (expr; expr; expr) expr
  * for ((ident,)? ident in iterable (where expr)?) expr
  * while (cond) expr
  * return expr
* ;
* then
* also
* = += *= %= <<= // etc
* cond `?` expr (: expr)? // Ternary
* Binary Operators
  * ?: // Null coalesce (boolable)
  * ||
  * &&
  * |
  * ^
  * &
  * == !=
  * << >> // Tokenized as `<``<`/`>``>`
  * < > <= >=
  * * / %
  * + -
* Unary Suffix
  * expr(Type)
  * expr(args...)
  * expr[expr]
  * expr.member
  * ++ --
  * + -
  * @ $
  * ~ !
  * #
  * ~
  * ` // return
  * '
  * " // .tostring().print()
* Atoms
  * (arg_list) -> expr // parens can be omitted for 1 arg
  * (expr) // Paren expr
  * [expr for ident in iterable] // list comprehension
  * [expr, expr, expr...] // list literal
  * {expr; expr; expr...} // Scope
  * self
  * Type expr // Bind vident type (Like a variable declaration)
  * literal
    * strlit
    * num
    * varname
    * initializer list


# Monomorphization, Unification, and Symtab Generation

Type unification is bidirectional, and happens post-template replacement (monomorphization, henceforth). Generally, type information travels from the bottom of the AST (the leaves) upwards. As it travels, (post-mono) types are chosen. When types hit constraints, they are checked against the constraint. Then either the type is coerced, or an error is thrown.

There is no iterative refinement of types, only:
  * Literals that don't yet have a post-mono type
  * Expressions not yet assigned a post-mono type
  * Types not yet specialized
  * Concrete types

# The Algorithm:
  * Tokenize, Parse
    * These steps are handled by pgen. The output is an abstract syntax tree with tokens in it.

  * Resolve Self

  * Monomorphize
    * Traverse the tree, and make another tree of all the template definitions and replacement sites.

  * Create a tree of symbol tables out of each scope.
    * Each scope is implied to contain the symbols belonging to its parents, but not its parents' children.

  * Preorder traverse the abstract syntax tree.
    * Pull out all of the type definitions. Stick their names and the constraints on them into a table in the the scope they came out of.
    * Pull out all of the trait definitions. Stick their names and their signatures into a table in the scope they came out of.
    * Pull out all the function definitions. Stick their names and what they're implemented on into a table in the scope they came out of.
    * List the type erased traits that each type says it implements.

  * Postorder traverse the abstract syntax tree.
    * 
  * 



After this, 


## Literals
  * Numbers (defaults to Int if stored unconstrained)
  * Strings (defaults to Char* (not String) if unconstrained)
    * Can become DString or CString (alias Char*)
    * Defaults to read only CString
  * Initializer lists (Coming, eventually)
    * Becomes the type of whatever it's meant to initialize.
    * Cannot initialize a trait object.
    * Can be inferred to unify against function return.
  * Lambda
    * Can only unify to a trait object, where that trait is missing only the definition of its call operator.

## Constraints
  * Boolable
    * The expressions that control loop iteration
  * Iterable
  * "for (expr, )? expr in expr where expr"
    * The first expr pair must be one or both vidents.
      * The second of these is declared as Size_t.
    * The last expr must be boolable expressions, the middle ...