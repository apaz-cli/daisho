
# Precedence

[C operator precedence](https://en.cppreference.com/w/c/language/operator_precedence)


## Lowest to Highest (Order of visitation, opposite of the order the resolve.)
* Definitions
  * Struct Declaration
  * Trait Declaration
  * Impl Declaration
  * Function Declaration
  * CType Declaration
  * CFunc Declaration
    * Arguments and return are daisho types, but should be verifiable at C level.
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
  * << >> // Tokenized as `<``<`
  * < > <= >=
  * * / %
  * + -
* (arg_list) -> expr // Lambda Expression is an atom, but must be parsed before a call.
* return expr
* Unary Suffix
  * expr(Type)
  * expr(args..)
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


# Unification and Symtab Generation

Type unification is bidirectional. Generally, type information flows from the bottom of the AST (the leaves) upwards. As it flows, (pre-monomorphization) types are chosen. When types hit constraints, they are checked against the constraint. Then either the type is coerced, or an error is thrown.

There is no iterative refinement of types, only:
  * Literals that don't yet have a pre-monomorphization type
  * Expressions not yet assigned a pre-monomorphization type
  * Types not yet specialized
  * Concrete types

# The Algorithm:
  * Tokenize
  * Parse

  * Create a tree of symbol tables out of each scope.
    * Each scope is implied to contain the symbols belonging to its parents, but not its parents' children.

  * Preorder traverse the abstract syntax tree.
    * Pull out all of the type definitions. Stick their names and the constraints on them into the scope they came out of.
    * Pull out all the function definitions. Stick their names and what they're implemented on into the scope they came out of.
    * List the type erased traits that each type says it implements.

  * Postorder traverse the abstract syntax tree.
    * 
  * 



After this, 


## Literals
  * Numbers (defaults to Int if unconstrained)
  * Strings (defaults to Char* (not String) if unconstrained)
    * Can become DString or CString (alias Char*)
    * Defaults to read only CString
  * Initializer lists (Coming, eventually)
    * Becomes the type of whatever it's meant to initialize.
    * Cannot initialize a trait object.
    * Can be inferred to unify against function return.
  * 

## Constraints
  * Boolable
    * The expressions that control loop iteration
  * Iterable
  * "for (expr, )? expr in expr where expr"
    * The first expr pair must be one or both vidents.
      * The second of these is declared as Size_t.
    * The last expr must be boolable expressions, the middle ...