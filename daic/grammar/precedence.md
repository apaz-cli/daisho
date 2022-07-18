
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
  * for (idx, ident in iterable) expr
  * if (cond) expr (else expr)? // Also acts as ternary
  * while(cond) expr
* ;
* then also
* = += *= %= <<= // etc
* cond ? expr : expr // Ternary
* Binary Operators
  * ?: // Null coalesce
  * ||
  * &&
  * |
  * ^
  * &
  * == !=
  * << >> // Tokenized '<' '<'
  * < > <= >=
  * * / %
  * + -
* (arg_list) -> expr // Lambda Expression is an atom, but must be parsed before a call.
* Unary Suffix
  * expr(Type)
  * expr(args..)
  * expr[expr]
  * expr.member
  * ++
  * --
  * +
  * -
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
  * literal
    * strlit
    * num
    * {initializer_list}
    * varname
