
# Precedence

[C operator precedence](https://en.cppreference.com/w/c/language/operator_precedence)


## Lowest to Highest (Order of visitation, opposite of the order the resolve.)
* Scope Expression
  * {expr expr...}, implicit per file.
* Type Definitions
  * Struct Declaration
  * Trait Declaration
  * Impl Declaration
  * Function Declaration
* Control Flow
  * for (expr; expr; expr)
  * for (ident in iterable)
  * if (cond) expr (else expr)?
  * while(cond) expr
* then also ; (; is then but doesn't carry value)
* = += *= %= <<= // etc
* cond ? expr : expr // Ternary
*  ?: // Null coalesce
* Binary Operators
  * ||
  * &&
  * |
  * ^
  * &
  * == !=
  * << >>
  * < > <= >=
  * * / %
  * + -
* (arg_list) -> expr // Lambda Expression is an atom, but must be parsed before a call.
* Unary Suffix
  * expr(Type)
  * expr(args..)
  * expr[expr]
  * expr.return // .ret also works
  * expr.bret
  * expr.member
  * @ $
  * # // .tostring().println()
  * ~ !
  * ++
  * --
  * +
  * -
  * ~
* Atoms
  * (expr) // Paren expr
  * [expr for ident in iterable] // list comprehension
  * [expr, expr, expr...] // list literal
  * {expr; expr; expr...}
  * self
  * literal
    * strlit
    * num
    * {initializer_list}
    * varname
