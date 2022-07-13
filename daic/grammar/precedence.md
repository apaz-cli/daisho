# Precedence

## Lowest to Highest (Order of visitation, opposite of the order the resolve.)
* Scope Expression
  * {}, implicit per file.
* Type Definitions
  * Struct Declaration
  * Trait Declaration
  * Impl Declaration
  * Function Declaration
* Control Flow
  * for (expr; expr; expr)
  * for (ident in iterable)
  * if (cond) expr
  * while(cond) expr
* then also
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
* Unary Suffix
  * (Cast)
  * (Call)
  * [Access]
  * @ $
  * #
  * ~ !
  * ++
  * --
  * +
  * -
  * ~
  * . // Selector
* (arg_list) -> expr // Lambda Expression
* (expr) // Paren expr
* [expr for ident in iterable] // list comprehension
* [item, item] // list literal
* literal
  * self
  * strlit
  * num
  * {initializer_list}
  * varname
