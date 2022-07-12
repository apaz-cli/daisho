# Precedence

## Lowest to Highest (Order of visitation, opposite of the order the resolve.)

* Struct Declaration
* Impl declaration
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
  * $ # ~ !
  * ++
  * --
  * +
  * -
  * ~
  * . // Selector
  * [] // Access
  * () // Call
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
