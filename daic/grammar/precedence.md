# Precedence

## Lowest to Highest (Order of visitation, opposite of the order the resolve.)

* then
* = += *= %= <<= // etc
* Ternary
 * ? : and ?:
* (arg_list) -> eqexpr
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
  * . [] () // Access, Call
* (expr) // Paren expr
* [expr for ident in iterable] // list comprehension
* [item, item] // list literal
* literal
  * strlit
  * num
  * {initializer_list}
  * varname
