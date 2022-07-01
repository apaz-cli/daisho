# Precedence

## Lowest to Highest (Order of visitation, opposite of the order the resolve.)

* ,
* =
* Ternary
 * ? : and ?:
* lambda
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
* Unary Prefix
  * (Cast)
  * $ # ~ !
  * ++
  * --
  * ~
  * !
* Unary Suffix
  * $ # ~ !
  * . [] ->
  * ++ --
* ()
* literal
  * strlit
  * num
  * {initializer_list}
  * varname
