# Questions:

* Arrays require an overload of the `[]` operator. How does
   that play with pointers to a type that also overloads `[]`?
   * You can convert from arr to ptr via a method.

* Ambiguity of `func();` in trait. Is it a default method that
   does nothing, or an abstract method returning `Void` which
   needs to be defined?
   * `func();` will be an abstract method returning `Void` which needs to be defined.
   * `func();;` will be a default method that does nothing.

* Syntax ambiguity in general. Which parts can be left off, and when?

* The meanings of `=`, `&`, `*`. Are they operators, or
   built in? How unfortunate the C pointer creation and
   multiplication are the same symbol.
	* Use `$var` to get the value of a variable instead of `*var`.
	* Let `&` and `$` be built in. This frees up `*` to overload multiplication.
	* By "built in," I mean to the syntax and type system. `$` removes a `*` from the type, and `&` adds one.
	* Unsure about `=`.

* What will the mangle operator be?
   * I like `#`.

* How does compile time evaluation work?
    * Integrate the notion of native-qualification or no?

* How can I strap a preprocessor macro system to the parser?
	* Should I?
	* Idea: Embed a language within the language. Use constructs like `<%``%>` that are not  valid elsewhere.
   * Counter idea: Don't embed language in language. Instead, compile time evaluation.

* No type implies `auto`. How do I differentiate instantiation and assignment?
   * Use `:=`?

* What should be done about nullability and option types?
   * Enum-switch is sort of the same thing.
   * This is pretty much the same thing as a union? Maybe?
   * Support for `+` and `|` types?

* How do String literals work?
  * Are they editable?
    * Get around this with format Strings?
  * How does this relate to how lists work?
  * Temporary strings?

* How do List literals?
  * How about storing string literal rvalues?
  * How does this relate to generics inferred?


* What form will C interop take?

* What form will Python interop take?


!!! danger MAJOR PEPEGA INCOMING

1. Investigate the following type checking papers:
    * ![](https://cdn.discordapp.com/attachments/542264318465671170/899288340241739827/unknown.png)
    * https://www.cl.cam.ac.uk/~nk480/bidir.pdf
    * https://cstheory.stackexchange.com/questions/42554/extending-hindley-milner-to-type-mutable-references
    * https://www.cl.cam.ac.uk/teaching/1415/L28/type-inference.pdf
    * https://github.com/wdamron/poly
    * https://github.com/rust-lang/rust/blob/d2454643e137bde519786ee9e650c455d7ad6f34/compiler/rustc_typeck/src/check/mod.rs
    * https://www.cis.upenn.edu/~bcpierce/papers/lti-toplas.pdf
    * https://dl.acm.org/doi/pdf/10.1145/3290322

#parser
#type_checking
