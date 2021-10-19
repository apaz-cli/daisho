# Questions:

1. Arrays require an overload of the `[]` operator. How does
   that play with pointers to a type that also overloads `[]`?
   * You can convert from arr to ptr via a method.

2. Ambiguity of `func();` in trait. Is it a default method that
   does nothing, or an abstract method returning `Void` which
   needs to be defined?

3. The meanings of `=`, `&`, `*`. Are they operators, or
   built in? How unfortunate the C pointer creation and
   multiplication are the same symbol.
	* Use `$var` to get the value of a variable instead of `*var`.
	* Let `&` and `$` be built in. This frees up `*` to overload multiplication.
    	* They're
	* Unsure about `=`.

4. How can I strap a preprocessor macro system to the parser?
	* Should I?
	* Idea: Embed a language within the language. This language
	  directly acts upon the AST.

!!! danger MAJOR PEPEGA INCOMING

5. Investigate the following type checking papers:
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
