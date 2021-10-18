# Questions:

1. Arrays require an overload of the `[]` operator. How does
   that play with pointers to a type that also overloads `[]`?

2. Ambiguity between default void method and abstract void
   method in trait.

3. The meanings of `=`, `&`, `*`. Are they operators, or
   built in? How unfortunate the C pointer creation and
   multiplication are the same symbol.
	* Use `$var` to get the value of a variable instead of `*var`.
	* Neither `&` or `$` should be overloadable. This frees up `*`.
	* Unsure about `=`.

4. How can I strap a preprocessor macro system to the parser?
	* Should I?
	* Idea: Embed a language within the language. This language
	  directly acts upon the AST.
