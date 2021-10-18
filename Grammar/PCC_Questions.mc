
# Questions

These are things that I've been wondering, and should probably be covered in the README.

1. What is the storage duration of `$$`? There's actually a StackOverflow question about this.
   https://stackoverflow.com/questions/66145396/how-to-use-the-value-returned-by-a-packcc-parser

2. How can I read from a file instead of stdin?

3. Suppose I want to generate an AST. Am I supposed to generate it with $$ C inside the rules manually?
   Is there some way to make this easier? Or is generating an AST beyond the scope of this parser generator?

4. Can I define an action and an error action on the same rule? How?

5. What's the deal with whitespace? It seems to be ignored. What if my language were whitespace-sensitive?
   Does it suck the whitespace out of string literals?

6. My language has C style single and multi-line comments in it. How can I ignore those like whitespace?

