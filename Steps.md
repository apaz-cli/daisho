
# Tokenize
# Parse
# Checker/Optimizer
* Traverse the AST. Pull out all the function and type signatures (Including generics with their context, and overloads).
* Build a hierarchy of types.
    * No multiple (or circular) inheritance.
    * No circular template implements.
* Infer Generics, keeping a note. Native methods cannot accept or return generics, but can be in a generic class.
* Traverse the AST, starting from the bottom.
    * Validate types and combine values known at compile time.
    * Apply widening conversions automatically. Disallow narrowing conversions without a cast.
    * Infer the return values of functions by their signature (mindful that overloads exist).
* Validate Interfaces are implemented and types match

# Code Generator
Information that must be known:
Function Signatures
Which generic overloads are used