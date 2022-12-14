## Questions:

3. How to keep track of compilation units
4. How to keep track of build instructions
   * Users can #include and call any libraries they want.
      * They might need linker flags.
      * They might need pull in extra headers.


## Rules:
1. Native methods cannot be defined on a trait.
   * However you can declare a native function and call it inside a Daisho method to get around this.
    ```rust
    // Ex:
    native Void nativeFn() { printf("Native Code.\n"); fflush(stdout); };
    trait Tr { Void nativeMethod() { nativeFn(); } };
    ```

2. The body of a `native` function or method is copy/pasted directly into the generated C code.

3. Don't use Daisho functions/methods inside of native methods.
   * A `native` function/method is a Daisho function/method.
   * Please only call C methods inside your `native` functions/methods.
   * This also means no recursion.
   * Basically, calling Daisho from C is unsupported. Although technically possible and prone to breakage.

4. The arguments of a native function must all be native-qualified types.
   * Passing a `class` means you can't use its methods, since those are mangled.
   * You can however access its members as if it were a C struct. Because it is.
   * A native-qualified type is one that:
       * Is a `ctype`
       or
       * Is a class with only native-qualified types as members
       and
       * Doesn't have generic parameters (Ex: `Box<T>`).
   * Note that generic members are not allowed inside native-qualified types (Ex: `T item;`and `List<T> items;`).
   * You may not omit the types of arguments to `native` functions/methods.

5. When you define a native method on a ctype or function, it includes `this` as an implicit first argument.

6. The return value of a native function must follow the same rules as the arguments.
   * You may return `this`.
