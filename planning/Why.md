# Stilts

## A high level programming language which compiles to C.

The goal is to create a language that's nice to work with, looks and feels like Java, but maps to low level C code and has manual memory management.


## Features

* Classes, Generics, Inheritance, Interfaces, Polymorphism, Interface-typed Lambda Expressions, and all the nice things about Java.

* List comprehensions, tuple unpacking, and all the nice things about Python.

* Fast binaries, operator overloading, library support, and all the nice things about C/C++.

* Implicit typing

* First class support for Streams, with little to no overhead.

* Manual memory management with operator `new` and `del` syntax.
    * Call `malloc()`, `realloc()`, and `free()` explicitly
    * Use the built-in memory debugger to trace exactly what's going wrong, and where.

* Excellent interoperability with C/C++, because your code predictably compiles to C.

## Example

Let's kick things off with a classic, and demonstrate some things about the language. The following are equivalent.

```java
import String;

Int main(String[] args) {
    ["Hello ", "World!"].map(toUppercase).forEach(println);
}
```

```java
import String;

Int main(String[] args) {
    List<? extends String> ls = ["Hello ", "World!"];
    List<Printable> lp = (List<Printable>) ls.map(toUppercase);
    l.forEach(println);
}
```

First, the language creates a specification of the generic type List<T> with the narrowest possible type. In this case, List<String>. The language knows that println() is a function which accepts a Printable and returns Void. 
This means it satisfies the interface `Consumer<? extends Printable>`, because String implements Printable. This is what `forEach()` is looking for as an argument. The implementation of println() then knows how to print

## But why? What's wrong with Java/C++?
* C++
    * The code that C++ compilers generate is great, but the syntax is awful, very unintuitive, and leads to gnarly bugs. Sure, `std::cout << var << std::endl;` looks bad. People have been complaining about this since the 90s. But that's not the only thing wrong with this particular example. If you want your type to be printable via `std::ostream`, you must implement the following: 
    ```c++
    // Am I the only one who sees anything wrong with this?
    class myclass {
        private:
        int i;
        // ...
        public:
        // ...
        friend ostream& operator<<(std::ostream& os, const myclass& dt);
    }
    std::ostream& operator<<(std::ostream &os, myclass const &m) {
        return os << m.i;
    }
    ```
    Stilts only requires the following:
    ```rust
    class MyClass impl Stringable {
        Int i;
        String toString() return String.of(this.i);
    }
    ```
    
    * The C++ standard is a shantytown of deprecated solutions to non-issues. See iterators.
    * Undefined behavior lurks around every corner. See the unintuitive undefined behavior around, once again, [Iterators](https://en.wikipedia.org/wiki/Criticism_of_C++#Iterators).
    * Despite how far it's come, I very much dislike writing modern C++. I am stubborn, I think it smells, and I will never forgive it.
* Java
    * For nontrivial applications, the JVM's garbage collection doesn't take the strain off the programmer. Instead of thinking about lifetimes, now it's about pruning object graphs.
    * Type Erasure makes Java's generics unusable for many tasks. The runtime type of any generic variable is `java.lang.Object`, which has a large overhead both on memory and cpu cycles due to method ID lookups. There are no generics for integral types.
    * Java programs are about 3x slower than equivalent C/C++ programs (Citation needed), for basically no reason.
    * Java cannot be properly optimized, because new classes can be loaded at runtime. You cannot optimize a program if nobody will tell you what the program is.
    * Runtime reflection conflates the class injection issue. Even if a function is private, unused, and should not be accessable, unused code cannot be deleted because a class could be injected at runtime that refers to the unused code reflectively and calls it. This also sort of defeats the purpose of having `private` in the first place.

The combination of these reasons led me to want to create my own programming language. There are also some much smaller API gripes that I had.
