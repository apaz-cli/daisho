# Stilts

## A high level programming language which compiles to C.

The goal is to create a language that's nice to work with, looks and feels like Java, but maps to low level C code and has manual memory management.


## Features

* Classes, Generics, Inheritance, Interfaces, Polymorphism, and all the nice things about Java

* Monads with little to no overhead

* Manual memory management with operator `new` and `del` syntax

* Compiles to C for any system

* Excellent interoperability with C/C++
    * The keywords `native` and `ctype` allow the user to generate C `.h` header files, implement them, and use their C code within Stilts to have it be statically compiled into the binary.


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
        friend ostream& operator<<(ostream& os, const myclass& dt);
    }
    std::ostream &operator<<(std::ostream &os, myclass const &m) {
        return os << m.i;
    }
    ```
    Stilts only requires the following:
    ```java
    class MyClass implements Printable {
        private Int i;
        String toString() {
            return "" + i;
        }
    }
    ```
    
    * The C++ standard is a shantytown of deprecated solutions to non-issues. See iterators.
    * Undefined behavior lurks around every corner. See the unintuitive undefined behavior around, once again, [Iterators](https://en.wikipedia.org/wiki/Criticism_of_C++#Iterators).
    * Despite how far it's come, I very much dislike writing modern C++. I am stubborn and I think it smells.
* Java
    * The JVM's garbage collection doesn't take the strain off the programmer. Instead of thinking about lifetimes, now it's about pruning object graphs.
    * Type Erasure makes Java's generics unusable for many tasks. The runtime type of any generic variable is `java.lang.Object`, which has a large overhead both on memory and cpu cycles due to method ID lookups. There are no generics for integral types.
    * Java programs are about 3x slower than equivalent C/C++ programs (Citation needed), for basically no reason other than portability.
    * Java cannot be properly optimized, because new classes can be loaded at runtime. You cannot optimize a program if nobody will tell you what the program is.
    * Runtime reflection conflates the class injection issue. Even if a function is private, unused, and should not be accessable, unused code cannot be deleted because a class could be injected at runtime that refers to the unused code reflectively.

The combination of these reasons led me to want to create my own programming language. There are also some other features I felt were left out of modern languages.
