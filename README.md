# Stilts

## A high level programming language which compiles to C.

The goal is to create a language that's nice to work with, looks and feels like Java, but maps to low level C code and has manual memory management.



### Example:

The following:
```
int main(String[] args) {
    println("Hello World!");
    return 0;
}
```
Generates:
```c
#include <stilts_headers.h>
// ...
char static_str_0[] = "Hello World!";
// ...
int main() {
    // (From <stilts_headers>, which dispatches using _Generic())
    PRINTLN("%s\n", static_str_0);
    return 0;
}
```

Which gets macro-expanded and optimized by any modern C compiler to essentially:
```c
#include <stdio.h>
int main() {
    printf("%s\n", "Hello World!");
    return 0;
}
```


## But why? What's wrong with Java/C++?
* C++
    * C++ is great, but its syntax is awful, very unintuitive, and leads to gnarly bugs. Sure, `std::cout << var << std::endl;` looks bad. People have been complaining about this since the 90s. But that's not the only thing wrong with it. If you want your type to be printable via `std::ostream`, you must implement the following: 
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
    
    * The C++ standard is a shantytown of deprecated solutions to non-issues. See iterators.
    * Undefined behavior lurks around every corner. See the unintuitive undefined behavior around, once again, [Iterators](https://en.wikipedia.org/wiki/Criticism_of_C++#Iterators).
    * Despite how far it's come, I very much dislike writing modern C++. I think it smells.
* Java
    * The JVM's garbage collection doesn't take the strain off the programmer. Instead of thinking about lifetimes, now it's about pruning object graphs.
    * Type Erasure makes Java's generics unusable for many tasks. The runtime type of any generic variable is `java.lang.Object`, which has a large overhead both on memory and cpu cycles due to method ID lookups. There are no generics for integral types.
    * Java programs are about 3x slower than equivalent C/C++ programs (Citation needed), for basically no reason other than portability.
    * Java cannot be properly optimized, because new classes can be loaded at runtime. You cannot optimize a program if nobody will tell you what the program is.
    * Runtime reflection conflates the class injection issue. Even if a function is private, unused, and should not be accessable, unused code cannot be deleted because a class could be injected at runtime that refers to the unused code reflectively.

The combination of these reasons led me to want to create my own programming language. There are also some other features I felt were left out of modern languages.

1. Data mashing
2. 