**************
* References *
**************
# Grammar for C
https://gist.github.com/arslancharyev31/c48d18d8f917ffe217a0e23eb3535957
# Grammar for Java
http://cui.unige.ch/isi/bnf/JAVA/BNFindex.html


************
* FEATURES *
************

* Standard fixed sized types (Not machine dependent, Int directly translates to uint32_t, etc).

* Manual memory management with new, .destroy() syntax

* Collections

* Minimal overhead exceptions with enforced management


Other Reserved Words:
  Access Modifiers: namespace, public, private, protected (default private)
  Control Flow: if, elif, else, for, while, break, continue, return
  Exceptions: try, catch, finally, throw, throws
  Abstraction: struct, class, interface, enum, inherits, implements

  Allocation: new
  Threading: concurrent, synchronized

  Array[]
  List ([])
  Lambda expression


Basic:
  * class namespaces
      Like constexpr, but traces variable lifetimes rather than
  * import statements. 
      Everything compiles to a single file, like C.
  * lambda expressions


Tokenizer -- 
    

Preprocessor -- 
    import
    compile statements


Parser -- 
    Type identifiers (other than builtin reserved words) begin with a 
    capital letter.
    Function identifiers always have a () at the end.

AST Optimizer --
    Trace compile statements starting from leaves, and simplify.

Compiler --


# Introduction<a name="introduction"></a>

Stilts should be the following:
* Provides high level abstractions
* Compiles to C

Stilts should not be the following:
* Difficult to implement


# Table of Contents<a name="contents"></a>

* [Introduction](#introduction)
* [Table of Contents](#contents)
* [Chapter 1: The Pre-Processor](#ch1)
* [Chapter 2: The Tokenizer](#ch2)
* [Chapter 3: The Parser](#ch3)
* [Chapter 4: The Optimizer](#ch4)
* [Chapter 5: The Code Generator](#ch5)
* [Chapter 6: The Language Server](#ch6)
* [Chapter 7: Syntax and Language Features](#ch7)


# Chapter 1: <a name="ch1"></a>
## The Pre-Processor.

The initial processor is in charge of:
* Getting rid of comments

It does this with a finite state machine, described by the transition table below. The program is fed into the state machine, which looks ahead one character and marks each character with whether it is to be erased. 

```yaml
Transition Table:
X-------X------------------------------------------------X
|       |                     TOKEN                      |
X-------X------X------X------X------X------X------X------X
| STATE |  O   |  /*  |  */  |  //  |  \n  |  "   |  \"  |
X-------X------X------X------X------X------X------X------X
| neut  | neut | mlc  | ERR  | slc  | neut | str  | ERR  |
X-------X------X------X------X------X------X------X------X
| str   | str  | str  | str  | str  | ERR  | neut | str  |
X-------X------X------X------X------X------X------X------X
| slc   | slc  | smlc | slc  | slc  | neut | slc  | slc  |
X-------X------X------X------X------X------X------X------X
| mlc   | mlc  | mlc  | neut | smlc | mlc  | mlc  | mlc  |
X-------X------X------X------X------X------X------X------X
| smlc  | smlc | smlc | slc  | smlc | mlc  | smlc | smlc |
X-------X------X------X------X------X------X------X------X
```

There are a few things to note about the table above.

1. If an ERR transition is taken, the program fails to compile immediately, and the user is notified.
2. If the string literal delimiter `"` is excaped by a backslash `\"`, and then both characters count together as `O`, for "other".
3. To accomodate for escaping quotes, the transition table actually reads two characters at a time, advancing two characters if neither of the characters could potentially cause a change in state, or one if they could `('\n', '/', `\\`. '*', '"')`.

```java

String in = ...;
String out = "";
boolean escaped;
boolean comm = false;

for(int i = 0; i < program.length-1;) {
  // consume 1 char and look ahead 1 char.
  char f = in.charAt(i);
  char s = in.charAt(i+1);

  if (f == '\\' && s == '\"') {

  } else if (f == '\"') {
  
  } else if (f == '/' && s == '*') {

  } else if (f == '*' && s == '/') {

  } else if (f == '/' && s == '/') {

  } else if (f == '\n')  

  } else {

  }
}
```


# Chapter 2: <a name="ch2"></a>
## The Tokenizer.

# Chapter 3: <a name="ch3"></a>
## The Parser.

# Chapter 4: <a name="ch4"></a>
## The Optimizer.

# Chapter 5: <a name="ch5"></a>
## The Code Generator.

# Chapter 6: <a name="ch6"></a>
## The Language Server.

https://medium.com/ballerina-techblog/implementing-a-language-server-how-hard-can-it-be-part-1-introduction-c915d2437076

# Chapter 7: <a name="ch7"></a>
## Syntax and Language Features.

For complete syntax, see `Grammar.bnf`.
