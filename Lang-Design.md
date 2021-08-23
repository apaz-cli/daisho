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

Data types:
  bool  (as defined in stdbool.h)
  char  (int8_t)  uchar (uint8_t)
  short (int16_t) ushort (uint16_t)
  int   (int32_t) uint (uint32_t)
  long  (int64_t) ulong (uint64_t)
  float
  double
  void


Other Reserved Words:
  Access Modifiers: namespace, public, private, protected (default private)
  Control Flow: if, elif, else, for, while, break, continue, return
  Case/Switch: case, switch, default
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
* Reasonably fast like C

Stilts should not be the following:
* Difficult to implement


# Table of Contents<a name="contents"></a>

* [Introduction](#introduction)
* [Table of Contents](#contents)
* [Chapter 1: The initial Processor](#ch1)



# Chapter 1: <a name="ch1"></a>
## The Pre-Processor.

The initial processor is in charge of:
* Getting rid of comments

It does this with a finite state machine, described by the transition table below. The program is fed into the state machine, which looks ahead one character and marks each character with whether it is to be erased. 

```yaml
Transition Table:
X-------X-----------------------------------------X
|       |                  TOKEN                  |
X-------X------X------X------X------X------X------X
| STATE |  O   |  \n  |  /*  |  */  |  //  |  "   |
X-------X------X------X------X------X------X------X
| neut  | neut | neut | mlc  | ERR  | slc  | str  |
X-------X------X------X------X------X------X------X
| str   | str  | ERR  | str  | str  | str  | neut |
X-------X------X------X------X------X------X------X
| slc   | slc  | neut | smlc | slc  | slc  | slc  |
X-------X------X------X------X------X------X------X
| mlc   | mlc  | mlc  | mlc  | neut | smlc | mlc  |
X-------X------X------X------X------X------X------X
| smlc  | smlc | mlc  | smlc | slc  | smlc | smlc |
X-------X------X------X------X------X------X------X
```

There are a few things to note about the table above.

1. If an ERR transition is taken, the program fails to compile immediately, and the user is notified.
2. The string literal delimiter `"` is excaped by a backslash `\"`, and then counts as `O`, for "other".
3. 



# Chapter 2: <a name="ch2"></a>
## The Tokenizer.
    
# Chapter 3: <a name="ch3"></a>
## The Parser.

# Chapter 4: <a name="ch4"></a>
## The Optimizer.

# Chapter 5: <a name="ch5"></a>
## The Code Generator.

