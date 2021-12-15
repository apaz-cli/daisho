# Stilts Documentation
## Introduction
Stilts is a statically typed, general purpose compiled programming language.

It's similar to Java or Rust, but compiles to C. In fact, everything is a wrapper over C.

The hope is that Stilts allows the programmer to reach the high level of abstraction that they desire (generics, polymorphism) while retaining low-level performance. A bit as if standing on stilts, no longer required to remain low to the ground.

## Install:
Assuming you are on a POSIX operating system (Linux, MacOS, BSD), follow these steps. Note that as the compiler is not written yet, you cannot compile any Stilts code. Nor is the language specification written yet, so good luck figuring out what that even is.

First, install a C11+ compiler with your package manager. Make sure it's aliased with `cc` on your `PATH`. Next, navigate into the repository folder and run the following:

```bash
./install.sh release
```

Now you have the compiler, `stiltc`. You can check to make sure everything installed correctly by trying to run it. It should spit out a help message.

```bash
stiltc
```

If you're not on a POSIX operating system (If you're on Windows), I recommend switching to one as quickly as possible. It's possible that Stilts gets ported to Windows, but it's a low priority and I'm busy.


Now that you have the compiler, let's write a simple program... Is what I would say if the compiler were actually ready.


<br>


## Hello World
```c
#include <std.stilt>

Int main() {
    println("Hello World!");
}
```
