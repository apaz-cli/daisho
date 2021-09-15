# Stilts Documentation
## Introduction
Stilts is a statically typed, general purpose compiled programming language.

It's similar to Java and C, which it compiles to.

The hope is that Stilts allows the programmer to reach the high level of abstraction that they desire (generics, polymorphism) while retaining low-level performance. A bit as if standing on stilts, no longer required to remain low to the ground.

## Install:
Stilts is only available for POSIX systems (Linux/MacOS/BSD). If you're on Windows, I would recommend switching to a real operating system as quickly as possible.

TODO


## Hello World
```c
Int main() {
    println("Hello World!");
}
```
Save this as `hello.stilt`. Now do `stiltc hello.stilt`. After a fair bit of delay, you'll notice this produces a file `a.out`. That's the binary. Now do `./a.out` to run the binary you've created.

You should see something like:
```bash
username@device:~ stiltc hello.stilt
username@device:~ ./a.out
Hello World!
```
