
# Named Lifetimes and Their Practical Implementation
### An interactive approach to memory management.

## Abstract
 * Write the abstract last.


## Introduction

Despite the existence of alternative memory management strategies {Cite a bunch of them including Rust}, most
programming languages in common use today (with the notable exception of Rust) {Cite PYPL} do memory management in
one of two ways. They are either garbage collected (like Java/Go/JS/Python), or manual (like C/C++). There are many
ways to implement garbage collection, the most popular being "mark and sweep" {Cite} and reference counting {Cite}.
Each strategy has its tradeoffs. Different garbage collectors have different performance tradeoffs, and garbage
collectors are generally a lot slower than manual management. However, without a garbage collector and language
features designed around it, the cognitive overhead on the programmer is much greater. Memory management strategy
becomes a balance between appeasing the programmer and the processor. Because of the tradeoffs, languages sometimes
offer additional memory management strategies. For example, C++11 offers "smart pointers," {cite} a colletction of
standard types which automatically manage the resources of the objects they reference. We propose another
additional memory management strategy, "named lifetimes." This strategy has minimal performance overhead, while
still presenting a significant improvement in terms of mental overhead over manual memory management in many
situations.


# Outline

## Overview of memory allocators
 * Define Arena
 * Memory from malloc vs the OS
 * Stack or global memory may be an alternative, depening on the lifetime.

 * Once you have this memory, you have to chunk it up and give it out.

 * Define Bump Allocator
   * Trivial, and very fast.
   * No free() on individual regions, unless just allocated. Memory comitted can't be reclaimed.
   * Not what malloc() implementations use.

 * Other allocator strategies
   * Restrictions
   * First available (with pre/postfixes)
   * Bit Masks
   * Free lists
   * Buddy allocation

 * Each type of allocator has its own tradeoffs as well.

 * Optimizing C code is about not doing slow things. Quote the pareto principle.

 * Allocating memory is one of the slowest things your program does, unless it does IO. This means
   optimizing C means writing memory allocators.


## The strategy
 * High level syntax
 * Implicit or explicit creation of memory allocators
 * Explicit destruction of allocator and all contents
 * Build allocator information into the programming language


## Upsides
 * Frontloads the cost of asking the OS for memory
 * Very fast compared to garbage collection
 * Faster than calling malloc() in most cases
   * Don't have to call free(), which is another speedup.
 * Reduces time spent writing custom allocators
 * Names allow you to reason about lifetimes
 * Easier for an optimizer to reason about in some cases


## Drawbacks
 * No single memory allocator is an upside and a downside
   * Performance depends on the pattern you dereference.
 * Extending lifetime -> Move to another allocator, get new pointer
   * This sort of copy can't be elided.


## Example Syntax


## Implementation
 * Basic implementation (global arenas)
 * Optimized implementation (Semantic analysis, customized allocators)


## References:
https://pypl.github.io/PYPL.html
https://blog.sigplan.org/2022/01/13/provably-space-efficient-parallel-functional-programming/
https://www.semanticscholar.org/paper/Region-Based-Memory-Management-for-the-Logic-Ingenieurswetenschappen/096928ce03c488db5bb42ad71d7e719b3c6aff71

