# What is Daisho?

<p align="center">
<img src="https://cdn.discordapp.com/attachments/886799296819765279/1029882805397758023/best_logo_transparent_cropped.png" width=300>
</p>

The goal of this project is to create a language that's basically
<a href="https://en.wikipedia.org/wiki/C_(programming_language)">C <img src="https://upload.wikimedia.org/wikipedia/commons/1/19/C_Logo.png" width=15></a>,
but way nicer to work with, and focused on trait metaprogramming. It transpiles to
<a href="https://en.wikipedia.org/wiki/POSIX">POSIX</a>
<a href="https://en.wikipedia.org/wiki/C_(programming_language)">C <img src="https://upload.wikimedia.org/wikipedia/commons/1/19/C_Logo.png" width=15></a>,
but provides a way to pave over the sharp edges that come with writing C directly.

Interop between
<a href="https://en.wikipedia.org/wiki/C_(programming_language)">C <img src="https://upload.wikimedia.org/wikipedia/commons/1/19/C_Logo.png" width=15></a>,
<a href="https://github.com/apaz-cli/daisho/">Daisho <img src="https://cdn.discordapp.com/attachments/886799296819765279/1029882805397758023/best_logo_transparent_cropped.png" width=15></a>,
and
<a href="https://github.com/python/cpython">Python <img src="https://upload.wikimedia.org/wikipedia/commons/c/c3/Python-logo-notext.svg" width=15></a>
code should be seamless, and no performance shall be left on the table.


## Status
The language is currently still in very early stages. I've been working on it for a few months, and everything is still a WIP. If you see something in the repo, talk to me first. It's probably a proof of concept, and it's probably broken. I'm writing pretty much every part at once to get a feel for how everything is supposed to work together. See <a href="https://github.com/apaz-cli/Daisho/blob/master/planning/TODO.md">planning/TODO.md</a> for a roadmap and who is doing what. A lot of people want to help, but unfortunately there's not a lot that other people can do. I just need to work on it every day for a few more months. After that, there should be a bit more to help with.

Although everything is a WIP, it's not like no progress has been made. The collection of C libraries that will underpin the compiler and language runtime is almost done. These libraries are already a useful tool in their own right. The goal of this project is to make writing C less painful, and these libraries already accomplish that to some degree. They provide many things that C programmers usually spend a considerable amount of time rewriting for every project.

Right now, a lot of work is happening in <a href="https://github.com/apaz-cli/pgen">pgen</a>, a tokenizer/parser generator that I'm bootstrapping for compiling the grammar of this language.

<br>

# How can I get involved?

<a href="https://discord.gg/yM8ZBDHGdR">
<p align="center">
<img src="https://raw.githubusercontent.com/apaz-cli/apaz-cli.github.io/cd362cfc9014c90e02c08d741448914cda069efc/Join%20Our%20Discord.png">
</p>
</a>

If you have suggestions or want to talk about type systems and their implementation, <a href="https://discord.gg/yM8ZBDHGdR">come on over to our Discord</a>.

On the code side, there's not a lot that people can help with. Once a prototype compiler is working, there should be a lot more to do. But until then, I'm the limiting factor.

For right now, what would be useful is to free up some of my time. What would get us to a working compiler the fastest isn't people pitching in to help write it, but people pitching in to write documentation and tests.

The other thing that would be very helpful would be to have people to talk to about language features and their implementation. I have clear goals, but certain aspects of the design of the language are unfinished, particularly the type unification and monomorphization algorithms. These thoughts have plagued me for months. If you know something about type systems, or know someone who does and is willing to talk, let me know. Having people to talk to about that would be excellent, and would also get the language done a lot faster.

<br>

# Project Structure

If you're planning on contributing, here's the general lay of the land.

* `planning/` - Documentation about how the language is going to work.
  * Contains an example parser.
* `daic/` - The compiler.
  * Gutted and broken beyond repair, but some can be repurposed.
* `config/` - Configure scripts.
  * Detects which features are available on the platform it's running on.
  * Generates `stdlib/Native/Configs/GeneratedConfig.h. See it for more details.
* `grammar/` -  Materials related to generating the parser.
  * This will probably be renamed as the parser-generator is added as a submodule.
* `research/` - Interesting research materials related to building the language.
* `stdlib/` - The Daisho standard library and C runtime libraries
  * Everything is header-only. To use the C runtime library, just `#include "Daisho.h"`.
  * Features:
    * Formatted signal and thread-safe backtraces (depends on glibc)
    * Multiple memory allocators
      * Bump, Fixed size bitmask, and mallocator
    * A memory debugger
      * Keeps a list of unfreed memory.
    * Uniform error handling
    * Optimizing tagged pointers
    * Performance Profiling
    * Threadpools
    * Macros for `std::numeric_limits<T>::min()/max()`
    * Pseudo-Random number generation
    * A utf-8 Parser
  * All of these features are fully integrated with each other and work together.

<br>

# System Requirements
* A POSIX-compliant operating system (Like Linux, MacOS, BSD)
* A working C toolchain that supports C11.
  * The C compiler should have an optimizer.
* Python 3.7+ (optional, to support inline python library interop)
* Reasonable hardware. 
  * Daisho doesn't support all the platforms that C does. It assumes `CHAR_BIT` is 8, an `int` is 32 bits, `long` is 64, etc.
  * If your computer isn't 15-20 years old, you're probably fine. If you're not fine, the configure script will fail and you'll get an error message as to why. If that happens, reach out to me on discord with details of your system. If it's a bug, we'll get it worked out.

If you're not on a POSIX operating system (if you're still on Windows), I recommend switching to one. There are good beginner linux distributions, and they're quickly getting better and better. It's possible that Daisho gets ported to Windows, but it's nowhere near my list of priorities, and I don't want to be the one who does it. If you want to be the one that does it, please contact me on Discord. In about a year.


<br>

## List of inspiring languages:
|  Lang  |                      Inspiration |
| :----: | -------------------------------: |
|   C    |    Simplicity, flat memory model |
|  C++   | Templates, zero cost abstraction |
|  Java  |         Collections/Streams APIs |
| Python |             List comprehensions, |
|  Rust  |                static/dyn Traits |
|  Vala  |                Compilation model |
| Cello  |      Metaprogramming on top of C |

## Daisho is:
* C, with modern high level language features.
* Fast to execute (like C), but also fast to write (unlike C).
* Easy to write and use, mixing C, Python, and Daisho code in the same file.
* Easy to debug, with tools to find memory leaks and errors.
* Focused on tooling and user experience.
* A passion project.


## Daisho is not:
* Memory safe
  * Just like the C that it's based on and compiles to.
  * In practice, you should be fine. Unsafety can be solved through tooling.
    * Memory and UB sanitizer tooling is being built, and will be available as compile flags.
* Fast at compiling programs
  * This is a goal, but not a priority.
  * For now, having a compiler at all is a higher priority.


# Sub-Projects:
* Daisho Compiler  (`daic` folder)
* C Standard Library (`stdlib` folder)
* Memory Sanitizer (coming soon)
* UB Sanitizer (coming soon)
* Package Manager  (coming eventually)
* Language Server  (coming eventually)
* VSCode Extension (coming eventually)
* Code Formatter   (coming eventually)
