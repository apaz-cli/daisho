# What is Stilts?

<p align="center">
<img src="https://apaz-cli.github.io/Stilts_Blue.png", alt="Boy on Stilts">
</p>

The goal of this project is to create a language that's nice to work with, looks and feels like Java, but maps to low level C code with manual memory management.

The language is currently still in a planning stage. I'm writing multiple parts of the language at the same time to get a feel for how things are supposed to work, and thinking through how I'm going to accomplish everything I want to accomplish. I'm currently going down the rabbit hole of generic type validation semantics and implicit conversions of generic types, with how that's going to map to C. Type checking and control flow analysis are going to be the hardest part of this project. Parsing and code generation are the easy parts.

<br>

# How can I get involved?

<a href="https://discord.gg/yM8ZBDHGdR">
<p align="center">
<img src="https://apaz-cli.github.io/Join%20Our%20Discord.png">
</p>
</a>

If you want some input into the direction of the language, or have suggestions, or if you want to submit a PR, <a href="https://discord.gg/yM8ZBDHGdR">come on over to our Discord</a>.

Regardless of if the language gains popularity or not, I want to share the results of my work because writing compilers is hard.  

<br>

# Getting Started
Assuming you are on a POSIX operating system (Linux, MacOS, BSD), follow these steps. Note that as the compiler is not written yet, you cannot compile any Stilts code. Nor is the language specification written yet, so good luck figuring out what that even is.

First, install a C compiler with your package manager. Make sure it's aliased with `cc`. Next, navigate into the repository folder. Finally, run the following:

```bash
./install.sh release
```

Now you have the compiler, `stiltc`. You can check to make sure everything installed correctly by trying to run it. It should spit out a help message.

```bash
stiltc
```

If you're not on a POSIX operating system (Windows, etc), I recommend switching to one. It's possible that Stilts gets ported to Windows, but I don't want to be the one who does it.


<br>


# Design Vision:

## Stilts is:
* The best parts of most popular languages
* Fast to write, and fast to execute
* Easy to learn
* Literal zero overhead interoperability with C
* Focused on tooling and user experience
* A passion project
* A community


## Stilts is not:
* Memory safe
  * Just like the C that it compiles to.
  * In practice, you should be fine if you stick to standard containers.
* Fast at compiling programs
  * This is an eventual goal, but not a priority.
  * For now, having a compiler at all is a higher priority.
* Supported on platforms other than POSIX
  * I only want to write the standard library and compiler once. However, I will never make the task harder than it needs to be. Every platform dependency will be wrapped and documented. If you're on Windows and want in on the action, <a href="https://discord.gg/yM8ZBDHGdR">let me know</a>. 
* A full time job
  * I already have one. I don't have the time to not make progress. I want immediate results. That means careful planning and a focus on simplicity.


# Sub-Projects:
* Stilts Compiler (`stiltc`)
* Standard Library
* Language Server
* VSCode Extension
* Code Formatter
