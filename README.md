# What is Stilts?

![Boy on stilts](https://apaz-cli.github.io/Stilts.png)

The goal of this project is to create a language that's nice to work with, looks and feels like Java, but maps to low level C code with manual memory management.

The language is currently still in a planning stage. I'm writing the grammar and language specification right now at the same time as the parser, and thinking through how I'm going to accomplish everything I want to accomplish. Currently I'm going down the rabbit hole of generic type validation semantics and implicit conversions of generic types. Type checking and control flow analysis are going to be the hardest part of this project. Code generation is the easy part.

<br>

# How can I get involved?

<a href="https://discord.gg/HfP64r7Nxe">
<center><img src="https://apaz-cli.github.io/Join%20Our%20Discord.png"></center>
</a>

If you want some input into the direction of the language, or have suggestions, or if you want to help write, come on over to our Discord.

Regardless of if the language gains popularity or not, I want to share the results of my work because writing compilers is hard.  

<br>

# Getting Started
Assuming you are on a POSIX operating system (Linux, MacOS, BSD), follow these steps. Note that as the compiler is not written yet, you cannot compile any Stilts code.

First, install a C compiler with your package manager. Make sure it's aliased with `cc`.

Next, navigate into the repository folder with cd.

Finally, run the following:

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
* The language that Java should have been
* Fast to write, and fast to execute
* Easy to understand
* Flawlessly interoperable with C
* Focused on tooling and user experience
* A passion project


## Stilts is not:
* Fast to compile
  * This is an eventual goal, but not a priority.
* Supported on platforms other than POSIX
  * I only want to write the standard library and the bootstrapping scripts once. However, it should be easy enough to port. If you're on Windows and you want in on the action, let me know. I will never make the task harder than it needs to be.
* A full time job
  * I already have one. I don't have the time to not make progress. I want immediate results. That means careful planning and a focus on simplicity.


# Sub-Projects:
* Stilts Compiler (stiltc)
* Standard Library
* Language Server
* VSCode Extension
* Code Formatter
