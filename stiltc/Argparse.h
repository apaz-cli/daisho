#ifndef ARGPARSE_INCLUDE
#define ARGPARSE_INCLUDE

#include <apaz-libc.h>

#include "Declarations/Declarations.h"

static const char* usageMesasge =
    "Daisho v0.1\n"
    "Usage:\n"
    "  -h --help : Display this message and exit.\n"
    "\n"
    "Pipeline Flags:\n"
    "  --tokenize : Only tokenize the target file.\n"
    "  --parse    : Only tokenize and create an AST of the target file.\n"
    "  --check    : Only validate the types/syntax of the target file.\n"
    "  --codegen  : Only tokenize/parse/check the source file, and output C.\n"
    "  --compile  : Execute the whole pipeline and produce a binary (defaut).\n"
    "\n"
    "C Compiler Flags:\n"
    "  --cc       : Specify which C compiler to use (System cc by default).\n"
    "  --cflags   : Specify which flags to give to the C compiler.\n"
    "\n"
    "Runtime Extension Flags:\n"
    " --python    : Embed python support by linking against system Python3.\n"
    " --no-python : Don't add python support.\n"
    "\n"
    "Debugging Flags:\n"
    " --pedantic : Add pedantic sanity checks. Slow, but good for debugging.\n"
    " --sane     : Basic sanity checks are performed. (Null checks, OOM, "
    "etc.)\n"
    " --insane   : No sanity checks. Difficult to debug, but very fast.\n"
    "\n"
    "Memdebug Flags:\n"
    " --no-memdebug    : Don't wrap malloc(), calloc(), realloc(), free().\n"
    " --memdebug       : Wrap memory functions for tracking leaks and bugs.\n"
    " --memdebug-print : Also print every allocation and free to stderr.\n"
    "\n"
    "Allocator Flags:\n"
    ""
    "\n"
    "Malloc Flags:\n"
    " --normal-malloc  : malloc() is normal system malloc.\n"
    " --replace-malloc : Wrap malloc() in a macro using a custom allocator.\n"
    "\n"
    "Stiltc Flags:\n"
    "  --jobs -j  : Specify how many threads daic should use.\n"
    "\n";

// Lambdas
static inline void
str_destroy(String s, void* none) {
    (void)none;
    String_destroy(s);
}
static inline bool
filterEmpty(String str, void* none) {
    (void)none;
    bool empty = str[0] == '\0';
    if (empty) String_destroy(str);
    return !empty;
}

// Helpers
static inline void
arg_err(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}
static inline void
usage() {
    // Consumes.
    int ex = puts(usageMesasge);
    destroyFlags();
    print_heap();
    exit(ex);
}

static inline void
parseFlags(int argc, char** argv) {
    // Set defaults
    cmdFlags.temp_folder = (char*)"/tmp/daisho/";
    cmdFlags.cc = (char*)"cc";
    cmdFlags.cflags = List_String_new_cap(0);
    cmdFlags.targets = List_Target_new_cap(1);
    cmdFlags.parse = true;
    cmdFlags.check = true;
    cmdFlags.codegen = true;
    cmdFlags.compileC = true;
    cmdFlags.python = true;
    cmdFlags.sanity = SANITY_SANE;

    bool grabNext = false;
    if (argc <= 1) {
        usage();
    } else {
        for (size_t i = 1; i < (size_t)argc; i++) {
            // If the previous flag had an argument, grab it instead of
            // interpreting the argument as a flag.
            if (grabNext) {
                grabNext = false;

                if (apaz_str_equals(argv[i - 1], (char*)"--cc")) {
                    cmdFlags.cc = String_new_of_strlen(argv[i]);
                    continue;
                } else if (apaz_str_equals(argv[i - 1], (char*)"--cflags")) {
                    String sarg = String_new_of_strlen(argv[i]);
                    List_String_destroy(cmdFlags.cflags);
                    cmdFlags.cflags =
                        List_String_filter(String_split(sarg, (char*)" "), filterEmpty, NULL);
                    String_destroy(sarg);
                    continue;
                } else if (apaz_str_equals(argv[i - 1], (char*)"-j")) {
                    int j = atoi(argv[i]);
                    if (!(j > 0)) arg_err("The number of jobs must be a number greater than zero.");
                    cmdFlags.num_threads = (size_t)i;
                }
            }

            // Help flag
            else if (apaz_str_equals(argv[i], (char*)"-h") |
                     apaz_str_equals(argv[i], (char*)"--help")) {
                usage();
            }

            // Pipeline Flags
            else if (apaz_str_equals(argv[i], (char*)"--tokenize"))
                cmdFlags.parse = false;
            else if (apaz_str_equals(argv[i], (char*)"--parse"))
                cmdFlags.check = false;
            else if (apaz_str_equals(argv[i], (char*)"--check"))
                cmdFlags.codegen = false;
            else if (apaz_str_equals(argv[i], (char*)"--codegen"))
                cmdFlags.compileC = false;

            // C Compiler Flags
            else if (apaz_str_equals(argv[i], (char*)"--cc")) {
                if (i == (size_t)argc)
                    arg_err("--cc requires an argument (The C compiler to use).");
                grabNext = true;
            } else if (apaz_str_equals(argv[i], (char*)"--cflags")) {
                if (i == (size_t)argc)
                    arg_err(
                        "--cflags requires an argument (The flags to pass to "
                        "the C compiler, all in one argument).");
                grabNext = true;
            } else if (apaz_str_equals(argv[i], (char*)"-j") ||
                       apaz_str_equals(argv[i], (char*)"--jobs")) {
                if (i == (size_t)argc)
                    arg_err(
                        "--jobs/-j requires an argument (The number of threads "
                        "to create).");
                grabNext = true;
            }

            // Runtime Extension Flags
            else if (apaz_str_equals(argv[i], (char*)"--python"))
                cmdFlags.python = true;
            else if (apaz_str_equals(argv[i], (char*)"--no-python"))
                cmdFlags.python = false;

            // Debugging Flags
            else if (apaz_str_equals(argv[i], (char*)"--pedantic"))
                cmdFlags.sanity = SANITY_PEDANTIC;
            else if (apaz_str_equals(argv[i], (char*)"--sane"))
                cmdFlags.sanity = SANITY_SANE;
            else if (apaz_str_equals(argv[i], (char*)"--insane"))
                cmdFlags.sanity = SANITY_INSANE;

            // Memdebug Flags

            // Allocator Flags

            // Malloc Flags

            // Targets
            else {
                Target t = {.file_name = argv[i]};
                cmdFlags.targets = List_Target_addeq(cmdFlags.targets, t);
            }
        }
    }

    cmdFlags.cflags = List_String_trim(cmdFlags.cflags);
    cmdFlags.targets = List_Target_trim(cmdFlags.targets);
}

static inline void
destroyFlags() {
    List_String_foreach(cmdFlags.cflags, str_destroy, NULL);
    List_Target_destroy(cmdFlags.targets);
}

static inline const char*
strb(bool b) {
    return b ? "yes" : "no";
}
static inline void
printFlags() {
    printf(
        "Command Line Flags:\n\n    /* Pipeline Options */\n    parse:   %s\n  "
        " "
        " check:   %s\n    codegen: %s\n    compile: %s\n\n",
        strb(cmdFlags.parse), strb(cmdFlags.check), strb(cmdFlags.codegen),
        strb(cmdFlags.compileC));

    puts("    /* Codegen Options */");
    printf("    cc:      %s\n", cmdFlags.cc);
    printf("    cflags:  [");
    if (List_String_len(cmdFlags.cflags)) printf("%s", cmdFlags.cflags[0]);
    for (size_t i = 1; i < List_String_len(cmdFlags.cflags); i++)
        printf(", %s", cmdFlags.cflags[i]);
    printf("]\n");

    printf("    targets: [");
    if (List_Target_len(cmdFlags.targets)) printf("%s", cmdFlags.targets[0].file_name);
    for (size_t i = 1; i < List_Target_len(cmdFlags.targets); i++)
        printf(", %s", cmdFlags.targets[i].file_name);
    printf("]\n\n");
    fflush(stdout);
}

#endif