#ifndef DAIC_ARGPARSE_INCLUDE
#define DAIC_ARGPARSE_INCLUDE
#include <daisho/Daisho.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_WITH_ERR(...)            \
    do {                              \
        fflush(stdout);               \
        fprintf(stderr, "Error: ");   \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n");        \
        exit(1);                      \
    } while (0)

typedef struct {
    char* target;
    char* outputfile;
    bool h : 1;  // Help
    bool t : 1;  // Tokens
    bool a : 1;  // AST
} Daic_Args;

static inline Daic_Args
daic_argparse(int argc, char** argv) {
    char helpmsg[] =
        "daic - Compile Daisho to C.\n"
        "    daic [OPTION]... DAISHO_FILE [-o OUTPUT_PATH]                     \n"
        "                                                                      \n"
        "  Options:                                                            \n"
        "    -h, --help               Display this help message and exit.      \n"
        "    -t, --tokens             Print out the tokens from the target.    \n"
        "    -a, --ast                Print out the AST parsed from the target.\n";

    Daic_Args args;
    args.target = NULL;
    args.outputfile = NULL;
    args.h = 0;
    args.t = 0;
    args.a = 0;

    for (int i = 1; i < argc; i++) {
        char* a = argv[i];
        // Flags
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            args.h = 1;
        } else if (!strcmp(a, "-t") || !strcmp(a, "--tokens")) {
            args.t = 0;
        } else if (!strcmp(a, "-a") || !strcmp(a, "--ast")) {
            args.a = 0;
        }
        // Flags with an argument
        else if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            if (i != argc - 1) {
                args.outputfile = argv[++i];
            } else {
                EXIT_WITH_ERR("-o requires an argument.");
            }
        }
        // Unrecognized
        else if (strlen(a) && a[0] == '-') {
            EXIT_WITH_ERR("Unrecognized option \"%s\"", a);
        }
        // Targets
        else {
            if (!args.target) {
                args.target = a;
            } else {
                char* errfmt =
                    "Too many target Daisho files. "
                    "Tried to parse the argument %s, "
                    "but %s was already a target.";
                EXIT_WITH_ERR(errfmt, a, args.target);
            }
        }
    }

    if (args.h || argc == 1) {
        puts(helpmsg);
        exit(0);
    }

    if (!args.target) {
        EXIT_WITH_ERR("No target file was provided.");
    }

    if (!args.outputfile) args.outputfile = "out.c";

    return args;
}

#endif /* DAIC_ARGPARSE_INCLUDE */
