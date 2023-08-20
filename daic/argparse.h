#ifndef DAIC_ARGPARSE_INCLUDE
#define DAIC_ARGPARSE_INCLUDE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"

#include "../stdlib/Daisho.h"

static const char helpmsg[] =
    "daic - Compile Daisho to C.\n"
    "    daic [OPTION]... DAISHO_FILE [-o OUTPUT_PATH]                     \n"
    "                                                                      \n"
    "  Options:                                                            \n"
    "    -h, --help               Display this help message and exit.      \n"
    "    -v, --version            Display the version and exit.            \n"
    "    -t, --tokens             Print out the tokens from the target.    \n"
    "    -a, --ast                Print out the AST parsed from the target.\n"
    "    -c, --color              Color the output.                        \n"
    "    -n, --no-color           Don't color the output.                  \n"
    "    -o, --output             Specify the output file.                 \n";

static const char versionmsg[] = "0.0.1";

// We use this after allocation error, knowing that it allocates and will fail.
// When it does, it will set errfail.
#define ARG_ERROR(...)                      \
    do {                                    \
        daic_arg_error(&args, __VA_ARGS__); \
        daic_arg_error(&args, "\n");        \
        return args;                        \
    } while (0)

static inline int
daic_arg_error(Daic_Args* args, const char* fmt, ...) {
    if (args->errfail) return -1;
    if (!args->errstr) {
        size_t initialcap = 4096;
        args->errstr = (char*)malloc(initialcap);
        args->errstrlen = 0;
        args->errstrcap = initialcap;
        if (!args->errstr) {
            args->errfail = 1;
            return -1;
        }
    }

    va_list va;
    va_start(va, fmt);
    int written = vsprintf(args->errstr + args->errstrlen, fmt, va);
    va_end(va);
    if (written < 0) {
        args->errfail = 1;
        args->errstr = NULL;
        free(args->errstr);
        return written;
    }

    size_t need_cap = (size_t)written + 1;
    if (args->errstrcap <= need_cap) {
        size_t new_cap = need_cap * 2;
        args->errstr = (char*)realloc(args->errstr, new_cap);
        args->errstrcap = new_cap;
        if (!args->errstr) {
            args->errfail = 1;
            return -1;
        }

        va_start(va, fmt);
        written = vsprintf(args->errstr + args->errstrlen, fmt, va);
        va_end(va);
        if (written < 0) {
            args->errfail = 1;
            args->errstr = NULL;
            free(args->errstr);
            return written;
        }
    }

    args->errstrlen += written;
    return written;
}

// If args.errstr then it is malloced.
static inline Daic_Args
daic_argparse(int argc, char** argv) {
    Daic_Args args;
    args.target = NULL;
    args.outputfile = NULL;
    args.errstr = NULL;
    args.errfail = 0;
    args.errstrcap = 0;
    args.errstrlen = 0;
    args.h = 0;
    args.v = 0;
    args.t = 0;
    args.a = 0;
    args.c = strlen(_DAI_COLOR_RESET) ? 1 : 0;

    for (int i = 1; i < argc; i++) {
        // Flags without an argument
        char* a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            args.h = 1;
        } else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            args.v = 1;
        } else if (!strcmp(a, "-t") || !strcmp(a, "--tokens")) {
            args.t = 1;
        } else if (!strcmp(a, "-a") || !strcmp(a, "--ast")) {
            args.a = 1;
        } else if ((!strcmp(a, "-c") || !strcmp(a, "--color")) ||
                   (!strcmp(a, "-n") || !strcmp(a, "--no-color"))) {
            args.c = a[2] == 'c';
        }
        // Flags with an argument
        else if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            if (i != argc - 1) {
                args.outputfile = strdup(argv[++i]);
                if (!args.outputfile) ARG_ERROR("Failed to allocate memory for the output file.");
            } else {
                ARG_ERROR("-o requires an argument.");
            }
        }
        // Unrecognized
        else if (a[0] == '-') {
            ARG_ERROR("Unrecognized option \"%s\"", a);
        }
        // Targets
        else {
            if (!args.target) {
                args.target = strdup(a);
            } else {
                char* errfmt =
                    "Too many target Daisho files. "
                    "Tried to parse the argument %s, but %s was already a target.";
                ARG_ERROR(errfmt, a, args.target);
            }
        }
    }

    if (!args.target) ARG_ERROR("No target file was provided.");

    if (!args.outputfile) {
        args.outputfile = strdup("out.c");
        if (!args.outputfile) ARG_ERROR("Failed to allocate memory for the output file.");
    }

    return args;
}

static inline void
daic_argdestroy(Daic_Args* args) {
    free(args->errstr);
    free(args->target);
    free(args->outputfile);
}

#endif /* DAIC_ARGPARSE_INCLUDE */
