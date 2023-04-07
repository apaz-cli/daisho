#ifndef DAIC_ARGPARSE_INCLUDE
#define DAIC_ARGPARSE_INCLUDE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../stdlib/Daisho.h"

static const char helpmsg[] =
    "daic - Compile Daisho to C.\n"
    "    daic [OPTION]... DAISHO_FILE [-o OUTPUT_PATH]                     \n"
    "                                                                      \n"
    "  Options:                                                            \n"
    "    -h, --help               Display this help message and exit.      \n"
    "    -t, --tokens             Print out the tokens from the target.    \n"
    "    -a, --ast                Print out the AST parsed from the target.\n";

typedef struct {
    char* target;
    char* outputfile;
    char* errstr;
    size_t errstrlen;
    size_t errstrcap;
    bool errfail : 1;
    bool h : 1;  // Help
    bool t : 1;  // Tokens
    bool a : 1;  // AST
} Daic_Args;

#define ARG_ERRCAP ()

#define ARG_ERROR(...)                      \
    do {                                    \
        daic_arg_error(&args, "Error: ");   \
        if (args.errfail) return args;      \
        daic_arg_error(&args, __VA_ARGS__); \
        if (args.errfail) return args;      \
        daic_arg_error(&args, "\n");        \
        return args;                        \
    } while (0)

static inline int
daic_arg_error(Daic_Args* args, const char* fmt, ...) {
    if (!args->errstr) {
        size_t initialcap = 4 * 4096;
        args->errstr = malloc(initialcap);
        args->errstrlen = 0;
        args->errstrcap = initialcap;
        if (!args->errstr) return args->errfail = 1, -1;
    }

    va_list va;
    va_start(va, fmt);
    int written = vsprintf(args->errstr, fmt, va);
    va_end(va);
    if (written < 0) return args->errfail = 1, written;

    size_t need_cap = (size_t)written + 1;
    size_t new_cap = need_cap * 2;
    if (args->errstrcap <= need_cap) {
        args->errstr = (char*)realloc(args->errstr, new_cap);
        args->errstrcap = new_cap;
        if (!args->errstr) return args->errfail = 1, -1;

        va_start(va, fmt);
        written = vsprintf(args->errstr, fmt, va);
        va_end(va);
        if (written < 0) return args->errfail = 1, written;
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
    args.t = 0;
    args.a = 0;

    size_t err_len = 0;
    size_t err_cap = 0;

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
                ARG_ERROR("-o requires an argument.");
            }
        }
        // Unrecognized
        else if (strlen(a) && a[0] == '-') {
            ARG_ERROR("Unrecognized option \"%s\"", a);
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
                ARG_ERROR(errfmt, a, args.target);
            }
        }
    }

    if (!args.target) ARG_ERROR("No target file was provided.");

    if (!args.outputfile) args.outputfile = "out.c";

    return args;
}

#endif /* DAIC_ARGPARSE_INCLUDE */
