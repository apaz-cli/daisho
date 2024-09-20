#!/usr/bin/env python3
import argparse
import sys
from dataclasses import dataclass, field
import tempfile
from typing import Iterable, Sequence

import daisho_parser
import clang.cindex as cindex

DAISHO_VERSION = "0.0.1"

example_program = """
int add(int a, int b) {
    return a + b;
}

int main() {
    int result = add(2, 3);
    return 0;
}
"""

c_includes = """

/* Grab all the C11 headers. */
/* note: pthread.h is used over C11's threads.h because
   it's better and actually more portable. */
#ifndef __cplusplus
/* Base C */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* C95 */
#include <iso646.h>
#include <wchar.h>
#include <wctype.h>

/* C99 */
#include <complex.h>
#include <fenv.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <tgmath.h>

/* C11 */
#include <stdalign.h>
#include <stdnoreturn.h>
#include <uchar.h>
// #include <stdatomic.h>
// #include <threads.h>

#else /* __cplusplus */
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cfloat>
#include <climits>
#include <clocale>
#include <cmath>
#include <csetjmp>
#include <csignal>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

/* C95 */
#include <ciso646>
#include <cwchar>
#include <cwctype>

/* C99 */
#include <ccomplex>
#include <cfenv>
#include <cinttypes>
#include <cstdbool>
#include <cstdint>
#include <ctgmath>

/* C11 */
#include <cstdalign>
#include <cuchar>
// #include <cstdatomic>
// #include <cthreads>

#endif /* End of stdlib includes */

/************************/
/* Additional Libraries */
/************************/

/* POSIX */
// TODO deal with _GNU_SOURCE
#define _GNU_SOURCE 1
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>

#define PREPROCESSOR_DECL 1
"""


@dataclass
class DaicArgs:
    target: str
    outputfile: str = "out.c"
    version: bool = False
    tokens: bool = False
    ast: bool = False
    color: bool = True

    @staticmethod
    def from_argv(argv: Sequence[str]) -> "DaicArgs":
        parser = argparse.ArgumentParser(
            description="Compile Daisho to C.", add_help=True
        )

        parser.add_argument("target", nargs="?", help="The target Daisho file.")
        parser.add_argument(
            "-o", "--output", default="out.c", help="Specify the output file."
        )
        parser.add_argument(
            "-v", "--version", action="store_true", help="Display the version and exit."
        )
        parser.add_argument(
            "-t",
            "--tokens",
            action="store_true",
            help="Print out the tokens from the target.",
        )
        parser.add_argument(
            "-a",
            "--ast",
            action="store_true",
            help="Print out the AST parsed from the target.",
        )
        color_group = parser.add_mutually_exclusive_group()
        color_group.add_argument(
            "-c", "--color", action="store_true", help="Color the output."
        )
        color_group.add_argument(
            "-n", "--no-color", action="store_true", help="Don't color the output."
        )

        args = parser.parse_args(argv)

        if args.version:
            print(DAISHO_VERSION)
            sys.exit(0)

        if not args.target:
            print("Error: No target file was provided.", file=sys.stderr)
            sys.exit(1)

        color_output = args.color if args.color else not args.no_color

        return DaicArgs(
            target=args.target,
            outputfile=args.output,
            version=args.version,
            tokens=args.tokens,
            ast=args.ast,
            color=color_output,
        )


def parse_target(args: DaicArgs) -> dict:
    with open(args.target, "r") as f:
        source = f.read()
    return daisho_parser.parse_program(source)  # type: ignore (Linter doesn't know about binding)


def clang_parse_stdlib(c_source) -> cindex.TranslationUnit:
    index = cindex.Index.create()

    # Temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as f:
        f.write(bytes(c_source, "utf-8"))
        f.flush()
        f.seek(0)
        tu = index.parse(f.name, args=[])
    
    # Function to recursively extract symbols
    def extract_symbols(node, symbols):
        #print("------------------------------")
        #print(node.kind)
        #print(node.type.spelling)
        print(node.spelling)
        #print(node.location)
        #print(node.extent)
        if node.kind.is_declaration():
            symbols.append((node.kind, node.spelling))
        for child in node.get_children():
            extract_symbols(child, symbols)

    # Extract symbols
    symbols = []
    cursor = tu.cursor
    kinds = set()
    for child in cursor.get_children():
        kinds.add(child.kind)
        print(child.kind, child.spelling, child.type.spelling)

    print("Kinds:", kinds)
    decl_kinds = [k for k in cindex.CursorKind.get_all_kinds() if cindex.CursorKind.is_declaration(k)]
    print(decl_kinds)


    return tu



def main():
    args = DaicArgs.from_argv(sys.argv[1:])
    parsed = parse_target(args)
    ast = parsed["ast"]
    error_list = parsed["error_list"]
    # TODO: tokens = parsed["tokens"]

    if not ast:
        if error_list:
            for error in error_list:
                print(error, file=sys.stderr)
        else:
            print("Error: No AST was generated.", file=sys.stderr)
        sys.exit(1)

    clang_parse_stdlib(c_includes + example_program)


if __name__ == "__main__":
    main()
