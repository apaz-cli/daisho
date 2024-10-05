#!/usr/bin/env python3
import argparse
import sys
from dataclasses import dataclass, field
import tempfile
import json
from typing import Iterable, Sequence

import daisho_parser

DAISHO_VERSION = "0.0.1"

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
        parser.add_argument("-o", "--output", default="out.c", help="Specify the output file.")

        parser.add_argument("-v", "--version", action="store_true", help="Display the version and exit.")
        parser.add_argument("-t", "--tokens", action="store_true", help="Print out the tokens from the target and exit.")
        parser.add_argument("-a", "--ast", action="store_true", help="Print out the AST parsed from the target and exit.")

        parser.add_argument("-L", "--link", action="append", help="Add the directory to the library search path.")
        parser.add_argument("-I", "--include", action="append", help="Add the directory to the include search path.")

        color_group = parser.add_mutually_exclusive_group()
        color_group.add_argument("-c", "--color", action="store_true", help="Color the output.")
        color_group.add_argument("-n", "--no-color", action="store_true", help="Don't color the output.")

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


def print_ast(ast: dict):
    import anytree
    from anytree.node.anynode import AnyNode
    import anytree.importer

    class PrintNode(AnyNode):
        def __repr__(self):
            assert hasattr(self, "kind")
            classname = self.kind # type: ignore

            args = []
            for key, value in filter(
                lambda item: not item[0].startswith("_") and item[0] != "kind",
                sorted(self.__dict__.items(), key=lambda item: item[0]),
            ):
                args.append(f"{key}={value}")
            return f"{classname}({', '.join(args)})"

    root = anytree.importer.DictImporter(nodecls=PrintNode).import_(ast)
    print(anytree.RenderTree(root))


def parse_target(args: DaicArgs) -> dict:
    with open(args.target, "r") as f:
        source = f.read()
    
    parsed: dict = daisho_parser.parse_program(source)  # type: ignore (Linter doesn't know about binding)

    ast: dict | None = parsed["ast"]
    error_list: list[dict] = parsed["error_list"]

    if not ast:
        if error_list:
            for error in error_list:
                # TODO: Format
                print(error, file=sys.stderr)
        else:
            print("Error: No AST was generated, and no specific error reported.", file=sys.stderr)
        sys.exit(1)
    
    if args.ast:
        print_ast(ast)
        sys.exit(0)

    return ast


def main():
    args = DaicArgs.from_argv(sys.argv[1:])

    ast: dict = parse_target(args)
    
    


if __name__ == "__main__":
    main()
