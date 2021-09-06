#!/bin/sh
./build-antlr.sh
./build-grammar.sh
./build-compiler.sh release

if [ $1 ] && [ $1 = "clean" ]; then
  ./clean-grammar.sh
  ./clean-antlr.sh
fi
