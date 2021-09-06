#!/bin/sh

FLAGS="-Iantlr-generated/"
FLAGS="${FLAGS} -I/usr/local/include/antlr4-runtime/"
FLAGS="${FLAGS} -L/usr/local/lib/libantlr4-runtime/"
FLAGS="${FLAGS}   /usr/local/lib/libantlr4-runtime.a"

if [ $1 ] && [ $1 = "release" ]; then
  FLAGS="${FLAGS} -O3 -march=native"
else
  FLAGS="${FLAGS} -O0 -g -fsanitize=address"
fi

# echo "Compiling stiltc with: $FLAGS"

cd src/
c++ Compiler.cpp $FLAGS

sudo mv a.out /usr/bin/stiltc
