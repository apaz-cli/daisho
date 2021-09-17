#!/bin/sh

# COMPILE STILTS
FLAGS=""
if [ $1 ] && [ $1 = "release" ]; then
  FLAGS="${FLAGS} -O3 -flto -march=native"
else
  FLAGS="${FLAGS} -O0 -g -fsanitize=address -DMEMDEBUG=1"
fi

# Install stiltc executable
cc src/Compiler.c $FLAGS 
sudo mv a.out /usr/bin/stiltc

# Move common headers into place
sudo cp -r stilts-stdlib/ /usr/include/stilts-stdlib/
