#!/bin/sh

# COMPILE STILTS
FLAGS="-lpthread"
if [ $1 ] && [ $1 = "release" ]; then
  FLAGS="${FLAGS} -O3 -march=native"
elif [ $1 ] && [ $1 = "aggressive-optimizations" ]; then
  FLAGS="${FLAGS} -O3 -march=native -DAPAZ_HANDLE_UNLIKELY_ERRORS=0"
elif [ $1 ] && [ $1 = "memdebug" ]; then
  FLAGS="${FLAGS} -Og -g -rdynamic -fsanitize=address -DMEMDEBUG=1"
else
  FLAGS="${FLAGS} -O0 -g -rdynamic -fsanitize=address"
fi

# Install stiltc executable
cc src/Compiler.c $FLAGS
sudo mv a.out /usr/bin/stiltc

# Move common headers into place
sudo cp -r stilts-stdlib/ /usr/include/stilts-stdlib/
