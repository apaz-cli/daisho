#!/bin/sh

# COMPILE DAISHO
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

# Move common headers into place
sudo rm -rf /usr/include/daisho/
sudo cp -r stdlib/ /usr/include/daisho/

# Install daic executable
cc daic/Compiler.c $FLAGS
sudo mv a.out /usr/bin/daic

