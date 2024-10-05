#!/usr/bin/sh

if [ "$1" = "test" ]; then shift; TEST="1"; else TEST="0"; fi

# Requires pgen to be installed.
rm daic daisho.peg.h 2>/dev/null
pgen -l -d $@ daisho.peg -o daisho.peg.h
if [ ! "$?" = "0" ]; then echo "pgen failed."; exit 1; fi
if [ "$TEST" = "1" ]; then
  #cc daic.c -ggdb3 -O0 -Wall -Wno-unused -Wextra -Wpedantic -o daic
  cc daic.c -ggdb3 -O0 -Wall -Wno-unused -Wextra -Wpedantic -fsanitize=address -o daic
  if [ ! "$?" = "0" ]; then echo "Compilation failed."; exit 1; fi
  ./daic "sample3.dai"
fi
