#!/usr/bin/sh

if [ "$1" = "test" ]; then shift; TEST="1"; else TEST="0"; fi

# Requires pgen to be installed.
rm a.out daisho_tokenizer_parser.h 2>/dev/null
pgen -l -d $@ daisho.peg -o daisho_tokenizer_parser.h
if [ ! "$?" = "0" ]; then echo "pgen failed."; exit 1; fi
if [ "$TEST" = "1" ]; then
  cc test.c -ggdb3 -O0 -Wall -Wno-unused -Wextra -Wpedantic -fsanitize=address
  if [ ! "$?" = "0" ]; then echo "Compilation failed."; exit 1; fi
  ./a.out
fi
