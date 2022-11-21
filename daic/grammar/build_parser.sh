#!/usr/bin/sh

# Requires pgen to be installed.
rm a.out daisho_tokenizer_parser.h 2>/dev/null
pgen $@ daisho.tok daisho.peg -o daisho_tokenizer_parser.h
cc test.c -g -O0 -Wall -Wno-unused -Wextra -Wpedantic -fsanitize=address
