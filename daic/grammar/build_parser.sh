#!/usr/bin/sh

# Requires pgen to be installed.
pgen $@ daisho.tok daisho.peg -o daisho_tokenizer_parser.h
cc test.c -g -O0 -Wall -Wno-unused -Wextra -Wpedantic -fsanitize=address
