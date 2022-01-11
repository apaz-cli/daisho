#!/bin/sh

# Try to compile
if cc config/assertions.c -o assertions.cfg; then :; else
  exit 1
fi
rm assertions.cfg