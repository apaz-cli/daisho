#!/bin/sh

# Build test
if cc config/locale.c -o locale.cfg 2>/dev/null; then :; else
    exit 1
fi

# Run test
if ./locale.cfg; then
    rm locale.cfg
    exit 0
else
    rm locale.cfg
    exit 1
fi