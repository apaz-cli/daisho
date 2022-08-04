#!/bin/sh

# Try to compile with backtraces
if cc config/backtraces.c -o backtraces.cfg 2>/dev/null; then :; else
    exit 1
fi

echo "compilation suceeded."

# Try to run it, which will load and test the library.
if ./backtraces.cfg; then
    rm backtraces.cfg
    exit 0
else
    rm backtraces.cfg
    exit 1
fi
