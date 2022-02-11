#!/bin/sh

# Try to compile
if cc config/label_values.c -o label_values.cfg; then :; else
  exit 1
fi
rm label_values.cfg
