#!/bin/sh

# Returns 0 if little-endian, 1 otherwise.
if test $(echo -n I | od -to2 | awk 'FNR==1{ print substr($2,6,1)}') -eq 1; then
    exit 0;
else
    exit 1;
fi
