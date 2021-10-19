#!/bin/sh

cd src/Declarations/Generated

if ! command -v python3 >/dev/null
then
	python GenNodeTypes.py
	python GenTokTypes.py
else
	python3 GenNodeTypes.py
	python3 GenTokTypes.py
fi

cd ../../../Grammar


cc -O0 packcc.c -o peg
./peg -o StiltsParser Grammar.peg

cat StiltsParser.h StiltsParser.c > StiltsParser
awk '!/#include "StiltsParser.h"/' StiltsParser > StiltsParser.h
rm StiltsParser.c StiltsParser
