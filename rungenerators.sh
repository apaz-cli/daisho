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

cc packcc/src/packcc.c -o peg
./peg -o StiltsParser Grammar.peg
rm peg
