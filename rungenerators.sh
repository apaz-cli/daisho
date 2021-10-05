#!/bin/sh

cd src/Declarations/Generated

if ! command -v python3  &>/dev/null
then
	echo "Could not find python3. Falling back to system python, which may be Python2, resulting in a syntax error." 1>&2
	python GenNodeTypes.py
	python GenTokTypes.py
else
	python3 GenNodeTypes.py
	python3 GenTokTypes.py
fi
