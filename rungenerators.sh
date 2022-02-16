#!/bin/sh

# To be run from the root directory of the project.

cd daic/Declarations/Generated

if ! command -v python3 >/dev/null
then
    python GenNodeTypes.py
    python GenTokTypes.py
else
    python3 GenNodeTypes.py
    python3 GenTokTypes.py
fi
