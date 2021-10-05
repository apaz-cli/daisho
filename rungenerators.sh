#!/bin/sh

cd src/Declarations/Generated
python3 GenNodeTypes.py
python3 GenTokTypes.py
