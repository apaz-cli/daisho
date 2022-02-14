#!/usr/bin/python3

from glob import glob
from os.path import isfile
from re import sub


for file in glob("**/*", recursive=True):
    if not isfile(file):
        continue
    if not (file.endswith(".c") or file.endswith(".py") or file.endswith(".h")):
        continue

    print(file)
    with open(file, 'r') as f:
        try:
            lines = f.readlines()
        except:
            continue

        nls = []
        for l in lines:
            l  = l[:len(l)-1]
            nl = sub("__STILTS", "__DAI", l)
            nl = sub("__Stilts", "__Dai", nl)
            nl = sub("stilts", "daisho", nl)
            nl = sub("Stilts", "Daisho", nl)
            nl = sub("STILTS", "DAISHO", l)
            nl = sub("stiltc", "daic", nl)

            print(nl)
