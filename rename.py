#!/usr/bin/python3

from glob import glob
from os.path import isfile


for file in glob("**/*", recursive=True):
    if not isfile(file):
        continue
    if not (file.endswith(".c") or file.endswith(".py") or file.endswith(".h") or file.endswith(".md") or file.endswith(".sh")):
        continue

    print(file)

    with open(file, 'w+') as f:
        try:
            lines = f.readlines()
        except:
            continue

        nls = []
        for l in lines:
            nl  = l[:len(l)-1]
            nl = nl.replace("__STILTS", "__DAI")
            nl = nl.replace("__Stilts", "__Dai")
            nl = nl.replace("stilts", "daisho")
            nl = nl.replace("Stilts", "Daisho")
            nl = nl.replace("STILTS", "DAISHO")
            nl = nl.replace("stiltc", "daic")
            f.write(nl + '\n')

