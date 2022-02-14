#!/usr/bin/python3

from glob import glob
from os.path import isfile


for file in glob("**/*", recursive=True):
    if not isfile(file):
        continue
    if not (file.endswith(".c") or file.endswith(".py") or file.endswith(".h") or file.endswith(".md") or file.endswith(".sh")):
        continue

    print(file)

    nls = []
    with open(file, 'r') as f:
        try:
            lines = f.readlines()
        except:
            continue

        for l in lines:
            nl  = l
            nl = nl.replace("__STILTS", "__DAI")
            nl = nl.replace("__Stilts", "__Dai")
            nl = nl.replace("stilts", "daisho")
            nl = nl.replace("Stilts", "Daisho")
            nl = nl.replace("STILTS", "DAISHO")
            nl = nl.replace("stiltc", "daic")
            nls.append(nl)

    with open(file, 'w+') as f:
        for nl in nls:
            f.write(nl)
