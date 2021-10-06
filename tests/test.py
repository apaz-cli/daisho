#!/bin/python
#from subprocess import run

import os
from os import chdir as cd
from glob import glob

def pwd(): return print(os.getcwd)
def run(s): print(s); os.system(s)
def mkdir(s): pass


def build():
    # Build stiltc
    cd('..')
    run('./rungenerators.sh')
    print("Building the compiler.")
    run('./install.sh')

    # Build the test scripts
    cd('tests/')
    for file in glob('scripts/*.c'):
        fname = file[len('scripts/'):len(file)-2]
        out_loc = f"bin/{fname}"
        run(f'cc -g -Og -fsanitize=address -DMEMDEBUG=1 {file} -o {out_loc}')


def runTests():
    pass


def cleanTests():
    pass


build()
runTests()
cleanTests()
