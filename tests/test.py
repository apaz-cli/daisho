#!/usr/bin/python3
#from subprocess import run

import os
import subprocess
from shlex import split
from os import chdir as cd
from glob import glob

def pwd(): return print(os.getcwd)
def run(s): print(s); subprocess.run(split(s), check=True)
def mkdir(s):
    try:
        os.mkdir(s)
    except OSError:
        pass


cc = "clang"


def build():
    # Build stiltc
    cd('..')
    run('./rungenerators.sh')
    run('./install.sh')
    cd('tests/')

    # Build the c test scripts
    mkdir('bin/')
    for script in glob('scripts/*.c'):
        exename = script[len('scripts/'):len(script)-2]
        run(f'{cc} -g -Og -fsanitize=address -DMEMDEBUG=1 {script} -o bin/{exename}')

    # Move the python test scripts
    for script in glob('scripts/*.py'):
        exename = script[len('scripts/'):len(script)-3]
        run(f'chmod +x {script}')
        run(f'cp {script} bin/{exename}')


def runTests():
    # Run the test scripts.
    print()
    for exe in glob('bin/*'):
        run(exe)
        print()


def cleanTests():
    pass


build()
runTests()
cleanTests()
