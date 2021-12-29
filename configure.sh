#!/bin/sh

# To be run from the root directory of the project.

# Generates a config file by appending to this variable.
CONFIG=""
WRITE_TO="stdlib/Native/StiltsGeneratedConfig.h"
COLS=$(expr $(stty size | cut -d' ' -f2) - 23)
NL=$(printf %s '\n')
msg() { printf "%-20s: %"$COLS"s\n" "$1" "$2"; }
append() { CONFIG="$CONFIG$1$(printf %s '\n')"; }
guard() { CONFIG="#pragma once$NL#ifndef __STILTS_STDLIB_GENERATEDCONFIG$NL#define __STILTS_STDLIB_GENERATEDCONFIG$NL$NL$CONFIG$NL#endif"; }
writeconfig() { echo $CONFIG > $WRITE_TO; }


##############
# ASSERTIONS #
##############
if sh ./config/assertions.sh; then :; else
    echo
    echo "Stilts is not supported on this system for the reason specified in the error message above."
    exit 1
fi;
if sh ./config/endianness.sh; then :; else
    echo "Stilts is not supported on Big-Endian or Unknown-Endianness machines."
    exit 1
fi


echo "###########################"
echo "# Configuration Variables #"
echo "###########################"


##########
# PYTHON #
##########
PYEXEC=$(sh config/findpython.sh)
if test $PYEXEC; then
    msg "PYTHON EXECUTABLE" $PYEXEC
    append "#define __SILTS_HAS_PYTHON 1"
    append "#define __STILTS_PYTHON_EXECUTABLE \"$PYEXEC\""
else
    msg "PYTHON EXECUTABLE" "NONE"
    append "#define __STILTS_HAS_PYTHON 0"
    append "#define __STILTS_PYTHON_EXECUTABLE NULL"
fi


#############
# PAGE SIZE #
#############
PAGESIZE=$(sh config/pagesize.sh)
msg "PAGE SIZE" "$PAGESIZE"
append "#define __STILTS_PAGESIZE $PAGESIZE"


#################
# THREAD NUMBER #
#################
THREADS=$(sh config/threads.sh)
msg "THREADS" "$THREADS"
append "#define __STILTS_IDEAL_NUM_THREADS $THREADS"


##############
# BACKTRACES #
##############
if sh config/backtraces.sh; then
    msg "BACKTRACES" "YES"
    append "#define __STILTS_BACKTRACES_SUPPORTED 1"
else
    msg "BACKTRACES" "NO"
    append "#define __STILTS_BACKTRACES_SUPPORTED 0"
fi

guard
writeconfig