#!/bin/sh

# To be run from the root directory of the project.

# Generates a config file by appending to this variable.
CONFIG=""
WRITE_TO="stdlib/Native/Configs/StiltsGeneratedConfig.h"
COLS=$(expr $(stty size | cut -d' ' -f2) - 23)
if test $COLS -gt 90; then COLS=57; fi
NL=$(printf %s '\n')

# COLORS
ncolors=$(tput colors)
if test -n "$ncolors" && test "$ncolors" -ge 8; then
    hascolors=1
    bold="$(tput bold)"
    underline="$(tput smul)"
    standout="$(tput smso)"
    normal="$(tput sgr0)"
    black="$(tput setaf 0)"
    red="$(tput setaf 1)"
    green="$(tput setaf 2)"
    yellow="$(tput setaf 3)"
    blue="$(tput setaf 4)"
    magenta="$(tput setaf 5)"
    cyan="$(tput setaf 6)"
    white="$(tput setaf 7)"
else
    hascolors=0
    bold=""
    underline=""
    standout=""
    normal=""
    black=""
    red=""
    green=""
    yellow=""
    blue=""
    magenta=""
    cyan=""
    white=""
fi

msg() { printf "${green}%-20s:${normal} ${yellow}%"$COLS"s${normal}\n" "$1" "$2"; }
append() { CONFIG="$CONFIG$1$(printf %s '\n')"; }
guard() { CONFIG="#pragma once$NL#ifndef __STILTS_STDLIB_GENERATEDCONFIG$NL#define __STILTS_STDLIB_GENERATEDCONFIG$NL$NL$CONFIG$NL#endif"; }
writeconfig() { echo $CONFIG > $WRITE_TO; }


echo $magenta"#######################"
echo         "# Compatibility Tests #"
echo         "#######################"$normal


##############
# ASSERTIONS #
##############
if sh ./config/assertions.sh; then
    msg "ASSERTIONS" "PASSED"
else
    echo
    echo "Stilts is not supported on this system for the reason specified in the error message above."
    exit 1
fi;
if sh ./config/endianness.sh; then
   msg "ENDIANNESS" "PASSED"
else
    echo "Stilts is not supported on Big-Endian or Unknown-Endianness machines."
    exit 1
fi


echo
echo $magenta"###########################"
echo         "# Configuration Variables #"
echo         "###########################"$normal


##########
# COLORS #
##########
if test $hascolors -eq 1; then
    msg "ANSI COLORS" "YES"
    append "#define __STILTS_HAS_ANSI_COLORS 1"
else
    msg "ANSI COLORS" "NO"
    append "#define __STILTS_HAS_ANSI_COLORS 1"
fi

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
