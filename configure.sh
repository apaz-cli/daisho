#!/bin/sh

# To be run from the root directory of the project.

# Generates a config file by appending to this variable.
CONFIG=""
WRITE_TO="stdlib/Native/Configs/StiltsGeneratedConfig.h"
COLS=$(expr $(stty size | cut -d' ' -f2) - 23)
if test $COLS -gt 90; then COLS=57; fi
IN_CMT="// __STILTS_STDLIB_GENERATEDCONFIG"

# COLORS
ncolors=$(tput colors)
if test -n "$ncolors" && test "$ncolors" -ge 8; then
    hascolors=1
    normal="$(tput sgr0)"
    green="$(tput setaf 2)"
    yellow="$(tput setaf 3)"
    magenta="$(tput setaf 5)"
else
    hascolors=0
    normal=""
    green=""
    yellow=""
    magenta=""
fi


msg() { printf "${green}%-20s:${normal} ${yellow}%""$COLS""s${normal}\n" "$1" "$2"; }
append() { CONFIG="$CONFIG$1\n"; }
guard() { CONFIG="#pragma once\n#ifndef __STILTS_STDLIB_GENERATEDCONFIG\n#define __STILTS_STDLIB_GENERATEDCONFIG\n\n$CONFIG\n#endif $IN_CMT"; }
writeconfig() { printf "%b" "$CONFIG" > $WRITE_TO; }


#############################
#                           #
#    COMPATIBILITY TESTS    #
#                           #
#############################
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


##############
# ENDIANNESS #
##############
if sh ./config/endianness.sh; then
   msg "ENDIANNESS" "PASSED"
else
    echo "Stilts is not supported on Big-Endian or Unknown-Endianness machines."
    exit 1
fi



#################################
#                               #
#    CONFIGURATION VARIABLES    #
#                               #
#################################
echo
echo $magenta"###########################"
echo         "# Configuration Variables #"
echo         "###########################"$normal
append
append "/***************************/"
append "/* Configuration Variables */"
append "/***************************/"

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


############################
#                          #
#    SUPPORTED FEATURES    #
#                          #
############################
echo
echo $magenta"######################"
echo         "# Supported Features #"
echo         "######################"$normal
append
append "/**********************/"
append "/* Supported Features */"
append "/**********************/"

##########
# PYTHON #
##########
PYEXEC=$(sh config/findpython.sh)
if test $PYEXEC; then
    msg "PYTHON EXECUTABLE" $PYEXEC
    append "#define __SILTS_HAS_PYTHON 1"
    append "#define __STILTS_PYTHON_EXECUTABLE \"$PYEXEC\""

    PYV=$($PYEXEC -c "import platform;print(platform.python_version())")
    msg "PYTHON VERSION" "$PYV"
    append "#define __STILTS_PYTHON_VERSION \"$PYV\""
    append "#define __STILTS_PYTHON_MAJOR_VERSION $(echo $PYV | cut -d. -f1)"
    append "#define __STILTS_PYTHON_MINOR_VERSION $(echo $PYV | cut -d. -f2)"
    append "#define __STILTS_PYTHON_SUBMINOR_VERSION $(echo $PYV | cut -d. -f3)"
else
    msg "PYTHON EXECUTABLE" "NONE"
    append "#define __STILTS_HAS_PYTHON 0"
    append "#define __STILTS_PYTHON_EXECUTABLE NULL"
    
    msg "PYTHON VERSION" "NONE"
    append "#define __STILTS_PYTHON_VERSION \"\""
    append "#define __STILTS_PYTHON_MAJOR_VERSION 0"
    append "#define __STILTS_PYTHON_MINOR_VERSION 0"
    append "#define __STILTS_PYTHON_SUBMINOR_VERSION 0"
fi


###############
# ANSI COLORS #
###############
if test $hascolors -eq 1; then
    msg "ANSI COLORS" "YES"
    append ""
    append "#define __STILTS_HAS_ANSI_COLORS 1"
else
    msg "ANSI COLORS" "NO"
    append ""
    append "#define __STILTS_HAS_ANSI_COLORS 0"
fi


##############
# BACKTRACES #
##############
if sh config/backtraces.sh; then
    msg "BACKTRACES" "YES"
    append ""
    append "#define __STILTS_HAS_BACKTRACES 1"
else
    msg "BACKTRACES" "NO"
    append ""
    append "#define __STILTS_HAS_BACKTRACES 0"
fi


####################
# LABELS AS VALUES #
####################
if sh config/label_values.sh; then
    msg "LABEL VALUES" "YES"
    append ""
    append "#define __STILTS_HAS_LABEL_VALUES 1"
else
    msg "LABEL VALUES" "NO"
    append ""
    append "#define __STILTS_HAS_LABEL_VALUES 0"
fi

guard
writeconfig