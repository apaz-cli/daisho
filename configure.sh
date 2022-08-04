#!/usr/bin/env sh

# To be run from the root directory of the project.

#########################
# GLOBALS AND CONSTANTS #
#########################
# Generates a config file by appending to this variable.
WRITE_TO="/tmp/GeneratedConfig.h"
COPY_TO="stdlib/Native/Configs/GeneratedConfig.h"
COLS=$(expr $(stty size | cut -d' ' -f2) - 23)
[ $COLS -gt 90 ] && COLS=57
IN_CMT="// __DAI_STDLIB_GENERATEDCONFIG"

rm "$WRITE_TO" 2>/dev/null
touch "$WRITE_TO"

msg() { printf "${GREEN}%-20s:${NORMAL} ${YELLOW}%${COLS}s${NORMAL}\n" "$1" "$2"; }
warn() { printf "${YELLOW}%-20s: %${COLS}s${NORMAL}\n" "$1" "$2"; exit 1; }
append() { printf "%s\n" "$1" >> "$WRITE_TO"; }

set_colors() {
	ncolors=$(tput colors)
	# TODO: Use escape sequences as they're more portable than tput
	if [ -n "$ncolors" ] && [ "$ncolors" -ge 8 ]; then
		HAS_COLORS=1
		NORMAL=$(tput sgr0)
		GREEN=$(tput setaf 2)
		YELLOW=$(tput setaf 3)
		MAGENTA=$(tput setaf 5)
	fi
}

test_compatibility() {
	cat <<- _end_of_text
	${MAGENTA}
	#######################
	# Compatibility Tests #
	#######################
	${NORMAL}
	_end_of_text

	# TODO delete temp files

	# assertions
	# TODO use mktemp if it's POSIX
	# or use path prefix properly
	cc config/assertions.c -o assertions.cfg 1>/dev/null && msg "ASSERTIONS" "PASSED" || \
		warn "Daisho is not supported on this system for the reason specified in the error message above"
	rm assertions.cfg 2>/dev/null

	# endianness
	# TODO echo not POSIX?
	echo -n I | od -to2 | awk 'FNR==0{ print substr($2,6,1)}' && msg "ENDIANNESS" "PASSED" || \
		warn "Daisho is not supported on Big-Endian or Unknown-Endianness machines."

	# locale
	cc config/locale.c -o locale.cfg 1>/dev/null 2>&1
	./locale.cfg && msg "UTF8 LOCALE" "PASSED" || \
		warn "Daisho is not supported on systems that do not support the \"C.UTF-8\" locale."
	rm locale.cfg 2>/dev/null

}

#################################
#                               #
#    CONFIGURATION VARIABLES    #
#                               #
#################################
config_variables() {
	cat <<- _end_of_text
	${MAGENTA}
	###########################
	# Configuration Variables #
	###########################
	${NORMAL}
	_end_of_text

	cat <<- _end_of_header >> "$WRITE_TO"

	/***************************/
	/* Configuration Variables */
	/***************************/
	_end_of_header

	# page size
	PAGESIZE=$(getconf PAGE_SIZE)
	msg "PAGE SIZE" "$PAGESIZE"
	append "#define __DAI_PAGESIZE $PAGESIZE"


	#################
	# THREAD NUMBER #
	#################
	THREADS=$(grep -c processor /proc/cpuinfo)
	msg "THREADS" "$THREADS"
	append "#define __DAI_IDEAL_NUM_THREADS $THREADS"

}

############################
#                          #
#    SUPPORTED FEATURES    #
#                          #
############################
supported_features() {
	cat <<- _end_of_text
	${MAGENTA}
	######################
	# Supported Features #
	######################
	${NORMAL}
	_end_of_text

	cat <<- _end_of_header >> "$WRITE_TO"

	/**********************/
	/* Supported Features */
	/**********************/
	_end_of_header

	##########
	# PYTHON #
	##########
	PYEXEC=$(command -pv python3 || command -pv python || command -pv python2)
	PYEXEC=${PYEXEC:-NONE}
	if [ -n "$PYEXEC" ]; then
		msg "PYTHON EXECUTABLE" "$PYEXEC"
		append "#define __DAI_HAS_PYTHON 1"
		append "#define __DAI_PYTHON_EXECUTABLE \"$PYEXEC\""

		PYV=$($PYEXEC --version | cut -d' ' -f2)
		PYV=${PYV:-0.0.0}
		msg "PYTHON VERSION" "$PYV"
		append "#define __DAI_PYTHON_VERSION \"$PYV\""
		append "#define __DAI_PYTHON_MAJOR_VERSION $(echo $PYV | cut -d. -f1)"
		append "#define __DAI_PYTHON_MINOR_VERSION $(echo $PYV | cut -d. -f2)"
		append "#define __DAI_PYTHON_SUBMINOR_VERSION $(echo $PYV | cut -d. -f3)"
	fi


	###############
	# ANSI COLORS #
	###############
	msg "ANSI COLORS" "$HAS_COLORS"
	append ""
	append "#define __DAI_HAS_ANSI_COLORS $HAS_COLORS"


	##############
	# BACKTRACES #
	##############
	cc config/backtraces.c -o backtraces.cfg 2>/dev/null
	./backtraces.cfg 2>/dev/null
	ret=$(expr $? = 0)
	msg "BACKTRACES" "$ret"
	append ""
	append "#define __DAI_HAS_BACKTRACES $ret"
	rm backtraces.cfg 2>/dev/null

	####################
	# LABELS AS VALUES #
	####################
	cc config/label_values.c -o label_values.cfg 2>/dev/null
	ret=$(expr $? = 0)
	msg "LABEL VALUES" "$ret"
	append ""
	append "#define __DAI_HAS_LABEL_VALUES $ret"
	rm label_values.cfg 2>/dev/null
}

write_config() {

	test_compatibility

	cat <<- _end_of_guard > "$WRITE_TO"
	#pragma once
	#ifndef __DAI_STDLIB_GENERATEDCONFIG
	#define __DAI_STDLIB_GENERATEDCONFIG
	_end_of_guard

	config_variables
	supported_features

	append "#endif $IN_CMT"
}

set_colors
write_config


cat << _end_of_status
${MAGENTA}
Wrote config file to:
${NORMAL}${WRITE_TO}
_end_of_status
