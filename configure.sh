#!/usr/bin/env sh

# To be run from the root directory of the project.

#########################
# GLOBALS AND CONSTANTS #
#########################


#######################
# CONFIG FILE HELPERS #
#######################

# Generates a config file by appending to WRITE_TO, then copying to COPY_TO.
# Prints pretty messages along the way.
WRITE_TO="/tmp/GeneratedConfig.h"
COPY_TO="stdlib/Native/Configs/GeneratedConfig.h"
rm "$WRITE_TO" 2>/dev/null
touch "$WRITE_TO"

COLS=$(expr $(stty size | cut -d' ' -f2) - 23)
[ $COLS -gt 90 ] && COLS=57
IN_CMT="/* _DAI_STDLIB_GENERATEDCONFIG */"


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
	cat <<-_end_of_text
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
	cc config/assertions.c -D_DAI_RUNNING_CONFIGURE_SCRIPT -o assertions.cfg 1>/dev/null && msg "ASSERTIONS" "PASSED" ||
		warn "Daisho is not supported on this system for the reason specified in the error message above"
	rm assertions.cfg 2>/dev/null

	# endianness
	echo -n I | od -to2 | awk 'FNR==0{ print substr($2,6,1)}' && msg "ENDIANNESS" "PASSED" ||
		warn "Daisho is not supported on Big-Endian or Unknown-Endianness machines."

	# locale
	cc config/locale.c -D_DAI_RUNNING_CONFIGURE_SCRIPT -o locale.cfg 1>/dev/null 2>&1
	./locale.cfg && msg "UTF8 LOCALE" "PASSED" ||
		warn "Daisho is not supported on systems that do not support the \"C.UTF-8\" locale."
	rm locale.cfg 2>/dev/null

	# strerror_r
	cc config/strerror_r.c -D_DAI_RUNNING_CONFIGURE_SCRIPT -o strerror_r.cfg 1>/dev/null 2>&1
	./strerror_r.cfg && msg "STRERROR_R" "PASSED" ||
	        warn "Daisho is not supported on systems without an XSI-compliant implementation of strerror_r."
	rm strerror_r.cfg 2>/dev/null

}

#################################
#                               #
#    CONFIGURATION VARIABLES    #
#                               #
#################################
config_variables() {
	cat <<-_end_of_text
		${MAGENTA}
		###########################
		# Configuration Variables #
		###########################
		${NORMAL}
	_end_of_text

	cat <<-_end_of_header >>"$WRITE_TO"

		/***************************/
		/* Configuration Variables */
		/***************************/
	_end_of_header

	# page size
	PAGESIZE=$(getconf PAGE_SIZE)
	msg "PAGE SIZE" "$PAGESIZE"
	append "#define _DAI_PAGESIZE $PAGESIZE"

	#################
	# THREAD NUMBER #
	#################
	THREADS=$(grep -c processor /proc/cpuinfo)
	msg "THREADS" "$THREADS"
	append "#define _DAI_IDEAL_NUM_THREADS $THREADS"

	###############
	# STDLIB PATH #
	###############
	LIBPATH=$(realpath stdlib/)
	msg "LIBPATH" "$LIBPATH"
	append "#define _DAIC_LIB_INCLUDE_PATH \"$LIBPATH\""
}

gitrev() {
	LONGREV=$(git rev-parse HEAD)
	SHORTREV=$(git rev-parse --short HEAD)
	VERSION_MAJOR="0"
	VERSION_MINOR="0"
	VERSION_SUBMINOR="1"

	cat <<-_end_of_text
		${MAGENTA}
		###########
		# Version #
		###########
		${NORMAL}
	_end_of_text

	cat <<-_end_of_header >>"$WRITE_TO"

		/***********/
		/* Version */
		/***********/
	_end_of_header

	msg "Version" "0.0.1"
	append "#define _DAI_VERSION \"$VERSION_MAJOR.$VERSION_MINOR.$VERSION_SUBMINOR\""
	append "#define _DAI_VERSION_MAJOR $VERSION_MINOR"
	append "#define _DAI_VERSION_MINOR $VERSION_MAJOR"
	append "#define _DAI_VERSION_SUBMINOR $VERSION_SUBMINOR"

	msg "Revision" "$LONGREV"
	append "#define _DAI_SHORT_REV \"$SHORTREV\""
	append "#define _DAI_LONG_REV \"$LONGREV\""
}

############################
#                          #
#    SUPPORTED FEATURES    #
#                          #
############################
supported_features() {
	cat <<-_end_of_text
		${MAGENTA}
		######################
		# Supported Features #
		######################
		${NORMAL}
	_end_of_text

	cat <<-_end_of_header >>"$WRITE_TO"

		/**********************/
		/* Supported Features */
		/**********************/
	_end_of_header

	###############
	# ANSI COLORS #
	###############
	msg "ANSI COLORS" "$HAS_COLORS"
	append "#define _DAI_HAS_ANSI_COLORS $HAS_COLORS"

	##############
	# BACKTRACES #
	##############
	cc config/backtraces.c -D_DAI_RUNNING_CONFIGURE_SCRIPT -o backtraces.cfg 2>/dev/null
	./backtraces.cfg 2>/dev/null
	ret=$(expr $? = 0)
	msg "BACKTRACES" "$ret"
	append "#define _DAI_HAS_BACKTRACES $ret"
	rm backtraces.cfg 2>/dev/null

	####################
	# LABELS AS VALUES #
	####################
	cc config/label_values.c -D_DAI_RUNNING_CONFIGURE_SCRIPT -o label_values.cfg 2>/dev/null
	ret=$(expr $? = 0)
	msg "LABEL VALUES" "$ret"
	append "#define _DAI_HAS_LABEL_VALUES $ret"
	rm label_values.cfg 2>/dev/null

	append ""
}

write_config() {

	test_compatibility

	cat <<-_end_of_guard >"$WRITE_TO"
		#pragma once
		#ifndef _DAI_STDLIB_GENERATEDCONFIG
		#define _DAI_STDLIB_GENERATEDCONFIG
	_end_of_guard

	gitrev

	config_variables
	supported_features

	append "#endif $IN_CMT"
}

set_colors
write_config

cp "$WRITE_TO" "$COPY_TO"
cat <<_end_of_status
${MAGENTA}
Wrote config file to:
${NORMAL}${COPY_TO}
_end_of_status
