#ifndef _DAI_STDLIB_COLOR
#define _DAI_STDLIB_COLOR

#ifndef _DAI_ANSI_TERMINAL
#ifdef _WIN32
#define _DAI_ANSI_TERMINAL 0
#else
#define _DAI_ANSI_TERMINAL 1
#endif /* _WIN32 */
#endif /* _DAI_ANSI_TERMINAL */

#if _DAI_ANSI_TERMINAL
#define _DAI_COLOR_BLACK   "\x1b[30m"
#define _DAI_COLOR_RED     "\x1b[31m"
#define _DAI_COLOR_GREEN   "\x1b[32m"
#define _DAI_COLOR_YELLOW  "\x1b[33m"
#define _DAI_COLOR_BLUE    "\x1b[34m"
#define _DAI_COLOR_MAGENTA "\x1b[35m"
#define _DAI_COLOR_CYAN    "\x1b[36m"
#define _DAI_COLOR_RESET   "\x1b[0m"
#else
#define _DAI_COLOR_BLACK ""
#define _DAI_COLOR_RED ""
#define _DAI_COLOR_GREEN ""
#define _DAI_COLOR_YELLOW ""
#define _DAI_COLOR_BLUE ""
#define _DAI_COLOR_MAGENTA ""
#define _DAI_COLOR_CYAN ""
#define _DAI_COLOR_RESET ""

#endif /* _DAI_ANSI_TERMINAL */

#define _DAI_COLOR_HEAD _DAI_COLOR_RED
#define _DAI_COLOR_PNIC _DAI_COLOR_RED
#define _DAI_COLOR_PNTR _DAI_COLOR_MAGENTA
#define _DAI_COLOR_BYTE _DAI_COLOR_BLUE
#define _DAI_COLOR_FILE _DAI_COLOR_GREEN
#define _DAI_COLOR_FUNC _DAI_COLOR_YELLOW
#define _DAI_COLOR_LINE _DAI_COLOR_CYAN

#endif /* _DAI_STDLIB_COLOR */
