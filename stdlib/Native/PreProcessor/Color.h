#ifndef __DAI_STDLIB_COLOR
#define __DAI_STDLIB_COLOR

#ifndef __DAI_ANSI_TERMINAL
#ifdef _WIN32
#define __DAI_ANSI_TERMINAL 0
#else
#define __DAI_ANSI_TERMINAL 1
#endif /* _WIN32 */
#endif /* __DAI_ANSI_TERMINAL */

#if __DAI_ANSI_TERMINAL
#define __DAI_COLOR_BLACK "\x1b[30m"
#define __DAI_COLOR_RED "\x1b[31m"
#define __DAI_COLOR_GREEN "\x1b[32m"
#define __DAI_COLOR_YELLOW "\x1b[33m"
#define __DAI_COLOR_BLUE "\x1b[34m"
#define __DAI_COLOR_MAGENTA "\x1b[35m"
#define __DAI_COLOR_CYAN "\x1b[36m"
#define __DAI_COLOR_RESET "\x1b[0m"
#else
#define __DAI_COLOR_BLACK ""
#define __DAI_COLOR_RED ""
#define __DAI_COLOR_GREEN ""
#define __DAI_COLOR_YELLOW ""
#define __DAI_COLOR_BLUE ""
#define __DAI_COLOR_MAGENTA ""
#define __DAI_COLOR_CYAN ""
#define __DAI_COLOR_RESET ""

#define __DAI_BT_COLOR_HEAD ""
#define __DAI_BT_COLOR_PNIC ""
#define __DAI_BT_COLOR_PNTR ""
#define __DAI_BT_COLOR_BYTE ""
#define __DAI_BT_COLOR_FILE ""
#define __DAI_BT_COLOR_FUNC ""
#define __DAI_BT_COLOR_LINE ""

#endif /* __DAI_ANSI_TERMINAL */

#define __DAI_COLOR_HEAD(str) __DAI_COLOR_RED str __DAI_COLOR_RESET
#define __DAI_COLOR_PNIC(str) __DAI_COLOR_RED str __DAI_COLOR_RESET
#define __DAI_COLOR_PNTR(str) __DAI_COLOR_MAGENTA str __DAI_COLOR_RESET
#define __DAI_COLOR_BYTE(str) __DAI_COLOR_BLUE str __DAI_COLOR_RESET
#define __DAI_COLOR_FILE(str) __DAI_COLOR_GREEN str __DAI_COLOR_RESET
#define __DAI_COLOR_FUNC(str) __DAI_COLOR_YELLOW str __DAI_COLOR_RESET
#define __DAI_COLOR_LINE(str) __DAI_COLOR_CYAN str __DAI_COLOR_RESET

#define __DAI_BT_COLOR_HEAD __DAI_COLOR_RED
#define __DAI_BT_COLOR_PNIC __DAI_COLOR_RED
#define __DAI_BT_COLOR_PNTR __DAI_COLOR_MAGENTA
#define __DAI_BT_COLOR_BYTE __DAI_COLOR_BLUE
#define __DAI_BT_COLOR_FILE __DAI_COLOR_GREEN
#define __DAI_BT_COLOR_FUNC __DAI_COLOR_YELLOW
#define __DAI_BT_COLOR_LINE __DAI_COLOR_CYAN

#endif /* __DAI_STDLIB_COLOR */
