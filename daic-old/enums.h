#ifndef DAIC_ENUMS_INCLUDE
#define DAIC_ENUMS_INCLUDE
#include "../stdlib/Daisho.h"

#define STAGES                                      \
    X(ARGS, _DAI_COLOR_BLUE, "Argument Parsing")    \
    X(TOKENIZER, _DAI_COLOR_YELLOW, "Tokenization") \
    X(PARSER, _DAI_COLOR_MAGENTA, "Parsing")        \
    X(TYPING, _DAI_COLOR_CYAN, "Type Checking")     \
    X(CODEGEN, _DAI_COLOR_GREEN, "Code Generation") \
    X(OTHER, _DAI_COLOR_RED, "Other")

#define X(name, color, disp) DAIC_ERROR_STAGE_##name,
typedef enum { STAGES } DaicStage;
#undef X

#define X(name, color, disp) color,
static char* daic_stagecolor[] = {STAGES};
#undef X

#define X(name, color, disp) disp,
static char* daic_stagedisplay[] = {STAGES};
#undef X

#undef STAGES
#define SEVS                                            \
    X(INFO, _DAI_COLOR_BLUE, "INFO", "Info", "info")    \
    X(WARN, _DAI_COLOR_MAGENTA, "WARN", "Warn", "warn") \
    X(ERROR, _DAI_COLOR_RED, "ERROR", "Error", "error") \
    X(PANIC, _DAI_COLOR_RED, "PANIC", "Panic", "panic")

#define X(name, color, up, cap, low) _DAIC_ERROR_SEV_##name,
typedef enum { SEVS } DaicSeverity;
#undef X

#define X(name, color, up, cap, low) up,
static char* daic_sevstr_upper[] = {SEVS};
#undef X

#define X(name, color, up, cap, low) low,
static char* daic_sevstr_lower[] = {SEVS};
#undef X

#define X(name, color, up, cap, low) cap,
static char* daic_sevstr_capital[] = {SEVS};
#undef X

#define X(name, color, up, cap, low) color,
static char* daic_sevstr_color[] = {SEVS};
#undef X

#undef SEVS

#endif /* DAIC_ENUMS_INCLUDE */
