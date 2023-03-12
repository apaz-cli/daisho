#ifndef _DAI_STDLIB_START
#define _DAI_STDLIB_START
#include "../PreProcessor/PreProcessor.h"
#include "Mutex.h"

/* Routines that should happen before main(). */

/*********/
/* To be called in Start */
/*********/

/* _Dai_configure_buffering() */
#include "Buffering.h"

/* Stack Traces */
static char _Dai_stacktrace_buffer[50];
static _Dai_Mutex _Dai_stacktrace_mutex = _DAI_MUTEX_INITIALIZER;
_DAI_FN void
_Dai_configure_signals(void) {}

/* Locale */
_DAI_FN void
_Dai_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, _DAI_LOCALE)) {
        fprintf(stderr, "Could not set locale to the \"" _DAI_LOCALE " locale.");
        exit(70);
    }
}

/******************/
/* Start Function */
/******************/

_DAI_FN void
_Dai_initialize(int argc, char** argv) {
    /* Start python (which sets the locale),
       or set the locale ourselves. */
    (void)argc;
    (void)argv;
    _Dai_setlocale();

    /* Configure stdio buffering. The python runtime, if we're using it,
       has been configured not to mess this up. */
    _Dai_configure_buffering();
}

/********/
/* Exit */
/********/

_DAI_FN _DAI_NORETURN void
_Dai_exit(int code) {
    exit(code);
}

#endif /* _DAI_STDLIB_START */
