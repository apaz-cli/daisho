#ifndef __DAI_STDLIB_START
#define __DAI_STDLIB_START
#include "../PreProcessor/PreProcessor.h"
#include "Mutex.h"

/* Routines that should happen before main(). */

/*********/
/* To be called in Start */
/*********/

/* __Dai_configure_buffering() */
#include "Buffering.h"

/* __Dai_py_init() */
#include "Python.h"

/* Stack Traces */
static char __Dai_stacktrace_buffer[50];
static __Dai_Mutex __Dai_stacktrace_mutex = __DAI_MUTEX_INITIALIZER;
__DAI_FN void
__Dai_configure_signals(void) {}

/* Locale */
__DAI_FN void
__Dai_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, __DAI_LOCALE)) {
        fprintf(stderr, "Could not set locale to the \"" __DAI_LOCALE " locale.");
        exit(70);
    }
}

/******************/
/* Start Function */
/******************/

__DAI_FN void
__Dai_initialize(int argc, char** argv) {
    /* Start python (which sets the locale),
       or set the locale ourselves. */
#if __DAI_EMBED_PYTHON
    __Dai_py_init(argc, argv);
#else
    (void)argc;
    (void)argv;
    __Dai_setlocale();
#endif

    /* Configure stdio buffering. The python runtime, if we're using it,
       has been configured not to mess this up. */
    __Dai_configure_buffering();
}

/********/
/* Exit */
/********/

__DAI_FN __DAI_NORETURN void
__Dai_exit(int code) {
#if __DAI_EMBED_PYTHON
    __Dai_py_exit();
#endif
    exit(code);
}

#endif /* __DAI_STDLIB_START */
