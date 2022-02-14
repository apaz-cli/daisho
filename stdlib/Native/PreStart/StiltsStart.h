#ifndef __DAI_STDLIB_START
#define __DAI_STDLIB_START
#include "../PreProcessor/DaishoPreprocessor.h"
#include "DaishoBuffering.h"
#include "DaishoPython.h"

/* Routines that should happen before main(). */

/*********/
/* Start */
/*********/

__DAI_FN void
__Dai_signal(void) {}

__DAI_FN void
__Dai_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, "")) {
        fprintf(stderr, "Could not set locale to system locale.\n");
        exit(70);
    }
}

__DAI_FN void
__Dai_pre_main(int argc, char** argv) {

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
