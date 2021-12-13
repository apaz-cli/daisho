#pragma once
#ifndef __STILTS_STDLIB_START
#define __STILTS_STDLIB_START
#include "../StiltsStdInclude.h"
#include "../StiltsPython/StiltsPython.h"

/* Routines that should happen before main(). */

/*********/
/* Start */
/*********/

__STILTS_FN void
__Stilts_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, "")) {
        fprintf(stderr, "Could not set locale to system locale.\n");
        exit(70);
    }
}

__STILTS_FN void
__Stilts_pre_main(int argc, char** argv) {
    /* Start python (which sets the locale),
       or set the locale ourselves. */
#if __STILTS_EMBED_PYTHON
    __Stilts_py_init(argc, argv);
#else
    (void) argc; (void)argv;
    __Stilts_setlocale();
#endif
}


/********/
/* Exit */
/********/

__STILTS_FN __STILTS_NORETURN void
__Stilts_exit(int code) {
#if __STILTS_EMBED_PYTHON
    __Stilts_py_exit();
#endif
    exit(code);
}

#endif /* __STILTS_STDLIB_START */
