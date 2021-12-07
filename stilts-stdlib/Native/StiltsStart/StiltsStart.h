#pragma once
#ifndef __STILTS_STDLIB_START
#define __STILTS_STDLIB_START
#include "../StiltsStdInclude.h"
#include "../StiltsPython/StiltsPython.h"

/* Routines that should happen before main(). */

/*********/
/* Start */
/*********/

static inline void
__Stilts_setlocale(void) {
    if (!setlocale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "Could not set locale to utf8.\n");
        exit(70);
    }
}

static inline void
__Stilts_pre_main(int argc, char** argv) {
    __Stilts_setlocale();
#if __STILTS_EMBED_PYTHON
    __Stilts_py_init(argc, argv);
#endif
}


/********/
/* Exit */
/********/

static inline void __Stilts_exit(int code) {
#if __STILTS_EMBED_PYTHON
    __Stilts_py_exit();
#endif
    exit(code);
}

#endif /* __STILTS_STDLIB_START */
