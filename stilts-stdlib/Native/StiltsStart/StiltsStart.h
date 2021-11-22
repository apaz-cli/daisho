#ifndef __STILTS_STDLIB_START
#define __STILTS_STDLIB_START
#include "../StiltsStdInclude.h"

/* Routines that should happen before main(). */

static inline void
__Stilts_setlocale() {
    if (!setlocale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "Could not set locale to utf8.\n");
        exit(70);
    }
}

static inline void
__Stilts_pre_main() {
    __Stilts_setlocale();
}

#endif /* __STILTS_STDLIB_START */