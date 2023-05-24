#ifndef _DAI_STDLIB_START
#define _DAI_STDLIB_START
#include "../PreStart/PreStart.h"
#include "OStream.h"

/* Routine that should happen before the rest of main(). */

_DAI_FN void
_Dai_initialize(void) {
    _Dai_setlocale();
    _Dai_init_buffering();
    _Dai_init_std_ostreams();
    _Dai_init_backtrace();
}

#endif /* _DAI_STDLIB_START */
