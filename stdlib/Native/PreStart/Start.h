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

/* */
#include "Backtrace.h"


/* Locale */
_DAI_FN void
_Dai_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, _DAI_LOCALE))
        if (!setlocale(LC_ALL, "C.UTF-8"))
            if (!setlocale(LC_ALL, "en_US.UTF-8"))
                _DAI_INIT_ASSERT(false, "Could not set the locale to utf8.");
}

_DAI_FN void
_Dai_initialize(void) {
    _Dai_setlocale();
    _Dai_configure_buffering();
}

#endif /* _DAI_STDLIB_START */
