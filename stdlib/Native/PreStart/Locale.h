#ifndef _DAI_STDLIB_LOCALE
#define _DAI_STDLIB_LOCALE
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

_DAI_FN void
_Dai_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, _DAI_LOCALE))
        if (!setlocale(LC_ALL, "C.UTF-8"))
            if (!setlocale(LC_ALL, "en_US.UTF-8"))
                _DAI_INIT_ASSERT(false, "Could not set the locale to utf8.");
}

#endif /* _DAI_STDLIB_LOCALE */
