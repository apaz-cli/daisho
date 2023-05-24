#ifndef _DAI_STDLIB_LOCALE
#define _DAI_STDLIB_LOCALE
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

_DAI_FN void
_Dai_setlocale(void) {
    /* I'm putting off messing with this further until it inevitably becomes a problem. */
    int do_check = 0;
    char* ret = setlocale(LC_ALL, _DAI_LOCALE);
    if (!ret) {
        do_check = 1;
        ret = setlocale(LC_ALL, "");
        if (!ret) _DAI_INIT_ASSERT(false, "Could not set the default locale.");
    }
    if (do_check && !(strstr(ret, "UTF-8") || strstr(ret, "utf8") || strstr(ret, "UTF8") ||
                      strstr(ret, "utf-8")))
        _DAI_INIT_ASSERT(false, "Could not set the locale to utf8.");
}

#endif /* _DAI_STDLIB_LOCALE */
