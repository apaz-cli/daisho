#ifndef _DAI_STDLIB_BUFFERING
#define _DAI_STDLIB_BUFFERING

#include "../PreProcessor/PreProcessor.h"

_DAI_FN void
_Dai_configure_buffering(void) {


#if _DAI_OUTPUT_BUFFERING == 0 /* No buffering */
    char errmsg0[] = "Could not set unbuffered IO.";
    if (setvbuf(stdout, NULL, _IONBF, 0) && _DAI_SANE) {
        write(STDOUT_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) && _DAI_SANE) {
        write(STDERR_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
#elif _DAI_OUTPUT_BUFFERING == 1 /* Line buffering */
    /* Line buffering is the default in the C standard. */
    // char errmsg1[] = "Could not set line buffered IO.";
    // setvbuf(stdout, NULL, _IOLBF, 0);
#elif _DAI_OUTPUT_BUFFERING == 2 /* Full buffering */
    char errmsg2[] = "Could not set fully buffered IO.";
    if (setvbuf(stdout, NULL, _IOFBF, 0) && _DAI_SANE) {
        write(STDOUT_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IOFBF, 0) && _DAI_SANE) {
        write(STDERR_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
#else
    _DAI_STATIC_ASSERT(false, "_DAI_OUTPUT_BUFFERING may only be 0, 1, or 2.");
#endif
}

_DAI_FN void
_Dai_newline_flush(FILE* file) {
#if _DAI_OUTPUT_BUFFERING == 2
    fflush(file);
#else
    (void)file;
#endif
}

#endif /* _DAI_STDLIB_BUFFERING */
