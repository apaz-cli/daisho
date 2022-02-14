#ifndef __DAI_STDLIB_BUFFERING
#define __DAI_STDLIB_BUFFERING

#include "../PreProcessor/DaishoPreprocessor.h"

__DAI_FN void
__Dai_configure_buffering() {


#if __DAI_OUTPUT_BUFFERING == 0 /* No buffering */
    char errmsg0[] = "Could not set unbuffered IO.";
    if (setvbuf(stdout, NULL, _IONBF, 0) && (__DAI_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) && (__DAI_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
#elif __DAI_OUTPUT_BUFFERING == 1 /* Line buffering */
    /* Line buffering is the default in the C standard. */
    // char errmsg1[] = "Could not set line buffered IO.";
    // setvbuf(stdout, NULL, _IOLBF, 0);
#elif __DAI_OUTPUT_BUFFERING == 2 /* Full buffering */
    char errmsg2[] = "Could not set fully buffered IO.";
    if (setvbuf(stdout, NULL, _IOFBF, 0) && (__DAI_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IOFBF, 0) && (__DAI_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
#else
    __DAI_STATIC_ASSERT(false, "__DAI_OUTPUT_BUFFERING may only be 0, 1, or 2.");
#endif
}

__DAI_FN void
__Dai_newline_flush(FILE* file) {
#if __DAI_OUTPUT_BUFFERING == 2
    fflush(file);
#else
    (void)file;
#endif
}

#endif /* __DAI_STDLIB_BUFFERING */
