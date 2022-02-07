#ifndef __STILTS_STDLIB_BUFFERING
#define __STILTS_STDLIB_BUFFERING

#include "../PreProcessor/StiltsPreprocessor.h"

__STILTS_FN void
__Stilts_configure_buffering() {


#if __STILTS_OUTPUT_BUFFERING == 0 /* No buffering */
    char errmsg0[] = "Could not set unbuffered IO.";
    if (setvbuf(stdout, NULL, _IONBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg0, strlen(errmsg0));
        exit(1);
    }
#elif __STILTS_OUTPUT_BUFFERING == 1 /* Line buffering */
    /* Line buffering is the default in the C standard. */
    // char errmsg1[] = "Could not set line buffered IO.";
    // setvbuf(stdout, NULL, _IOLBF, 0);
#elif __STILTS_OUTPUT_BUFFERING == 2 /* Full buffering */
    char errmsg2[] = "Could not set fully buffered IO.";
    if (setvbuf(stdout, NULL, _IOFBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IOFBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg2, strlen(errmsg2));
        exit(1);
    }
#else
    __STILTS_STATIC_ASSERT(false, "__STILTS_OUTPUT_BUFFERING may only be 0, 1, or 2.");
#endif
}

__STILTS_FN void
__Stilts_newline_flush(FILE* file) {
#if __STILTS_OUTPUT_BUFFERING == 2
    fflush(file);
#else
    (void)file;
#endif
}

#endif /* __STILTS_STDLIB_BUFFERING */
