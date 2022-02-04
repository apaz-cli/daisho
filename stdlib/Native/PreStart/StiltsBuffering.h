#ifndef __STILTS_STDLIB_BUFFERING
#define __STILTS_STDLIB_BUFFERING

#include "../PreProcessor/StiltsPreprocessor.h"

__STILTS_FN void
__Stilts_configure_buffering() {

    char errmsg0[] = "Could not set unbuffered IO.";
    char errmsg1[] = "Could not set line buffered IO.";
    char errmsg2[] = "Could not set fully buffered IO.";
    char* errmsgs[] = {errmsg0, errmsg1, errmsg2};

    int in, out, err;

    /* Determine the current buffering mode. */
#if __STILTS_EMBED_PYTHON
    
#else
    in = out = 1; err = 0;
#endif

#if __STILTS_OUTPUT_BUFFERING == 0 /* No buffering */
    if (setvbuf(stdout, NULL, _IONBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg, strlen(errmsg));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IONBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg, strlen(errmsg));
        exit(1);
    }
#elif __STILTS_OUTPUT_BUFFERING == 1 /* Line buffering */
    /* Line buffering is the default in the C standard. */
    // setvbuf(stdout, NULL, _IOLBF, 0);
#elif __STILTS_OUTPUT_BUFFERING == 2 /* Full buffering */
    if (setvbuf(stdout, NULL, _IOFBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDOUT_FILENO, errmsg, strlen(errmsg));
        exit(1);
    }
    if (setvbuf(stderr, NULL, _IOFBF, 0) && (__STILTS_SANITY_CHECK == 2)) {
        write(STDERR_FILENO, errmsg, strlen(errmsg));
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
