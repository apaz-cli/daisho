#ifndef __STILTS_STDLIB_START
#define __STILTS_STDLIB_START
#include "../PreProcessor/StiltsPreprocessor.h"
#include "StiltsPython.h"

/* Routines that should happen before main(). */

/*********/
/* Start */
/*********/

__STILTS_FN void
__Stilts_signal(void) {}

__STILTS_FN void
__Stilts_setlocale(void) {
    /* I'm putting off messing with this until it inevitably becomes a problem. */
    if (!setlocale(LC_ALL, "")) {
        fprintf(stderr, "Could not set locale to system locale.\n");
        exit(70);
    }
}

__STILTS_FN void
__Stilts_configure_buffering() {
#if __STILTS_OUTPUT_BUFFERING == 0 /* No buffering */
    char errmsg[] = "Could not set unbuffered stdout/stderr output.";
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
    char errmsg[] = "Could not set fully buffered stdout/stderr output.";
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
__Stilts_pre_main(int argc, char** argv) {
    __Stilts_configure_buffering();

    /* Start python (which sets the locale),
       or set the locale ourselves. */
#if __STILTS_EMBED_PYTHON
    __Stilts_py_init(argc, argv);
#else
    (void)argc;
    (void)argv;
    __Stilts_setlocale();
#endif
}

/********/
/* Exit */
/********/

__STILTS_FN __STILTS_NORETURN void
__Stilts_exit(int code) {
#if __STILTS_EMBED_PYTHON
    __Stilts_py_exit();
#endif
    exit(code);
}

#endif /* __STILTS_STDLIB_START */
