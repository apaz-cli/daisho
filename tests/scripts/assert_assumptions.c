#include "../../stdlib/Native/Daisho.h"

/*****************************************/
/* LIST OF PLATFORM SPECIFIC ASSUMPTIONS */
/*****************************************/

/*
 *
 *
 *
 *
 */

static inline void
types_valid(void) {
    if (sizeof(uint32_t) != 4 * sizeof(uint8_t)) {
        fprintf(stderr,
                "The Daisho standard library is not supported on platforms "
                "where sizeof(uint32_t) != 4 * sizeof(uint8_t).");
        exit(1);
    }
}

static inline void
utf8_locale(void) {
    if (!setlocale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "Could not set locale to utf8.\n");
        exit(1);
    }
}

/* Returns cleanly on success, prints error message and exits on failure. */
typedef void (*Test)(void);

Test tests[] = {types_valid, utf8_locale};

int
main(void) {
    static size_t num_tests = (sizeof(tests) / sizeof(Test));
    for (size_t i = 0; i < num_tests; i++) tests[i]();

    puts("SUCCESS");
}
