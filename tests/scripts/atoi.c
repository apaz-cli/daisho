#define __DAI_NO_LIBRARIES
#include "../../stdlib/Daisho.h"

int
main(void) {
    char space[80];

#define TEST_ATOTYPE(t, func, fmt)                                     \
    for (t i = __DAI_MIN_OF_TYPE(t); i <= __DAI_MAX_OF_TYPE(t); i++) { \
        /* Write a string to decode. */                                \
        int written = sprintf(valid, fmt, i);                          \
    }
}
