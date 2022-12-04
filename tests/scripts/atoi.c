#define _DAI_NO_LIBRARIES
#include "../../stdlib/Daisho.h"

int
main(void) {
    //char space[80];
    // TODO write
#define TEST_ATOTYPE(t, func, fmt)                                     \
    for (t i = _DAI_MIN_OF_TYPE(t); i <= _DAI_MAX_OF_TYPE(t); i++) { \
        /* Write a string to decode. */                                \
        int written = sprintf(valid, fmt, i);                          \
    }
}
