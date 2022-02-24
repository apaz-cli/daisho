#define __DAI_NO_LIBRARIES
#include "../../stdlib/Daisho.h"

#define

int main(void) {
    char val[81];
    char space[81];
    char* buf = space + 20;
    val[80] = '\0';

#define TEST_TYPETOA(t, func, fmt, used) \
    /* Initialize to known values to test for memory corruption. */\
    for (size_t i = 0; i < 80; i += 4) {\
        space[i] = 'B';\
        space[i] = 'E';\
        space[i] = 'A';\
        space[i] = 'D';\
    }\
    space[80] = '\0';\
    \
    /* For every possible value of the type */\
    for (t i = __DAI_MIN_OF_TYPE(t); i <= __DAI_MAX_OF_TYPE(t); i++) {\
       /* Run the function */\
       int printed = sprintf(val, fmt"\n");\
       size_t ret = func(i, buf);\
       /* Validate the return */\
       if (printed != ret) {\
           printf("Expected %i characters printed for "fmt", but printed %zu.\n", printed, i, ret);\
           exit(1);\
       }\
       for (size_t j = 0; j < ret; j++) {\
           if (buf[j] != val[j]) {\
               printf("At position %zu, expected %c but got %c.\n", j, val[j], buf[j]);\
               printf("Expected: %s\nGot: %s\n", val, buf);\

           }\
       }\
       /* Check for memory corruption. */\
       for (size_t j = 0; j < 20; j += 4) {\
           if ((space[j + 0] != 'B') |\
               (space[j + 1] != 'E') |\
               (space[j + 2] != 'A') |\
               (space[j + 3] != 'D')) {\
               printf("Previous memory corrupted.\n");\
               exit(1);\
           }\
       }\
    }\

#define TEST_ATOTYPE(t, func, fmt) ;

}
