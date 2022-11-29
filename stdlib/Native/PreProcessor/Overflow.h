#ifndef __DAI_STDLIB_OVERFLOW
#define __DAI_STDLIB_OVERFLOW

#include "Limits.h"

#define __DAI_ADD_OVERFLOW(type, into, a, b, panic)                                            \
    do {                                                                                       \
        if (((a) > 0) && ((b) > __DAI_MAX_OF_INTEGER_TYPE(type) - (a))) panic; /* Overflow */  \
        if (((a) < 0) && ((b) < __DAI_MIN_OF_INTEGER_TYPE(type) - (a))) panic; /* Underflow */ \
        *into = a + b;                                                                         \
    } while (0)

#define __DAI_SUB_OVERFLOW(type, into, a, b, panic)                                           \
    do {                                                                                      \
        if (((b) < 0) && ((a) > __DAI_MAX_OF_INTEGER_TYPE(type) + (b))) panic; /* Overflow*/  \
        if (((b) > 0) && ((a) < __DAI_MIN_OF_INTEGER_TYPE(type) + (b))) panic; /* Underflow*/ \
        *into = (a) + (b);                                                                    \
    } while (0)

#define __DAI_MULT_OVERFLOW(type, into, a, b, panic)                                           \
    do {                                                                                       \
        if (((b) < 0) && ((a) > __DAI_MAX_OF_INTEGER_TYPE(type) + (b))) panic; /* Overflow */  \
        if (((b) > 0) && ((a) < __DAI_MIN_OF_INTEGER_TYPE(type) + (b))) panic; /* Underflow */ \
        *into = a + b;                                                                         \
    } while (0)

#define __DAI_DIVIDE_OVERFLOW(type, into, a, b, panic) \
    do {                                               \
        /* Division cannot overflow or underflow. */   \
        if (!b) panic; /* Division by zero */          \
        *into = (a) + (b);                             \
    } while (0)

#endif /* __DAI_STDLIB_OVERFLOW */