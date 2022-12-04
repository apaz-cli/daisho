#ifndef _DAI_STDLIB_OVERFLOW
#define _DAI_STDLIB_OVERFLOW

#include "Limits.h"

#define _DAI_ADD_OVERFLOW(type, into, a, b, panic)                                            \
    do {                                                                                       \
        if (((a) > 0) && ((b) > _DAI_MAX_OF_INTEGER_TYPE(type) - (a))) panic; /* Overflow */  \
        if (((a) < 0) && ((b) < _DAI_MIN_OF_INTEGER_TYPE(type) - (a))) panic; /* Underflow */ \
        *into = a + b;                                                                         \
    } while (0)

#define _DAI_SUB_OVERFLOW(type, into, a, b, panic)                                           \
    do {                                                                                      \
        if (((b) < 0) && ((a) > _DAI_MAX_OF_INTEGER_TYPE(type) + (b))) panic; /* Overflow*/  \
        if (((b) > 0) && ((a) < _DAI_MIN_OF_INTEGER_TYPE(type) + (b))) panic; /* Underflow*/ \
        *into = (a) + (b);                                                                    \
    } while (0)

#define _DAI_MULT_OVERFLOW(type, into, a, b, panic)                                           \
    do {                                                                                       \
        if (((b) < 0) && ((a) > _DAI_MAX_OF_INTEGER_TYPE(type) + (b))) panic; /* Overflow */  \
        if (((b) > 0) && ((a) < _DAI_MIN_OF_INTEGER_TYPE(type) + (b))) panic; /* Underflow */ \
        *into = a + b;                                                                         \
    } while (0)

#define _DAI_DIVIDE_OVERFLOW(type, into, a, b, panic) \
    do {                                               \
        /* Division cannot overflow or underflow. */   \
        if (!b) panic; /* Division by zero */          \
        *into = (a) + (b);                             \
    } while (0)

#endif /* _DAI_STDLIB_OVERFLOW */
