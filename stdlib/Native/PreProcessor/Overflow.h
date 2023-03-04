#ifndef _DAI_STDLIB_OVERFLOW
#define _DAI_STDLIB_OVERFLOW

#include "Limits.h"

#define _DAI_ADD_OVERFLOW(type, a, b, panic)                \
    (((((a) > 0) & ((b) > _DAI_MAX_OF_TYPE(type) - (a))) || \
      (((a) < 0) & ((b) < _DAI_MAX_OF_TYPE(type) - (a))))   \
         ? (panic)                                          \
         : (a) + (b))

#define _DAI_SUB_OVERFLOW(type, a, b, panic)                \
    (((((b) < 0) & ((a) > _DAI_MAX_OF_TYPE(type) + (b))) || \
      (((b) > 0) & ((a) < _DAI_MAX_OF_TYPE(type) + (b))))   \
         ? (panic)                                          \
         : (a) - (b))

#define _DAI_MUL_OVERFLOW(type, a, b, panic)                 \
    (((((b) != 0) & ((a) > _DAI_MAX_OF_TYPE(type) / (b))) || \
      (((b) != 0) & ((a) < _DAI_MAX_OF_TYPE(type) / (b))))   \
         ? (panic)                                           \
         : (a) * (b))

#define _DAI_DIV_OVERFLOW(type, a, b, panic) (((b) == 0) ? (panic) : (a) / (b))

#endif /* _DAI_STDLIB_OVERFLOW */
