#ifndef __cplusplus
#define __STILTS_STATIC_ASSERT(x, msg) _Static_assert(x, msg)
#else
#define __STILTS_STATIC_ASSERT(x, msg) static_assert(x, msg)
#endif

#include "stdint.h"

__STILTS_STATIC_ASSERT(
    SIZE_MAX <= UINT64_MAX,
    "The Stilts standard library assumes that size_t's max value "
    "is less than or equal to uint64_t's max value.");

int main() {
    return 0;
}
