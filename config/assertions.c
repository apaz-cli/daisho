#ifndef __cplusplus
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#else
#include <limits>
#include <signal>
#include <stddef>
#include <stdint>
#include <wchar>
#endif

#define __STILTS_ASSERTING 1
#include "../stdlib/Native/PreProcessor/StiltsPreprocessor.h"

__STILTS_STATIC_ASSERT(CHAR_BIT == 8,
                       "Stilts's implementation of String assumes CHAR_BIT to be 8.");
__STILTS_STATIC_ASSERT(SIZE_MAX <= UINT64_MAX,
                       "The Stilts standard library assumes that size_t's max value "
                       "is less than or equal to uint64_t's max value.");

__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(clock_t) > UINT32_MAX,
                       "The Stilts standard library assumes that the max value "
                       "of clock_t is more than 32 bits.");

/*
 * Make sure the numeric limits macros work on this system.
 * If integral types have padding bits in them, they might not.
 * Such an implementation would be very rare.
 */

__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(char) == CHAR_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(char) == CHAR_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(unsigned char) == UCHAR_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(short) == SHRT_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(short) == SHRT_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(unsigned short) == USHRT_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(int) == INT_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(int) == INT_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(unsigned int) == UINT_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(long) == LONG_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(long) == LONG_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(unsigned long) == ULONG_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(long long) == LLONG_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(long long) == LLONG_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(unsigned long long) == ULLONG_MAX, "");

__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(ptrdiff_t) == PTRDIFF_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(ptrdiff_t) == PTRDIFF_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(size_t) == SIZE_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(sig_atomic_t) == SIG_ATOMIC_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(sig_atomic_t) == SIG_ATOMIC_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(wchar_t) == WCHAR_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(wchar_t) == WCHAR_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(wint_t) == WINT_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(wint_t) == WINT_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MIN_OF_TYPE(intmax_t) == INTMAX_MIN, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(intmax_t) == INTMAX_MAX, "");
__STILTS_STATIC_ASSERT(__STILTS_MAX_OF_TYPE(uintmax_t) == UINTMAX_MAX, "");

int
main() {
    return 0;
}
