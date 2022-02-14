#ifndef __cplusplus
#include <float.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#else
#include <cfloat>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#endif

/* Don't include external libraries. */
#define __DAI_ASSERTING 1
#include "../stdlib/Native/PreProcessor/DaishoPreprocessor.h"

__DAI_STATIC_ASSERT(__STDC_VERSION__ >= 201112L, "Daisho requires a C11 compiler or above.");

__DAI_STATIC_ASSERT(CHAR_BIT == 8,
                       "Daisho's implementation of String assumes CHAR_BIT to be 8.");

__DAI_STATIC_ASSERT(SIZE_MAX <= UINT64_MAX,
                       "The Daisho standard library assumes that size_t's max value "
                       "is less than or equal to uint64_t's max value.");

__DAI_STATIC_ASSERT(__DAI_MAX_OF_INTEGER_TYPE(clock_t) > UINT32_MAX,
                       "The Daisho standard library assumes that the max value "
                       "of clock_t is more than 32 bits.");

__DAI_STATIC_ASSERT((~(long)0U) == (long)(-1),
                       "The Daisho standard library assumes "
                       "that the archetecture uses two's complement to represent "
                       "numbers.");

/*
 * Make sure the numeric limits macros work on this system.
 * If integral types have padding bits in them, they might not.
 * Such an implementation would be very rare.
 */

#define TWOS_COMPLEMENT(type)                                                             \
    __DAI_STATIC_ASSERT(!__DAI_IS_TYPE_SIGNED(type) ? 1 : (~(type)0) == (type)(-1), \
                           #type " is not represented as two's complement.");

#define ASSERT_TYPE(type, min, max)                                        \
    TWOS_COMPLEMENT(type)                                                  \
    __DAI_STATIC_ASSERT(__DAI_MIN_OF_INTEGER_TYPE(type) == min, ""); \
    __DAI_STATIC_ASSERT(__DAI_MAX_OF_INTEGER_TYPE(type) == max, "");

#define ASSERT_FLOAT_TYPE(type, min, max)                     \
    if (__DAI_MIN_OF_FLOATING_TYPE(type) != min) return 1; \
    if (__DAI_MAX_OF_FLOATING_TYPE(type) != max) return 1;

ASSERT_TYPE(char, CHAR_MIN, CHAR_MAX)
ASSERT_TYPE(unsigned char, 0, UCHAR_MAX)
ASSERT_TYPE(short, SHRT_MIN, SHRT_MAX)
ASSERT_TYPE(unsigned short, 0, USHRT_MAX)
ASSERT_TYPE(int, INT_MIN, INT_MAX)
ASSERT_TYPE(unsigned int, 0, UINT_MAX)
ASSERT_TYPE(long, LONG_MIN, LONG_MAX)
ASSERT_TYPE(unsigned long, 0, ULONG_MAX)
ASSERT_TYPE(long long, LLONG_MIN, LLONG_MAX)
ASSERT_TYPE(unsigned long long, 0, ULLONG_MAX)

ASSERT_TYPE(ptrdiff_t, PTRDIFF_MIN, PTRDIFF_MAX)
ASSERT_TYPE(size_t, 0, SIZE_MAX)
ASSERT_TYPE(sig_atomic_t, SIG_ATOMIC_MIN, SIG_ATOMIC_MAX)
ASSERT_TYPE(wint_t, WINT_MIN, WINT_MAX)
ASSERT_TYPE(intmax_t, INTMAX_MIN, INTMAX_MAX)
ASSERT_TYPE(uintmax_t, 0, UINTMAX_MAX)

int
main(void) {
    /* Unfortunately , _Static_assert cannot */
    ASSERT_FLOAT_TYPE(float, FLT_MIN, FLT_MAX)
    ASSERT_FLOAT_TYPE(double, DBL_MIN, DBL_MAX)
    ASSERT_FLOAT_TYPE(long double, LDBL_MIN, LDBL_MAX)
}
