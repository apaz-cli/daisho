#ifndef __DAI_STDLIB_STRCONVERT
#define __DAI_STDLIB_STRCONVERT
#include "../PreProcessor/PreProcessor.h"

/*
 * Convert int types to ascii.
 *
 * Ex: 100 -> "100"
 *
 * Writes the ascii representation of i to a.
 * Does not null terminate.
 *
 * returns the number of characters written to a.
 *
 * For the number of characters required to format
 * into, see the macro __DAI_<type>TOA_SPACE() for each
 * function.
 */

#define __DAI_STOA_SPACE 6
#define __DAI_USTOA_SPACE 5
#define __DAI_ITOA_SPACE 11
#define __DAI_UITOA_SPACE 10
#define __DAI_LTOA_SPACE 20
#define __DAI_ULTOA_SPACE 20

__DAI_FN size_t __Dai_stoa(short s, char* a);
__DAI_FN size_t __Dai_ustoa(unsigned short us, char* a);
__DAI_FN size_t __Dai_itoa(int i, char* a);
__DAI_FN size_t __Dai_uitoa(unsigned int ui, char* a);
__DAI_FN size_t __Dai_ltoa(long l, char* a);
__DAI_FN size_t __Dai_ultoa(unsigned long ul, char* a);

__DAI_FN size_t
__Dai_ultoa(unsigned long ul, char* a) {
    const char digits[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    char space[__DAI_ULTOA_SPACE];
    size_t copied = 0;

    // Write number into temp buffer from the back
    do {
        space[__DAI_ULTOA_SPACE - (++copied)] = digits[ul % 10];
    } while ((ul /= 10) != 0);

    // Copy into result
    for (size_t z = 0; z < copied; z++) {
        a[z] = space[(__DAI_ULTOA_SPACE - copied) + z];
    }

    return copied;
}

__DAI_FN size_t
__Dai_ltoa(long l, char* a) {
    size_t neg = (l < 0);
    if (neg) *a++ = '-';  // Casting before conversion works for abs(LONG_MIN).
    return neg + __Dai_ultoa((neg ? -(unsigned long)l : l), a);
}

/*
 * Convert ascii to int types.
 *
 * Ex:                            return,   ret
 *     __Dai_atoi("1000a", &ret)  -> 1000, "1000a" (parsed successfully)
 *                                              ^
 *     __Dai_atoi("abcde", &ret)  -> ????,  NULL   (doesn't match pattern)
 *
 *     __Dai_atos("-99999", &ret) -> ????,  NULL   (overflow / underflow)
 *
 *
 * Parses and returns a number from its ascii representation a.
 * The ascii representation is expected to be a null or nondigit
 * terminated string matching the pattern:
 *
 *     [+-]?[0-9]+
 *
 * An error is thrown if the ascii string does not match this
 * pattern, or would overflow/underflow the type being parsed.
 * As many digits are matched as possible.
 *
 * On success, writes the position to resume parsing from to ret,
 * directly after the parsed digits.
 *
 * On error, writes NULL to ret.
 */

__DAI_FN short __Dai_atos(char* a, char** ret);
__DAI_FN unsigned short __Dai_atous(char* a, char** ret);
__DAI_FN int __Dai_atoi(char* a, char** ret);
__DAI_FN unsigned int __Dai_atoui(char* a, char** ret);
__DAI_FN long __Dai_atol(char* a, char** ret);
__DAI_FN unsigned long __Dai_atoul(char* a, char** ret);

/* Pointer to Hex */
__DAI_FN int __Dai_ptoh(void* ptr, char* h, size_t s);

#endif /* __DAI_STDLIB_STRCONVERT */
