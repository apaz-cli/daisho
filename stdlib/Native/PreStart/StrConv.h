#ifndef _DAI_STDLIB_STRCONVERT
#define _DAI_STDLIB_STRCONVERT
#include "../PreProcessor/PreProcessor.h"
#include "Error.h"

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
 * into, see the macro _DAI_<type>TOA_SPACE() for each
 * function.
 */

#define _DAI_STOA_SPACE 6
#define _DAI_USTOA_SPACE 5
#define _DAI_ITOA_SPACE 11
#define _DAI_UITOA_SPACE 10
#define _DAI_LTOA_SPACE 20
#define _DAI_ULTOA_SPACE 20

_DAI_FN size_t _Dai_stoa(short s, char* a);
_DAI_FN size_t _Dai_ustoa(unsigned short us, char* a);
_DAI_FN size_t _Dai_itoa(int i, char* a);
_DAI_FN size_t _Dai_uitoa(unsigned int ui, char* a);
_DAI_FN size_t _Dai_ltoa(long l, char* a);
_DAI_FN size_t _Dai_ultoa(unsigned long ul, char* a);

_DAI_FN size_t
_Dai_ultoa(unsigned long ul, char* a) {
    const char digits[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    char space[_DAI_ULTOA_SPACE];
    size_t copied = 0;

    // Write number into temp buffer from the back
    do {
        space[_DAI_ULTOA_SPACE - (++copied)] = digits[ul % 10];
    } while ((ul /= 10) != 0);

    // Copy into result
    for (size_t z = 0; z < copied; z++) {
        a[z] = space[(_DAI_ULTOA_SPACE - copied) + z];
    }

    return copied;
}

_DAI_FN size_t
_Dai_ltoa(long l, char* a) {
    size_t neg = (l < 0);
    if (neg) *a++ = '-';  // Casting before conversion works for abs(LONG_MIN).
    return neg + _Dai_ultoa((neg ? -(unsigned long)l : l), a);
}

/*
 * Convert ascii to int types.
 *
 * Ex:                            return,   ret
 *     _Dai_atoi("1000a", &ret)  -> 1000, "1000a" (parsed successfully)
 *                                              ^
 *     _Dai_atoi("abcde", &ret)  -> ????,  NULL   (doesn't match pattern)
 *
 *     _Dai_atos("-99999", &ret) -> ????,  NULL   (overflow / underflow)
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

_DAI_FN short _Dai_atos(char* a, char** ret);
_DAI_FN unsigned short _Dai_atous(char* a, char** ret);
_DAI_FN int _Dai_atoi(char* a, char** ret);
_DAI_FN unsigned int _Dai_atoui(char* a, char** ret);
_DAI_FN long _Dai_atol(char* a, char** ret);
_DAI_FN unsigned long _Dai_atoul(char* a, char** ret);

/* Pointer to Hex */
_DAI_FN int _Dai_ptoh(void* ptr, char* h, size_t s);


/*
static inline unsigned long long
codepoint_atoull_nosigns(const codepoint_t *a, size_t len, size_t *read) {

  unsigned long long parsing = 0;
  size_t chars = 0;
  for (size_t i = 0; i < len; i++) {
    codepoint_t c = a[i];
    if (!((c >= 48) && (c <= 57)))
      break;
    parsing *= 10; // TODO overflow/underflow checks.
    parsing += (c - 48);
    chars++;
  }

  *read = chars;
  return parsing;
}

static inline int codepoint_atoi(const codepoint_t *a, size_t len,
                                 size_t *read) {

  int neg = a[0] == '-';
  int consumed = (neg | (a[0] == '+'));
  a += consumed;
  len -= consumed;

  size_t ullread;
  unsigned long long ull = codepoint_atoull_nosigns(a, len, &ullread);
  if (neg ? -ull < INT_MIN : ull > INT_MAX)
    return *read = 0, 0;
  int l = (int)(neg ? -ull : ull);

  *read = ullread + consumed;
  return l;
}
*/

#endif /* _DAI_STDLIB_STRCONVERT */
