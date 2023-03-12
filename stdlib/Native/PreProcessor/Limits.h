#ifndef _DAI_STDLIB_LIMITS
#define _DAI_STDLIB_LIMITS

/* Assumes two's compliment, and CHAR_BIT = 8, as asserted in the confugure file. */
/* Also assumes that uintmax_t is indeed the largest unsigned int type (which may not actually
 * always be correct). Works up to */

#define _DAI_LIMITS_LEFTSHIFT(num, shf) ((num) << (shf))

#define _DAI_IS_TYPE_SIGNED(t) (((t)(-1)) <= ((t)0))
#define _DAI_IS_TYPE_FLOATING(t) _Generic((t)0, float : 1, double : 1, long double : 1, default : 0)

#define _DAI_MAX_OF_UNSIGNED_INTEGER_TYPE(t)                           \
    ((t)(_DAI_LIMITS_LEFTSHIFT((uintmax_t)1, sizeof(t) * 8 - 1) - 1) | \
     _DAI_LIMITS_LEFTSHIFT((uintmax_t)15, sizeof(t) * 8 - 4))
#define _DAI_MAX_OF_SIGNED_INTEGER_TYPE(t)                             \
    ((t)(_DAI_LIMITS_LEFTSHIFT((uintmax_t)1, sizeof(t) * 8 - 1) - 1) | \
     _DAI_LIMITS_LEFTSHIFT((uintmax_t)7, (sizeof(t) * 8) - 4))
#define _DAI_MIN_OF_UNSIGNED_INTEGER_TYPE(t) ((t)0)
#define _DAI_MIN_OF_SIGNED_INTEGER_TYPE(t) \
    ((t) - ((_DAI_LIMITS_LEFTSHIFT((t)1, sizeof(t) * 8 - 2) - 1) * 2 + 1) - 1)

#define _DAI_MAX_OF_INTEGER_TYPE(t)                                   \
    ((t)((_DAI_IS_TYPE_SIGNED(t) ? _DAI_MAX_OF_SIGNED_INTEGER_TYPE(t) \
                                 : _DAI_MAX_OF_UNSIGNED_INTEGER_TYPE(t))))
#define _DAI_MIN_OF_INTEGER_TYPE(t)                                   \
    ((t)((_DAI_IS_TYPE_SIGNED(t) ? _DAI_MIN_OF_SIGNED_INTEGER_TYPE(t) \
                                 : _DAI_MIN_OF_UNSIGNED_INTEGER_TYPE(t))))

/* Assumes that there are only three floating point types, float, double, and long double.
   Those are the only ones that C defines, but hypothetically other types could exist as an
   extension. Eventually, this should be fixed. */
#define _DAI_MAX_OF_FLOATING_TYPE(t) \
    _Generic((t)0, float : FLT_MAX, double : DBL_MAX, long double : LDBL_MAX, default : 0)
#define _DAI_MIN_OF_FLOATING_TYPE(t) \
    _Generic((t)0, float : FLT_MIN, double : DBL_MIN, long double : LDBL_MIN, default : 0)

#define _DAI_MAX_OF_TYPE(t) \
    ((t)(_DAI_IS_TYPE_FLOATING(t) ? _DAI_MAX_OF_FLOATING_TYPE(t) : _DAI_MAX_OF_INTEGER_TYPE(t)))
#define _DAI_MIN_OF_TYPE(t) \
    ((t)(_DAI_IS_TYPE_FLOATING(t) ? _DAI_MIN_OF_FLOATING_TYPE(t) : _DAI_MIN_OF_INTEGER_TYPE(t)))

#endif /* _DAI_STDLIB_LIMITS */
