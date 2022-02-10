#ifndef __STILTS_STDLIB_LIMITS
#define __STILTS_STDLIB_LIMITS

/* Assumes two's compliment, as asserted in the . */

#define __STILTS_IS_TYPE_SIGNED(t)   (((t)(-1)) < ((t)0))
#define __STILTS_IS_TYPE_FLOATING(t) (((t)1.5) > 1)

#define __STILTS_MAX_OF_UNSIGNED_INTEGER_TYPE(t) \
    ((((uintmax_t)1 << ((sizeof(t) * (uintmax_t)8) - (uintmax_t)1)) - (uintmax_t)1) | ((uintmax_t)15 << ((sizeof(t) * (uintmax_t)8) - (uintmax_t)4)))
#define __STILTS_MAX_OF_SIGNED_INTEGER_TYPE(t) \
    ((((uintmax_t)1 << ((sizeof(t) * (uintmax_t)8) - (uintmax_t)1)) - (uintmax_t)1) | ((uintmax_t)7 << ((sizeof(t) * (uintmax_t)8) - (uintmax_t)4)))
#define __STILTS_MIN_OF_UNSIGNED_INTEGER_TYPE(t) ((uintmax_t)0)
#define __STILTS_MIN_OF_SIGNED_INTEGER_TYPE(t) ((t) - ((((t)1 << (sizeof(t) * 8 - 2)) - 1) * 2 + 1) - 1)

#define __STILTS_MAX_OF_INTEGER_TYPE(t)                                      \
    ((t)(__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MAX_OF_SIGNED_INTEGER_TYPE(t) \
                                  : __STILTS_MAX_OF_UNSIGNED_INTEGER_TYPE(t)))
#define __STILTS_MIN_OF_INTEGER_TYPE(t)                                      \
    ((t)(__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MIN_OF_SIGNED_INTEGER_TYPE(t) \
                                  : __STILTS_MIN_OF_UNSIGNED_INTEGER_TYPE(t)))

/* Assumes that there are only three floating point types, float, double, and long double.
   Those are the only ones that C defines, but hypothetically other types could exist as an extension.
   Eventually, this should be fixed. */
#define __STILTS_MAX_OF_FLOATING_TYPE(t) \
    ((t)(sizeof(t) == sizeof(float) ? FLT_MAX : sizeof(t) == sizeof(double) ? DBL_MAX : LDBL_MAX))
#define __STILTS_MIN_OF_FLOATING_TYPE(t) \
    ((t)(sizeof(t) == sizeof(float) ? FLT_MIN : sizeof(t) == sizeof(double) ? DBL_MIN : LDBL_MIN))

#define __STILTS_MAX_OF_TYPE(t) \
    ((t)(__STILTS_IS_TYPE_FLOATING(t) \
    ? __STILTS_MAX_OF_FLOATING_TYPE(t) \
    : __STILTS_MAX_OF_INTEGER_TYPE(t)))
#define __STILTS_MIN_OF_TYPE(t) \
    ((t)(__STILTS_IS_TYPE_FLOATING(t) \
    ? __STILTS_MIN_OF_FLOATING_TYPE(t) \
    : __STILTS_MIN_OF_INTEGER_TYPE(t)))


#endif /* __STILTS_STDLIB_LIMITS */
