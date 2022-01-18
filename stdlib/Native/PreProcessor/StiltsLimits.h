#ifndef __STILTS_STDLIB_LIMITS
#define __STILTS_STDLIB_LIMITS

/* Returns as unsigned long long. Cast it yourself to the desired type. */

#define __STILTS_IS_TYPE_SIGNED(t) (((t)(-1)) < ((t)0))
#define __STILTS_MAX_OF_UNSIGNED_TYPE(t) \
    (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0xFULL << ((sizeof(t) * 8ULL) - 4ULL)))
#define __STILTS_MAX_OF_SIGNED_TYPE(t) \
    (((0x1ULL << ((sizeof(t) * 8ULL) - 1ULL)) - 1ULL) | (0x7ULL << ((sizeof(t) * 8ULL) - 4ULL)))
#define __STILTS_MIN_OF_UNSIGNED_TYPE(t) (0ULL)
#define __STILTS_MIN_OF_SIGNED_TYPE(t) \
    (-(((1ULL << (sizeof(t) * CHAR_BIT - 2)) - 1) * 2 + 1) - (((~(t)0U) == (t)(-1))))

#define __STILTS_MAX_OF_TYPE(t)                                                       \
    ((unsigned long long)(__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MAX_OF_SIGNED_TYPE(t) \
                                                     : __STILTS_MAX_OF_UNSIGNED_TYPE(t)))
#define __STILTS_MIN_OF_TYPE(t)                                                     \
    (signed long long)((__STILTS_IS_TYPE_SIGNED(t) ? __STILTS_MIN_OF_SIGNED_TYPE(t) \
                                                   : __STILTS_MIN_OF_UNSIGNED_TYPE(t)))

#endif /* __STILTS_STDLIB_LIMITS */
