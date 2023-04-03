#ifndef _DAI_STDLIB_COMPUTEDCONFIG
#define _DAI_STDLIB_COMPUTEDCONFIG

#if defined(_DAI_TESTING_BACKTRACES)
#define _DAI_USING_BACKTRACES 1
#else
#if _DAI_HAS_BACKTRACES && _DAI_BACKTRACES_ENABLED
#define _DAI_USING_BACKTRACES 1
#else
#define _DAI_USING_BACKTRACES 0
#endif
#endif

#define _DAI_STRERROR_R_VERSION            \
    _Generic(strerror_r,                   \
        int (*)(int, char*, size_t) : 1,   \
        char* (*)(int, char*, size_t) : 0, \
        default : -1)

#define _DAI_INSANE (_DAI_SANITY_CHECK == 0)
#define _DAI_SANE (_DAI_SANITY_CHECK > 0)
#define _DAI_PEDANTIC (_DAI_SANITY_CHECK > 1)

#endif /* _DAI_STDLIB_COMPUTEDCONFIG */
