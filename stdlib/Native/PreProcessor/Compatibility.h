#pragma once
#ifndef _DAI_STDLIB_COMPATIBILITY
#define _DAI_STDLIB_COMPATIBILITY

#define _DAI_FN static inline

// TODO [[noreturn]] is coming in c23, and _Noreturn is C11.

#ifndef __cplusplus /* C */
#define _DAI_ALIGNOF(type) _Alignof(type)
#define _DAI_NORETURN _Noreturn
#else /* __cplusplus */
#define _DAI_ALIGNOF(type) alignof(type)
#define _DAI_NORETURN
#endif /* __cplusplus */

#if defined __has_include
#define _DAI_HAS_INCLUDE 1
#else
#define _DAI_HAS_INCLUDE 0
#endif

#define _DAI_ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

#endif /* _DAI_STDLIB_COMPATIBILITY */
