#pragma once
#ifndef _DAI_STDLIB_COMPATIBILITY
#define _DAI_STDLIB_COMPATIBILITY

#define _DAI_FN static inline

#ifndef __cplusplus /* C */
#define _DAI_ALIGNOF(type) _Alignof(type)
#define _DAI_NORETURN _Noreturn
#define _DAI_RESTRICT restrict
#else /* __cplusplus */
#define _DAI_ALIGNOF(type) alignof(type)
#define _DAI_NORETURN
#define _DAI_RESTRICT
#endif /* __cplusplus */

#if defined __has_include
#define _DAI_HAS_INCLUDE 1
#else
#define _DAI_HAS_INCLUDE 0
#endif

#endif /* _DAI_STDLIB_COMPATIBILITY */
