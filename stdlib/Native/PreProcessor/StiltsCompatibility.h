#pragma once
#ifndef __STILTS_STDLIB_COMPATIBILITY
#define __STILTS_STDLIB_COMPATIBILITY
#define __STILTS_FN static inline
#ifndef __cplusplus /* C */
#define __STILTS_ALIGNOF(type) _Alignof(type)
#define __STILTS_NORETURN _Noreturn
#define __STILTS_RESTRICT restrict
#else /* __cplusplus */
#define __STILTS_ALIGNOF(type) alignof(type)
#define __STILTS_NORETURN
#define __STILTS_RESTRICT
#endif /* __cplusplus */
#endif /* __STILTS_STDLIB_COMPATIBILITY */
