#pragma once
#ifndef __DAI_STDLIB_COMPATIBILITY
#define __DAI_STDLIB_COMPATIBILITY

#define __DAI_FN static inline

#ifndef __cplusplus /* C */
#define __DAI_ALIGNOF(type) _Alignof(type)
#define __DAI_NORETURN _Noreturn
#define __DAI_RESTRICT restrict
#else /* __cplusplus */
#define __DAI_ALIGNOF(type) alignof(type)
#define __DAI_NORETURN
#define __DAI_RESTRICT
#endif /* __cplusplus */

#endif /* __DAI_STDLIB_COMPATIBILITY */
