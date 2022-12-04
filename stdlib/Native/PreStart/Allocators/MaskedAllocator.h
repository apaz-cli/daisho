#ifndef _DAI_STDLIB_MASKEDALLOCATOR
#define _DAI_STDLIB_MASKEDALLOCATOR
#include "../../PreProcessor/PreProcessor.h"

// cap must be a multiple of 64.
#define _DAI_MASKEDALLOCATOR_DEFINE(type, cap)                                                   \
    _DAI_STATIC_ASSERT(                                                                          \
        !(cap % 64), "In _DAI_MASKEDALLOCATOR_DEFINE(type, cap), cap must be a multple of 64."); \
    typedef struct {                                                                              \
        uint64_t mask[(cap) / 64];                                                                \
        type buf[(cap)];                                                                          \
    } _Dai_MaskedAllocator_##type;                                                               \
    typedef struct {                                                                              \
        type* ptr;                                                                                \
        size_t pos;                                                                               \
    } _Dai_MaskedAllocator_ret_##type;                                                           \
                                                                                                  \
    _DAI_FN _Dai_MaskedAllocator_##type _Dai_MaskedAllocator_##type##_init(void) {             \
        _Dai_MaskedAllocator_##type allocator;                                                   \
        for (size_t i = 0; i < (cap) / 64; i++) allocator.mask[i] = 0;                            \
        return allocator;                                                                         \
    }

// _DAI_MASKEDALLOCATOR_DEFINE(size_t, 64)

#endif /* _DAI_STDLIB_MASKEDALLOCATOR */
