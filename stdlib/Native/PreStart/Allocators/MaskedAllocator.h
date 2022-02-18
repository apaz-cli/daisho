#ifndef __DAI_STDLIB_MASKEDALLOCATOR
#define __DAI_STDLIB_MASKEDALLOCATOR
#include "../../PreProcessor/PreProcessor.h"

// cap must be a multiple of 64.
#define __DAI_MASKEDALLOCATOR_DEFINE(type, cap)                                                   \
    __DAI_STATIC_ASSERT(                                                                          \
        !(cap % 64), "In __DAI_MASKEDALLOCATOR_DEFINE(type, cap), cap must be a multple of 64."); \
    typedef struct {                                                                              \
        uint64_t mask[(cap) / 64];                                                                \
        type buf[(cap)];                                                                          \
    } __Dai_MaskedAllocator_##type;                                                               \
    typedef struct {                                                                              \
        type* ptr;                                                                                \
        size_t pos;                                                                               \
    } __Dai_MaskedAllocator_ret_##type;                                                           \
                                                                                                  \
    __DAI_FN __Dai_MaskedAllocator_##type __Dai_MaskedAllocator_##type##_init(void) {             \
        __Dai_MaskedAllocator_##type allocator;                                                   \
        for (size_t i = 0; i < (cap) / 64; i++) allocator.mask[i] = 0;                            \
        return allocator;                                                                         \
    }

// __DAI_MASKEDALLOCATOR_DEFINE(size_t, 64)

#endif /* __DAI_STDLIB_MASKEDALLOCATOR */