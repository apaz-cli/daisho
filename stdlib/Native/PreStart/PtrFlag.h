#ifndef __DAI_STDLIB_PTRFLAG
#define __DAI_STDLIB_PTRFLAG

#include "../PreProcessor/PreProcessor.h"

#define __DAI_RESERVED_PTR_BITS 16

/* Tagged Pointers. */
#define __DAI_DEFINE_PTR(TYPE)                                                 \
    static inline TYPE* __Dai_zero_ptrflags_##TYPE(TYPE* ptr) {                \
        return (TYPE*)((((uintptr_t)ptr) << __DAI_RESERVED_PTR_BITS) >>        \
                       __DAI_RESERVED_PTR_BITS);                               \
    }                                                                             \
    static inline TYPE* __Dai_set_ptrflag_##TYPE(TYPE* ptr, size_t offset) {   \
        return (TYPE*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));              \
    }                                                                             \
    static inline TYPE* __Dai_clear_ptrflag_##TYPE(TYPE* ptr, size_t offset) { \
        return (TYPE*)(((uintptr_t)ptr) & ~((uintptr_t)1 << offset));             \
    }                                                                             \
    static inline int __Dai_get_ptrflag_##TYPE(TYPE* ptr, size_t offset) {     \
        return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;             \
    }                                                                             \
    static inline TYPE __Dai_deref_##TYPE(TYPE* ptr) {                         \
        return *__Dai_zero_ptrflags_##TYPE(ptr);                               \
    }

/* More of the same, but void is done separately
   because it is generic and cannot be dereferenced. */
static inline void*
__Dai_zero_ptrflags(void* ptr) {
    return (void*)((((uintptr_t)ptr) << __DAI_RESERVED_PTR_BITS) >> __DAI_RESERVED_PTR_BITS);
}
static inline void*
__Dai_zero_ptrflags_void(void* ptr) {
    return __Dai_zero_ptrflags(ptr);
}
static inline void*
__Dai_set_ptrflag(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));
}
static inline void*
__Dai_set_ptrflag_void(void* ptr, size_t offset) {
    return __Dai_set_ptrflag(ptr, offset);
}
static inline void*
__Dai_clear_ptrflag(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) & ~((uintptr_t)1 << offset));
}
static inline void*
__Dai_clear_ptrflag_void(void* ptr, size_t offset) {
    return __Dai_clear_ptrflag(ptr, offset);
}
static inline int
__Dai_get_ptrflag(void* ptr, size_t offset) {
    return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;
}
static inline int
__Dai_get_ptrflag_void(void* ptr, size_t offset) {
    return __Dai_get_ptrflag(ptr, offset);
}

/* Define some types. */
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

/* Define tagged pointers for all standard types supported. */
__DAI_DEFINE_PTR(bool)
__DAI_DEFINE_PTR(char)
__DAI_DEFINE_PTR(uchar)
__DAI_DEFINE_PTR(short)
__DAI_DEFINE_PTR(ushort)
__DAI_DEFINE_PTR(int)
__DAI_DEFINE_PTR(uint)
__DAI_DEFINE_PTR(long)
__DAI_DEFINE_PTR(ulong)

__DAI_DEFINE_PTR(int8_t)
__DAI_DEFINE_PTR(uint8_t)
__DAI_DEFINE_PTR(int16_t)
__DAI_DEFINE_PTR(uint16_t)
__DAI_DEFINE_PTR(int32_t)
__DAI_DEFINE_PTR(uint32_t)
__DAI_DEFINE_PTR(int64_t)
__DAI_DEFINE_PTR(uint64_t)

__DAI_DEFINE_PTR(size_t)
__DAI_DEFINE_PTR(ssize_t)
__DAI_DEFINE_PTR(intptr_t)
__DAI_DEFINE_PTR(uintptr_t)
__DAI_DEFINE_PTR(ptrdiff_t)

#endif /* __DAI_STDLIB_PTRFLAG */
