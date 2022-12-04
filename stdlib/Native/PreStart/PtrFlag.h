#ifndef _DAI_STDLIB_PTRFLAG
#define _DAI_STDLIB_PTRFLAG

#include "../PreProcessor/PreProcessor.h"

#define _DAI_RESERVED_PTR_BITS 16

/* Tagged Pointers. */
#define _DAI_DEFINE_PTR(TYPE)                                                 \
    static inline TYPE* _Dai_zero_ptrflags_##TYPE(TYPE* ptr) {                \
        return (TYPE*)((((uintptr_t)ptr) << _DAI_RESERVED_PTR_BITS) >>        \
                       _DAI_RESERVED_PTR_BITS);                               \
    }                                                                             \
    static inline TYPE* _Dai_set_ptrflag_##TYPE(TYPE* ptr, size_t offset) {   \
        return (TYPE*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));              \
    }                                                                             \
    static inline TYPE* _Dai_clear_ptrflag_##TYPE(TYPE* ptr, size_t offset) { \
        return (TYPE*)(((uintptr_t)ptr) & ~((uintptr_t)1 << offset));             \
    }                                                                             \
    static inline int _Dai_get_ptrflag_##TYPE(TYPE* ptr, size_t offset) {     \
        return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;             \
    }                                                                             \
    static inline TYPE _Dai_deref_##TYPE(TYPE* ptr) {                         \
        return *_Dai_zero_ptrflags_##TYPE(ptr);                               \
    }

/* More of the same, but void is done separately
   because it is generic and cannot be dereferenced. */
static inline void*
_Dai_zero_ptrflags(void* ptr) {
    return (void*)((((uintptr_t)ptr) << _DAI_RESERVED_PTR_BITS) >> _DAI_RESERVED_PTR_BITS);
}
static inline void*
_Dai_zero_ptrflags_void(void* ptr) {
    return _Dai_zero_ptrflags(ptr);
}
static inline void*
_Dai_set_ptrflag(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));
}
static inline void*
_Dai_set_ptrflag_void(void* ptr, size_t offset) {
    return _Dai_set_ptrflag(ptr, offset);
}
static inline void*
_Dai_clear_ptrflag(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) & ~((uintptr_t)1 << offset));
}
static inline void*
_Dai_clear_ptrflag_void(void* ptr, size_t offset) {
    return _Dai_clear_ptrflag(ptr, offset);
}
static inline int
_Dai_get_ptrflag(void* ptr, size_t offset) {
    return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;
}
static inline int
_Dai_get_ptrflag_void(void* ptr, size_t offset) {
    return _Dai_get_ptrflag(ptr, offset);
}

/* Define some types. */
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

/* Define tagged pointers for all standard types supported. */
_DAI_DEFINE_PTR(bool)
_DAI_DEFINE_PTR(char)
_DAI_DEFINE_PTR(uchar)
_DAI_DEFINE_PTR(short)
_DAI_DEFINE_PTR(ushort)
_DAI_DEFINE_PTR(int)
_DAI_DEFINE_PTR(uint)
_DAI_DEFINE_PTR(long)
_DAI_DEFINE_PTR(ulong)

_DAI_DEFINE_PTR(int8_t)
_DAI_DEFINE_PTR(uint8_t)
_DAI_DEFINE_PTR(int16_t)
_DAI_DEFINE_PTR(uint16_t)
_DAI_DEFINE_PTR(int32_t)
_DAI_DEFINE_PTR(uint32_t)
_DAI_DEFINE_PTR(int64_t)
_DAI_DEFINE_PTR(uint64_t)

_DAI_DEFINE_PTR(size_t)
_DAI_DEFINE_PTR(ssize_t)
_DAI_DEFINE_PTR(intptr_t)
_DAI_DEFINE_PTR(uintptr_t)
_DAI_DEFINE_PTR(ptrdiff_t)

#endif /* _DAI_STDLIB_PTRFLAG */
