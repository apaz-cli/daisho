#ifndef __STILTS_STDLIB_PTRFLAG
#define __STILTS_STDLIB_PTRFLAG
#include "../StiltsStdInclude.h"

/* Tagged Pointers. */
#define __STILTS_DEFINE_PTR(TYPE) \
static inline TYPE* __Stilts_zero_ptrflags_##TYPE(TYPE* ptr) {\
    return (TYPE*)((((uintptr_t)ptr) << 8) >> 8);\
}\
\
static inline TYPE* __Stilts_set_ptrflag_##TYPE(TYPE* ptr, size_t offset) {\
    return (TYPE*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));\
}\
\
static inline int __Stilts_get_ptrflag_##TYPE(TYPE* ptr, size_t offset) {\
    return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;\
}\
\
static inline TYPE __Stilts_deref_##TYPE(TYPE* ptr) {\
    return *__Stilts_zero_ptrflags_##TYPE(ptr);\
}


/* The type void is done separately because it is generic,
   changes returns, and cannot be dereferenced. */
static inline void* __Stilts_zero_ptrflags(void* ptr) {
    return (void*)((((uintptr_t)ptr) << 8) >> 8);
}
static inline void* __Stilts_zero_ptrflags_void(void* ptr) {
    return (void*)((((uintptr_t)ptr) << 8) >> 8);
}
static inline void* __Stilts_set_ptrflag(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));
}
static inline void* __Stilts_set_ptrflag_void(void* ptr, size_t offset) {
    return (void*)(((uintptr_t)ptr) | ((uintptr_t)1 << offset));
}
static inline int __Stilts_get_ptrflag(void* ptr, size_t offset) {
    return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;
}
static inline int __Stilts_get_ptrflag_void(void* ptr, size_t offset) {
    return (((uintptr_t)ptr) & ((uintptr_t)1 << offset)) ? 1 : 0;
}


typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

__STILTS_DEFINE_PTR(bool);
__STILTS_DEFINE_PTR(char);
__STILTS_DEFINE_PTR(short);
__STILTS_DEFINE_PTR(int);
__STILTS_DEFINE_PTR(long);
__STILTS_DEFINE_PTR(uchar);
__STILTS_DEFINE_PTR(ushort);
__STILTS_DEFINE_PTR(uint);
__STILTS_DEFINE_PTR(ulong);

__STILTS_DEFINE_PTR(int8_t);
__STILTS_DEFINE_PTR(uint8_t);
__STILTS_DEFINE_PTR(int16_t);
__STILTS_DEFINE_PTR(uint16_t);
__STILTS_DEFINE_PTR(int32_t);
__STILTS_DEFINE_PTR(uint32_t);
__STILTS_DEFINE_PTR(int64_t);
__STILTS_DEFINE_PTR(uint64_t);

__STILTS_DEFINE_PTR(size_t);
__STILTS_DEFINE_PTR(ssize_t);

__STILTS_DEFINE_PTR(intptr_t);
__STILTS_DEFINE_PTR(uintptr_t);
__STILTS_DEFINE_PTR(ptrdiff_t);


#endif /* __STILTS_STDLIB_PTRFLAG */
