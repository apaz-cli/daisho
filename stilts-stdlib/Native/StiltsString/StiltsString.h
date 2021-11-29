#ifndef __STILTS_STDLIB_STRING
#define __STILTS_STDLIB_STRING
#include "../StiltsStdInclude.h"

/*
 * This is the layout. Addressing it is harder.
 * What I'm about to do is so complicated that
 * there's no other way to express this
 * in a standards-compliant manner.
 *
 * This is ugly as hell, and there will be bugs.
 * But it's fast.
 */
typedef struct {
    uint8_t* buffer;
#define __STILTS_STR_BUF_OFFSET 0
    uint64_t size;
#define __STILTS_STR_SIZE_OFFSET (sizeof(uint8_t*))
    uint64_t _cap;
#define __STILTS_STR_CAP_OFFSET (sizeof(uint8_t*) + sizeof(uint64_t))
} __Stilts_STR_SIZE_STRUCT;

#define __STILTS_STR_SSOPT_BUF_LEN \
    ((sizeof(__Stilts_STR_SIZE_STRUCT) / sizeof(uint8_t)) - 1)

_Static_assert(
    (sizeof(__Stilts_STR_SIZE_STRUCT) % sizeof(uint8_t)) == 0,
    "The size of the small string optimization buffer is not divisible by the "
    "size of uint8_t. Something is very wacky here.");

#define __STILTS_STR_SSOPT_REMAINING_OFFSET \
    (__STILTS_STR_SSOPT_BUF_LEN * sizeof(uint8_t))

/* Define it as raw chars. We'll cast to the right types. */
typedef struct {
    char buf[sizeof(__Stilts_STR_SIZE_STRUCT)];
} __Stilts_String;

/*********************/
/* Utility functions */
/*********************/

static inline char*
__Stilts_String_offset(__Stilts_String* self, size_t n) {
    return (((char*)self) + n);
}

/* For large */
static inline uint8_t*
__Stilts_String_get_buffer(__Stilts_String* self) {
    return *(uint8_t**)__Stilts_String_offset(self, __STILTS_STR_BUF_OFFSET);
}

/* For both */
static inline uint8_t
__Stilts_String_get_flag(__Stilts_String* self) {
    return *(uint8_t*)__Stilts_String_offset(
        self, __STILTS_STR_SSOPT_REMAINING_OFFSET);
}

/* For small */
static inline uint64_t
__Stilts_String_get_remaining(__Stilts_String* self) {
    return (uint64_t) * (uint8_t*)__Stilts_String_offset(
                            self, __STILTS_STR_SSOPT_REMAINING_OFFSET);
}

/* For small */
static inline void
__Stilts_String_set_remaining(__Stilts_String* self, uint64_t remaining) {
    *(uint8_t*)__Stilts_String_offset(
        self, __STILTS_STR_SSOPT_REMAINING_OFFSET) = (uint8_t)remaining;
}

static inline void
__Stilts_String_set_flag(__Stilts_String* self, uint8_t flag) {
    *(uint8_t*)__Stilts_String_offset(
        self, __STILTS_STR_SSOPT_REMAINING_OFFSET) = flag;
}

static inline bool
__Stilts_String_isLarge(__Stilts_String* self) {
    return __Stilts_String_get_flag(self) == 0xFF;
}

static inline uint8_t*
__Stilts_String_get_ssopt(__Stilts_String* self) {
    return (uint8_t*)(self->buf);
}

static inline uint64_t
__Stilts_String_len(__Stilts_String* self) {
    return __Stilts_String_isLarge(self)
               ? (uint64_t) * (uint64_t*)__Stilts_String_offset(
                                  self, __STILTS_STR_SIZE_OFFSET)
               : (uint64_t) * (uint8_t*)__Stilts_String_offset(
                                  self, __STILTS_STR_SSOPT_REMAINING_OFFSET);
}

static inline uint64_t
__Stilts_String_get_cap(__Stilts_String* self) {
    (void)self;
    return 0;
}

static inline void
__Stilts_String_set_cap(__Stilts_String* self, uint64_t cap) {
(void)self; (void)cap;
}

static inline uint64_t
u8_strlen(uint8_t* strbuf) {
    uint64_t len = 0;
    while (strbuf[++len])
        ;
    return len;
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Returns the empty string. */
static inline __Stilts_String*
StiltsString_initempty(__Stilts_String* self) {
    *__Stilts_String_get_ssopt(self) = 0;
    __Stilts_String_set_flag(self, __STILTS_STR_SSOPT_BUF_LEN);
    return self;
}

static inline __Stilts_String*
StiltsString_initwith(__Stilts_String* self, uint8_t* data, uint64_t len) {
    (void)data;
    /* Small */
    if (len <= __STILTS_STR_SSOPT_BUF_LEN) {
        /* Use small string optimization */
    }

    /* Large */
    else {
        /* Allocate and copy */
    }

    return self;
}

static inline __Stilts_String*
StiltsString_initWithMallocedData(__Stilts_String* self, char* data,
                                  uint64_t cap, uint64_t len) {
                                      (void)data; (void)cap; (void)len;
    return self;
}

static inline __Stilts_String*
StiltsString_initlen(__Stilts_String* self, uint8_t* data) {
    return StiltsString_initwith(self, data, u8_strlen(data));
}

static inline void
StiltsString_destroy(__Stilts_String* self) {
    if (__Stilts_String_isLarge(self)) free(__Stilts_String_get_buffer(self));
}

static inline char*
__Stilts_String_cstr(__Stilts_String* self) {
    (void)self;
    return NULL;
}

#endif /* __STILTS_STDLIB_STRING */
