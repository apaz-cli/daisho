#pragma once
#ifndef __STILTS_STDLIB_STRING
#define __STILTS_STDLIB_STRING
#include "../StiltsAllocator/StiltsAllocator.h"
#include "../StiltsStdInclude.h"

/* Classic triple with small
 * string optimization. */
typedef struct {
    char* buffer;
    uint64_t size;
    uint64_t _cap;
} __Stilts_String;

#define __STILTS_STR_BUF_OFFSET 0
#define __STILTS_STR_SIZE_OFFSET sizeof(char*)
#define __STILTS_STR_CAP_OFFSET (sizeof(char*) + sizeof(uint64_t))
#define __STILTS_STR_FLAG_OFFSET (sizeof(__Stilts_String) - 1)
#define __STILTS_STR_SSOPT_BUF_LEN (sizeof(__Stilts_String) - 1)
#define __STILTS_STR_ALLOC_SIZE (__STILTS_PAGESIZE / 4)

#define __STILTS_STRING_NONNULL(self) \
    if (__STILTS_SANITY_CHECK == 2 && !self) __STILTS_SANITY_FAIL()

/* Little endianness is asserted elsewhere. */
_Static_assert(CHAR_BIT == 8,
               "Stilts's implementation of String assumes CHAR_BIT to be 8.");
_Static_assert(sizeof(size_t) == sizeof(uint64_t),
               "Stilts's implementation of String assumes size_t and uint64_t "
               "are the same.");
_Static_assert((__STILTS_STR_ALLOC_SIZE % 2) == 0,
               "The config __STILTS_PAGESIZE must be a multiple of 8.");

/***********************/
/* "Private" functions */
/***********************/

/* Only works for multiples of 2 */
__STILTS_FN uint64_t
__Stilts_String_roundUp(uint64_t numToRound, uint64_t multiple) {
    if (__STILTS_SANITY_CHECK && ((multiple % 2) != 0)) __STILTS_SANITY_FAIL();
    return (numToRound + multiple - 1) & -multiple;
}

__STILTS_FN char
__Stilts_String_get_flag(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return *((char*)self + __STILTS_STR_FLAG_OFFSET);
}

__STILTS_FN void
__Stilts_String_set_flag(__Stilts_String* self, char flag) {
    __STILTS_STRING_NONNULL(self);
    *((char*)self + __STILTS_STR_FLAG_OFFSET) = flag;
}

__STILTS_FN bool
__Stilts_String_isLarge(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_get_flag(self) == CHAR_MAX;
}

__STILTS_FN uint64_t
__Stilts_String_get_cap(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    if ((__STILTS_SANITY_CHECK == 2) && !__Stilts_String_isLarge(self))
        __STILTS_SANITY_FAIL();

    uint64_t cap = self->_cap;
    return cap >> CHAR_BIT;
}

__STILTS_FN void
__Stilts_String_set_cap(__Stilts_String* self, uint64_t cap) {
    __STILTS_STRING_NONNULL(self);
    if ((__STILTS_SANITY_CHECK == 2) && !__Stilts_String_isLarge(self))
        __STILTS_SANITY_FAIL();

    uint64_t flag = (uint64_t)__Stilts_String_get_flag(self);
    uint64_t shifted_cap = cap << CHAR_BIT;
    uint64_t newcap = shifted_cap | flag;
    self->_cap = newcap;
}

__STILTS_FN void
__Stilts_String_set_flag_cap(__Stilts_String* self, char flag, uint64_t cap) {
    __STILTS_STRING_NONNULL(self);
    self->_cap = ((cap << CHAR_BIT) | flag);
}

/**********************/
/* "Public" Functions */
/**********************/

__STILTS_FN uint64_t
__Stilts_String_len(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_isLarge(self)
               ? self->size
               : (uint64_t)__Stilts_String_get_flag(self);
}

__STILTS_FN char*
__Stilts_String_cstr(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_isLarge(self) ? self->buffer : (char*)self;
}

__STILTS_FN void
__Stilts_String_print(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    printf("%s", __Stilts_String_cstr(self));
}

__STILTS_FN void
__Stilts_String_println(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    printf("%s\n", __Stilts_String_cstr(self));
}

__STILTS_FN void
__Stilts_String_set_char(__Stilts_String* self, uint64_t pos, char c) {
    __STILTS_STRING_NONNULL(self);
    // TODO Extend if needed
    if (__Stilts_String_isLarge(self)) {
        self->buffer[pos] = c;
    } else {
        ((char*)self)[pos] = c;
    }
}

__STILTS_FN char
__Stilts_String_get_char(__Stilts_String* self, uint64_t pos) {
    __STILTS_STRING_NONNULL(self);
    if (__STILTS_SANITY_CHECK && pos >= __Stilts_String_len(self))
        __STILTS_SANITY_FAIL();
    return __Stilts_String_isLarge(self) ? self->buffer[pos]
                                         : ((char*)self)[pos];
}

__STILTS_FN bool
__Stilts_String_isEmpty(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_isLarge(self) ? self->buffer[0] == '\0'
                                         : ((char*)self)[0] == '\0';
}

__STILTS_FN __Stilts_String*
__Stilts_String_promote(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    if (__Stilts_String_isLarge(self)) return self;

    __Stilts_String s = *self;
    __Stilts_String* sp = &s;
    char* spc = (char*)sp;

    char* buffer =
        (char*)malloc(__Stilts_String_roundUp(s.size, __STILTS_STR_ALLOC_SIZE));
    // TODO oom check, stilts_malloc
    strcpy(buffer, spc);

    return self;
}

__STILTS_FN __Stilts_String*
__Stilts_String_shrink(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    bool large = __Stilts_String_isLarge(self);
    if (large) {
        // If small enough, use ssopt.
        if (__Stilts_String_len(self) <= __STILTS_STR_SSOPT_BUF_LEN) {
            /* Copy large into small and free */
            char* s = (char*)self;
            uint64_t len = self->size;
            char* buf = self->buffer;

            uint64_t i;
            for (i = 0; i < len; i++) s[i] = buf[i];
            s[i] = '\0';
            s[__STILTS_STR_SSOPT_BUF_LEN] = __STILTS_STR_SSOPT_BUF_LEN - len;

            free(buf);
        }
        /* If not small enough for ssopt, shrink. */
        else {
            char* buf = (char*)realloc(self->buffer, (size_t)self->size);
            // TODO oom, stilts_realloc, errcheck
            self->buffer = buf;
            __Stilts_String_set_cap(self, self->size);
        }
    }

    return self;
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Create an empty string. */
__STILTS_FN __Stilts_String*
__Stilts_String_initEmpty(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    *(char*)self = '\0';
    __Stilts_String_set_flag(self, __STILTS_STR_SSOPT_BUF_LEN);
    return self;
}

/* Create a string with content */
__STILTS_FN __Stilts_String*
__Stilts_String_initWith(__Stilts_String* self, char* data, uint64_t len) {
    __STILTS_STRING_NONNULL(self);
    /* Small */
    if (len <= __STILTS_STR_SSOPT_BUF_LEN) {
        /* Use small string optimization */
        char* s = (char*)self;
        uint64_t i;
        for (i = 0; i < len; i++) s[i] = data[i];
        s[i] = '\0';
        s[__STILTS_STR_SSOPT_BUF_LEN] = __STILTS_STR_SSOPT_BUF_LEN - len;
    }

    /* Large */
    else {
        /* Allocate and copy */
        uint64_t cap = __Stilts_String_get_cap(self);
        char* buffer = (char*)malloc(len);
    }

    return self;
}

/* Takes ownership of the memory. Assumes that it's allocated on the heap with
 * malloc(). */
__STILTS_FN __Stilts_String*
__Stilts_String_initMalloced(__Stilts_String* self, char* data, uint64_t cap,
                             uint64_t len) {
    __STILTS_STRING_NONNULL(self);
    self->buffer = data;
    self->size = len;
    __Stilts_String_set_flag_cap(self, CHAR_MAX, cap);
    return self;
}

/* Calls strlen. Try not to use this one, as it's better to know the length. */
__STILTS_FN __Stilts_String*
__StiltsString_initLen(__Stilts_String* self, char* data) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_initWith(self, data, (uint64_t)strlen(data));
}

__STILTS_FN __Stilts_String*
__Stilts_String_copy(__Stilts_String* __STILTS_RESTRICT self,
                     __Stilts_String* __STILTS_RESTRICT other) {
    __STILTS_STRING_NONNULL(self);
    __STILTS_STRING_NONNULL(other);
    if (__Stilts_String_isLarge(self)) {
        char* buffer = (char*)malloc((size_t)__Stilts_String_get_cap(self));
        // TODO oom check, stilts_malloc
        other->buffer = strcpy(buffer, self->buffer);
        other->size = self->size;
        other->_cap = self->_cap; /* Also copy flag bits */
        return other;
    } else {
        memcpy(other, self, sizeof(__Stilts_String));
        return other;
    }
}

__STILTS_FN void
__Stilts_String_destroy(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    if (__Stilts_String_isLarge(self)) free(self->buffer);
}

#endif /* __STILTS_STDLIB_STRING */
