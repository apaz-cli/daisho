#pragma once
#ifndef __STILTS_STDLIB_STRING
#define __STILTS_STDLIB_STRING
#include "../PreStart/StiltsPreStart.h"

/* Classic triple with small string
   optimization. (abbreviated ssopt.) */
typedef struct {
    char* buffer;
    size_t size;
    size_t _cap;
} __Stilts_String;

/* Only a cstr and a length is required for many operations.
   The representation doesn't matter, so there should be an
   easy way to extract it. */
typedef struct {
    char* cstr;
    size_t len;
} __Stilts_String_Raw;

#define __STILTS_STR_BUF_OFFSET 0
#define __STILTS_STR_SIZE_OFFSET sizeof(char*)
#define __STILTS_STR_CAP_OFFSET (sizeof(char*) + sizeof(size_t))
#define __STILTS_STR_FLAG_OFFSET (sizeof(__Stilts_String) - 1)
#define __STILTS_STR_SSOPT_BUF_LEN (sizeof(__Stilts_String) - 1)

#define __STILTS_SIZE_BIT (sizeof(size_t) * CHAR_BIT)
#define __STILTS_STR_MAX_LEN ((1 << __STILTS_SIZE_BIT) - 1)

#if __STILTS_SANITY_CHECK
#define __STILTS_STRING_NONNULL(self) \
    if (__STILTS_SANITY_CHECK == 2 && !self) __STILTS_SANITY_FAIL()
#define __STILTS_STRING_NULL_TERM(self)                                     \
    do {                                                                    \
        if (__STILTS_SANITY_CHECK == 2) {                                   \
            if (!*(__Stilts_String_cstr(self) + __Stilts_String_len(self))) \
                __STILTS_SANITY_FAIL();                                     \
        }                                                                   \
    } while (0)
#else
#define __STILTS_STRING_NONNULL(self)
#define __STILTS_STRING_NULL_TERM(self)
#endif

/* Little endianness is asserted elsewhere. */
__STILTS_STATIC_ASSERT(CHAR_BIT == 8,
                       "Stilts's implementation of String assumes CHAR_BIT to be 8.");
__STILTS_STATIC_ASSERT(sizeof(size_t) <= sizeof(uint64_t),
                       "Stilts's implementation of String assumes size_t to be "
                       "uint64_t or smaller.");

/***********************/
/* "Private" functions */
/***********************/

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

__STILTS_FN size_t
__Stilts_String_get_cap(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    if ((__STILTS_SANITY_CHECK == 2) && !__Stilts_String_isLarge(self)) __STILTS_SANITY_FAIL();
    return (self->_cap) >> CHAR_BIT;
}

__STILTS_FN void
__Stilts_String_set_cap(__Stilts_String* self, size_t cap) {
    __STILTS_STRING_NONNULL(self);
    if ((__STILTS_SANITY_CHECK == 2) && !__Stilts_String_isLarge(self)) __STILTS_SANITY_FAIL();
    self->_cap = (cap << CHAR_BIT) | ((size_t)__Stilts_String_get_flag(self));
}

__STILTS_FN void
__Stilts_String_set_flag_cap(__Stilts_String* self, char flag, size_t cap) {
    __STILTS_STRING_NONNULL(self);
    self->_cap = (cap << CHAR_BIT) | flag;
}

__STILTS_FN size_t
__Stilts_String_small_len(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return (size_t)(__STILTS_STR_SSOPT_BUF_LEN - __Stilts_String_get_flag(self));
}

__STILTS_FN size_t
__Stilts_String_large_len(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return self->size;
}

__STILTS_FN __Stilts_String_Raw
__Stilts_String_getRaw(__Stilts_String* self) {
    __Stilts_String_Raw raw;
    if (__Stilts_String_isLarge(self)) {
        raw.cstr = self->buffer;
        raw.len = self->size;
    } else {
        raw.cstr = (char*)self;
        raw.len = __Stilts_String_small_len(self);
    }
    return raw;
}

/**********************/
/* "Public" Functions */
/**********************/

__STILTS_FN size_t
__Stilts_String_len(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_isLarge(self) ? __Stilts_String_large_len(self)
                                         : __Stilts_String_small_len(self);
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
__Stilts_String_set_char(__Stilts_String* self, size_t pos, char c) {
    __STILTS_STRING_NONNULL(self);
    if (__STILTS_SANITY_CHECK && pos >= __Stilts_String_len(self)) __STILTS_SANITY_FAIL();
    if (__Stilts_String_isLarge(self)) {
        self->buffer[pos] = c;
    } else {
        ((char*)self)[pos] = c;
    }
}

__STILTS_FN char
__Stilts_String_get_char(__Stilts_String* self, size_t pos) {
    __STILTS_STRING_NONNULL(self);
    if (__STILTS_SANITY_CHECK && pos >= __Stilts_String_len(self)) __STILTS_SANITY_FAIL();
    return __Stilts_String_isLarge(self) ? self->buffer[pos] : ((char*)self)[pos];
}

__STILTS_FN bool
__Stilts_String_isEmpty(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    return __Stilts_String_isLarge(self) ? self->buffer[0] == '\0' : ((char*)self)[0] == '\0';
}

/******************/
/* Memory Methods */
/******************/

/* If the string's using ssopt, convert it to large format. */
__STILTS_FN __Stilts_String*
__Stilts_String_promote(__Stilts_String* self, __STILTS_SRC_INFO_ARGS) {
    __STILTS_STRING_NONNULL(self);
    if (__Stilts_String_isLarge(self)) return self;

    size_t newcap = __Stilts_align(self->size);
    char* buffer = (char*)__Stilts_malloc(newcap, __STILTS_SRC_INFO_PASS);
    self->buffer = strcpy(buffer, (char*)self);
    self->size = __Stilts_String_small_len(self);
    __Stilts_String_set_flag_cap(self, CHAR_MAX, newcap);
    return self;
}

/* If the string's in large format not using ssopt, and it could, make it.
 * Otherwise, shrink the allocation to size.
 */
__STILTS_FN __Stilts_String*
__Stilts_String_shrink(__Stilts_String* self, __STILTS_SRC_INFO_ARGS) {
    __STILTS_STRING_NONNULL(self);
    bool large = __Stilts_String_isLarge(self);
    if (large) {
        // If small enough, use ssopt.
        if (__Stilts_String_len(self) <= __STILTS_STR_SSOPT_BUF_LEN) {
            /* Copy large into small and free */
            size_t i, len = self->size;
            char *s = (char*)self, *buf = self->buffer;
            for (i = 0; i < len; i++) s[i] = buf[i];
            s[i] = '\0';
            s[__STILTS_STR_SSOPT_BUF_LEN] = __STILTS_STR_SSOPT_BUF_LEN - len;

            __Stilts_free(buf, __STILTS_SRC_INFO_PASS);
        }
        /* If not small enough for ssopt, shrink. */
        else {
            // len unchanged
            self->buffer =
                (char*)__Stilts_realloc(self->buffer, self->size, __STILTS_SRC_INFO_PASS);
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
__Stilts_String_initWith(__Stilts_String* self, char* data, size_t len) {
    __STILTS_STRING_NONNULL(self);
    size_t i;

    /* Small */
    if (len <= __STILTS_STR_SSOPT_BUF_LEN) {
        /* Use small string optimization */
        char* s = (char*)self;

        for (i = 0; i < len; i++) s[i] = data[i];
        s[i] = '\0';
        s[__STILTS_STR_SSOPT_BUF_LEN] = __STILTS_STR_SSOPT_BUF_LEN - len;
    }

    /* Large */
    else {
        /* Allocate and copy */
        size_t buf_cap = __Stilts_align(len);
        char* buffer = (char*)__STILTS_MALLOC(buf_cap);

        for (i = 0; i < len; i++) buffer[i] = data[i];
        buffer[i] = '\0';

        self->buffer = buffer;
        self->size = len;
        __Stilts_String_set_flag_cap(self, CHAR_MAX, buf_cap);
    }

    return self;
}

/* Takes ownership of the memory. Assumes that it's allocated on the heap with
 * malloc(). */
__STILTS_FN __Stilts_String*
__Stilts_String_initMalloced(__Stilts_String* self, char* data, size_t cap, size_t len) {
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
    return __Stilts_String_initWith(self, data, strlen(data));
}

__STILTS_FN __Stilts_String*
__Stilts_String_copy(__Stilts_String* __STILTS_RESTRICT self,
                     __Stilts_String* __STILTS_RESTRICT other) {
    __STILTS_STRING_NONNULL(self);
    __STILTS_STRING_NONNULL(other);
    if (__Stilts_String_isLarge(self)) {
        char* buffer = (char*)__STILTS_MALLOC(__Stilts_String_get_cap(self));
        other->buffer = strcpy(buffer, self->buffer);
        other->size = self->size;
        other->_cap = self->_cap;
        return other;
    } else {
        memcpy(other, self, sizeof(__Stilts_String));
        return other;
    }
}

__STILTS_FN void
__Stilts_String_destroy(__Stilts_String* self) {
    __STILTS_STRING_NONNULL(self);
    if (__Stilts_String_isLarge(self)) __STILTS_FREE(self->buffer);
}

// TODO:
// find, findIdx, rfind, rfindidx
// clear, resize
// split, splitFirst, splitLast
// replace, replaceFirst, replaceLast
// trim
// startsWith, endsWith
// append
// swap
// substring
// insert
// format
// toUpper, toLower
// hash
// equals
// compareto

__STILTS_FN bool
__Stilts_String_cstr_startsWith(char* self, char* delim) {
    char* prefix = delim;
    while (*prefix)
        if (*prefix++ != *self++) return false;
    return true;
}

__STILTS_FN char*
__Stilts_String_find_cstr(char* str, char* subseq) {
    while (*str) {
        if (__Stilts_String_cstr_startsWith(str, subseq))
            return str;
        else
            str++;
    }
    return NULL;
}

// cstr startsWith(), but returns strlen(delim) instead of true on match.
__STILTS_FN size_t
__Stilts_String_split_helper(char* self, char* delim) {
    char* str = self;
    while (*delim)
        if (*delim++ != *self++) return 0;
    return (size_t)(self - str);
}

__STILTS_FN void
__Stilts_String_split_impl(char* self, char* delim) {
    // Iterate over self, until the end of the string.
    char* checkpoint = self;  // after delim of last match.
    while (true) {
        // Find the next match, or the end of the string.
        size_t startsWithdelimlen = 0;
        char* match = checkpoint;
        while (__STILTS_UNLIKELY(*match)) {
            startsWithdelimlen = __Stilts_String_split_helper(match, delim);
            if (__STILTS_UNLIKELY(startsWithdelimlen))
                break;
            else
                match++;
        }

        /* If there's no more matches, we're done. */
        if (match == checkpoint) break;

        // Copy from the last checkpoint until start of the match (or the whole
        // string if no match) into a new __Stilts_String.
        __Stilts_String newstr;
        __Stilts_String_initWith(&newstr, checkpoint, (size_t)(match - checkpoint));

        // TODO: Figure out how better to output the list of strings. This may
        // have to wait until generics are implemented.
        __Stilts_String_println(&newstr);

        checkpoint = match + startsWithdelimlen;
    }
}

#endif /* __STILTS_STDLIB_STRING */
