#pragma once
#ifndef __DAI_STDLIB_STRING
#define __DAI_STDLIB_STRING
#include "../PreStart/PreStart.h"

/* Classic triple with small string
   optimization. (abbreviated ssopt.) */
typedef struct {
    char* buffer;
    size_t size;
    size_t _cap;
} __Dai_String;

/* Only a cstr and a length is required for many operations.
   The representation doesn't matter, so there should be an
   easy way to extract it. */
/* As a side note, __Dai_String and __Dai_String_View should
   be compatible types. We shouldn't assume they are in our
   source code for the sake of C standard compliance, but
   all unpacking and repacking should end up getting
   optimized out. */
typedef struct {
    char* str;
    size_t len;
} __Dai_String_View;

#define __DAI_STR_FLAG_OFFSET (sizeof(__Dai_String) - 1)
#define __DAI_STR_SSOPT_BUF_LEN (sizeof(__Dai_String) - 1)

#if __DAI_SANE
#define __DAI_STRING_NONNULL(self) __DAI_PEDANTIC_ASSERT(self, "The \"self\" argument cannot be null.")
#define __DAI_STRING_NULL_TERM(self)                                                       \
    do {                                                                                   \
        if (__DAI_SANITY_PEDANTIC) {                                                       \
            if (!*(__Dai_String_cstr(self) + __Dai_String_len(self))) __DAI_SANITY_FAIL(); \
        }                                                                                  \
    } while (0)
#else
#define __DAI_STRING_NONNULL(self)
#define __DAI_STRING_NULL_TERM(self)
#endif

/***********************/
/* "Private" functions */
/***********************/

__DAI_FN char
__Dai_String_get_flag(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return *((char*)self + __DAI_STR_FLAG_OFFSET);
}

__DAI_FN void
__Dai_String_set_flag(__Dai_String* self, char flag) {
    __DAI_STRING_NONNULL(self);
    *((char*)self + __DAI_STR_FLAG_OFFSET) = flag;
}

__DAI_FN bool
__Dai_String_isLarge(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return __Dai_String_get_flag(self) == CHAR_MAX;
}

__DAI_FN size_t
__Dai_String_get_cap(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    __DAI_PEDANTIC_ASSERT(__Dai_String_isLarge(self), "The string must be large to have a capacity to get.");
    return (self->_cap) >> CHAR_BIT;
}

__DAI_FN void
__Dai_String_set_cap(__Dai_String* self, size_t cap) {
    __DAI_STRING_NONNULL(self);
    __DAI_PEDANTIC_ASSERT(__Dai_String_isLarge(self), "The string must be large to have a capacity to set.");
    self->_cap = (cap << CHAR_BIT) | ((size_t)__Dai_String_get_flag(self));
}

__DAI_FN void
__Dai_String_set_flag_cap(__Dai_String* self, char flag, size_t cap) {
    __DAI_STRING_NONNULL(self);
    self->_cap = (cap << CHAR_BIT) | flag;
}

__DAI_FN size_t
__Dai_String_small_len(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return (size_t)(__DAI_STR_SSOPT_BUF_LEN - __Dai_String_get_flag(self));
}

__DAI_FN size_t
__Dai_String_large_len(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return self->size;
}

/**********************/
/* "Public" Functions */
/**********************/

__DAI_FN size_t
__Dai_String_len(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return __Dai_String_isLarge(self) ? __Dai_String_large_len(self) : __Dai_String_small_len(self);
}

__DAI_FN char*
__Dai_String_cstr(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return __Dai_String_isLarge(self) ? self->buffer : (char*)self;
}

__DAI_FN __Dai_String_View
__DAI_String_to_View(__Dai_String* self) {
    __Dai_String_View view;
    if (__Dai_String_isLarge(self)) {
        view.str = self->buffer;
        view.len = self->size;
    } else {
        view.str = (char*)self;
        view.len = __Dai_String_small_len(self);
    }
    return view;
}

__DAI_FN void
__Dai_String_print(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    printf("%s", __Dai_String_cstr(self));
}

__DAI_FN void
__Dai_String_println(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    printf("%s\n", __Dai_String_cstr(self));
}

__DAI_FN void
__Dai_String_set_char(__Dai_String* self, size_t pos, char c) {
    __DAI_STRING_NONNULL(self);
    __DAI_PEDANTIC_ASSERT(pos < __Dai_String_len(self), "Out of bounds.");
    if (__Dai_String_isLarge(self)) {
        self->buffer[pos] = c;
    } else {
        ((char*)self)[pos] = c;
    }
}

__DAI_FN char
__Dai_String_get_char(__Dai_String* self, size_t pos) {
    __DAI_STRING_NONNULL(self);
    __DAI_PEDANTIC_ASSERT(pos < __Dai_String_len(self), "Out of bounds.");
    return __Dai_String_isLarge(self) ? self->buffer[pos] : ((char*)self)[pos];
}

__DAI_FN bool
__Dai_String_isEmpty(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    return __Dai_String_isLarge(self) ? self->buffer[0] == '\0' : ((char*)self)[0] == '\0';
}

/******************/
/* Memory Methods */
/******************/

/* If the string's using ssopt, convert it to large format. */
__DAI_FN __Dai_String*
__Dai_String_promote(__Dai_String* self, __DAI_SRC_INFO_ARGS) {
    __DAI_STRING_NONNULL(self);
    if (__Dai_String_isLarge(self)) return self;

    size_t newcap = __Dai_align(self->size);
    char* buffer = (char*)__Dai_malloc(newcap, __DAI_SRC_INFO_PASS);
    self->buffer = strcpy(buffer, (char*)self);
    self->size = __Dai_String_small_len(self);
    __Dai_String_set_flag_cap(self, CHAR_MAX, newcap);
    return self;
}

/* If the string's in large format not using ssopt, and it could, make it.
 * Otherwise, shrink the allocation to size.
 */
__DAI_FN __Dai_String*
__Dai_String_shrink(__Dai_String* self, __DAI_SRC_INFO_ARGS) {
    __DAI_STRING_NONNULL(self);
    bool large = __Dai_String_isLarge(self);
    if (large) {
        // If small enough, use ssopt.
        if (__Dai_String_len(self) <= __DAI_STR_SSOPT_BUF_LEN) {
            /* Copy large into small and free */
            size_t i, len = self->size;
            char *s = (char*)self, *buf = self->buffer;
            for (i = 0; i < len; i++) s[i] = buf[i];
            s[i] = '\0';
            s[__DAI_STR_SSOPT_BUF_LEN] = __DAI_STR_SSOPT_BUF_LEN - len;

            __Dai_free(buf, __DAI_SRC_INFO_PASS);
        }
        /* If not small enough for ssopt, shrink. */
        else {
            // len unchanged
            self->buffer = (char*)__Dai_realloc(self->buffer, self->size, __DAI_SRC_INFO_PASS);
            __Dai_String_set_cap(self, self->size);
        }
    }

    return self;
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Create an empty string. */
__DAI_FN __Dai_String*
__Dai_String_initEmpty(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    *(char*)self = '\0';
    __Dai_String_set_flag(self, __DAI_STR_SSOPT_BUF_LEN);
    return self;
}

/* Create a string with content */
__DAI_FN __Dai_String*
__Dai_String_initWith(__Dai_String* self, char* data, size_t len) {
    __DAI_STRING_NONNULL(self);
    size_t i;

    /* Small */
    if (len <= __DAI_STR_SSOPT_BUF_LEN) {
        /* Use small string optimization */
        char* s = (char*)self;

        for (i = 0; i < len; i++) s[i] = data[i];
        s[i] = '\0';
        s[__DAI_STR_SSOPT_BUF_LEN] = __DAI_STR_SSOPT_BUF_LEN - len;
    }

    /* Large */
    else {
        /* Allocate and copy */
        size_t buf_cap = __Dai_align(len);
        char* buffer = (char*)__DAI_MALLOC(buf_cap);

        for (i = 0; i < len; i++) buffer[i] = data[i];
        buffer[i] = '\0';

        self->buffer = buffer;
        self->size = len;
        __Dai_String_set_flag_cap(self, CHAR_MAX, buf_cap);
    }

    return self;
}

/* Takes ownership of the memory. Assumes that it's allocated on the heap with
 * malloc(). */
__DAI_FN __Dai_String*
__Dai_String_initMalloced(__Dai_String* self, char* data, size_t cap, size_t len) {
    __DAI_STRING_NONNULL(self);
    self->buffer = data;
    self->size = len;
    __Dai_String_set_flag_cap(self, CHAR_MAX, cap);
    return self;
}

/* Calls strlen. Try not to use this one, as it's better to know the length. */
__DAI_FN __Dai_String*
__DaiString_initLen(__Dai_String* self, char* data) {
    __DAI_STRING_NONNULL(self);
    return __Dai_String_initWith(self, data, strlen(data));
}

__DAI_FN __Dai_String*
__Dai_String_copy(__Dai_String* __DAI_RESTRICT self, __Dai_String* __DAI_RESTRICT other) {
    __DAI_STRING_NONNULL(self);
    __DAI_STRING_NONNULL(other);
    if (__Dai_String_isLarge(self)) {
        char* buffer = (char*)__DAI_MALLOC(__Dai_String_get_cap(self));
        other->buffer = strcpy(buffer, self->buffer);
        other->size = self->size;
        other->_cap = self->_cap;
        return other;
    } else {
        memcpy(other, self, sizeof(__Dai_String));
        return other;
    }
}

__DAI_FN void
__Dai_String_destroy(__Dai_String* self) {
    __DAI_STRING_NONNULL(self);
    if (__Dai_String_isLarge(self)) __DAI_FREE(self->buffer);
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

__DAI_FN bool
__Dai_String_cstr_startsWith(char* self, char* delim) {
    char* prefix = delim;
    while (*prefix)
        if (*prefix++ != *self++) return false;
    return true;
}

__DAI_FN char*
__Dai_String_find_cstr(char* str, char* subseq) {
    while (*str) {
        if (__Dai_String_cstr_startsWith(str, subseq))
            return str;
        else
            str++;
    }
    return NULL;
}

// cstr startsWith(), but returns strlen(delim) instead of true on match.
__DAI_FN size_t
__Dai_String_split_helper(char* self, char* delim) {
    char* str = self;
    while (*delim)
        if (*delim++ != *self++) return 0;
    return (size_t)(self - str);
}

__DAI_FN void
__Dai_String_split_impl(char* self, char* delim) {
    // Iterate over self, until the end of the string.
    char* checkpoint = self;  // after delim of last match.
    while (true) {
        // Find the next match, or the end of the string.
        size_t startsWithdelimlen = 0;
        char* match = checkpoint;
        while (__DAI_UNLIKELY(*match)) {
            startsWithdelimlen = __Dai_String_split_helper(match, delim);
            if (__DAI_UNLIKELY(startsWithdelimlen))
                break;
            else
                match++;
        }

        /* If there's no more matches, we're done. */
        if (match == checkpoint) break;

        // Copy from the last checkpoint until start of the match (or the whole
        // string if no match) into a new __Dai_String.
        __Dai_String newstr;
        __Dai_String_initWith(&newstr, checkpoint, (size_t)(match - checkpoint));

        // TODO: Figure out how better to output the list of strings. This may
        // have to wait until generics are implemented.
        __Dai_String_println(&newstr);

        checkpoint = match + startsWithdelimlen;
    }
}

#endif /* __DAI_STDLIB_STRING */
