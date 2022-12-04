#pragma once
#ifndef _DAI_STDLIB_STRING
#define _DAI_STDLIB_STRING
#include "../PreStart/PreStart.h"

/* Classic triple with small string
   optimization. (abbreviated ssopt.) */
typedef struct {
    char* buffer;
    size_t size;
    size_t _cap;
} _Dai_String;

/* Only a cstr and a length is required for many operations.
   The representation doesn't matter, so there should be an
   easy way to extract it. */
/* As a side note, _Dai_String and _Dai_String_View should
   be compatible types. We shouldn't assume they are in our
   source code for the sake of C standard compliance, but
   all unpacking and repacking should end up getting
   optimized out. */
typedef struct {
    char* str;
    size_t len;
} _Dai_String_View;

#define _DAI_STR_FLAG_OFFSET (sizeof(_Dai_String) - 1)
#define _DAI_STR_SSOPT_BUF_LEN (sizeof(_Dai_String) - 1)

#if _DAI_SANE
#define _DAI_STRING_NONNULL(self) _DAI_SANE_ASSERT(self, "The \"self\" argument cannot be null.")
#define _DAI_STRING_NULL_TERM(self)                                                       \
    do {                                                                                   \
        if (_DAI_SANITY_PEDANTIC) {                                                       \
            if (!*(_Dai_String_cstr(self) + _Dai_String_len(self))) _DAI_SANITY_FAIL(); \
        }                                                                                  \
    } while (0)
#else
#define _DAI_STRING_NONNULL(self)
#define _DAI_STRING_NULL_TERM(self)
#endif

/***********************/
/* "Private" functions */
/***********************/

_DAI_FN char
_Dai_String_get_flag(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return *((char*)self + _DAI_STR_FLAG_OFFSET);
}

_DAI_FN void
_Dai_String_set_flag(_Dai_String* self, char flag) {
    _DAI_STRING_NONNULL(self);
    *((char*)self + _DAI_STR_FLAG_OFFSET) = flag;
}

_DAI_FN bool
_Dai_String_isLarge(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_get_flag(self) == CHAR_MAX;
}

_DAI_FN size_t
_Dai_String_get_cap(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(_Dai_String_isLarge(self), "The string must be large to have a capacity to get.");
    return (self->_cap) >> CHAR_BIT;
}

_DAI_FN void
_Dai_String_set_cap(_Dai_String* self, size_t cap) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(_Dai_String_isLarge(self), "The string must be large to have a capacity to set.");
    self->_cap = (cap << CHAR_BIT) | ((size_t)_Dai_String_get_flag(self));
}

_DAI_FN void
_Dai_String_set_flag_cap(_Dai_String* self, char flag, size_t cap) {
    _DAI_STRING_NONNULL(self);
    self->_cap = (cap << CHAR_BIT) | flag;
}

_DAI_FN size_t
_Dai_String_small_len(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return (size_t)(_DAI_STR_SSOPT_BUF_LEN - _Dai_String_get_flag(self));
}

_DAI_FN size_t
_Dai_String_large_len(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return self->size;
}

/**********************/
/* "Public" Functions */
/**********************/

_DAI_FN size_t
_Dai_String_len(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self) ? _Dai_String_large_len(self) : _Dai_String_small_len(self);
}

_DAI_FN char*
_Dai_String_cstr(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self) ? self->buffer : (char*)self;
}

_DAI_FN _Dai_String_View
_DAI_String_to_View(_Dai_String* self) {
    _Dai_String_View view;
    if (_Dai_String_isLarge(self)) {
        view.str = self->buffer;
        view.len = self->size;
    } else {
        view.str = (char*)self;
        view.len = _Dai_String_small_len(self);
    }
    return view;
}

_DAI_FN void
_Dai_String_print(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    printf("%s", _Dai_String_cstr(self));
}

_DAI_FN void
_Dai_String_println(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    printf("%s\n", _Dai_String_cstr(self));
}

_DAI_FN void
_Dai_String_set_char(_Dai_String* self, size_t pos, char c) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(pos < _Dai_String_len(self), "Out of bounds.");
    if (_Dai_String_isLarge(self)) {
        self->buffer[pos] = c;
    } else {
        ((char*)self)[pos] = c;
    }
}

_DAI_FN char
_Dai_String_get_char(_Dai_String* self, size_t pos) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(pos < _Dai_String_len(self), "Out of bounds.");
    return _Dai_String_isLarge(self) ? self->buffer[pos] : ((char*)self)[pos];
}

_DAI_FN bool
_Dai_String_isEmpty(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self) ? self->buffer[0] == '\0' : ((char*)self)[0] == '\0';
}

/******************/
/* Memory Methods */
/******************/

/* If the string's using ssopt, convert it to large format. */
_DAI_FN _Dai_String*
_Dai_String_promote(_Dai_String* self, _DAI_SRC_INFO_ARGS) {
    _DAI_STRING_NONNULL(self);
    if (_Dai_String_isLarge(self)) return self;

    size_t newcap = _Dai_align(self->size);
    char* buffer = (char*)_Dai_malloc(newcap, _DAI_SRC_INFO_PASS);
    self->buffer = strcpy(buffer, (char*)self);
    self->size = _Dai_String_small_len(self);
    _Dai_String_set_flag_cap(self, CHAR_MAX, newcap);
    return self;
}

/* If the string's in large format not using ssopt, and it could, make it.
 * Otherwise, shrink the allocation to size.
 */
_DAI_FN _Dai_String*
_Dai_String_shrink(_Dai_String* self, _DAI_SRC_INFO_ARGS) {
    _DAI_STRING_NONNULL(self);
    bool large = _Dai_String_isLarge(self);
    if (large) {
        // If small enough, use ssopt.
        if (_Dai_String_len(self) <= _DAI_STR_SSOPT_BUF_LEN) {
            /* Copy large into small and free */
            size_t i, len = self->size;
            char *s = (char*)self, *buf = self->buffer;
            for (i = 0; i < len; i++) s[i] = buf[i];
            s[i] = '\0';
            s[_DAI_STR_SSOPT_BUF_LEN] = _DAI_STR_SSOPT_BUF_LEN - len;

            _Dai_free(buf, _DAI_SRC_INFO_PASS);
        }
        /* If not small enough for ssopt, shrink. */
        else {
            // len unchanged
            self->buffer = (char*)_Dai_realloc(self->buffer, self->size, _DAI_SRC_INFO_PASS);
            _Dai_String_set_cap(self, self->size);
        }
    }

    return self;
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Create an empty string. */
_DAI_FN _Dai_String*
_Dai_String_initEmpty(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    *(char*)self = '\0';
    _Dai_String_set_flag(self, _DAI_STR_SSOPT_BUF_LEN);
    return self;
}

/* Create a string with content */
_DAI_FN _Dai_String*
_Dai_String_initWith(_Dai_String* self, char* data, size_t len) {
    _DAI_STRING_NONNULL(self);
    size_t i;

    /* Small */
    if (len <= _DAI_STR_SSOPT_BUF_LEN) {
        /* Use small string optimization */
        char* s = (char*)self;

        for (i = 0; i < len; i++) s[i] = data[i];
        s[i] = '\0';
        s[_DAI_STR_SSOPT_BUF_LEN] = _DAI_STR_SSOPT_BUF_LEN - len;
    }

    /* Large */
    else {
        /* Allocate and copy */
        size_t buf_cap = _Dai_align(len);
        char* buffer = (char*)_DAI_MALLOC(buf_cap);

        for (i = 0; i < len; i++) buffer[i] = data[i];
        buffer[i] = '\0';

        self->buffer = buffer;
        self->size = len;
        _Dai_String_set_flag_cap(self, CHAR_MAX, buf_cap);
    }

    return self;
}

/* Takes ownership of the memory. Assumes that it's allocated on the heap with
 * malloc(). */
_DAI_FN _Dai_String*
_Dai_String_initMalloced(_Dai_String* self, char* data, size_t cap, size_t len) {
    _DAI_STRING_NONNULL(self);
    self->buffer = data;
    self->size = len;
    _Dai_String_set_flag_cap(self, CHAR_MAX, cap);
    return self;
}

/* Calls strlen. Try not to use this one, as it's better to know the length. */
_DAI_FN _Dai_String*
_Dai_String_initLen(_Dai_String* self, char* data) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_initWith(self, data, strlen(data));
}

_DAI_FN _Dai_String*
_Dai_String_copy(_Dai_String* _DAI_RESTRICT self, _Dai_String* _DAI_RESTRICT other) {
    _DAI_STRING_NONNULL(self);
    _DAI_STRING_NONNULL(other);
    if (_Dai_String_isLarge(self)) {
        char* buffer = (char*)_DAI_MALLOC(_Dai_String_get_cap(self));
        other->buffer = strcpy(buffer, self->buffer);
        other->size = self->size;
        other->_cap = self->_cap;
        return other;
    } else {
        memcpy(other, self, sizeof(_Dai_String));
        return other;
    }
}

_DAI_FN void
_Dai_String_destroy(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    if (_Dai_String_isLarge(self)) _DAI_FREE(self->buffer);
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

_DAI_FN bool
_Dai_String_cstr_startsWith(char* self, char* delim) {
    char* prefix = delim;
    while (*prefix)
        if (*prefix++ != *self++) return false;
    return true;
}

_DAI_FN char*
_Dai_String_find_cstr(char* str, char* subseq) {
    while (*str) {
        if (_Dai_String_cstr_startsWith(str, subseq))
            return str;
        else
            str++;
    }
    return NULL;
}

// cstr startsWith(), but returns strlen(delim) instead of true on match.
_DAI_FN size_t
_Dai_String_split_helper(char* self, char* delim) {
    char* str = self;
    while (*delim)
        if (*delim++ != *self++) return 0;
    return (size_t)(self - str);
}

_DAI_FN void
_Dai_String_split_impl(char* self, char* delim) {
    // Iterate over self, until the end of the string.
    char* checkpoint = self;  // after delim of last match.
    while (true) {
        // Find the next match, or the end of the string.
        size_t startsWithdelimlen = 0;
        char* match = checkpoint;
        while (_DAI_UNLIKELY(*match)) {
            startsWithdelimlen = _Dai_String_split_helper(match, delim);
            if (_DAI_UNLIKELY(startsWithdelimlen))
                break;
            else
                match++;
        }

        /* If there's no more matches, we're done. */
        if (match == checkpoint) break;

        // Copy from the last checkpoint until start of the match (or the whole
        // string if no match) into a new _Dai_String.
        _Dai_String newstr;
        _Dai_String_initWith(&newstr, checkpoint, (size_t)(match - checkpoint));

        // TODO: Figure out how better to output the list of strings. This may
        // have to wait until generics are implemented.
        _Dai_String_println(&newstr);

        checkpoint = match + startsWithdelimlen;
    }
}

#endif /* _DAI_STDLIB_STRING */
