#pragma once
#ifndef _DAI_STDLIB_STRING
#define _DAI_STDLIB_STRING
#include "../PreStart/PreStart.h"

/* Classic triple with small string
   optimization. (abbreviated ssopt.) */
typedef struct {
    char* _buf;
    size_t _len;
    size_t _cap;
    /* char flag; is inside _cap */
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

#define _DAI_STR_SSOPT_BUF_CAP (sizeof(_Dai_String) - 1)
#define _DAI_STR_LARGE_FLAG CHAR_MAX
#define _DAI_STR_SMALL_FLAG (char)0

#if _DAI_SANE
#define _DAI_STRING_NONNULL(self) _DAI_SANE_ASSERT(self, "The \"self\" argument cannot be null.")
#define _DAI_CSTR_NONNULL(cstr) _DAI_SANE_ASSERT(cstr, "The \"cstr\" argument cannot be null.")
#define _DAI_STRING_OOMCHECK(ptr) _DAI_SANE_ASSERT(ptr, "Out of memory allocating a string.")
#define _DAI_STRING_NULL_TERM(self)                                                     \
    do {                                                                                \
        if (_DAI_SANITY_PEDANTIC) {                                                     \
            if (!*(_Dai_String_cstr(self) + _Dai_String_len(self))) _DAI_SANITY_FAIL(); \
        }                                                                               \
    } while (0)
#else
#define _DAI_STRING_NONNULL(self)
#define _DAI_CSTR_NONNULL(cstr)
#define _DAI_STRING_NULL_TERM(self)
#endif

/***********************/
/* "Private" functions */
/***********************/

_DAI_FN char
_Dai_String_get_flag(_Dai_String* self) {
    return *((char*)self + _DAI_STR_SSOPT_BUF_CAP);
}

_DAI_FN void
_Dai_String_set_flag(_Dai_String* self, char flag) {
    _DAI_SANE_ASSERT(flag == _DAI_STR_LARGE_FLAG,
                     "_Dai_String_set_flag should only be called for large strings.");
    *((char*)self + _DAI_STR_SSOPT_BUF_CAP) = flag;
}

_DAI_FN bool
_Dai_String_isLarge(_Dai_String* self) {
    return _Dai_String_get_flag(self) == CHAR_MAX;
}

_DAI_FN bool
_Dai_String_isSmall(_Dai_String* self) {
    return _Dai_String_get_flag(self) != CHAR_MAX;
}

_DAI_FN size_t
_Dai_String_small_len(_Dai_String* self) {
    return (size_t)(_DAI_STR_SSOPT_BUF_CAP - _Dai_String_get_flag(self));
}

_DAI_FN size_t
_Dai_String_large_len(_Dai_String* self) {
    return self->_len;
}

_DAI_FN void
_Dai_String_set_small_len(_Dai_String* self, size_t len) {
    _DAI_SANE_ASSERT(len <= _DAI_STR_SSOPT_BUF_CAP,
                     "_Dai_String_set_len is only valid for sizes less than or equal to "
                     "*usually* 23, depending on the platform.");
    _Dai_String_set_flag(self, _DAI_STR_SSOPT_BUF_CAP - _Dai_String_get_flag(self));
}

_DAI_FN void
_Dai_String_set_large_len(_Dai_String* self, size_t len) {
    self->_len = len;
}

_DAI_FN void
_Dai_String_set_len(_Dai_String* self, size_t len) {
    if (!_Dai_String_isLarge(self))
        _Dai_String_set_small_len(self, len);
    else
        _Dai_String_set_large_len(self, len);
}

_DAI_FN size_t
_Dai_String_small_cap(_Dai_String* self) {
    return (void)self, _DAI_STR_SSOPT_BUF_CAP;
}

_DAI_FN size_t
_Dai_String_large_cap(_Dai_String* self) {
    return (self->_cap) >> CHAR_BIT;
}

_DAI_FN size_t
_Dai_String_get_cap(_Dai_String* self) {
    if (!_Dai_String_isLarge(self))
        return _Dai_String_small_cap(self);
    else
        return _Dai_String_large_cap(self);
}

_DAI_FN void
_Dai_String_set_large_cap(_Dai_String* self, size_t cap) {
    self->_cap = (cap << CHAR_BIT) | ((size_t)_Dai_String_get_flag(self));
}

_DAI_FN void
_Dai_String_set_large_flag_cap(_Dai_String* self, char flag, size_t cap) {
    self->_cap = (cap << CHAR_BIT) | flag;
}

/**********************/
/* "Public" Functions */
/**********************/

_DAI_FN size_t
_Dai_String_len(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self) ? _Dai_String_large_len(self) : _Dai_String_small_len(self);
}

_DAI_FN size_t
_Dai_String_cap(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self) ? _Dai_String_large_cap(self) : _Dai_String_small_cap(self);
}
_DAI_FN _Dai_String* _Dai_String_grow(_Dai_String* self, size_t size);
_DAI_FN char*
_Dai_String_cstr(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_isLarge(self)
               ? (self->_buf ? self->_buf : (_Dai_String_grow(self, 1), self->_buf))
               : (char*)self;
}

_DAI_FN _Dai_String_View
_Dai_String_to_View(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    _Dai_String_View view;
    if (_Dai_String_isLarge(self)) {
        view.str = self->_buf;
        view.len = self->_len;
    } else {
        view.str = (char*)self;
        view.len = _Dai_String_small_len(self);
    }
    return view;
}

_DAI_FN void
_Dai_String_set_char(_Dai_String* self, size_t pos, char c) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(pos < _Dai_String_len(self), "Out of bounds.");
    _Dai_String_cstr(self)[pos] = c;
}

_DAI_FN char
_Dai_String_get_char(_Dai_String* self, size_t pos) {
    _DAI_STRING_NONNULL(self);
    _DAI_PEDANTIC_ASSERT(pos < _Dai_String_len(self), "Out of bounds.");
    return _Dai_String_cstr(self)[pos];
}

_DAI_FN bool
_Dai_String_isEmpty(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_len(self) == 0;
}

/******************/
/* Memory Methods */
/******************/

/* If the string's using ssopt, convert it to large format. */
_DAI_FN _Dai_String*
_Dai_String_promote(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    if (_Dai_String_isLarge(self)) return self;

    size_t newlen = _Dai_String_small_cap(self);
    size_t newcap = 64;
    char* newbuf = (char*)_DAI_MALLOC(newcap);
    _DAI_STRING_OOMCHECK(newbuf);
    strcpy(newbuf, (char*)self);

    self->_buf = newbuf;
    _Dai_String_set_large_flag_cap(self, _DAI_STR_LARGE_FLAG, newcap);
    _Dai_String_set_large_len(self, newlen);
    return self;
}

// Returns malloced buffer
_DAI_FN char*
_Dai_String_revert(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_promote(self)->_buf;
}

/* If the string's in large format not using ssopt, and it could, make it.
 * Otherwise, shrink the allocation to size.
 */
_DAI_FN _Dai_String*
_Dai_String_shrink(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    bool large = _Dai_String_isLarge(self);
    if (large) {
        // If small enough, use ssopt.
        if (_Dai_String_len(self) <= _DAI_STR_SSOPT_BUF_CAP) {
            /* Copy large into small and free */
            size_t i;
            char* s = (char*)self;
            char* oldbuf = self->_buf;
            size_t oldlen = self->_len;
            for (i = 0; i < oldlen; i++) s[i] = oldbuf[i];
            s[i] = '\0';
            _Dai_String_set_small_len(self, oldlen);

            _DAI_FREE(oldbuf);
        }
        /* If not small enough for ssopt, shrink. */
        else {
            self->_buf = (char*)_DAI_REALLOC(self->_buf, self->_len);
            _DAI_STRING_OOMCHECK(self->_buf);
            _Dai_String_set_large_cap(self, self->_len);
            // Flag is large, len unchanged
        }
    }

    return self;
}

_DAI_FN _Dai_String*
_Dai_String_grow(_Dai_String* self, size_t size) {
    _DAI_STRING_NONNULL(self);
    self = _Dai_String_promote(self);

    // If it's big enough, nothing to do.
    if (size <= _Dai_String_get_cap(self)) return self;

    size = _Dai_align_max(size);
    self->_buf = (char*)_DAI_REALLOC(self->_buf, size);
    _DAI_STRING_OOMCHECK(self->_buf);
    _Dai_String_set_large_cap(self, self->_len);
    // Flag is large, len unchanged.

    return self;
}

_DAI_FN _Dai_String*
_Dai_String_append_len(_Dai_String* self, char* cstr, size_t size) {
    _DAI_STRING_NONNULL(self);
    _DAI_CSTR_NONNULL(cstr);
    if (!size) return self;

    size_t oldlen = _Dai_String_len(self);
    size_t newlen = oldlen + size;
    size_t oldcap = _Dai_String_cap(self);
    if (newlen <= oldcap) {
        // No need to reallocate
        strcpy(_Dai_String_cstr(self) + oldlen, cstr);
        _Dai_String_set_len(self, newlen);
        // Cap, buf, flag are unchanged.
    } else {
        // Need to reallocate
        if (newlen <= _DAI_STR_SSOPT_BUF_CAP) {
            // Reallocate small string
            _Dai_String newstr;
            char* newbuf = (char*)&newstr;
            char* oldbuf = _Dai_String_cstr(self);
            memcpy(newbuf, oldbuf, oldlen);
            memcpy(newbuf + oldlen, cstr, size);
            newbuf[newlen] = '\0';
            _Dai_String_set_small_len(self, newlen);
            *self = newstr;
            // Copy since may be backed by small string
        } else {
            // Reallocate large string
            self = _Dai_String_grow(self, newlen * 2);
            memcpy(self->_buf + oldlen, cstr, size);
            self->_buf[newlen] = '\0';
            _Dai_String_set_large_len(self, newlen);
            // New cap, buf, flag handled by grow
        }
    }

    return self;
}

_DAI_FN _Dai_String*
_Dai_String_append(_Dai_String* self, char* cstr) {
    _DAI_STRING_NONNULL(self);
    _DAI_CSTR_NONNULL(cstr);
    return _Dai_String_append_len(self, cstr, strlen(cstr));
}

_DAI_FN _Dai_String*
_Dai_String_join(_Dai_String* self, _Dai_String* append) {
    _DAI_STRING_NONNULL(self);
    return _Dai_String_append_len(self, _Dai_String_cstr(append), _Dai_String_len(append));
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Create an empty string. */
_DAI_FN _Dai_String
_Dai_String_init(void) {
    _Dai_String self;
    *(char*)(&self) = '\0';
    _Dai_String_set_small_len(&self, 0);
    return self;
}

_DAI_FN _Dai_String
_Dai_String_initLarge(void) {
    _Dai_String self;
    _Dai_String_set_large_flag_cap(&self, _DAI_STR_LARGE_FLAG, 0);
    _Dai_String_set_large_len(&self, 0);
    self._buf = NULL;
    return self;
}

/* Create a string with content */
_DAI_FN _Dai_String
_Dai_String_initWith(char* data, size_t len) {
    _Dai_String self;
    size_t i;

    /* Small */
    if (len <= _DAI_STR_SSOPT_BUF_CAP) {
        /* Use small string optimization */
        char* s = (char*)&self;
        for (i = 0; i < len; i++) s[i] = data[i];
        s[i] = '\0';
        _Dai_String_set_small_len(&self, len);
    }

    /* Large */
    else {
        /* Allocate and copy */
        size_t buf_cap = _Dai_align_max(len);
        char* buffer = (char*)_DAI_MALLOC(buf_cap);
        _DAI_STRING_OOMCHECK(buffer);

        for (i = 0; i < len; i++) buffer[i] = data[i];
        buffer[i] = '\0';

        _Dai_String_set_large_flag_cap(&self, CHAR_MAX, buf_cap);
        _Dai_String_set_large_len(&self, len);
        self._buf = buffer;
    }

    return self;
}

_DAI_FN _Dai_String
_Dai_String_initLen(char* data) {
    return _Dai_String_initWith(data, strlen(data));
}

/* Takes ownership of the memory. Assumes that it's allocated on the heap with malloc(). */
_DAI_FN _Dai_String
_Dai_String_initMalloced(char* data, size_t cap, size_t len) {
    _Dai_String self;
    _Dai_String_set_large_flag_cap(&self, CHAR_MAX, cap);
    _Dai_String_set_large_len(&self, len);
    self._buf = data;
    return self;
}

_DAI_FN _Dai_String
_Dai_String_copy(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    _Dai_String other;
    if (_Dai_String_isLarge(self)) {
        size_t cap = _Dai_String_get_cap(self);
        char* buffer = (char*)_DAI_MALLOC(cap);
        _DAI_STRING_OOMCHECK(buffer);
        other._buf = strcpy(buffer, self->_buf);
        size_t lastpart = offsetof(_Dai_String, _len);
        size_t firstpart = sizeof(_Dai_String) - lastpart;
        memcpy(&other + firstpart, self + firstpart, lastpart);
        return other;
    } else {
        memcpy(&other, self, sizeof(_Dai_String));
        return other;
    }
}

_DAI_FN void
_Dai_String_destroy(_Dai_String* self) {
    _DAI_STRING_NONNULL(self);
    if (_Dai_String_isLarge(self)) _DAI_FREE(self->_buf);
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
        _Dai_String newstr = _Dai_String_initWith(checkpoint, (size_t)(match - checkpoint));

        // TODO: Figure out how better to output the list of strings. This may
        // have to wait until generics are implemented.
        _Dai_String_println(&newstr);

        checkpoint = match + startsWithdelimlen;
    }
}

#endif /* _DAI_STDLIB_STRING */
