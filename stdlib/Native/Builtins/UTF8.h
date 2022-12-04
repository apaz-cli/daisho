#pragma once
#ifndef _DAI_STDLIB_UTF8
#define _DAI_STDLIB_UTF8
#include "../PreStart/PreStart.h"
#include "Files.h"
#include "String.h"

#define _DAI_UTF8_END -1  // 1111 1111
#define _DAI_UTF8_ERR -2  // 1111 1110

/* The functions in this file convert between
 * _Dai_Unicode_Codepoint_String_View and
 * _Dai_UTF8_String_View.
 */

typedef int32_t _Dai_Unicode_Codepoint;

typedef struct {
    _Dai_Unicode_Codepoint* content;
    size_t len;
} _Dai_Unicode_Codepoint_String_View;

typedef struct {
    char* content;
    size_t len;
} _Dai_UTF8_String_View;

typedef struct {
    size_t idx;
    size_t len;
    size_t chr;
    size_t byte;
    char* inp;
} _Dai_UTF8State;

/***********/
/* Helpers */
/***********/

/* Get the next byte. Returns _DAI_UTF8_END if there are no more bytes. */
_DAI_FN char
_Dai_UTF8_cont_8(_Dai_UTF8State* state) {
    if (state->idx >= state->len) return _DAI_UTF8_END;
    char c = (state->inp[state->idx] & 0xFF);
    state->idx += 1;
    return c;
}

/*
 * Get the 6-bit payload of the next continuation byte.
 * Return _DAI_UTF8_ERR if it is not a contination byte.
 */
_DAI_FN char
_Dai_UTF8_cont_6(_Dai_UTF8State* state) {
    char c = _Dai_UTF8_cont_8(state);
    return ((c & 0xC0) == 0x80) ? (c & 0x3F) : _DAI_UTF8_ERR;
}

/**************/
/* Public API */
/**************/

/**********/
/* DECODE */
/**********/

/* Initialize the UTF-8 decoder. The decoder is not reentrant. */
_DAI_FN void
_Dai_UTF8_decode_init(_Dai_UTF8State* state, char* str, size_t len) {
    state->idx = 0;
    state->inp = str;
    state->len = len;
    state->chr = 0;
    state->byte = 0;
}

/* Get the current byte offset. This is generally used in error reporting. */
_DAI_FN size_t
_Dai_UTF8_atByte(_Dai_UTF8State* state) {
    return state->byte;
}

/*
 * Get the current character offset. This is generally used in error reporting.
 * The character offset matches the byte offset if the text is strictly ASCII.
 */
_DAI_FN size_t
_Dai_UTF8_atCharacter(_Dai_UTF8State* state) {
    return (state->chr > 0) ? state->chr - 1 : 0;
}

/*
 * Extract the next unicode code point.
 * Returns the character, or _DAI_UTF8_END, or _DAI_UTF8_ERR.
 */
_DAI_FN _Dai_Unicode_Codepoint
_Dai_UTF8_decodeNext(_Dai_UTF8State* state) {
    char c;                    /* the first byte of the character */
    char c1;                   /* the first continuation character */
    char c2;                   /* the second continuation character */
    char c3;                   /* the third continuation character */
    _Dai_Unicode_Codepoint r; /* the result */

    if (state->idx >= state->len) return state->idx == state->len ? _DAI_UTF8_END : _DAI_UTF8_ERR;

    state->byte = state->idx;
    state->chr += 1;
    c = _Dai_UTF8_cont_8(state);

    /* Zero continuation (0 to 127) */
    if ((c & 0x80) == 0) {
        return c;
    }
    /* One continuation (128 to 2047) */
    else if ((c & 0xE0) == 0xC0) {
        c1 = _Dai_UTF8_cont_6(state);
        if (c1 >= 0) {
            r = ((c & 0x1F) << 6) | c1;
            if (r >= 128) return r;
        }
    }
    /* Two continuations (2048 to 55295 and 57344 to 65535) */
    else if ((c & 0xF0) == 0xE0) {
        c1 = _Dai_UTF8_cont_6(state);
        c2 = _Dai_UTF8_cont_6(state);
        if ((c1 | c2) >= 0) {
            r = ((c & 0x0F) << 12) | (c1 << 6) | c2;
            if (r >= 2048 && (r < 55296 || r > 57343)) return r;
        }
    }
    /* Three continuations (65536 to 1114111) */
    else if ((c & 0xF8) == 0xF0) {
        c1 = _Dai_UTF8_cont_6(state);
        c2 = _Dai_UTF8_cont_6(state);
        c3 = _Dai_UTF8_cont_6(state);
        if ((c1 | c2 | c3) >= 0) {
            r = ((c & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3;
            if (r >= 65536 && r <= 1114111) return r;
        }
    }
    return _DAI_UTF8_ERR;
}

/**********/
/* ENCODE */
/**********/

/*
 * Encodes the given UTF8 code point into the given buffer.
 * Returns the number of characters in the buffer used.
 */
_DAI_FN size_t
_Dai_UTF8_encodeNext(_Dai_Unicode_Codepoint codepoint, char* buf4) {
    if (codepoint <= 0x7F) {
        buf4[0] = (char)codepoint;
        return 1;
    } else if (codepoint <= 0x07FF) {
        buf4[0] = (char)(((codepoint >> 6) & 0x1F) | 0xC0);
        buf4[1] = (char)(((codepoint >> 0) & 0x3F) | 0x80);
        return 2;
    } else if (codepoint <= 0xFFFF) {
        buf4[0] = (char)(((codepoint >> 12) & 0x0F) | 0xE0);
        buf4[1] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        buf4[2] = (char)(((codepoint >> 0) & 0x3F) | 0x80);
        return 3;
    } else if (codepoint <= 0x10FFFF) {
        buf4[0] = (char)(((codepoint >> 18) & 0x07) | 0xF0);
        buf4[1] = (char)(((codepoint >> 12) & 0x3F) | 0x80);
        buf4[2] = (char)(((codepoint >> 6) & 0x3F) | 0x80);
        buf4[3] = (char)(((codepoint >> 0) & 0x3F) | 0x80);
        return 4;
    }
    return 0;
}

#define _Dai_UTF8_encode(codepoints, len) \
    _Dai__UTF8_encode(codepoints, len, __LINE__, __func__, __FILE__)
_DAI_FN _Dai_UTF8_String_View
_Dai__UTF8_encode(_Dai_Unicode_Codepoint* codepoints, size_t len, size_t line, const char* func,
                   const char* file) {
    _Dai_UTF8_String_View ret;
    ret.content = NULL;
    ret.len = 0;

    // Allocate at least enough memory.
    char buf4[4];
    char* out_buf =
        (char*)_Dai_malloc(len * sizeof(_Dai_Unicode_Codepoint) + 1, line, func, file);
    if (!out_buf) return ret;

    size_t characters_used = 0;

    // For each unicode codepoint
    for (size_t i = 0; i < len; i++) {
        // Decode it, handle error
        size_t used = _Dai_UTF8_encodeNext(codepoints[i], buf4);
        if (!used) return ret;

        // Copy the result onto the end of the buffer
        for (size_t j = 0; j < used; j++) out_buf[characters_used++] = buf4[j];
    }

    // Add the null terminator, shrink to size
    out_buf[characters_used] = '\0';
    out_buf = (char*)_Dai_realloc(out_buf, characters_used + 1, line, func, file);

    // Return the result
    ret.content = out_buf;
    ret.len = characters_used;
    return ret;
}

_DAI_FN _Dai_UTF8_String_View
_Dai_UTF8_encode_len(_Dai_Unicode_Codepoint* codepoints) {
    // strlen()
    const _Dai_Unicode_Codepoint* s;
    for (s = codepoints; *s; ++s)
        ;
    size_t len = (s - codepoints);
    return _Dai_UTF8_encode(codepoints, len);
}

_DAI_FN _Dai_UTF8_String_View
_Dai_UTF8_encode_view(_Dai_Unicode_Codepoint_String_View view) {
    return _Dai_UTF8_encode(view.content, view.len);
}

/****************/
/* File Interop */
/****************/

/* Open the file, ensuring that it parses as UTF8. */
_DAI_FN _Dai_UTF8_String_View
_Dai_UTF8_readFile(char* filePath) {
    _Dai_String_View view = _Dai_readFile(filePath);
    _Dai_UTF8State state;
    _Dai_UTF8_decode_init(&state, view.str, view.len);

    _Dai_Unicode_Codepoint cp;
    _Dai_UTF8_String_View sv;
    for (;;) {
        cp = _Dai_UTF8_decodeNext(&state);

        if (cp == _DAI_UTF8_ERR) {
            sv.content = NULL;
            sv.len = 0;
            return sv;
        } else if (cp == _DAI_UTF8_END) {
            break;
        }
    };

    sv.content = view.str;
    sv.len = view.len;
    return sv;
}

/* Open the file, converting to  that it parses as UTF8. */
_DAI_FN _Dai_Unicode_Codepoint_String_View
_Dai_Unicode_readFile(char* filePath) {
    _Dai_String_View view = _Dai_readFile(filePath);
    _Dai_UTF8State state;
    _Dai_UTF8_decode_init(&state, view.str, view.len);

    /* Over-allocate enough space. */
    _Dai_Unicode_Codepoint* cps =
        (_Dai_Unicode_Codepoint*)_DAI_MALLOC(sizeof(_Dai_Unicode_Codepoint) * view.len + 1);

    /* Parse */
    _Dai_Unicode_Codepoint cp;
    _Dai_Unicode_Codepoint_String_View sv;
    for (;;) {
        cp = _Dai_UTF8_decodeNext(&state);

        if (cp == _DAI_UTF8_ERR) {
            sv.content = NULL;
            sv.len = 0;
            return sv;
        } else if (cp == _DAI_UTF8_END) {
            break;
        }
    };

    /* Don't resize it at the end. The caller can if they want. */
    cps[view.len] = '\0';
    sv.content = cps;
    sv.len = view.len;
    return sv;
}

#endif /* _DAI_STDLIB_UTF8 */
