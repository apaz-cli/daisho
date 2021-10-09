/*
    Very Strict UTF-8 Decoder

    UTF-8 is a multibyte character encoding of Unicode. A character can be
    represented by 1-4 bytes. The bit pattern of the first byte indicates the
    number of continuation bytes.

    Most UTF-8 decoders tend to be lenient, attempting to recover as much
    information as possible, even from badly encoded input. This UTF-8
    decoder is not lenient. It will reject input which does not include
    proper continuation bytes. It will reject aliases (or suboptimal
    codings). It will reject surrogates. (Surrogate encoding should only be
    used with UTF-16.)

    Code     Contination Minimum Maximum
    0xxxxxxx           0       0     127
    10xxxxxx       error
    110xxxxx           1     128    2047
    1110xxxx           2    2048   65535 excluding 55296 - 57343
    11110xxx           3   65536 1114111
    11111xxx       error
*/

/* 2016-04-05 */

/*
Copyright (c) 2005 JSON.org

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

The Software shall be used for Good, not Evil.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// I have made some changes for stiltc, such as renaming functions, merging
// header and implementation, utf8_t type, etc.

#ifndef UTF8_INCLUDE
#define UTF8_INCLUDE

#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <stdint.h>

/* utf8_decode.h */
#define UTF8_END -1
#define UTF8_ERROR -2
typedef int utf8_t;

/* utf8_decode.c */

static int _the_index = 0;
static int _the_length = 0;
static int _the_char = 0;
static int _the_byte = 0;
static char *_the_input;

struct UTF8State {
  int _the_index;
  int _the_length;
  int _the_char;
  int _the_byte;
  char *_the_input;
};
typedef struct UTF8State UTF8State;

/* Get the next byte. It returns UTF8_END if there are no more bytes. */
static inline int _utf8_get() {
  int c;
  if (_the_index >= _the_length)
    return UTF8_END;
  c = _the_input[_the_index] & 0xFF;
  _the_index += 1;
  return c;
}

/*
 * Get the 6-bit payload of the next continuation byte.
 * Return UTF8_ERROR if it is not a contination byte.
 */
static inline int _utf8_cont() {
  int c = _utf8_get();
  return ((c & 0xC0) == 0x80) ? (c & 0x3F) : UTF8_ERROR;
}

/* Initialize the UTF-8 decoder. The decoder is not reentrant. */
static inline void utf8_decode_init(char *str, int len) {
  _the_index = 0;
  _the_input = str;
  _the_length = len;
  _the_char = 0;
  _the_byte = 0;
}

/* Get the current byte offset. This is generally used in error reporting. */
static inline int utf8_decode_at_byte() { return _the_byte; }

/*
 * Get the current character offset. This is generally used in error reporting.
 * The character offset matches the byte offset if the text is strictly ASCII.
 */
static inline int utf8_decode_at_character() {
  return (_the_char > 0) ? _the_char - 1 : 0;
}

/*
    Extract the next character.
    Returns: the character (between 0 and 1114111)
         or  UTF8_END   (the end)
         or  UTF8_ERROR (error)
*/
static inline utf8_t utf8_decode_next() {
  int c;    /* the first byte of the character */
  int c1;   /* the first continuation character */
  int c2;   /* the second continuation character */
  int c3;   /* the third continuation character */
  utf8_t r; /* the result */

  if (_the_index >= _the_length) {
    return _the_index == _the_length ? UTF8_END : UTF8_ERROR;
  }
  _the_byte = _the_index;
  _the_char += 1;
  c = _utf8_get();
  /* Zero continuation (0 to 127) */
  if ((c & 0x80) == 0) {
    return c;
  }
  /* One continuation (128 to 2047) */
  if ((c & 0xE0) == 0xC0) {
    c1 = _utf8_cont();
    if (c1 >= 0) {
      r = ((c & 0x1F) << 6) | c1;
      if (r >= 128) {
        return r;
      }
    }
    /* Two continuations (2048 to 55295 and 57344 to 65535) */
  } else if ((c & 0xF0) == 0xE0) {
    c1 = _utf8_cont();
    c2 = _utf8_cont();
    if ((c1 | c2) >= 0) {
      r = ((c & 0x0F) << 12) | (c1 << 6) | c2;
      if (r >= 2048 && (r < 55296 || r > 57343)) {
        return r;
      }
    }
    /* Three continuations (65536 to 1114111) */
  } else if ((c & 0xF8) == 0xF0) {
    c1 = _utf8_cont();
    c2 = _utf8_cont();
    c3 = _utf8_cont();
    if ((c1 | c2 | c3) >= 0) {
      r = ((c & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3;
      if (r >= 65536 && r <= 1114111) {
        return r;
      }
    }
  }
  return UTF8_ERROR;
}

#endif // UTF8_INCLUDE