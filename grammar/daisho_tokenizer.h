
/* START OF UTF8 LIBRARY */

#ifndef PGEN_UTF8_INCLUDED
#define PGEN_UTF8_INCLUDED
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#define UTF8_END -1 /* 1111 1111 */
#define UTF8_ERR -2 /* 1111 1110 */

typedef int32_t codepoint_t;
#define PRI_CODEPOINT PRIu32

typedef struct {
  size_t idx;
  size_t len;
  size_t chr;
  size_t byte;
  char *inp;
} UTF8Decoder;

static inline void UTF8_decoder_init(UTF8Decoder *state, char *str,
                                     size_t len) {
  state->idx = 0;
  state->len = len;
  state->chr = 0;
  state->byte = 0;
  state->inp = str;
}

static inline char UTF8_nextByte(UTF8Decoder *state) {
  char c;
  if (state->idx >= state->len)
    return UTF8_END;
  c = (state->inp[state->idx] & 0xFF);
  state->idx += 1;
  return c;
}

static inline char UTF8_contByte(UTF8Decoder *state) {
  char c;
  c = UTF8_nextByte(state);
  return ((c & 0xC0) == 0x80) ? (c & 0x3F) : UTF8_ERR;
}

/* Extract the next unicode code point. Returns c, UTF8_END, or UTF8_ERR. */
static inline codepoint_t UTF8_decodeNext(UTF8Decoder *state) {
  codepoint_t c;
  char c0, c1, c2, c3;

  if (state->idx >= state->len)
    return state->idx == state->len ? UTF8_END : UTF8_ERR;

  state->byte = state->idx;
  state->chr += 1;
  c0 = UTF8_nextByte(state);

  if ((c0 & 0x80) == 0) {
    return (codepoint_t)c0;
  } else if ((c0 & 0xE0) == 0xC0) {
    c1 = UTF8_contByte(state);
    if (c1 >= 0) {
      c = ((c0 & 0x1F) << 6) | c1;
      if (c >= 128)
        return c;
    }
  } else if ((c0 & 0xF0) == 0xE0) {
    c1 = UTF8_contByte(state);
    c2 = UTF8_contByte(state);
    if ((c1 | c2) >= 0) {
      c = ((c0 & 0x0F) << 12) | (c1 << 6) | c2;
      if ((c >= 2048) & ((c < 55296) | (c > 57343)))
        return c;
    }
  } else if ((c0 & 0xF8) == 0xF0) {
    c1 = UTF8_contByte(state);
    c2 = UTF8_contByte(state);
    c3 = UTF8_contByte(state);
    if ((c1 | c2 | c3) >= 0) {
      c = ((c0 & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3;
      if ((c >= 65536) & (c <= 1114111))
        return c;
    }
  }
  return UTF8_ERR;
}

static inline size_t UTF8_encodeNext(codepoint_t codepoint, char *buf4) {
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

/*
 * Convert UTF32 codepoints to a utf8 string.
 * This will malloc() a buffer large enough, and store it to retstr and its
 * length to retcps. The result is not null terminated.
 * Returns 1 on success, 0 on failure. Cleans up the buffer and does not store
 * to retstr or retlen on failure.
 */
static inline int UTF8_encode(codepoint_t *codepoints, size_t len, char **retstr,
                       size_t *retlen) {
  char buf4[4];
  size_t characters_used = 0, used, i, j;
  char *out_buf, *new_obuf;

  if ((!codepoints) | (!len))
    return 0;
  if (!(out_buf = (char *)malloc(len * sizeof(codepoint_t) + 1)))
    return 0;

  for (i = 0; i < len; i++) {
    if (!(used = UTF8_encodeNext(codepoints[i], buf4)))
      return 0;
    for (j = 0; j < used; j++)
      out_buf[characters_used++] = buf4[j];
  }

  out_buf[characters_used] = '\0';
  new_obuf = (char *)realloc(out_buf, characters_used + 1);
  *retstr = new_obuf ? new_obuf : out_buf;
  *retlen = characters_used;
  return 1;
}

/*
 * Convert a UTF8 string to UTF32 codepoints.
 * This will malloc() a buffer large enough, and store it to retstr and its
 * length to retcps. The result is not null terminated.
 * Returns 1 on success, 0 on failure. Cleans up the buffer and does not store
 * to retcps or retlen on failure.
 */
static inline int UTF8_decode(char *str, size_t len, codepoint_t **retcps,
                              size_t *retlen) {
  UTF8Decoder state;
  codepoint_t *cpbuf, cp;
  size_t cps_read = 0;

  if ((!str) | (!len))
    return 0;
  if (!(cpbuf = (codepoint_t *)malloc(sizeof(codepoint_t) * len)))
    return 0;

  UTF8_decoder_init(&state, str, len);
  for (;;) {
    cp = UTF8_decodeNext(&state);
    if ((cp == UTF8_ERR) | (cp == UTF8_END))
      break;
    cpbuf[cps_read++] = cp;
  }

  if (cp == UTF8_ERR)
    return free(cpbuf), 0;

  *retcps = cpbuf;
  *retlen = cps_read;
  return 1;
}

#endif /* PGEN_UTF8 */

/* END OF UTF8 LIBRARY */


#ifndef DAISHO_TOKENIZER_INCLUDE
#define DAISHO_TOKENIZER_INCLUDE

#ifndef DAISHO_TOKENIZER_SOURCEINFO
#define DAISHO_TOKENIZER_SOURCEINFO 1
#endif

typedef enum {
  DAISHO_TOK_STREAMEND,
  DAISHO_TOK_PLUS,
  DAISHO_TOK_MINUS,
  DAISHO_TOK_MUL,
  DAISHO_TOK_DIV,
  DAISHO_TOK_MOD,
  DAISHO_TOK_AND,
  DAISHO_TOK_OR,
  DAISHO_TOK_XOR,
  DAISHO_TOK_NOT,
  DAISHO_TOK_BITNOT,
  DAISHO_TOK_LOGAND,
  DAISHO_TOK_LOGOR,
  DAISHO_TOK_DEQ,
  DAISHO_TOK_NEQ,
  DAISHO_TOK_LT,
  DAISHO_TOK_LEQ,
  DAISHO_TOK_GT,
  DAISHO_TOK_GEQ,
  DAISHO_TOK_EQ,
  DAISHO_TOK_PLEQ,
  DAISHO_TOK_MINEQ,
  DAISHO_TOK_MULEQ,
  DAISHO_TOK_DIVEQ,
  DAISHO_TOK_MODEQ,
  DAISHO_TOK_ANDEQ,
  DAISHO_TOK_OREQ,
  DAISHO_TOK_XOREQ,
  DAISHO_TOK_BNEQ,
  DAISHO_TOK_BSREQ,
  DAISHO_TOK_BSLEQ,
  DAISHO_TOK_INCR,
  DAISHO_TOK_DECR,
  DAISHO_TOK_ELVIS,
  DAISHO_TOK_QUEST,
  DAISHO_TOK_COLON,
  DAISHO_TOK_IF,
  DAISHO_TOK_ELSE,
  DAISHO_TOK_WHILE,
  DAISHO_TOK_DO,
  DAISHO_TOK_THEN,
  DAISHO_TOK_ALSO,
  DAISHO_TOK_CLASS,
  DAISHO_TOK_TRAIT,
  DAISHO_TOK_DYN,
  DAISHO_TOK_CTYPE,
  DAISHO_TOK_SEMI,
  DAISHO_TOK_DOT,
  DAISHO_TOK_COMMA,
  DAISHO_TOK_OPEN,
  DAISHO_TOK_CLOSE,
  DAISHO_TOK_HASH,
  DAISHO_TOK_DOLLAR,
  DAISHO_TOK_AT,
  DAISHO_TOK_GRAVE,
  DAISHO_TOK_RET,
  DAISHO_TOK_IMPL,
  DAISHO_TOK_OP,
  DAISHO_TOK_IDENT,
  DAISHO_TOK_NUM,
  DAISHO_TOK_STRLIT,
  DAISHO_TOK_WS,
  DAISHO_TOK_MLCOM,
  DAISHO_TOK_SLCOM,
  DAISHO_TOK_SHEBANG,
} daisho_token_kind;

// The 0th token is end of stream.
// Tokens 1 through 64 are the ones you defined.
// This totals 65 kinds of tokens.
static size_t daisho_num_tokens = 65;
static const char* daisho_kind_name[] = {
  "DAISHO_TOK_STREAMEND",
  "DAISHO_TOK_PLUS",
  "DAISHO_TOK_MINUS",
  "DAISHO_TOK_MUL",
  "DAISHO_TOK_DIV",
  "DAISHO_TOK_MOD",
  "DAISHO_TOK_AND",
  "DAISHO_TOK_OR",
  "DAISHO_TOK_XOR",
  "DAISHO_TOK_NOT",
  "DAISHO_TOK_BITNOT",
  "DAISHO_TOK_LOGAND",
  "DAISHO_TOK_LOGOR",
  "DAISHO_TOK_DEQ",
  "DAISHO_TOK_NEQ",
  "DAISHO_TOK_LT",
  "DAISHO_TOK_LEQ",
  "DAISHO_TOK_GT",
  "DAISHO_TOK_GEQ",
  "DAISHO_TOK_EQ",
  "DAISHO_TOK_PLEQ",
  "DAISHO_TOK_MINEQ",
  "DAISHO_TOK_MULEQ",
  "DAISHO_TOK_DIVEQ",
  "DAISHO_TOK_MODEQ",
  "DAISHO_TOK_ANDEQ",
  "DAISHO_TOK_OREQ",
  "DAISHO_TOK_XOREQ",
  "DAISHO_TOK_BNEQ",
  "DAISHO_TOK_BSREQ",
  "DAISHO_TOK_BSLEQ",
  "DAISHO_TOK_INCR",
  "DAISHO_TOK_DECR",
  "DAISHO_TOK_ELVIS",
  "DAISHO_TOK_QUEST",
  "DAISHO_TOK_COLON",
  "DAISHO_TOK_IF",
  "DAISHO_TOK_ELSE",
  "DAISHO_TOK_WHILE",
  "DAISHO_TOK_DO",
  "DAISHO_TOK_THEN",
  "DAISHO_TOK_ALSO",
  "DAISHO_TOK_CLASS",
  "DAISHO_TOK_TRAIT",
  "DAISHO_TOK_DYN",
  "DAISHO_TOK_CTYPE",
  "DAISHO_TOK_SEMI",
  "DAISHO_TOK_DOT",
  "DAISHO_TOK_COMMA",
  "DAISHO_TOK_OPEN",
  "DAISHO_TOK_CLOSE",
  "DAISHO_TOK_HASH",
  "DAISHO_TOK_DOLLAR",
  "DAISHO_TOK_AT",
  "DAISHO_TOK_GRAVE",
  "DAISHO_TOK_RET",
  "DAISHO_TOK_IMPL",
  "DAISHO_TOK_OP",
  "DAISHO_TOK_IDENT",
  "DAISHO_TOK_NUM",
  "DAISHO_TOK_STRLIT",
  "DAISHO_TOK_WS",
  "DAISHO_TOK_MLCOM",
  "DAISHO_TOK_SLCOM",
  "DAISHO_TOK_SHEBANG",
};

typedef struct {
  daisho_token_kind kind;
  size_t start; // The token begins at tokenizer->start[token->start]. 
  size_t len;   // It goes until tokenizer->start[token->start + token->len] (non-inclusive).
#if DAISHO_TOKENIZER_SOURCEINFO
  size_t line;
  size_t col;
  char* sourceFile;
#endif
} daisho_token;

typedef struct {
  codepoint_t* start;
  size_t len;
  size_t pos;
#if DAISHO_TOKENIZER_SOURCEINFO
  size_t pos_line;
  size_t pos_col;
  char* pos_sourceFile;
#endif
} daisho_tokenizer;

static inline void daisho_tokenizer_init(daisho_tokenizer* tokenizer, codepoint_t* start, size_t len, char* sourceFile) {
  tokenizer->start = start;
  tokenizer->len = len;
  tokenizer->pos = 0;
#if DAISHO_TOKENIZER_SOURCEINFO
  tokenizer->pos_line = 0;
  tokenizer->pos_col = 0;
  tokenizer->pos_sourceFile = sourceFile;
#else
  (void)sourceFile;
#endif
}

static inline daisho_token daisho_nextToken(daisho_tokenizer* tokenizer) {
  codepoint_t* current = tokenizer->start + tokenizer->pos;
  size_t remaining = tokenizer->len - tokenizer->pos;

  int trie_state = 0;
  int smaut_state_0 = 0;
  int smaut_state_1 = 0;
  int smaut_state_2 = 0;
  int smaut_state_3 = 0;
  int smaut_state_4 = 0;
  int smaut_state_5 = 0;
  int smaut_state_6 = 0;
  int smaut_state_7 = 0;
  int smaut_state_8 = 0;
  int smaut_state_9 = 0;
  size_t trie_munch_size = 0;
  size_t smaut_munch_size_0 = 0;
  size_t smaut_munch_size_1 = 0;
  size_t smaut_munch_size_2 = 0;
  size_t smaut_munch_size_3 = 0;
  size_t smaut_munch_size_4 = 0;
  size_t smaut_munch_size_5 = 0;
  size_t smaut_munch_size_6 = 0;
  size_t smaut_munch_size_7 = 0;
  size_t smaut_munch_size_8 = 0;
  size_t smaut_munch_size_9 = 0;
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_0 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_1 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_2 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_3 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_4 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_5 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_6 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_7 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_8 = DAISHO_TOK_STREAMEND;
  daisho_token_kind smaut_tokenkind_9 = DAISHO_TOK_STREAMEND;


  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 9;
        else if (c == 35 /*'#'*/) trie_state = 79;
        else if (c == 36 /*'$'*/) trie_state = 80;
        else if (c == 37 /*'%'*/) trie_state = 5;
        else if (c == 38 /*'&'*/) trie_state = 6;
        else if (c == 40 /*'('*/) trie_state = 77;
        else if (c == 41 /*')'*/) trie_state = 78;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 76;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 75;
        else if (c == 47 /*'/'*/) trie_state = 4;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 74;
        else if (c == 60 /*'<'*/) trie_state = 16;
        else if (c == 61 /*'='*/) trie_state = 13;
        else if (c == 62 /*'>'*/) trie_state = 18;
        else if (c == 63 /*'?'*/) trie_state = 35;
        else if (c == 64 /*'@'*/) trie_state = 81;
        else if (c == 94 /*'^'*/) trie_state = 8;
        else if (c == 96 /*'`'*/) trie_state = 82;
        else if (c == 97 /*'a'*/) trie_state = 55;
        else if (c == 99 /*'c'*/) trie_state = 59;
        else if (c == 100 /*'d'*/) trie_state = 49;
        else if (c == 101 /*'e'*/) trie_state = 40;
        else if (c == 105 /*'i'*/) trie_state = 38;
        else if (c == 116 /*'t'*/) trie_state = 51;
        else if (c == 119 /*'w'*/) trie_state = 44;
        else if (c == 124 /*'|'*/) trie_state = 7;
        else if (c == 126 /*'~'*/) trie_state = 10;
        else trie_state = -1;
      }
      else if (trie_state == 1) {
        if (c == 43 /*'+'*/) trie_state = 33;
        else if (c == 61 /*'='*/) trie_state = 20;
        else trie_state = -1;
      }
      else if (trie_state == 2) {
        if (c == 45 /*'-'*/) trie_state = 34;
        else if (c == 61 /*'='*/) trie_state = 21;
        else trie_state = -1;
      }
      else if (trie_state == 3) {
        if (c == 61 /*'='*/) trie_state = 22;
        else trie_state = -1;
      }
      else if (trie_state == 4) {
        if (c == 61 /*'='*/) trie_state = 23;
        else trie_state = -1;
      }
      else if (trie_state == 5) {
        if (c == 61 /*'='*/) trie_state = 24;
        else trie_state = -1;
      }
      else if (trie_state == 6) {
        if (c == 38 /*'&'*/) trie_state = 11;
        else if (c == 61 /*'='*/) trie_state = 25;
        else trie_state = -1;
      }
      else if (trie_state == 7) {
        if (c == 61 /*'='*/) trie_state = 26;
        else if (c == 124 /*'|'*/) trie_state = 12;
        else trie_state = -1;
      }
      else if (trie_state == 8) {
        if (c == 61 /*'='*/) trie_state = 27;
        else trie_state = -1;
      }
      else if (trie_state == 9) {
        if (c == 61 /*'='*/) trie_state = 15;
        else trie_state = -1;
      }
      else if (trie_state == 10) {
        if (c == 61 /*'='*/) trie_state = 28;
        else trie_state = -1;
      }
      else if (trie_state == 13) {
        if (c == 61 /*'='*/) trie_state = 14;
        else trie_state = -1;
      }
      else if (trie_state == 16) {
        if (c == 60 /*'<'*/) trie_state = 31;
        else if (c == 61 /*'='*/) trie_state = 17;
        else trie_state = -1;
      }
      else if (trie_state == 18) {
        if (c == 61 /*'='*/) trie_state = 19;
        else if (c == 62 /*'>'*/) trie_state = 29;
        else trie_state = -1;
      }
      else if (trie_state == 29) {
        if (c == 61 /*'='*/) trie_state = 30;
        else trie_state = -1;
      }
      else if (trie_state == 31) {
        if (c == 61 /*'='*/) trie_state = 32;
        else trie_state = -1;
      }
      else if (trie_state == 35) {
        if (c == 58 /*':'*/) trie_state = 36;
        else trie_state = -1;
      }
      else if (trie_state == 38) {
        if (c == 102 /*'f'*/) trie_state = 39;
        else trie_state = -1;
      }
      else if (trie_state == 40) {
        if (c == 108 /*'l'*/) trie_state = 41;
        else trie_state = -1;
      }
      else if (trie_state == 41) {
        if (c == 115 /*'s'*/) trie_state = 42;
        else trie_state = -1;
      }
      else if (trie_state == 42) {
        if (c == 101 /*'e'*/) trie_state = 43;
        else trie_state = -1;
      }
      else if (trie_state == 44) {
        if (c == 104 /*'h'*/) trie_state = 45;
        else trie_state = -1;
      }
      else if (trie_state == 45) {
        if (c == 105 /*'i'*/) trie_state = 46;
        else trie_state = -1;
      }
      else if (trie_state == 46) {
        if (c == 108 /*'l'*/) trie_state = 47;
        else trie_state = -1;
      }
      else if (trie_state == 47) {
        if (c == 101 /*'e'*/) trie_state = 48;
        else trie_state = -1;
      }
      else if (trie_state == 49) {
        if (c == 111 /*'o'*/) trie_state = 50;
        else if (c == 121 /*'y'*/) trie_state = 68;
        else trie_state = -1;
      }
      else if (trie_state == 51) {
        if (c == 104 /*'h'*/) trie_state = 52;
        else if (c == 114 /*'r'*/) trie_state = 64;
        else trie_state = -1;
      }
      else if (trie_state == 52) {
        if (c == 101 /*'e'*/) trie_state = 53;
        else trie_state = -1;
      }
      else if (trie_state == 53) {
        if (c == 110 /*'n'*/) trie_state = 54;
        else trie_state = -1;
      }
      else if (trie_state == 55) {
        if (c == 108 /*'l'*/) trie_state = 56;
        else trie_state = -1;
      }
      else if (trie_state == 56) {
        if (c == 115 /*'s'*/) trie_state = 57;
        else trie_state = -1;
      }
      else if (trie_state == 57) {
        if (c == 111 /*'o'*/) trie_state = 58;
        else trie_state = -1;
      }
      else if (trie_state == 59) {
        if (c == 108 /*'l'*/) trie_state = 60;
        else if (c == 116 /*'t'*/) trie_state = 70;
        else trie_state = -1;
      }
      else if (trie_state == 60) {
        if (c == 97 /*'a'*/) trie_state = 61;
        else trie_state = -1;
      }
      else if (trie_state == 61) {
        if (c == 115 /*'s'*/) trie_state = 62;
        else trie_state = -1;
      }
      else if (trie_state == 62) {
        if (c == 115 /*'s'*/) trie_state = 63;
        else trie_state = -1;
      }
      else if (trie_state == 64) {
        if (c == 97 /*'a'*/) trie_state = 65;
        else trie_state = -1;
      }
      else if (trie_state == 65) {
        if (c == 105 /*'i'*/) trie_state = 66;
        else trie_state = -1;
      }
      else if (trie_state == 66) {
        if (c == 116 /*'t'*/) trie_state = 67;
        else trie_state = -1;
      }
      else if (trie_state == 68) {
        if (c == 110 /*'n'*/) trie_state = 69;
        else trie_state = -1;
      }
      else if (trie_state == 70) {
        if (c == 121 /*'y'*/) trie_state = 71;
        else trie_state = -1;
      }
      else if (trie_state == 71) {
        if (c == 112 /*'p'*/) trie_state = 72;
        else trie_state = -1;
      }
      else if (trie_state == 72) {
        if (c == 101 /*'e'*/) trie_state = 73;
        else trie_state = -1;
      }
      else {
        trie_state = -1;
      }

      // Check accept
      if (trie_state == 1) {
        trie_tokenkind =  DAISHO_TOK_PLUS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 2) {
        trie_tokenkind =  DAISHO_TOK_MINUS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 3) {
        trie_tokenkind =  DAISHO_TOK_MUL;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 4) {
        trie_tokenkind =  DAISHO_TOK_DIV;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 5) {
        trie_tokenkind =  DAISHO_TOK_MOD;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 6) {
        trie_tokenkind =  DAISHO_TOK_AND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 7) {
        trie_tokenkind =  DAISHO_TOK_OR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 8) {
        trie_tokenkind =  DAISHO_TOK_XOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 9) {
        trie_tokenkind =  DAISHO_TOK_NOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 10) {
        trie_tokenkind =  DAISHO_TOK_BITNOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 11) {
        trie_tokenkind =  DAISHO_TOK_LOGAND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 12) {
        trie_tokenkind =  DAISHO_TOK_LOGOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 14) {
        trie_tokenkind =  DAISHO_TOK_DEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 15) {
        trie_tokenkind =  DAISHO_TOK_NEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 16) {
        trie_tokenkind =  DAISHO_TOK_LT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 17) {
        trie_tokenkind =  DAISHO_TOK_LEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 18) {
        trie_tokenkind =  DAISHO_TOK_GT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 19) {
        trie_tokenkind =  DAISHO_TOK_GEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 13) {
        trie_tokenkind =  DAISHO_TOK_EQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 20) {
        trie_tokenkind =  DAISHO_TOK_PLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 21) {
        trie_tokenkind =  DAISHO_TOK_MINEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 22) {
        trie_tokenkind =  DAISHO_TOK_MULEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 23) {
        trie_tokenkind =  DAISHO_TOK_DIVEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 24) {
        trie_tokenkind =  DAISHO_TOK_MODEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 25) {
        trie_tokenkind =  DAISHO_TOK_ANDEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 26) {
        trie_tokenkind =  DAISHO_TOK_OREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 27) {
        trie_tokenkind =  DAISHO_TOK_XOREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 28) {
        trie_tokenkind =  DAISHO_TOK_BNEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 30) {
        trie_tokenkind =  DAISHO_TOK_BSREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 32) {
        trie_tokenkind =  DAISHO_TOK_BSLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 33) {
        trie_tokenkind =  DAISHO_TOK_INCR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 34) {
        trie_tokenkind =  DAISHO_TOK_DECR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 36) {
        trie_tokenkind =  DAISHO_TOK_ELVIS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 35) {
        trie_tokenkind =  DAISHO_TOK_QUEST;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 37) {
        trie_tokenkind =  DAISHO_TOK_COLON;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 39) {
        trie_tokenkind =  DAISHO_TOK_IF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 43) {
        trie_tokenkind =  DAISHO_TOK_ELSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 48) {
        trie_tokenkind =  DAISHO_TOK_WHILE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 50) {
        trie_tokenkind =  DAISHO_TOK_DO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 54) {
        trie_tokenkind =  DAISHO_TOK_THEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 58) {
        trie_tokenkind =  DAISHO_TOK_ALSO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 63) {
        trie_tokenkind =  DAISHO_TOK_CLASS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 67) {
        trie_tokenkind =  DAISHO_TOK_TRAIT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 69) {
        trie_tokenkind =  DAISHO_TOK_DYN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 73) {
        trie_tokenkind =  DAISHO_TOK_CTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 74) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 75) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 76) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 77) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 78) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 79) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 80) {
        trie_tokenkind =  DAISHO_TOK_DOLLAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 81) {
        trie_tokenkind =  DAISHO_TOK_AT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 82) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
    }

    // Transition RET State Machine
    if (smaut_state_0 != -1) {
      all_dead = 0;

      if ((smaut_state_0 == 0) &
         (c == 114)) {
          smaut_state_0 = 1;
      }
      else if ((smaut_state_0 == 1) &
         (c == 101)) {
          smaut_state_0 = 2;
      }
      else if ((smaut_state_0 == 2) &
         (c == 116)) {
          smaut_state_0 = 3;
      }
      else if ((smaut_state_0 == 3) &
         (c == 117)) {
          smaut_state_0 = 4;
      }
      else if ((smaut_state_0 == 4) &
         (c == 114)) {
          smaut_state_0 = 5;
      }
      else if ((smaut_state_0 == 5) &
         (c == 110)) {
          smaut_state_0 = 6;
      }
      else {
        smaut_state_0 = -1;
      }

      // Check accept
      if ((smaut_state_0 == 3) | (smaut_state_0 == 6)) {
        smaut_tokenkind_0 = DAISHO_TOK_RET;
        smaut_munch_size_0 = iidx + 1;
      }
    }

    // Transition IMPL State Machine
    if (smaut_state_1 != -1) {
      all_dead = 0;

      if ((smaut_state_1 == 0) &
         (c == 105)) {
          smaut_state_1 = 1;
      }
      else if ((smaut_state_1 == 1) &
         (c == 109)) {
          smaut_state_1 = 2;
      }
      else if ((smaut_state_1 == 2) &
         (c == 112)) {
          smaut_state_1 = 3;
      }
      else if ((smaut_state_1 == 3) &
         (c == 108)) {
          smaut_state_1 = 4;
      }
      else if ((smaut_state_1 == 4) &
         (c == 101)) {
          smaut_state_1 = 5;
      }
      else if ((smaut_state_1 == 4) &
         (c == 105)) {
          smaut_state_1 = 5;
      }
      else if ((smaut_state_1 == 5) &
         (c == 109)) {
          smaut_state_1 = 6;
      }
      else if ((smaut_state_1 == 6) &
         (c == 101)) {
          smaut_state_1 = 7;
      }
      else if ((smaut_state_1 == 7) &
         (c == 110)) {
          smaut_state_1 = 8;
      }
      else if ((smaut_state_1 == 8) &
         (c == 116)) {
          smaut_state_1 = 9;
      }
      else if ((smaut_state_1 == 9) &
         (c == 115)) {
          smaut_state_1 = 10;
      }
      else {
        smaut_state_1 = -1;
      }

      // Check accept
      if ((smaut_state_1 == 4) | (smaut_state_1 == 10)) {
        smaut_tokenkind_1 = DAISHO_TOK_IMPL;
        smaut_munch_size_1 = iidx + 1;
      }
    }

    // Transition OP State Machine
    if (smaut_state_2 != -1) {
      all_dead = 0;

      if ((smaut_state_2 == 0) &
         (c == 111)) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 112)) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 101)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 114)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 97)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 116)) {
          smaut_state_2 = 6;
      }
      else if ((smaut_state_2 == 6) &
         (c == 111)) {
          smaut_state_2 = 7;
      }
      else if ((smaut_state_2 == 7) &
         (c == 114)) {
          smaut_state_2 = 8;
      }
      else {
        smaut_state_2 = -1;
      }

      // Check accept
      if ((smaut_state_2 == 2) | (smaut_state_2 == 8)) {
        smaut_tokenkind_2 = DAISHO_TOK_OP;
        smaut_munch_size_2 = iidx + 1;
      }
    }

    // Transition IDENT State Machine
    if (smaut_state_3 != -1) {
      all_dead = 0;

      if ((smaut_state_3 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)))) {
          smaut_state_3 = 1;
      }
      else if (((smaut_state_3 == 1) | (smaut_state_3 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_3 = 2;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 1) | (smaut_state_3 == 2)) {
        smaut_tokenkind_3 = DAISHO_TOK_IDENT;
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition NUM State Machine
    if (smaut_state_4 != -1) {
      all_dead = 0;

      if ((smaut_state_4 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_4 = 1;
      }
      else if (((smaut_state_4 == 0) | (smaut_state_4 == 1) | (smaut_state_4 == 2)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_4 = 2;
      }
      else {
        smaut_state_4 = -1;
      }

      // Check accept
      if (smaut_state_4 == 2) {
        smaut_tokenkind_4 = DAISHO_TOK_NUM;
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         (c == 34)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 1) &
         (c == 34)) {
          smaut_state_5 = 2;
      }
      else if ((smaut_state_5 == 1) &
         (c == 10)) {
          smaut_state_5 = 9;
      }
      else if ((smaut_state_5 == 1) &
         (c == 92)) {
          smaut_state_5 = 3;
      }
      else if ((smaut_state_5 == 1) &
         (1)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 110)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 102)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 98)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 114)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 116)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 101)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 92)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 39)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 3) &
         (c == 34)) {
          smaut_state_5 = 1;
      }
      else {
        smaut_state_5 = -1;
      }

      // Check accept
      if (smaut_state_5 == 2) {
        smaut_tokenkind_5 = DAISHO_TOK_STRLIT;
        smaut_munch_size_5 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_6 != -1) {
      all_dead = 0;

      if (((smaut_state_6 == 0) | (smaut_state_6 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_6 = 1;
      }
      else {
        smaut_state_6 = -1;
      }

      // Check accept
      if (smaut_state_6 == 1) {
        smaut_tokenkind_6 = DAISHO_TOK_WS;
        smaut_munch_size_6 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         (c == 47)) {
          smaut_state_7 = 1;
      }
      else if ((smaut_state_7 == 1) &
         (c == 42)) {
          smaut_state_7 = 2;
      }
      else if ((smaut_state_7 == 2) &
         (c == 42)) {
          smaut_state_7 = 3;
      }
      else if ((smaut_state_7 == 2) &
         (1)) {
          smaut_state_7 = 2;
      }
      else if ((smaut_state_7 == 3) &
         (c == 42)) {
          smaut_state_7 = 3;
      }
      else if ((smaut_state_7 == 3) &
         (c == 47)) {
          smaut_state_7 = 4;
      }
      else if ((smaut_state_7 == 3) &
         (1)) {
          smaut_state_7 = 2;
      }
      else {
        smaut_state_7 = -1;
      }

      // Check accept
      if (smaut_state_7 == 4) {
        smaut_tokenkind_7 = DAISHO_TOK_MLCOM;
        smaut_munch_size_7 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         (c == 47)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 1) &
         (c == 47)) {
          smaut_state_8 = 2;
      }
      else if ((smaut_state_8 == 2) &
         (!(c == 10))) {
          smaut_state_8 = 2;
      }
      else if ((smaut_state_8 == 2) &
         (c == 10)) {
          smaut_state_8 = 3;
      }
      else {
        smaut_state_8 = -1;
      }

      // Check accept
      if ((smaut_state_8 == 2) | (smaut_state_8 == 3)) {
        smaut_tokenkind_8 = DAISHO_TOK_SLCOM;
        smaut_munch_size_8 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         (c == 35)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 1) &
         (c == 33)) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 2) &
         (!(c == 10))) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 2) &
         (c == 10)) {
          smaut_state_9 = 3;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if (smaut_state_9 == 3) {
        smaut_tokenkind_9 = DAISHO_TOK_SHEBANG;
        smaut_munch_size_9 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_7;
  }
  if (smaut_munch_size_6 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_6;
  }
  if (smaut_munch_size_5 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_5;
  }
  if (smaut_munch_size_4 >= max_munch) {
    kind = DAISHO_TOK_NUM;
    max_munch = smaut_munch_size_4;
  }
  if (smaut_munch_size_3 >= max_munch) {
    kind = DAISHO_TOK_IDENT;
    max_munch = smaut_munch_size_3;
  }
  if (smaut_munch_size_2 >= max_munch) {
    kind = DAISHO_TOK_OP;
    max_munch = smaut_munch_size_2;
  }
  if (smaut_munch_size_1 >= max_munch) {
    kind = DAISHO_TOK_IMPL;
    max_munch = smaut_munch_size_1;
  }
  if (smaut_munch_size_0 >= max_munch) {
    kind = DAISHO_TOK_RET;
    max_munch = smaut_munch_size_0;
  }
  if (trie_munch_size >= max_munch) {
    kind = trie_tokenkind;
    max_munch = trie_munch_size;
  }

  daisho_token ret;
  ret.kind = kind;
  ret.start = tokenizer->pos;
  ret.len = max_munch;

#if PL0_TOKENIZER_SOURCEINFO
  ret.line = tokenizer->pos_line;
  ret.col = tokenizer->pos_col;
  ret.sourceFile = tokenizer->pos_sourceFile;

  for (size_t i = 0; i < ret.len; i++) {
    if (current[i] == '\n') {
      tokenizer->pos_line++;
      tokenizer->pos_col = 0;
    } else {
      tokenizer->pos_col++;
    }
  }
#endif

  tokenizer->pos += max_munch;
  return ret;
}

#endif /* DAISHO_TOKENIZER_INCLUDE */
