
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


#ifndef PGEN_DEBUG
#define PGEN_DEBUG 0

#define PGEN_ALLOCATOR_DEBUG 0

#endif /* PGEN_DEBUG */

/**************/
/* Directives */
/**************/


/* START OF AST ALLOCATOR */

#ifndef PGEN_ARENA_INCLUDED
#define PGEN_ARENA_INCLUDED
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PGEN_ALIGNMENT _Alignof(max_align_t)
#define PGEN_BUFFER_SIZE (PGEN_PAGESIZE * 1024)
#define NUM_ARENAS 256
#define NUM_FREELIST 256

#ifndef PGEN_PAGESIZE
#define PGEN_PAGESIZE 4096
#endif

#ifndef PGEN_OOM
#define PGEN_OOM()                                                             \
  do {                                                                         \
    fprintf(stderr, "Parser out of memory on line %i in %s in %s.\n",          \
            __LINE__, __func__, __FILE__);                                     \
    exit(1);                                                                   \
  } while (0);
#endif

#ifndef PGEN_DEBUG
#define PGEN_DEBUG 0
#define PGEN_AlLOCATOR_DEBUG 0
#endif

#if SIZE_MAX < UINT32_MAX
#define PGEN_SIZE_RANGE_CHECK
#endif

#if __STDC_VERSION__ >= 201112L
_Static_assert((PGEN_ALIGNMENT % 2) == 0,
               "Why would alignof(max_align_t) be odd? WTF?");
_Static_assert(PGEN_BUFFER_SIZE <= UINT32_MAX,
               "The arena buffer size must fit in uint32_t.");
#endif

static inline size_t pgen_align(size_t n, size_t align) {
  return (n + align - (n % align));
}

typedef struct {
  void (*freefn)(void *ptr);
  char *buf;
  uint32_t cap;
} pgen_arena_t;

typedef struct {
  uint32_t arena_idx;
  uint32_t filled;
} pgen_allocator_rewind_t;

typedef struct {
  pgen_allocator_rewind_t arew;
  size_t prew;
} pgen_parser_rewind_t;

#define PGEN_REWIND_START ((pgen_allocator_rewind_t){{0, 0}, 0})

typedef struct {
  void (*freefn)(void *);
  void *ptr;
  pgen_allocator_rewind_t rew;
} pgen_freelist_entry_t;

typedef struct {
  uint32_t len;
  uint32_t cap;
  pgen_freelist_entry_t *entries;
} pgen_freelist_t;

typedef struct {
  pgen_allocator_rewind_t rew;
  pgen_arena_t arenas[NUM_ARENAS];
  pgen_freelist_t freelist;
} pgen_allocator;

static inline pgen_allocator pgen_allocator_new(void) {
  pgen_allocator alloc;

  alloc.rew.arena_idx = 0;
  alloc.rew.filled = 0;

  for (size_t i = 0; i < NUM_ARENAS; i++) {
    alloc.arenas[i].freefn = NULL;
    alloc.arenas[i].buf = NULL;
    alloc.arenas[i].cap = 0;
  }

  alloc.freelist.entries = (pgen_freelist_entry_t *)malloc(
      sizeof(pgen_freelist_entry_t) * NUM_FREELIST);
  if (alloc.freelist.entries) {
    alloc.freelist.cap = NUM_FREELIST;
    alloc.freelist.len = 0;
  } else {
    alloc.freelist.cap = 0;
    alloc.freelist.len = 0;
    PGEN_OOM();
  }

  return alloc;
}

static inline int pgen_allocator_launder(pgen_allocator *allocator,
                                         pgen_arena_t arena) {
  for (size_t i = 0; i < NUM_ARENAS; i++) {
    if (!allocator->arenas[i].buf) {
      allocator->arenas[i] = arena;
      return 1;
    }
  }
  return 0;
}

static inline void pgen_allocator_destroy(pgen_allocator *allocator) {
  // Free all the buffers
  for (size_t i = 0; i < NUM_ARENAS; i++) {
    pgen_arena_t a = allocator->arenas[i];
    if (a.freefn)
      a.freefn(a.buf);
  }

  // Free everything in the freelist
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    void (*fn)(void *) = allocator->freelist.entries[i].freefn;
    void *ptr = allocator->freelist.entries[i].ptr;
    fn(ptr);
  }

  // Free the freelist itself
  free(allocator->freelist.entries);
}

#define PGEN_ALLOC_OF(allocator, type)                                         \
  pgen_alloc(allocator, sizeof(type), _Alignof(type))
static inline char *pgen_alloc(pgen_allocator *allocator, size_t n,
                               size_t alignment) {
#if PGEN_AlLOCATOR_DEBUG
  printf("Allocating, from: (%u, %u)\n", allocator->rew.arena_idx,
         allocator->rew.filled);
#endif

  char *ret = NULL;

#if PGEN_SIZE_RANGE_CHECK
  if (allocator->rew.filled > SIZE_MAX)
    PGEN_OOM();
#endif

  // Find the arena to allocate on and where we are inside it.
  size_t bufcurrent = pgen_align((size_t)allocator->rew.filled, alignment);
  size_t bufnext = bufcurrent + n;

  // Check for overflow
  if (bufnext < allocator->rew.filled)
    PGEN_OOM();

  while (1) {
    // If we need a new arena
    if (bufnext > allocator->arenas[allocator->rew.arena_idx].cap) {
      bufcurrent = 0;
      bufnext = n;

      // Make sure there's a spot for it
      if (allocator->rew.arena_idx + 1 >= NUM_ARENAS)
        return ret;

      // Allocate a new arena if necessary
      if (allocator->arenas[allocator->rew.arena_idx].buf)
        allocator->rew.arena_idx++;
      if (!allocator->arenas[allocator->rew.arena_idx].buf) {
        char *nb = (char *)malloc(PGEN_BUFFER_SIZE);
        if (!nb)
          PGEN_OOM();
        pgen_arena_t new_arena;
        new_arena.freefn = free;
        new_arena.buf = nb;
        new_arena.cap = PGEN_BUFFER_SIZE;
        allocator->arenas[allocator->rew.arena_idx] = new_arena;
      }
    } else {
      break;
    }
  }

  ret = allocator->arenas[allocator->rew.arena_idx].buf + bufcurrent;
  allocator->rew.filled = bufnext;

#if PGEN_AlLOCATOR_DEBUG
  printf("Allocated, to: (%u, %u)", allocator->rew.arena_idx,
         allocator->rew.filled);
#endif

  return ret;
}

// Does not take a pgen_allocator_rewind_t, so does not rebind the
// lifetime of the reallocated object.
static inline void pgen_allocator_realloced(pgen_allocator *allocator,
                                            void *old_ptr, void *new_ptr,
                                            void (*new_free_fn)(void *)) {

#if PGEN_AlLOCATOR_DEBUG
  printf("realloc(%p -> %p): ", old_ptr, new_ptr);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
#endif

  for (size_t i = 0; i < allocator->freelist.len; i++) {
    void *ptr = allocator->freelist.entries[i].ptr;
    if (ptr == old_ptr) {
      allocator->freelist.entries[i].ptr = new_ptr;
      allocator->freelist.entries[i].freefn = new_free_fn;
      return;
    }
  }

#if PGEN_AlLOCATOR_DEBUG
  printf("Realloced: ");
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

static inline void pgen_defer(pgen_allocator *allocator, void (*freefn)(void *),
                              void *ptr, pgen_allocator_rewind_t rew) {
#if PGEN_AlLOCATOR_DEBUG
  printf("defer(%p, (%u, %u)) (%u): ", ptr, rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
#endif

  // Grow list by factor of 2 if too small
  size_t next_len = allocator->freelist.len + 1;
  if (next_len >= allocator->freelist.cap) {
    uint32_t new_size = allocator->freelist.len * 2;

#if PGEN_SIZE_RANGE_CHECK
    if (new_size > SIZE_MAX)
      PGEN_OOM();
#endif

    pgen_freelist_entry_t *new_entries = (pgen_freelist_entry_t *)realloc(
        allocator->freelist.entries,
        sizeof(pgen_freelist_entry_t) * (size_t)new_size);
    if (!new_entries)
      PGEN_OOM();
    allocator->freelist.entries = new_entries;
    allocator->freelist.cap = allocator->freelist.len * 2;
  }

  // Append the new entry
  pgen_freelist_entry_t entry;
  entry.freefn = freefn;
  entry.ptr = ptr;
  entry.rew = rew;
  allocator->freelist.entries[allocator->freelist.len] = entry;
  allocator->freelist.len = next_len;

#if PGEN_AlLOCATOR_DEBUG
  printf("Deferred: (%u) ", allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, (%u, %u)) ", allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

static inline void pgen_allocator_rewind(pgen_allocator *allocator,
                                         pgen_allocator_rewind_t rew) {

#if PGEN_AlLOCATOR_DEBUG
  printf("rewind((%u, %u) -> (%u, %u)): (%u) ",
         allocator->freelist.entries->rew.arena_idx,
         allocator->freelist.entries->rew.filled, rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
#endif

  // Free all the objects associated with nodes implicitly destroyed.
  // These are the ones located beyond the rew we're rewinding back to.
  int freed_any = 0;
  size_t i = allocator->freelist.len;
  while (i--) {

    pgen_freelist_entry_t entry = allocator->freelist.entries[i];
    uint32_t arena_idx = entry.rew.arena_idx;
    uint32_t filled = entry.rew.filled;

    if ((rew.arena_idx <= arena_idx) | (rew.filled <= filled))
      break;

    freed_any = 1;
    entry.freefn(entry.ptr);
  }
  if (freed_any)
    allocator->freelist.len = i;
  allocator->rew = rew;

#if PGEN_AlLOCATOR_DEBUG
  printf("rewound(%u, %u): (%u) ", rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

#endif /* PGEN_ARENA_INCLUDED */

#ifndef PGEN_PARSER_MACROS_INCLUDED
#define PGEN_PARSER_MACROS_INCLUDED
#define PGEN_CAT_(x, y) x##y
#define PGEN_CAT(x, y) PGEN_CAT_(x, y)
#define PGEN_NARG(...) PGEN_NARG_(__VA_ARGS__, PGEN_RSEQ_N())
#define PGEN_NARG_(...) PGEN_128TH_ARG(__VA_ARGS__)
#define PGEN_128TH_ARG(                                                        \
    _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16,     \
    _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, \
    _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, \
    _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, \
    _62, _63, _64, _65, _66, _67, _68, _69, _70, _71, _72, _73, _74, _75, _76, \
    _77, _78, _79, _80, _81, _82, _83, _84, _85, _86, _87, _88, _89, _90, _91, \
    _92, _93, _94, _95, _96, _97, _98, _99, _100, _101, _102, _103, _104,      \
    _105, _106, _107, _108, _109, _110, _111, _112, _113, _114, _115, _116,    \
    _117, _118, _119, _120, _121, _122, _123, _124, _125, _126, _127, N, ...)  \
  N
#define PGEN_RSEQ_N()                                                          \
  127, 126, 125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, 113,   \
      112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, \
      97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84, 83, 82, 81, 80,  \
      79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68, 67, 66, 65, 64, 63, 62,  \
      61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44,  \
      43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26,  \
      25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, \
      6, 5, 4, 3, 2, 1, 0
#endif /* PGEN_PARSER_MACROS_INCLUDED */

#ifndef DAISHO_TOKENIZER_INCLUDE
#define DAISHO_TOKENIZER_INCLUDE

#ifndef DAISHO_TOKENIZER_SOURCEINFO
#define DAISHO_TOKENIZER_SOURCEINFO 1
#endif

typedef enum {
  DAISHO_TOK_STREAMEND,
  DAISHO_TOK_PLUS,
  DAISHO_TOK_MINUS,
  DAISHO_TOK_STAR,
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
  DAISHO_TOK_QUEST,
  DAISHO_TOK_COLON,
  DAISHO_TOK_NCOLL,
  DAISHO_TOK_FOR,
  DAISHO_TOK_WHILE,
  DAISHO_TOK_THEN,
  DAISHO_TOK_ALSO,
  DAISHO_TOK_CLASS,
  DAISHO_TOK_TRAIT,
  DAISHO_TOK_DYN,
  DAISHO_TOK_CTYPE,
  DAISHO_TOK_CFUNC,
  DAISHO_TOK_SELFTYPE,
  DAISHO_TOK_SELFVAR,
  DAISHO_TOK_VOIDTYPE,
  DAISHO_TOK_SEMI,
  DAISHO_TOK_DOT,
  DAISHO_TOK_COMMA,
  DAISHO_TOK_OPEN,
  DAISHO_TOK_CLOSE,
  DAISHO_TOK_LCBRACK,
  DAISHO_TOK_RCBRACK,
  DAISHO_TOK_LSBRACK,
  DAISHO_TOK_RSBRACK,
  DAISHO_TOK_HASH,
  DAISHO_TOK_REF,
  DAISHO_TOK_DEREF,
  DAISHO_TOK_GRAVE,
  DAISHO_TOK_RET,
  DAISHO_TOK_IMPL,
  DAISHO_TOK_OP,
  DAISHO_TOK_REDEF,
  DAISHO_TOK_TYPEIDENT,
  DAISHO_TOK_VARIDENT,
  DAISHO_TOK_CIDENT,
  DAISHO_TOK_NUMLIT,
  DAISHO_TOK_STRLIT,
  DAISHO_TOK_WS,
  DAISHO_TOK_MLCOM,
  DAISHO_TOK_SLCOM,
  DAISHO_TOK_SHEBANG,
} daisho_token_kind;

// The 0th token is end of stream.
// Tokens 1 through 73 are the ones you defined.
// This totals 74 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 74
static const char* daisho_tokenkind_name[DAISHO_NUM_TOKENKINDS] = {
  "DAISHO_TOK_STREAMEND",
  "DAISHO_TOK_PLUS",
  "DAISHO_TOK_MINUS",
  "DAISHO_TOK_STAR",
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
  "DAISHO_TOK_QUEST",
  "DAISHO_TOK_COLON",
  "DAISHO_TOK_NCOLL",
  "DAISHO_TOK_FOR",
  "DAISHO_TOK_WHILE",
  "DAISHO_TOK_THEN",
  "DAISHO_TOK_ALSO",
  "DAISHO_TOK_CLASS",
  "DAISHO_TOK_TRAIT",
  "DAISHO_TOK_DYN",
  "DAISHO_TOK_CTYPE",
  "DAISHO_TOK_CFUNC",
  "DAISHO_TOK_SELFTYPE",
  "DAISHO_TOK_SELFVAR",
  "DAISHO_TOK_VOIDTYPE",
  "DAISHO_TOK_SEMI",
  "DAISHO_TOK_DOT",
  "DAISHO_TOK_COMMA",
  "DAISHO_TOK_OPEN",
  "DAISHO_TOK_CLOSE",
  "DAISHO_TOK_LCBRACK",
  "DAISHO_TOK_RCBRACK",
  "DAISHO_TOK_LSBRACK",
  "DAISHO_TOK_RSBRACK",
  "DAISHO_TOK_HASH",
  "DAISHO_TOK_REF",
  "DAISHO_TOK_DEREF",
  "DAISHO_TOK_GRAVE",
  "DAISHO_TOK_RET",
  "DAISHO_TOK_IMPL",
  "DAISHO_TOK_OP",
  "DAISHO_TOK_REDEF",
  "DAISHO_TOK_TYPEIDENT",
  "DAISHO_TOK_VARIDENT",
  "DAISHO_TOK_CIDENT",
  "DAISHO_TOK_NUMLIT",
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
#ifdef DAISHO_TOKEN_EXTRA
  DAISHO_TOKEN_EXTRA
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
  int smaut_state_10 = 0;
  int smaut_state_11 = 0;
  int smaut_state_12 = 0;
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
  size_t smaut_munch_size_10 = 0;
  size_t smaut_munch_size_11 = 0;
  size_t smaut_munch_size_12 = 0;
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;

  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 9;
        else if (c == 35 /*'#'*/) trie_state = 95;
        else if (c == 36 /*'$'*/) trie_state = 97;
        else if (c == 37 /*'%'*/) trie_state = 5;
        else if (c == 38 /*'&'*/) trie_state = 6;
        else if (c == 40 /*'('*/) trie_state = 89;
        else if (c == 41 /*')'*/) trie_state = 90;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 88;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 87;
        else if (c == 47 /*'/'*/) trie_state = 4;
        else if (c == 58 /*':'*/) trie_state = 36;
        else if (c == 59 /*';'*/) trie_state = 86;
        else if (c == 60 /*'<'*/) trie_state = 16;
        else if (c == 61 /*'='*/) trie_state = 13;
        else if (c == 62 /*'>'*/) trie_state = 18;
        else if (c == 63 /*'?'*/) trie_state = 35;
        else if (c == 64 /*'@'*/) trie_state = 96;
        else if (c == 83 /*'S'*/) trie_state = 74;
        else if (c == 86 /*'V'*/) trie_state = 82;
        else if (c == 91 /*'['*/) trie_state = 93;
        else if (c == 93 /*']'*/) trie_state = 94;
        else if (c == 94 /*'^'*/) trie_state = 8;
        else if (c == 96 /*'`'*/) trie_state = 98;
        else if (c == 97 /*'a'*/) trie_state = 50;
        else if (c == 99 /*'c'*/) trie_state = 54;
        else if (c == 100 /*'d'*/) trie_state = 63;
        else if (c == 102 /*'f'*/) trie_state = 38;
        else if (c == 115 /*'s'*/) trie_state = 78;
        else if (c == 116 /*'t'*/) trie_state = 46;
        else if (c == 119 /*'w'*/) trie_state = 41;
        else if (c == 123 /*'{'*/) trie_state = 91;
        else if (c == 124 /*'|'*/) trie_state = 7;
        else if (c == 125 /*'}'*/) trie_state = 92;
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
        if (c == 58 /*':'*/) trie_state = 37;
        else trie_state = -1;
      }
      else if (trie_state == 38) {
        if (c == 111 /*'o'*/) trie_state = 39;
        else trie_state = -1;
      }
      else if (trie_state == 39) {
        if (c == 114 /*'r'*/) trie_state = 40;
        else trie_state = -1;
      }
      else if (trie_state == 41) {
        if (c == 104 /*'h'*/) trie_state = 42;
        else trie_state = -1;
      }
      else if (trie_state == 42) {
        if (c == 105 /*'i'*/) trie_state = 43;
        else trie_state = -1;
      }
      else if (trie_state == 43) {
        if (c == 108 /*'l'*/) trie_state = 44;
        else trie_state = -1;
      }
      else if (trie_state == 44) {
        if (c == 101 /*'e'*/) trie_state = 45;
        else trie_state = -1;
      }
      else if (trie_state == 46) {
        if (c == 104 /*'h'*/) trie_state = 47;
        else if (c == 114 /*'r'*/) trie_state = 59;
        else trie_state = -1;
      }
      else if (trie_state == 47) {
        if (c == 101 /*'e'*/) trie_state = 48;
        else trie_state = -1;
      }
      else if (trie_state == 48) {
        if (c == 110 /*'n'*/) trie_state = 49;
        else trie_state = -1;
      }
      else if (trie_state == 50) {
        if (c == 108 /*'l'*/) trie_state = 51;
        else trie_state = -1;
      }
      else if (trie_state == 51) {
        if (c == 115 /*'s'*/) trie_state = 52;
        else trie_state = -1;
      }
      else if (trie_state == 52) {
        if (c == 111 /*'o'*/) trie_state = 53;
        else trie_state = -1;
      }
      else if (trie_state == 54) {
        if (c == 102 /*'f'*/) trie_state = 70;
        else if (c == 108 /*'l'*/) trie_state = 55;
        else if (c == 116 /*'t'*/) trie_state = 66;
        else trie_state = -1;
      }
      else if (trie_state == 55) {
        if (c == 97 /*'a'*/) trie_state = 56;
        else trie_state = -1;
      }
      else if (trie_state == 56) {
        if (c == 115 /*'s'*/) trie_state = 57;
        else trie_state = -1;
      }
      else if (trie_state == 57) {
        if (c == 115 /*'s'*/) trie_state = 58;
        else trie_state = -1;
      }
      else if (trie_state == 59) {
        if (c == 97 /*'a'*/) trie_state = 60;
        else trie_state = -1;
      }
      else if (trie_state == 60) {
        if (c == 105 /*'i'*/) trie_state = 61;
        else trie_state = -1;
      }
      else if (trie_state == 61) {
        if (c == 116 /*'t'*/) trie_state = 62;
        else trie_state = -1;
      }
      else if (trie_state == 63) {
        if (c == 121 /*'y'*/) trie_state = 64;
        else trie_state = -1;
      }
      else if (trie_state == 64) {
        if (c == 110 /*'n'*/) trie_state = 65;
        else trie_state = -1;
      }
      else if (trie_state == 66) {
        if (c == 121 /*'y'*/) trie_state = 67;
        else trie_state = -1;
      }
      else if (trie_state == 67) {
        if (c == 112 /*'p'*/) trie_state = 68;
        else trie_state = -1;
      }
      else if (trie_state == 68) {
        if (c == 101 /*'e'*/) trie_state = 69;
        else trie_state = -1;
      }
      else if (trie_state == 70) {
        if (c == 117 /*'u'*/) trie_state = 71;
        else trie_state = -1;
      }
      else if (trie_state == 71) {
        if (c == 110 /*'n'*/) trie_state = 72;
        else trie_state = -1;
      }
      else if (trie_state == 72) {
        if (c == 99 /*'c'*/) trie_state = 73;
        else trie_state = -1;
      }
      else if (trie_state == 74) {
        if (c == 101 /*'e'*/) trie_state = 75;
        else trie_state = -1;
      }
      else if (trie_state == 75) {
        if (c == 108 /*'l'*/) trie_state = 76;
        else trie_state = -1;
      }
      else if (trie_state == 76) {
        if (c == 102 /*'f'*/) trie_state = 77;
        else trie_state = -1;
      }
      else if (trie_state == 78) {
        if (c == 101 /*'e'*/) trie_state = 79;
        else trie_state = -1;
      }
      else if (trie_state == 79) {
        if (c == 108 /*'l'*/) trie_state = 80;
        else trie_state = -1;
      }
      else if (trie_state == 80) {
        if (c == 102 /*'f'*/) trie_state = 81;
        else trie_state = -1;
      }
      else if (trie_state == 82) {
        if (c == 111 /*'o'*/) trie_state = 83;
        else trie_state = -1;
      }
      else if (trie_state == 83) {
        if (c == 105 /*'i'*/) trie_state = 84;
        else trie_state = -1;
      }
      else if (trie_state == 84) {
        if (c == 100 /*'d'*/) trie_state = 85;
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
        trie_tokenkind =  DAISHO_TOK_STAR;
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
      else if (trie_state == 35) {
        trie_tokenkind =  DAISHO_TOK_QUEST;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 36) {
        trie_tokenkind =  DAISHO_TOK_COLON;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 37) {
        trie_tokenkind =  DAISHO_TOK_NCOLL;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 40) {
        trie_tokenkind =  DAISHO_TOK_FOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 45) {
        trie_tokenkind =  DAISHO_TOK_WHILE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 49) {
        trie_tokenkind =  DAISHO_TOK_THEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 53) {
        trie_tokenkind =  DAISHO_TOK_ALSO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 58) {
        trie_tokenkind =  DAISHO_TOK_CLASS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 62) {
        trie_tokenkind =  DAISHO_TOK_TRAIT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 65) {
        trie_tokenkind =  DAISHO_TOK_DYN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 69) {
        trie_tokenkind =  DAISHO_TOK_CTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 73) {
        trie_tokenkind =  DAISHO_TOK_CFUNC;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 77) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 81) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 85) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 86) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 87) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 88) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 89) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 90) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 91) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 92) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 93) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 94) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 95) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 96) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 97) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
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
        smaut_munch_size_2 = iidx + 1;
      }
    }

    // Transition REDEF State Machine
    if (smaut_state_3 != -1) {
      all_dead = 0;

      if ((smaut_state_3 == 0) &
         (c == 114)) {
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 1) &
         (c == 101)) {
          smaut_state_3 = 2;
      }
      else if ((smaut_state_3 == 2) &
         (c == 100)) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 101)) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 102)) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 5) &
         (c == 105)) {
          smaut_state_3 = 6;
      }
      else if ((smaut_state_3 == 6) &
         (c == 110)) {
          smaut_state_3 = 7;
      }
      else if ((smaut_state_3 == 7) &
         (c == 101)) {
          smaut_state_3 = 8;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 5) | (smaut_state_3 == 8)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition TYPEIDENT State Machine
    if (smaut_state_4 != -1) {
      all_dead = 0;

      if ((smaut_state_4 == 0) &
         (((c >= 65) & (c <= 90)))) {
          smaut_state_4 = 1;
      }
      else if (((smaut_state_4 == 1) | (smaut_state_4 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_4 = 2;
      }
      else {
        smaut_state_4 = -1;
      }

      // Check accept
      if ((smaut_state_4 == 1) | (smaut_state_4 == 2)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition VARIDENT State Machine
    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_5 = 1;
      }
      else if (((smaut_state_5 == 1) | (smaut_state_5 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_5 = 2;
      }
      else {
        smaut_state_5 = -1;
      }

      // Check accept
      if ((smaut_state_5 == 1) | (smaut_state_5 == 2)) {
        smaut_munch_size_5 = iidx + 1;
      }
    }

    // Transition CIDENT State Machine
    if (smaut_state_6 != -1) {
      all_dead = 0;

      if ((smaut_state_6 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)))) {
          smaut_state_6 = 1;
      }
      else if (((smaut_state_6 == 1) | (smaut_state_6 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_6 = 2;
      }
      else {
        smaut_state_6 = -1;
      }

      // Check accept
      if ((smaut_state_6 == 1) | (smaut_state_6 == 2)) {
        smaut_munch_size_6 = iidx + 1;
      }
    }

    // Transition NUMLIT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 == 0) | (smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_7 = 2;
      }
      else if ((smaut_state_7 == 2) &
         (c == 46)) {
          smaut_state_7 = 3;
      }
      else if ((smaut_state_7 == 3) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_7 = 3;
      }
      else {
        smaut_state_7 = -1;
      }

      // Check accept
      if ((smaut_state_7 == 2) | (smaut_state_7 == 3)) {
        smaut_munch_size_7 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         (c == 34)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 1) &
         (c == 34)) {
          smaut_state_8 = 2;
      }
      else if ((smaut_state_8 == 1) &
         (c == 10)) {
          smaut_state_8 = 9;
      }
      else if ((smaut_state_8 == 1) &
         (c == 92)) {
          smaut_state_8 = 3;
      }
      else if ((smaut_state_8 == 1) &
         (1)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 110)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 102)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 98)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 114)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 116)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 101)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 92)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 39)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 34)) {
          smaut_state_8 = 1;
      }
      else {
        smaut_state_8 = -1;
      }

      // Check accept
      if (smaut_state_8 == 2) {
        smaut_munch_size_8 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if (((smaut_state_9 == 0) | (smaut_state_9 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_9 = 1;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if (smaut_state_9 == 1) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         (c == 47)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 1) &
         (c == 42)) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 2) &
         (c == 42)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 2) &
         (1)) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 3) &
         (c == 42)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 3) &
         (c == 47)) {
          smaut_state_10 = 4;
      }
      else if ((smaut_state_10 == 3) &
         (1)) {
          smaut_state_10 = 2;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if (smaut_state_10 == 4) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 47)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 47)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 2) &
         (!(c == 10))) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 2) &
         (c == 10)) {
          smaut_state_11 = 3;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if ((smaut_state_11 == 2) | (smaut_state_11 == 3)) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 35)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 33)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (!(c == 10))) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (c == 10)) {
          smaut_state_12 = 3;
      }
      else {
        smaut_state_12 = -1;
      }

      // Check accept
      if (smaut_state_12 == 3) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_7;
  }
  if (smaut_munch_size_6 >= max_munch) {
    kind = DAISHO_TOK_CIDENT;
    max_munch = smaut_munch_size_6;
  }
  if (smaut_munch_size_5 >= max_munch) {
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_5;
  }
  if (smaut_munch_size_4 >= max_munch) {
    kind = DAISHO_TOK_TYPEIDENT;
    max_munch = smaut_munch_size_4;
  }
  if (smaut_munch_size_3 >= max_munch) {
    kind = DAISHO_TOK_REDEF;
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

#if DAISHO_TOKENIZER_SOURCEINFO
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

#ifndef PGEN_DAISHO_ASTNODE_INCLUDE
#define PGEN_DAISHO_ASTNODE_INCLUDE

typedef struct {
  daisho_token* tokens;
  size_t len;
  size_t pos;
  pgen_allocator *alloc;
} daisho_parser_ctx;

static inline void daisho_parser_ctx_init(daisho_parser_ctx* parser,
                                       pgen_allocator* allocator,
                                       daisho_token* tokens, size_t num_tokens) {
  parser->tokens = tokens;
  parser->len = num_tokens;
  parser->pos = 0;
  parser->alloc = allocator;
}
typedef enum {
  daisho_NODE_EMPTY,
  DAISHO_NODE_PROG,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_LOGOR,
  DAISHO_NODE_LOGAND,
  DAISHO_NODE_OR,
  DAISHO_NODE_XOR,
  DAISHO_NODE_AND,
  DAISHO_NODE_DEQ,
  DAISHO_NODE_NEQ,
  DAISHO_NODE_BEQ,
  DAISHO_NODE_LT,
  DAISHO_NODE_GT,
  DAISHO_NODE_LEQ,
  DAISHO_NODE_GEQ,
  DAISHO_NODE_CMP,
  DAISHO_NODE_SHIFT,
  DAISHO_NODE_FACTOR,
  DAISHO_NODE_STAR,
  DAISHO_NODE_DIV,
  DAISHO_NODE_MOD,
  DAISHO_NODE_SUM,
  DAISHO_NODE_PLUS,
  DAISHO_NODE_MINUS,
  DAISHO_NODE_CAST,
  DAISHO_NODE_REF,
  DAISHO_NODE_DEREF,
  DAISHO_NODE_BLK,
  DAISHO_NODE_LAMBDA,
  DAISHO_NODE_LSHF,
  DAISHO_NODE_RSHF,
  DAISHO_NODE_VOIDTYPE,
  DAISHO_NODE_OPEN,
  DAISHO_NODE_CLOSE,
  DAISHO_NODE_VIDENT,
  DAISHO_NODE_NUMLIT,
  DAISHO_NODE_STRLIT,
  DAISHO_NODE_TYPEIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 39
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_PROG",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_LOGOR",
  "DAISHO_NODE_LOGAND",
  "DAISHO_NODE_OR",
  "DAISHO_NODE_XOR",
  "DAISHO_NODE_AND",
  "DAISHO_NODE_DEQ",
  "DAISHO_NODE_NEQ",
  "DAISHO_NODE_BEQ",
  "DAISHO_NODE_LT",
  "DAISHO_NODE_GT",
  "DAISHO_NODE_LEQ",
  "DAISHO_NODE_GEQ",
  "DAISHO_NODE_CMP",
  "DAISHO_NODE_SHIFT",
  "DAISHO_NODE_FACTOR",
  "DAISHO_NODE_STAR",
  "DAISHO_NODE_DIV",
  "DAISHO_NODE_MOD",
  "DAISHO_NODE_SUM",
  "DAISHO_NODE_PLUS",
  "DAISHO_NODE_MINUS",
  "DAISHO_NODE_CAST",
  "DAISHO_NODE_REF",
  "DAISHO_NODE_DEREF",
  "DAISHO_NODE_BLK",
  "DAISHO_NODE_LAMBDA",
  "DAISHO_NODE_LSHF",
  "DAISHO_NODE_RSHF",
  "DAISHO_NODE_VOIDTYPE",
  "DAISHO_NODE_OPEN",
  "DAISHO_NODE_CLOSE",
  "DAISHO_NODE_VIDENT",
  "DAISHO_NODE_NUMLIT",
  "DAISHO_NODE_STRLIT",
  "DAISHO_NODE_TYPEIDENT",
  "DAISHO_NODE_VARIDENT",
};

struct daisho_astnode_t;
typedef struct daisho_astnode_t daisho_astnode_t;
struct daisho_astnode_t {
  // No %extra directives.

  daisho_astnode_kind kind;
  daisho_astnode_t* parent;
  size_t num_children;
  size_t max_children;
  daisho_astnode_t** children;
};

static inline daisho_astnode_t* daisho_astnode_list(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             size_t initial_size) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t),
                         _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t*)ret;

  daisho_astnode_t **children;
  if (initial_size) {
    children = (daisho_astnode_t**)malloc(sizeof(daisho_astnode_t*) * initial_size);
    if (!children)
      PGEN_OOM();
    pgen_defer(alloc, free, children, alloc->rew);
  } else {
    children = NULL;
  }

  node->kind = kind;
  node->parent = NULL;
  node->max_children = initial_size;
  node->num_children = 0;
  node->children = children;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_leaf(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t),
                         _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t *children = NULL;
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 0;
  node->children = NULL;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_1(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 1,
                                        _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 1;
  node->children = children;
  children[0] = n0;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_2(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 2,
                                        _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 2;
  node->children = children;
  children[0] = n0;
  children[1] = n1;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_3(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 3,
                                        _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 3;
  node->children = children;
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_4(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2,
                             daisho_astnode_t* n3) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 4,
                                        _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 4;
  node->children = children;
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  children[3] = n3;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_5(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2,
                             daisho_astnode_t* n3,
                             daisho_astnode_t* n4) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 5,
                                        _Alignof(daisho_astnode_t));
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 5;
  node->children = children;
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  children[3] = n3;
  children[4] = n4;
  return node;
}

static inline void daisho_astnode_add(pgen_allocator* alloc, daisho_astnode_t *list, daisho_astnode_t *node) {
  if (list->max_children == list->num_children) {
    size_t new_max = list->max_children * 2;
    void* old_ptr = list->children;
    void* new_ptr = realloc(list->children, new_max);
    if (!new_ptr)
      PGEN_OOM();
    list->children = (daisho_astnode_t **)new_ptr;
    list->max_children = new_max;
    pgen_allocator_realloced(alloc, old_ptr, new_ptr, free);
  }
  node->parent = list;
  list->children[list->num_children++] = node;
}

static inline void daisho_parser_rewind(daisho_parser_ctx *ctx, pgen_parser_rewind_t rew) {
  pgen_allocator_rewind(ctx->alloc, rew.arew);
  ctx->pos = rew.prew;
}

#define rec(label)               pgen_parser_rewind_t _rew_##label = (pgen_parser_rewind_t){ctx->alloc->rew, ctx->pos};
#define rew(label)               daisho_parser_rewind(ctx, _rew_##label)
#define node(kind, ...)          PGEN_CAT(daisho_astnode_fixed_, PGEN_NARG(__VA_ARGS__))(ctx->alloc, DAISHO_NODE_##kind, __VA_ARGS__)
#define list(kind)               daisho_astnode_list(ctx->alloc, DAISHO_NODE_##kind, 16)
#define leaf(kind)               daisho_astnode_leaf(ctx->alloc, DAISHO_NODE_##kind)
#define add(list, node)  daisho_astnode_add(ctx->alloc, list, node)
#define defer(node, freefn, ptr) pgen_defer(ctx->alloc, freefn, ptr, ctx->alloc->rew)
#define SUCC                     ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t))

static inline void daisho_astnode_print_h(daisho_astnode_t *node, size_t depth, int fl) {
  #define indent() for (size_t i = 0; i < depth; i++) printf("  ")
  if (node == SUCC)
    puts("ERROR, CAPTURED SUCC."), exit(1);

  indent(); puts("{");
  depth++;
  indent(); printf("\"kind\": "); printf("\"%s\",\n", daisho_nodekind_name[node->kind] + 12);
  size_t cnum = node->num_children;
  indent(); printf("\"num_children\": %zu,\n", cnum);
  indent(); printf("\"children\": [");  if (cnum) {
    putchar('\n');
    for (size_t i = 0; i < cnum; i++)
      daisho_astnode_print_h(node->children[i], depth + 1, i == cnum - 1);
    indent();
  }
  printf("]\n");
  depth--;
  indent(); putchar('}'); if (fl != 1) putchar(','); putchar('\n');
}

static inline void daisho_astnode_print_json(daisho_astnode_t *node) {
  daisho_astnode_print_h(node, 0, 1);
}

static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfunc(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_classdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarglist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_classtype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_eneqexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lshf(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_rshf(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* expr_ret_1 = NULL;
  daisho_astnode_t* expr_ret_0 = NULL;
  #define rule expr_ret_0

  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_3 = NULL;
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
    // Capturing SHEBANG.
    expr_ret_3 = leaf(SHEBANG);
    ctx->pos++;
  } else {
    expr_ret_3 = NULL;
  }

  // optional
  if (!expr_ret_3)
    expr_ret_3 = SUCC;
  expr_ret_2 = expr_ret_3;
  sh = expr_ret_3;
  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2;
  return expr_ret_1 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_5 = NULL;
  daisho_astnode_t* expr_ret_4 = NULL;
  #define rule expr_ret_4

  daisho_astnode_t* expr_ret_6 = NULL;
  rec(mod_6);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      expr_ret_6 = SUCC; // Not capturing CTYPE.
      ctx->pos++;
    } else {
      expr_ret_6 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_6)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      expr_ret_6 = SUCC; // Not capturing CIDENT.
      ctx->pos++;
    } else {
      expr_ret_6 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_6)
  {
    daisho_astnode_t* expr_ret_7 = NULL;
    expr_ret_7 = SUCC;
    while (expr_ret_7)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        expr_ret_7 = SUCC; // Not capturing STAR.
        ctx->pos++;
      } else {
        expr_ret_7 = NULL;
      }

    }

    expr_ret_7 = SUCC;
    expr_ret_6 = expr_ret_7;
  }

  // ModExprList end
  if (!expr_ret_6) rew(mod_6);
  expr_ret_5 = expr_ret_6 ? SUCC : NULL;
  return expr_ret_5 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfunc(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_9 = NULL;
  daisho_astnode_t* expr_ret_8 = NULL;
  #define rule expr_ret_8

  daisho_astnode_t* expr_ret_10 = NULL;
  rec(mod_10);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFUNC) {
      expr_ret_10 = SUCC; // Not capturing CFUNC.
      ctx->pos++;
    } else {
      expr_ret_10 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_10)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      expr_ret_10 = SUCC; // Not capturing CIDENT.
      ctx->pos++;
    } else {
      expr_ret_10 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_10) rew(mod_10);
  expr_ret_9 = expr_ret_10 ? SUCC : NULL;
  return expr_ret_9 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_classdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* expr_ret_12 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  #define rule expr_ret_11

  daisho_astnode_t* expr_ret_13 = NULL;
  rec(mod_13);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLASS) {
      expr_ret_13 = SUCC; // Not capturing CLASS.
      ctx->pos++;
    } else {
      expr_ret_13 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_13)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_14 = leaf(TYPEIDENT);
      ctx->pos++;
    } else {
      expr_ret_14 = NULL;
    }

    expr_ret_13 = expr_ret_14;
    id = expr_ret_14;
  }

  // ModExprList 2
  if (expr_ret_13)
  {
    daisho_astnode_t* expr_ret_15 = NULL;
    daisho_astnode_t* expr_ret_16 = NULL;
    rec(mod_16);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        expr_ret_16 = SUCC; // Not capturing IMPL.
        ctx->pos++;
      } else {
        expr_ret_16 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_16)
    {
      expr_ret_16 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_16)
    {
      daisho_astnode_t* expr_ret_17 = NULL;
      expr_ret_17 = SUCC;
      while (expr_ret_17)
      {
        daisho_astnode_t* expr_ret_18 = NULL;
        rec(mod_18);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_18 = SUCC; // Not capturing COMMA.
            ctx->pos++;
          } else {
            expr_ret_18 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_18)
        {
          expr_ret_18 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_18) rew(mod_18);
        expr_ret_17 = expr_ret_18 ? SUCC : NULL;
      }

      expr_ret_17 = SUCC;
      expr_ret_16 = expr_ret_17;
    }

    // ModExprList end
    if (!expr_ret_16) rew(mod_16);
    expr_ret_15 = expr_ret_16 ? SUCC : NULL;
    // optional
    if (!expr_ret_15)
      expr_ret_15 = SUCC;
    expr_ret_13 = expr_ret_15;
    impl = expr_ret_15;
  }

  // ModExprList 3
  if (expr_ret_13)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_13 = SUCC; // Not capturing LCBRACK.
      ctx->pos++;
    } else {
      expr_ret_13 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_13)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_13 = SUCC; // Not capturing RCBRACK.
      ctx->pos++;
    } else {
      expr_ret_13 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_13) rew(mod_13);
  expr_ret_12 = expr_ret_13 ? SUCC : NULL;
  return expr_ret_12 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* expr_ret_20 = NULL;
  daisho_astnode_t* expr_ret_19 = NULL;
  #define rule expr_ret_19

  daisho_astnode_t* expr_ret_21 = NULL;
  rec(mod_21);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      expr_ret_21 = SUCC; // Not capturing TRAIT.
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_22 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_22 = leaf(TYPEIDENT);
      ctx->pos++;
    } else {
      expr_ret_22 = NULL;
    }

    expr_ret_21 = expr_ret_22;
    id = expr_ret_22;
  }

  // ModExprList 2
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_23 = NULL;
    daisho_astnode_t* expr_ret_24 = NULL;
    rec(mod_24);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        expr_ret_24 = SUCC; // Not capturing IMPL.
        ctx->pos++;
      } else {
        expr_ret_24 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_24)
    {
      expr_ret_24 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_24)
    {
      daisho_astnode_t* expr_ret_25 = NULL;
      expr_ret_25 = SUCC;
      while (expr_ret_25)
      {
        daisho_astnode_t* expr_ret_26 = NULL;
        rec(mod_26);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_26 = SUCC; // Not capturing COMMA.
            ctx->pos++;
          } else {
            expr_ret_26 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_26)
        {
          expr_ret_26 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_26) rew(mod_26);
        expr_ret_25 = expr_ret_26 ? SUCC : NULL;
      }

      expr_ret_25 = SUCC;
      expr_ret_24 = expr_ret_25;
    }

    // ModExprList end
    if (!expr_ret_24) rew(mod_24);
    expr_ret_23 = expr_ret_24 ? SUCC : NULL;
    // optional
    if (!expr_ret_23)
      expr_ret_23 = SUCC;
    expr_ret_21 = expr_ret_23;
    impl = expr_ret_23;
  }

  // ModExprList 3
  if (expr_ret_21)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_21 = SUCC; // Not capturing LCBRACK.
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_21)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_21 = SUCC; // Not capturing RCBRACK.
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_21) rew(mod_21);
  expr_ret_20 = expr_ret_21 ? SUCC : NULL;
  return expr_ret_20 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* expr_ret_28 = NULL;
  daisho_astnode_t* expr_ret_27 = NULL;
  #define rule expr_ret_27

  daisho_astnode_t* expr_ret_29 = NULL;
  rec(mod_29);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      expr_ret_29 = SUCC; // Not capturing IMPL.
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_30 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_30 = leaf(TYPEIDENT);
      ctx->pos++;
    } else {
      expr_ret_30 = NULL;
    }

    expr_ret_29 = expr_ret_30;
    tt = expr_ret_30;
  }

  // ModExprList 2
  if (expr_ret_29)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      expr_ret_29 = SUCC; // Not capturing FOR.
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_31 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_31 = leaf(TYPEIDENT);
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

    expr_ret_29 = expr_ret_31;
    ft = expr_ret_31;
  }

  // ModExprList 4
  if (expr_ret_29)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_29 = SUCC; // Not capturing LCBRACK.
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_29)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_29 = SUCC; // Not capturing RCBRACK.
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_29) rew(mod_29);
  expr_ret_28 = expr_ret_29 ? SUCC : NULL;
  return expr_ret_28 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_33 = NULL;
  daisho_astnode_t* expr_ret_32 = NULL;
  #define rule expr_ret_32

  daisho_astnode_t* expr_ret_34 = NULL;
  rec(mod_34);
  // ModExprList end
  if (!expr_ret_34) rew(mod_34);
  expr_ret_33 = expr_ret_34 ? SUCC : NULL;
  return expr_ret_33 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_36 = NULL;
  daisho_astnode_t* expr_ret_35 = NULL;
  #define rule expr_ret_35

  daisho_astnode_t* expr_ret_37 = NULL;
  rec(mod_37);
  // ModExprList end
  if (!expr_ret_37) rew(mod_37);
  expr_ret_36 = expr_ret_37 ? SUCC : NULL;
  return expr_ret_36 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_39 = NULL;
  daisho_astnode_t* expr_ret_38 = NULL;
  #define rule expr_ret_38

  daisho_astnode_t* expr_ret_40 = NULL;
  rec(mod_40);
  // ModExprList end
  if (!expr_ret_40) rew(mod_40);
  expr_ret_39 = expr_ret_40 ? SUCC : NULL;
  return expr_ret_39 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_42 = NULL;
  daisho_astnode_t* expr_ret_41 = NULL;
  #define rule expr_ret_41

  daisho_astnode_t* expr_ret_43 = NULL;
  rec(mod_43);
  // ModExprList end
  if (!expr_ret_43) rew(mod_43);
  expr_ret_42 = expr_ret_43 ? SUCC : NULL;
  return expr_ret_42 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_45 = NULL;
  daisho_astnode_t* expr_ret_44 = NULL;
  #define rule expr_ret_44

  daisho_astnode_t* expr_ret_46 = NULL;

  rec(slash_46);

  // SlashExpr 0
  if (!expr_ret_46)
  {
    daisho_astnode_t* expr_ret_47 = NULL;
    rec(mod_47);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        expr_ret_47 = SUCC; // Not capturing VOIDTYPE.
        ctx->pos++;
      } else {
        expr_ret_47 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_47)
    {
      daisho_astnode_t* expr_ret_48 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        expr_ret_48 = SUCC; // Not capturing STAR.
        ctx->pos++;
      } else {
        expr_ret_48 = NULL;
      }

      // invert
      expr_ret_48 = expr_ret_48 ? NULL : SUCC;
      expr_ret_47 = expr_ret_48;
    }

    // ModExprList end
    if (!expr_ret_47) rew(mod_47);
    expr_ret_46 = expr_ret_47 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_46)
  {
    daisho_astnode_t* expr_ret_49 = NULL;
    rec(mod_49);
    // ModExprList 0
    {
      expr_ret_49 = daisho_parse_traittype(ctx);
    }

    // ModExprList 1
    if (expr_ret_49)
    {
      daisho_astnode_t* expr_ret_50 = NULL;
      expr_ret_50 = SUCC;
      while (expr_ret_50)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          expr_ret_50 = SUCC; // Not capturing STAR.
          ctx->pos++;
        } else {
          expr_ret_50 = NULL;
        }

      }

      expr_ret_50 = SUCC;
      expr_ret_49 = expr_ret_50;
    }

    // ModExprList end
    if (!expr_ret_49) rew(mod_49);
    expr_ret_46 = expr_ret_49 ? SUCC : NULL;
  }

  // SlashExpr 2
  if (!expr_ret_46)
  {
    daisho_astnode_t* expr_ret_51 = NULL;
    rec(mod_51);
    // ModExprList 0
    {
      expr_ret_51 = daisho_parse_classtype(ctx);
    }

    // ModExprList 1
    if (expr_ret_51)
    {
      daisho_astnode_t* expr_ret_52 = NULL;
      expr_ret_52 = SUCC;
      while (expr_ret_52)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          expr_ret_52 = SUCC; // Not capturing STAR.
          ctx->pos++;
        } else {
          expr_ret_52 = NULL;
        }

      }

      expr_ret_52 = SUCC;
      expr_ret_51 = expr_ret_52;
    }

    // ModExprList end
    if (!expr_ret_51) rew(mod_51);
    expr_ret_46 = expr_ret_51 ? SUCC : NULL;
  }

  // SlashExpr 3
  if (!expr_ret_46)
  {
    daisho_astnode_t* expr_ret_53 = NULL;
    rec(mod_53);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_53 = leaf(VOIDTYPE);
      ctx->pos++;
    } else {
      expr_ret_53 = NULL;
    }

    // ModExprList end
    if (!expr_ret_53) rew(mod_53);
    expr_ret_46 = expr_ret_53;
  }

  // SlashExpr end
  if (!expr_ret_46) rew(slash_46);
  expr_ret_45 = expr_ret_46;

  return expr_ret_45 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_55 = NULL;
  daisho_astnode_t* expr_ret_54 = NULL;
  #define rule expr_ret_54

  daisho_astnode_t* expr_ret_56 = NULL;
  rec(mod_56);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      expr_ret_56 = SUCC; // Not capturing TYPEIDENT.
      ctx->pos++;
    } else {
      expr_ret_56 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_57 = NULL;
    expr_ret_57 = SUCC;
    while (expr_ret_57)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        expr_ret_57 = SUCC; // Not capturing GRAVE.
        ctx->pos++;
      } else {
        expr_ret_57 = NULL;
      }

    }

    expr_ret_57 = SUCC;
    expr_ret_56 = expr_ret_57;
  }

  // ModExprList end
  if (!expr_ret_56) rew(mod_56);
  expr_ret_55 = expr_ret_56 ? SUCC : NULL;
  return expr_ret_55 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_classtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_59 = NULL;
  daisho_astnode_t* expr_ret_58 = NULL;
  #define rule expr_ret_58

  daisho_astnode_t* expr_ret_60 = NULL;
  rec(mod_60);
  // ModExprList Forwarding
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
    // Capturing TYPEIDENT.
    expr_ret_60 = leaf(TYPEIDENT);
    ctx->pos++;
  } else {
    expr_ret_60 = NULL;
  }

  // ModExprList end
  if (!expr_ret_60) rew(mod_60);
  expr_ret_59 = expr_ret_60;
  return expr_ret_59 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_62 = NULL;
  daisho_astnode_t* expr_ret_61 = NULL;
  #define rule expr_ret_61

  daisho_astnode_t* expr_ret_63 = NULL;
  rec(mod_63);
  // ModExprList Forwarding
  expr_ret_63 = daisho_parse_logorexpr(ctx);
  // ModExprList end
  if (!expr_ret_63) rew(mod_63);
  expr_ret_62 = expr_ret_63;
  return expr_ret_62 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_65 = NULL;
  daisho_astnode_t* expr_ret_64 = NULL;
  #define rule expr_ret_64

  daisho_astnode_t* expr_ret_66 = NULL;
  rec(mod_66);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_67 = NULL;
    expr_ret_67 = daisho_parse_logandexpr(ctx);
    expr_ret_66 = expr_ret_67;
    n = expr_ret_67;
  }

  // ModExprList 1
  if (expr_ret_66)
  {
    // CodeExpr
    #define ret expr_ret_66
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_68 = NULL;
    expr_ret_68 = SUCC;
    while (expr_ret_68)
    {
      daisho_astnode_t* expr_ret_69 = NULL;
      rec(mod_69);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_70 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Capturing LOGOR.
          expr_ret_70 = leaf(LOGOR);
          ctx->pos++;
        } else {
          expr_ret_70 = NULL;
        }

        expr_ret_69 = expr_ret_70;
        op = expr_ret_70;
      }

      // ModExprList 1
      if (expr_ret_69)
      {
        daisho_astnode_t* expr_ret_71 = NULL;
        expr_ret_71 = daisho_parse_logandexpr(ctx);
        expr_ret_69 = expr_ret_71;
        n = expr_ret_71;
      }

      // ModExprList 2
      if (expr_ret_69)
      {
        // CodeExpr
        #define ret expr_ret_69
        ret = SUCC;

        rule=node(LOGOR,  op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_69) rew(mod_69);
      expr_ret_68 = expr_ret_69 ? SUCC : NULL;
    }

    expr_ret_68 = SUCC;
    expr_ret_66 = expr_ret_68;
  }

  // ModExprList end
  if (!expr_ret_66) rew(mod_66);
  expr_ret_65 = expr_ret_66 ? SUCC : NULL;
  return expr_ret_65 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_73 = NULL;
  daisho_astnode_t* expr_ret_72 = NULL;
  #define rule expr_ret_72

  daisho_astnode_t* expr_ret_74 = NULL;
  rec(mod_74);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_75 = NULL;
    expr_ret_75 = daisho_parse_binorexpr(ctx);
    expr_ret_74 = expr_ret_75;
    n = expr_ret_75;
  }

  // ModExprList 1
  if (expr_ret_74)
  {
    // CodeExpr
    #define ret expr_ret_74
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_74)
  {
    daisho_astnode_t* expr_ret_76 = NULL;
    expr_ret_76 = SUCC;
    while (expr_ret_76)
    {
      daisho_astnode_t* expr_ret_77 = NULL;
      rec(mod_77);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_78 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Capturing LOGAND.
          expr_ret_78 = leaf(LOGAND);
          ctx->pos++;
        } else {
          expr_ret_78 = NULL;
        }

        expr_ret_77 = expr_ret_78;
        op = expr_ret_78;
      }

      // ModExprList 1
      if (expr_ret_77)
      {
        daisho_astnode_t* expr_ret_79 = NULL;
        expr_ret_79 = daisho_parse_binorexpr(ctx);
        expr_ret_77 = expr_ret_79;
        n = expr_ret_79;
      }

      // ModExprList 2
      if (expr_ret_77)
      {
        // CodeExpr
        #define ret expr_ret_77
        ret = SUCC;

        rule=node(LOGAND, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_77) rew(mod_77);
      expr_ret_76 = expr_ret_77 ? SUCC : NULL;
    }

    expr_ret_76 = SUCC;
    expr_ret_74 = expr_ret_76;
  }

  // ModExprList end
  if (!expr_ret_74) rew(mod_74);
  expr_ret_73 = expr_ret_74 ? SUCC : NULL;
  return expr_ret_73 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_81 = NULL;
  daisho_astnode_t* expr_ret_80 = NULL;
  #define rule expr_ret_80

  daisho_astnode_t* expr_ret_82 = NULL;
  rec(mod_82);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_83 = NULL;
    expr_ret_83 = daisho_parse_binxorexpr(ctx);
    expr_ret_82 = expr_ret_83;
    n = expr_ret_83;
  }

  // ModExprList 1
  if (expr_ret_82)
  {
    // CodeExpr
    #define ret expr_ret_82
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_84 = NULL;
    expr_ret_84 = SUCC;
    while (expr_ret_84)
    {
      daisho_astnode_t* expr_ret_85 = NULL;
      rec(mod_85);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_86 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Capturing OR.
          expr_ret_86 = leaf(OR);
          ctx->pos++;
        } else {
          expr_ret_86 = NULL;
        }

        expr_ret_85 = expr_ret_86;
        op = expr_ret_86;
      }

      // ModExprList 1
      if (expr_ret_85)
      {
        daisho_astnode_t* expr_ret_87 = NULL;
        expr_ret_87 = daisho_parse_binxorexpr(ctx);
        expr_ret_85 = expr_ret_87;
        n = expr_ret_87;
      }

      // ModExprList 2
      if (expr_ret_85)
      {
        // CodeExpr
        #define ret expr_ret_85
        ret = SUCC;

        rule=node(OR,     op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_85) rew(mod_85);
      expr_ret_84 = expr_ret_85 ? SUCC : NULL;
    }

    expr_ret_84 = SUCC;
    expr_ret_82 = expr_ret_84;
  }

  // ModExprList end
  if (!expr_ret_82) rew(mod_82);
  expr_ret_81 = expr_ret_82 ? SUCC : NULL;
  return expr_ret_81 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_89 = NULL;
  daisho_astnode_t* expr_ret_88 = NULL;
  #define rule expr_ret_88

  daisho_astnode_t* expr_ret_90 = NULL;
  rec(mod_90);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_91 = NULL;
    expr_ret_91 = daisho_parse_binandexpr(ctx);
    expr_ret_90 = expr_ret_91;
    n = expr_ret_91;
  }

  // ModExprList 1
  if (expr_ret_90)
  {
    // CodeExpr
    #define ret expr_ret_90
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_90)
  {
    daisho_astnode_t* expr_ret_92 = NULL;
    expr_ret_92 = SUCC;
    while (expr_ret_92)
    {
      daisho_astnode_t* expr_ret_93 = NULL;
      rec(mod_93);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_94 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Capturing XOR.
          expr_ret_94 = leaf(XOR);
          ctx->pos++;
        } else {
          expr_ret_94 = NULL;
        }

        expr_ret_93 = expr_ret_94;
        op = expr_ret_94;
      }

      // ModExprList 1
      if (expr_ret_93)
      {
        daisho_astnode_t* expr_ret_95 = NULL;
        expr_ret_95 = daisho_parse_binandexpr(ctx);
        expr_ret_93 = expr_ret_95;
        n = expr_ret_95;
      }

      // ModExprList 2
      if (expr_ret_93)
      {
        // CodeExpr
        #define ret expr_ret_93
        ret = SUCC;

        rule=node(XOR,    op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_93) rew(mod_93);
      expr_ret_92 = expr_ret_93 ? SUCC : NULL;
    }

    expr_ret_92 = SUCC;
    expr_ret_90 = expr_ret_92;
  }

  // ModExprList end
  if (!expr_ret_90) rew(mod_90);
  expr_ret_89 = expr_ret_90 ? SUCC : NULL;
  return expr_ret_89 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_97 = NULL;
  daisho_astnode_t* expr_ret_96 = NULL;
  #define rule expr_ret_96

  daisho_astnode_t* expr_ret_98 = NULL;
  rec(mod_98);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_99 = NULL;
    expr_ret_99 = daisho_parse_eneqexpr(ctx);
    expr_ret_98 = expr_ret_99;
    n = expr_ret_99;
  }

  // ModExprList 1
  if (expr_ret_98)
  {
    // CodeExpr
    #define ret expr_ret_98
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_98)
  {
    daisho_astnode_t* expr_ret_100 = NULL;
    expr_ret_100 = SUCC;
    while (expr_ret_100)
    {
      daisho_astnode_t* expr_ret_101 = NULL;
      rec(mod_101);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_102 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Capturing AND.
          expr_ret_102 = leaf(AND);
          ctx->pos++;
        } else {
          expr_ret_102 = NULL;
        }

        expr_ret_101 = expr_ret_102;
        op = expr_ret_102;
      }

      // ModExprList 1
      if (expr_ret_101)
      {
        daisho_astnode_t* expr_ret_103 = NULL;
        expr_ret_103 = daisho_parse_eneqexpr(ctx);
        expr_ret_101 = expr_ret_103;
        n = expr_ret_103;
      }

      // ModExprList 2
      if (expr_ret_101)
      {
        // CodeExpr
        #define ret expr_ret_101
        ret = SUCC;

        rule=node(AND,    op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_101) rew(mod_101);
      expr_ret_100 = expr_ret_101 ? SUCC : NULL;
    }

    expr_ret_100 = SUCC;
    expr_ret_98 = expr_ret_100;
  }

  // ModExprList end
  if (!expr_ret_98) rew(mod_98);
  expr_ret_97 = expr_ret_98 ? SUCC : NULL;
  return expr_ret_97 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_105 = NULL;
  daisho_astnode_t* expr_ret_104 = NULL;
  #define rule expr_ret_104

  daisho_astnode_t* expr_ret_106 = NULL;
  rec(mod_106);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_107 = NULL;
    expr_ret_107 = daisho_parse_cmpexpr(ctx);
    expr_ret_106 = expr_ret_107;
    n = expr_ret_107;
  }

  // ModExprList 1
  if (expr_ret_106)
  {
    // CodeExpr
    #define ret expr_ret_106
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_106)
  {
    daisho_astnode_t* expr_ret_108 = NULL;
    expr_ret_108 = SUCC;
    while (expr_ret_108)
    {
      daisho_astnode_t* expr_ret_109 = NULL;
      rec(mod_109);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_110 = NULL;
        daisho_astnode_t* expr_ret_111 = NULL;

        rec(slash_111);

        // SlashExpr 0
        if (!expr_ret_111)
        {
          daisho_astnode_t* expr_ret_112 = NULL;
          rec(mod_112);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Capturing DEQ.
            expr_ret_112 = leaf(DEQ);
            ctx->pos++;
          } else {
            expr_ret_112 = NULL;
          }

          // ModExprList end
          if (!expr_ret_112) rew(mod_112);
          expr_ret_111 = expr_ret_112;
        }

        // SlashExpr 1
        if (!expr_ret_111)
        {
          daisho_astnode_t* expr_ret_113 = NULL;
          rec(mod_113);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Capturing NEQ.
            expr_ret_113 = leaf(NEQ);
            ctx->pos++;
          } else {
            expr_ret_113 = NULL;
          }

          // ModExprList end
          if (!expr_ret_113) rew(mod_113);
          expr_ret_111 = expr_ret_113;
        }

        // SlashExpr end
        if (!expr_ret_111) rew(slash_111);
        expr_ret_110 = expr_ret_111;

        expr_ret_109 = expr_ret_110;
        op = expr_ret_110;
      }

      // ModExprList 1
      if (expr_ret_109)
      {
        daisho_astnode_t* expr_ret_114 = NULL;
        expr_ret_114 = daisho_parse_cmpexpr(ctx);
        expr_ret_109 = expr_ret_114;
        n = expr_ret_114;
      }

      // ModExprList 2
      if (expr_ret_109)
      {
        // CodeExpr
        #define ret expr_ret_109
        ret = SUCC;

        rule=node(BEQ, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_109) rew(mod_109);
      expr_ret_108 = expr_ret_109 ? SUCC : NULL;
    }

    expr_ret_108 = SUCC;
    expr_ret_106 = expr_ret_108;
  }

  // ModExprList end
  if (!expr_ret_106) rew(mod_106);
  expr_ret_105 = expr_ret_106 ? SUCC : NULL;
  return expr_ret_105 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_116 = NULL;
  daisho_astnode_t* expr_ret_115 = NULL;
  #define rule expr_ret_115

  daisho_astnode_t* expr_ret_117 = NULL;
  rec(mod_117);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_118 = NULL;
    expr_ret_118 = daisho_parse_shfexpr(ctx);
    expr_ret_117 = expr_ret_118;
    n = expr_ret_118;
  }

  // ModExprList 1
  if (expr_ret_117)
  {
    // CodeExpr
    #define ret expr_ret_117
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_117)
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    expr_ret_119 = SUCC;
    while (expr_ret_119)
    {
      daisho_astnode_t* expr_ret_120 = NULL;
      rec(mod_120);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_121 = NULL;
        daisho_astnode_t* expr_ret_122 = NULL;

        rec(slash_122);

        // SlashExpr 0
        if (!expr_ret_122)
        {
          daisho_astnode_t* expr_ret_123 = NULL;
          rec(mod_123);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_123 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_123 = NULL;
          }

          // ModExprList end
          if (!expr_ret_123) rew(mod_123);
          expr_ret_122 = expr_ret_123;
        }

        // SlashExpr 1
        if (!expr_ret_122)
        {
          daisho_astnode_t* expr_ret_124 = NULL;
          rec(mod_124);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_124 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_124 = NULL;
          }

          // ModExprList end
          if (!expr_ret_124) rew(mod_124);
          expr_ret_122 = expr_ret_124;
        }

        // SlashExpr 2
        if (!expr_ret_122)
        {
          daisho_astnode_t* expr_ret_125 = NULL;
          rec(mod_125);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Capturing LEQ.
            expr_ret_125 = leaf(LEQ);
            ctx->pos++;
          } else {
            expr_ret_125 = NULL;
          }

          // ModExprList end
          if (!expr_ret_125) rew(mod_125);
          expr_ret_122 = expr_ret_125;
        }

        // SlashExpr 3
        if (!expr_ret_122)
        {
          daisho_astnode_t* expr_ret_126 = NULL;
          rec(mod_126);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Capturing GEQ.
            expr_ret_126 = leaf(GEQ);
            ctx->pos++;
          } else {
            expr_ret_126 = NULL;
          }

          // ModExprList end
          if (!expr_ret_126) rew(mod_126);
          expr_ret_122 = expr_ret_126;
        }

        // SlashExpr end
        if (!expr_ret_122) rew(slash_122);
        expr_ret_121 = expr_ret_122;

        expr_ret_120 = expr_ret_121;
        op = expr_ret_121;
      }

      // ModExprList 1
      if (expr_ret_120)
      {
        daisho_astnode_t* expr_ret_127 = NULL;
        expr_ret_127 = daisho_parse_shfexpr(ctx);
        expr_ret_120 = expr_ret_127;
        n = expr_ret_127;
      }

      // ModExprList 2
      if (expr_ret_120)
      {
        // CodeExpr
        #define ret expr_ret_120
        ret = SUCC;

        rule=node(CMP, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_120) rew(mod_120);
      expr_ret_119 = expr_ret_120 ? SUCC : NULL;
    }

    expr_ret_119 = SUCC;
    expr_ret_117 = expr_ret_119;
  }

  // ModExprList end
  if (!expr_ret_117) rew(mod_117);
  expr_ret_116 = expr_ret_117 ? SUCC : NULL;
  return expr_ret_116 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_128 = NULL;
  #define rule expr_ret_128

  daisho_astnode_t* expr_ret_130 = NULL;
  rec(mod_130);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_131 = NULL;
    expr_ret_131 = daisho_parse_multexpr(ctx);
    expr_ret_130 = expr_ret_131;
    n = expr_ret_131;
  }

  // ModExprList 1
  if (expr_ret_130)
  {
    // CodeExpr
    #define ret expr_ret_130
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_130)
  {
    daisho_astnode_t* expr_ret_132 = NULL;
    expr_ret_132 = SUCC;
    while (expr_ret_132)
    {
      daisho_astnode_t* expr_ret_133 = NULL;
      rec(mod_133);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_134 = NULL;
        daisho_astnode_t* expr_ret_135 = NULL;

        rec(slash_135);

        // SlashExpr 0
        if (!expr_ret_135)
        {
          daisho_astnode_t* expr_ret_136 = NULL;
          rec(mod_136);
          // ModExprList Forwarding
          expr_ret_136 = daisho_parse_lshf(ctx);
          // ModExprList end
          if (!expr_ret_136) rew(mod_136);
          expr_ret_135 = expr_ret_136;
        }

        // SlashExpr 1
        if (!expr_ret_135)
        {
          daisho_astnode_t* expr_ret_137 = NULL;
          rec(mod_137);
          // ModExprList Forwarding
          expr_ret_137 = daisho_parse_rshf(ctx);
          // ModExprList end
          if (!expr_ret_137) rew(mod_137);
          expr_ret_135 = expr_ret_137;
        }

        // SlashExpr end
        if (!expr_ret_135) rew(slash_135);
        expr_ret_134 = expr_ret_135;

        expr_ret_133 = expr_ret_134;
        op = expr_ret_134;
      }

      // ModExprList 1
      if (expr_ret_133)
      {
        daisho_astnode_t* expr_ret_138 = NULL;
        expr_ret_138 = daisho_parse_multexpr(ctx);
        expr_ret_133 = expr_ret_138;
        n = expr_ret_138;
      }

      // ModExprList 2
      if (expr_ret_133)
      {
        // CodeExpr
        #define ret expr_ret_133
        ret = SUCC;

        rule=node(SHIFT, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_133) rew(mod_133);
      expr_ret_132 = expr_ret_133 ? SUCC : NULL;
    }

    expr_ret_132 = SUCC;
    expr_ret_130 = expr_ret_132;
  }

  // ModExprList end
  if (!expr_ret_130) rew(mod_130);
  expr_ret_129 = expr_ret_130 ? SUCC : NULL;
  return expr_ret_129 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_140 = NULL;
  daisho_astnode_t* expr_ret_139 = NULL;
  #define rule expr_ret_139

  daisho_astnode_t* expr_ret_141 = NULL;
  rec(mod_141);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_142 = NULL;
    expr_ret_142 = daisho_parse_sumexpr(ctx);
    expr_ret_141 = expr_ret_142;
    n = expr_ret_142;
  }

  // ModExprList 1
  if (expr_ret_141)
  {
    // CodeExpr
    #define ret expr_ret_141
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_141)
  {
    daisho_astnode_t* expr_ret_143 = NULL;
    expr_ret_143 = SUCC;
    while (expr_ret_143)
    {
      daisho_astnode_t* expr_ret_144 = NULL;
      rec(mod_144);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_145 = NULL;
        daisho_astnode_t* expr_ret_146 = NULL;

        rec(slash_146);

        // SlashExpr 0
        if (!expr_ret_146)
        {
          daisho_astnode_t* expr_ret_147 = NULL;
          rec(mod_147);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Capturing STAR.
            expr_ret_147 = leaf(STAR);
            ctx->pos++;
          } else {
            expr_ret_147 = NULL;
          }

          // ModExprList end
          if (!expr_ret_147) rew(mod_147);
          expr_ret_146 = expr_ret_147;
        }

        // SlashExpr 1
        if (!expr_ret_146)
        {
          daisho_astnode_t* expr_ret_148 = NULL;
          rec(mod_148);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Capturing DIV.
            expr_ret_148 = leaf(DIV);
            ctx->pos++;
          } else {
            expr_ret_148 = NULL;
          }

          // ModExprList end
          if (!expr_ret_148) rew(mod_148);
          expr_ret_146 = expr_ret_148;
        }

        // SlashExpr 2
        if (!expr_ret_146)
        {
          daisho_astnode_t* expr_ret_149 = NULL;
          rec(mod_149);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Capturing MOD.
            expr_ret_149 = leaf(MOD);
            ctx->pos++;
          } else {
            expr_ret_149 = NULL;
          }

          // ModExprList end
          if (!expr_ret_149) rew(mod_149);
          expr_ret_146 = expr_ret_149;
        }

        // SlashExpr end
        if (!expr_ret_146) rew(slash_146);
        expr_ret_145 = expr_ret_146;

        expr_ret_144 = expr_ret_145;
        op = expr_ret_145;
      }

      // ModExprList 1
      if (expr_ret_144)
      {
        daisho_astnode_t* expr_ret_150 = NULL;
        expr_ret_150 = daisho_parse_sumexpr(ctx);
        expr_ret_144 = expr_ret_150;
        n = expr_ret_150;
      }

      // ModExprList 2
      if (expr_ret_144)
      {
        // CodeExpr
        #define ret expr_ret_144
        ret = SUCC;

        rule=node(FACTOR, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_144) rew(mod_144);
      expr_ret_143 = expr_ret_144 ? SUCC : NULL;
    }

    expr_ret_143 = SUCC;
    expr_ret_141 = expr_ret_143;
  }

  // ModExprList end
  if (!expr_ret_141) rew(mod_141);
  expr_ret_140 = expr_ret_141 ? SUCC : NULL;
  return expr_ret_140 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_152 = NULL;
  daisho_astnode_t* expr_ret_151 = NULL;
  #define rule expr_ret_151

  daisho_astnode_t* expr_ret_153 = NULL;
  rec(mod_153);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_154 = NULL;
    expr_ret_154 = daisho_parse_castexpr(ctx);
    expr_ret_153 = expr_ret_154;
    n = expr_ret_154;
  }

  // ModExprList 1
  if (expr_ret_153)
  {
    // CodeExpr
    #define ret expr_ret_153
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_153)
  {
    daisho_astnode_t* expr_ret_155 = NULL;
    expr_ret_155 = SUCC;
    while (expr_ret_155)
    {
      daisho_astnode_t* expr_ret_156 = NULL;
      rec(mod_156);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_157 = NULL;
        daisho_astnode_t* expr_ret_158 = NULL;

        rec(slash_158);

        // SlashExpr 0
        if (!expr_ret_158)
        {
          daisho_astnode_t* expr_ret_159 = NULL;
          rec(mod_159);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Capturing PLUS.
            expr_ret_159 = leaf(PLUS);
            ctx->pos++;
          } else {
            expr_ret_159 = NULL;
          }

          // ModExprList end
          if (!expr_ret_159) rew(mod_159);
          expr_ret_158 = expr_ret_159;
        }

        // SlashExpr 1
        if (!expr_ret_158)
        {
          daisho_astnode_t* expr_ret_160 = NULL;
          rec(mod_160);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Capturing MINUS.
            expr_ret_160 = leaf(MINUS);
            ctx->pos++;
          } else {
            expr_ret_160 = NULL;
          }

          // ModExprList end
          if (!expr_ret_160) rew(mod_160);
          expr_ret_158 = expr_ret_160;
        }

        // SlashExpr end
        if (!expr_ret_158) rew(slash_158);
        expr_ret_157 = expr_ret_158;

        expr_ret_156 = expr_ret_157;
        op = expr_ret_157;
      }

      // ModExprList 1
      if (expr_ret_156)
      {
        daisho_astnode_t* expr_ret_161 = NULL;
        expr_ret_161 = daisho_parse_castexpr(ctx);
        expr_ret_156 = expr_ret_161;
        n = expr_ret_161;
      }

      // ModExprList 2
      if (expr_ret_156)
      {
        // CodeExpr
        #define ret expr_ret_156
        ret = SUCC;

        rule=node(SUM, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_156) rew(mod_156);
      expr_ret_155 = expr_ret_156 ? SUCC : NULL;
    }

    expr_ret_155 = SUCC;
    expr_ret_153 = expr_ret_155;
  }

  // ModExprList end
  if (!expr_ret_153) rew(mod_153);
  expr_ret_152 = expr_ret_153 ? SUCC : NULL;
  return expr_ret_152 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* re = NULL;
  daisho_astnode_t* expr_ret_163 = NULL;
  daisho_astnode_t* expr_ret_162 = NULL;
  #define rule expr_ret_162

  daisho_astnode_t* expr_ret_164 = NULL;

  rec(slash_164);

  // SlashExpr 0
  if (!expr_ret_164)
  {
    daisho_astnode_t* expr_ret_165 = NULL;
    rec(mod_165);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_166 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_166 = leaf(OPEN);
        ctx->pos++;
      } else {
        expr_ret_166 = NULL;
      }

      expr_ret_165 = expr_ret_166;
      o = expr_ret_166;
    }

    // ModExprList 1
    if (expr_ret_165)
    {
      daisho_astnode_t* expr_ret_167 = NULL;
      expr_ret_167 = daisho_parse_type(ctx);
      expr_ret_165 = expr_ret_167;
      t = expr_ret_167;
    }

    // ModExprList 2
    if (expr_ret_165)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        expr_ret_165 = SUCC; // Not capturing CLOSE.
        ctx->pos++;
      } else {
        expr_ret_165 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_165)
    {
      daisho_astnode_t* expr_ret_168 = NULL;
      expr_ret_168 = daisho_parse_expr(ctx);
      expr_ret_165 = expr_ret_168;
      e = expr_ret_168;
    }

    // ModExprList 4
    if (expr_ret_165)
    {
      // CodeExpr
      #define ret expr_ret_165
      ret = SUCC;

       rule = node(CAST, o, t, e); ;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_165) rew(mod_165);
    expr_ret_164 = expr_ret_165 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_164)
  {
    daisho_astnode_t* expr_ret_169 = NULL;
    rec(mod_169);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_170 = NULL;
      expr_ret_170 = daisho_parse_refexpr(ctx);
      expr_ret_169 = expr_ret_170;
      re = expr_ret_170;
    }

    // ModExprList 1
    if (expr_ret_169)
    {
      // CodeExpr
      #define ret expr_ret_169
      ret = SUCC;

       rule = re; ;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_169) rew(mod_169);
    expr_ret_164 = expr_ret_169 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_164) rew(slash_164);
  expr_ret_163 = expr_ret_164;

  return expr_ret_163 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* a = NULL;
  daisho_astnode_t* expr_ret_172 = NULL;
  daisho_astnode_t* expr_ret_171 = NULL;
  #define rule expr_ret_171

  daisho_astnode_t* expr_ret_173 = NULL;
  rec(mod_173);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_174 = NULL;
    expr_ret_174 = daisho_parse_derefexpr(ctx);
    expr_ret_173 = expr_ret_174;
    d = expr_ret_174;
  }

  // ModExprList 1
  if (expr_ret_173)
  {
    daisho_astnode_t* expr_ret_175 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_175 = leaf(REF);
      ctx->pos++;
    } else {
      expr_ret_175 = NULL;
    }

    // optional
    if (!expr_ret_175)
      expr_ret_175 = SUCC;
    expr_ret_173 = expr_ret_175;
    a = expr_ret_175;
  }

  // ModExprList 2
  if (expr_ret_173)
  {
    // CodeExpr
    #define ret expr_ret_173
    ret = SUCC;

     rule = a != SUCC ? node(REF, a, d) : d ;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_173) rew(mod_173);
  expr_ret_172 = expr_ret_173 ? SUCC : NULL;
  return expr_ret_172 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_177 = NULL;
  daisho_astnode_t* expr_ret_176 = NULL;
  #define rule expr_ret_176

  daisho_astnode_t* expr_ret_178 = NULL;
  rec(mod_178);
  // ModExprList end
  if (!expr_ret_178) rew(mod_178);
  expr_ret_177 = expr_ret_178 ? SUCC : NULL;
  return expr_ret_177 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_180 = NULL;
  daisho_astnode_t* expr_ret_179 = NULL;
  #define rule expr_ret_179

  daisho_astnode_t* expr_ret_181 = NULL;

  rec(slash_181);

  // SlashExpr 0
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_182 = NULL;
    rec(mod_182);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_182 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_182 = NULL;
    }

    // ModExprList end
    if (!expr_ret_182) rew(mod_182);
    expr_ret_181 = expr_ret_182;
  }

  // SlashExpr 1
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_183 = NULL;
    rec(mod_183);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_183 = leaf(NUMLIT);
      ctx->pos++;
    } else {
      expr_ret_183 = NULL;
    }

    // ModExprList end
    if (!expr_ret_183) rew(mod_183);
    expr_ret_181 = expr_ret_183;
  }

  // SlashExpr 2
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_184 = NULL;
    rec(mod_184);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_184 = leaf(STRLIT);
      ctx->pos++;
    } else {
      expr_ret_184 = NULL;
    }

    // ModExprList end
    if (!expr_ret_184) rew(mod_184);
    expr_ret_181 = expr_ret_184;
  }

  // SlashExpr 3
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_185 = NULL;
    rec(mod_185);
    // ModExprList Forwarding
    expr_ret_185 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_185) rew(mod_185);
    expr_ret_181 = expr_ret_185;
  }

  // SlashExpr 4
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_186 = NULL;
    rec(mod_186);
    // ModExprList Forwarding
    expr_ret_186 = daisho_parse_castexpr(ctx);
    // ModExprList end
    if (!expr_ret_186) rew(mod_186);
    expr_ret_181 = expr_ret_186;
  }

  // SlashExpr 5
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_187 = NULL;
    rec(mod_187);
    // ModExprList Forwarding
    expr_ret_187 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_187) rew(mod_187);
    expr_ret_181 = expr_ret_187;
  }

  // SlashExpr 6
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_188 = NULL;
    rec(mod_188);
    // ModExprList Forwarding
    expr_ret_188 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_188) rew(mod_188);
    expr_ret_181 = expr_ret_188;
  }

  // SlashExpr 7
  if (!expr_ret_181)
  {
    daisho_astnode_t* expr_ret_189 = NULL;
    rec(mod_189);
    // ModExprList Forwarding
    expr_ret_189 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_189) rew(mod_189);
    expr_ret_181 = expr_ret_189;
  }

  // SlashExpr end
  if (!expr_ret_181) rew(slash_181);
  expr_ret_180 = expr_ret_181;

  return expr_ret_180 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_191 = NULL;
  daisho_astnode_t* expr_ret_190 = NULL;
  #define rule expr_ret_190

  daisho_astnode_t* expr_ret_192 = NULL;
  rec(mod_192);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_192 = SUCC; // Not capturing LCBRACK.
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_192)
  {
    // CodeExpr
    #define ret expr_ret_192
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_192)
  {
    daisho_astnode_t* expr_ret_193 = NULL;
    expr_ret_193 = SUCC;
    while (expr_ret_193)
    {
      daisho_astnode_t* expr_ret_194 = NULL;
      rec(mod_194);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_195 = NULL;
        expr_ret_195 = daisho_parse_expr(ctx);
        expr_ret_194 = expr_ret_195;
        e = expr_ret_195;
      }

      // ModExprList 1
      if (expr_ret_194)
      {
        // CodeExpr
        #define ret expr_ret_194
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_194) rew(mod_194);
      expr_ret_193 = expr_ret_194 ? SUCC : NULL;
    }

    expr_ret_193 = SUCC;
    expr_ret_192 = expr_ret_193;
  }

  // ModExprList 3
  if (expr_ret_192)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_192 = SUCC; // Not capturing RCBRACK.
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_192) rew(mod_192);
  expr_ret_191 = expr_ret_192 ? SUCC : NULL;
  return expr_ret_191 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_197 = NULL;
  daisho_astnode_t* expr_ret_196 = NULL;
  #define rule expr_ret_196

  daisho_astnode_t* expr_ret_198 = NULL;
  rec(mod_198);
  // ModExprList end
  if (!expr_ret_198) rew(mod_198);
  expr_ret_197 = expr_ret_198 ? SUCC : NULL;
  return expr_ret_197 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_200 = NULL;
  daisho_astnode_t* expr_ret_199 = NULL;
  #define rule expr_ret_199

  daisho_astnode_t* expr_ret_201 = NULL;
  rec(mod_201);
  // ModExprList end
  if (!expr_ret_201) rew(mod_201);
  expr_ret_200 = expr_ret_201 ? SUCC : NULL;
  return expr_ret_200 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_203 = NULL;
  daisho_astnode_t* expr_ret_202 = NULL;
  #define rule expr_ret_202

  daisho_astnode_t* expr_ret_204 = NULL;
  rec(mod_204);
  // ModExprList end
  if (!expr_ret_204) rew(mod_204);
  expr_ret_203 = expr_ret_204 ? SUCC : NULL;
  return expr_ret_203 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lshf(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* expr_ret_206 = NULL;
  daisho_astnode_t* expr_ret_205 = NULL;
  #define rule expr_ret_205

  daisho_astnode_t* expr_ret_207 = NULL;
  rec(mod_207);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_208 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_208 = leaf(LT);
      ctx->pos++;
    } else {
      expr_ret_208 = NULL;
    }

    expr_ret_207 = expr_ret_208;
    l = expr_ret_208;
  }

  // ModExprList 1
  if (expr_ret_207)
  {
    daisho_astnode_t* expr_ret_209 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_209 = leaf(LT);
      ctx->pos++;
    } else {
      expr_ret_209 = NULL;
    }

    expr_ret_207 = expr_ret_209;
    lt = expr_ret_209;
  }

  // ModExprList 2
  if (expr_ret_207)
  {
    // CodeExpr
    #define ret expr_ret_207
    ret = SUCC;

    rule=node(LSHF, l, lt);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_207) rew(mod_207);
  expr_ret_206 = expr_ret_207 ? SUCC : NULL;
  return expr_ret_206 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_rshf(daisho_parser_ctx* ctx) {
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  daisho_astnode_t* expr_ret_211 = NULL;
  daisho_astnode_t* expr_ret_210 = NULL;
  #define rule expr_ret_210

  daisho_astnode_t* expr_ret_212 = NULL;
  rec(mod_212);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_213 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_213 = leaf(GT);
      ctx->pos++;
    } else {
      expr_ret_213 = NULL;
    }

    expr_ret_212 = expr_ret_213;
    g = expr_ret_213;
  }

  // ModExprList 1
  if (expr_ret_212)
  {
    daisho_astnode_t* expr_ret_214 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_214 = leaf(GT);
      ctx->pos++;
    } else {
      expr_ret_214 = NULL;
    }

    expr_ret_212 = expr_ret_214;
    gt = expr_ret_214;
  }

  // ModExprList 2
  if (expr_ret_212)
  {
    // CodeExpr
    #define ret expr_ret_212
    ret = SUCC;

    rule=node(RSHF, g, gt);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_212) rew(mod_212);
  expr_ret_211 = expr_ret_212 ? SUCC : NULL;
  return expr_ret_211 ? rule : NULL;
  #undef rule
}



#undef rec
#undef rew
#undef node
#undef list
#undef leaf
#undef add
#undef defer
#undef SUCC

#endif /* PGEN_DAISHO_ASTNODE_INCLUDE */

