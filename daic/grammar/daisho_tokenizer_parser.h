
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


#ifndef PGEN_INTERACTIVE
#define PGEN_INTERACTIVE 0

#define PGEN_ALLOCATOR_DEBUG 0

#endif /* PGEN_INTERACTIVE */


/* START OF AST ALLOCATOR */

#ifndef PGEN_ARENA_INCLUDED
#define PGEN_ARENA_INCLUDED
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#endif

#ifndef PGEN_ALLOCATOR_DEBUG
#define PGEN_ALLOCATOR_DEBUG 0
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
  if (align == 1)
    return n;
  return (n + align - 1) & -align;
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

#if PGEN_ALLOCATOR_DEBUG
static inline void pgen_allocator_print_freelist(pgen_allocator *allocator) {

  if (allocator->freelist.len) {
    puts("Freelist:");
    for (size_t i = 0; i < allocator->freelist.len; i++) {
      printf("  {.freefn=%p, .ptr=%p, {.arena_idx=%u, .filled=%u}}\n",
             allocator->freelist.entries->freefn,
             allocator->freelist.entries->ptr,
             allocator->freelist.entries->rew.arena_idx,
             allocator->freelist.entries->rew.filled);
    }
  }
  puts("");
}
#endif

#define PGEN_ALLOC_OF(allocator, type)                                         \
  (type *)pgen_alloc(allocator, sizeof(type), _Alignof(type))
static inline char *pgen_alloc(pgen_allocator *allocator, size_t n,
                               size_t alignment) {
#if PGEN_ALLOCATOR_DEBUG
  printf("alloc({.arena_idx=%u, .filled=%u, .freelist_len=%u}, "
         "{.n=%zu, .alignment=%zu})\n",
         allocator->rew.arena_idx, allocator->rew.filled,
         allocator->freelist.len, n, alignment);
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
        PGEN_OOM();

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

#if PGEN_ALLOCATOR_DEBUG
  printf("New allocator state: {.arena_idx=%u, .filled=%u, .freelist_len=%u}"
         "\n\n",
         allocator->freelist.entries->rew.arena_idx,
         allocator->freelist.entries->rew.filled, allocator->freelist.len);
#endif

  return ret;
}

// Does not take a pgen_allocator_rewind_t, does not rebind the
// lifetime of the reallocated object.
static inline void pgen_allocator_realloced(pgen_allocator *allocator,
                                            void *old_ptr, void *new_ptr,
                                            void (*new_free_fn)(void *)) {

#if PGEN_ALLOCATOR_DEBUG
  printf("realloc({.arena_idx=%u, .filled=%u, .freelist_len=%u}, "
         "{.old_ptr=%p, .new_ptr=%p, new_free_fn=%p})\n",
         allocator->rew.arena_idx, allocator->rew.filled,
         allocator->freelist.len, old_ptr, new_ptr, new_free_fn);
  pgen_allocator_print_freelist(allocator);
#endif

  for (size_t i = 0; i < allocator->freelist.len; i++) {
    void *ptr = allocator->freelist.entries[i].ptr;
    if (ptr == old_ptr) {
      allocator->freelist.entries[i].ptr = new_ptr;
      allocator->freelist.entries[i].freefn = new_free_fn;
      return;
    }
  }

#if PGEN_ALLOCATOR_DEBUG
  puts("Realloced.");
  pgen_allocator_print_freelist(allocator);
#endif
}

static inline void pgen_defer(pgen_allocator *allocator, void (*freefn)(void *),
                              void *ptr, pgen_allocator_rewind_t rew) {
#if PGEN_ALLOCATOR_DEBUG
  printf("defer({.arena_idx=%u, .filled=%u, .freelist_len=%u}, "
         "{.freefn=%p, ptr=%p, {.arena_idx=%u, .filled=%u}})\n",
         allocator->rew.arena_idx, allocator->rew.filled,
         allocator->freelist.len, ptr, rew.arena_idx, rew.filled);
  pgen_allocator_print_freelist(allocator);
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

#if PGEN_ALLOCATOR_DEBUG
  puts("Deferred.");
  pgen_allocator_print_freelist(allocator);
#endif
}

static inline void pgen_allocator_rewind(pgen_allocator *allocator,
                                         pgen_allocator_rewind_t rew) {

#if PGEN_ALLOCATOR_DEBUG
  printf("rewind({.arena_idx=%u, .filled=%u, .freelist_len=%u}, "
         "{.arena_idx=%u, .filled=%u})\n",
         allocator->freelist.entries->rew.arena_idx,
         allocator->freelist.entries->rew.filled, allocator->freelist.len,
         rew.arena_idx, rew.filled);
  pgen_allocator_print_freelist(allocator);
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

#if PGEN_ALLOCATOR_DEBUG
  printf("rewound to: {.arena_idx=%u, .filled=%u, .freelist_len=%u}\n",
         allocator->freelist.entries->rew.arena_idx,
         allocator->freelist.entries->rew.filled, allocator->freelist.len);
  pgen_allocator_print_freelist(allocator);
#endif
}

#endif /* PGEN_ARENA_INCLUDED */


struct daisho_astnode_t;
typedef struct daisho_astnode_t daisho_astnode_t;

/******************/
/* Pre Directives */
/******************/
#include "../types.h"

#ifndef PGEN_PARSER_MACROS_INCLUDED
#define PGEN_PARSER_MACROS_INCLUDED

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && !defined(__cplusplus)
#  define PGEN_RESTRICT restrict
#elif defined(__clang__) || \
     (defined(__GNUC__) && (__GNUC__ >= 4)) || \
     (defined(_MSC_VER) && (_MSC_VER >= 1900))
#  define PGEN_RESTRICT __restrict
#else
#  define PGEN_RESTRICT
#endif

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

#ifndef DAISHO_SOURCEINFO
#define DAISHO_SOURCEINFO 1
#endif

typedef enum {
  DAISHO_TOK_STREAMBEGIN,
  DAISHO_TOK_STREAMEND,
  DAISHO_TOK_PLUS,
  DAISHO_TOK_MINUS,
  DAISHO_TOK_STAR,
  DAISHO_TOK_POW,
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
  DAISHO_TOK_IN,
  DAISHO_TOK_WHILE,
  DAISHO_TOK_THEN,
  DAISHO_TOK_ALSO,
  DAISHO_TOK_WHERE,
  DAISHO_TOK_STRUCT,
  DAISHO_TOK_UNION,
  DAISHO_TOK_TRAIT,
  DAISHO_TOK_IMPL,
  DAISHO_TOK_FN,
  DAISHO_TOK_FNTYPE,
  DAISHO_TOK_CTYPE,
  DAISHO_TOK_CFN,
  DAISHO_TOK_SELFTYPE,
  DAISHO_TOK_SELFVAR,
  DAISHO_TOK_VOIDTYPE,
  DAISHO_TOK_VOIDPTR,
  DAISHO_TOK_SIZEOF,
  DAISHO_TOK_NAMESPACE,
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
  DAISHO_TOK_ARROW,
  DAISHO_TOK_DARROW,
  DAISHO_TOK_RET,
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

// The 0th token is beginning of stream.
// The 1st token isend of stream.
// Tokens 1 through 83 are the ones you defined.
// This totals 85 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 85
static const char* daisho_tokenkind_name[DAISHO_NUM_TOKENKINDS] = {
  "DAISHO_TOK_STREAMBEGIN",
  "DAISHO_TOK_STREAMEND",
  "DAISHO_TOK_PLUS",
  "DAISHO_TOK_MINUS",
  "DAISHO_TOK_STAR",
  "DAISHO_TOK_POW",
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
  "DAISHO_TOK_IN",
  "DAISHO_TOK_WHILE",
  "DAISHO_TOK_THEN",
  "DAISHO_TOK_ALSO",
  "DAISHO_TOK_WHERE",
  "DAISHO_TOK_STRUCT",
  "DAISHO_TOK_UNION",
  "DAISHO_TOK_TRAIT",
  "DAISHO_TOK_IMPL",
  "DAISHO_TOK_FN",
  "DAISHO_TOK_FNTYPE",
  "DAISHO_TOK_CTYPE",
  "DAISHO_TOK_CFN",
  "DAISHO_TOK_SELFTYPE",
  "DAISHO_TOK_SELFVAR",
  "DAISHO_TOK_VOIDTYPE",
  "DAISHO_TOK_VOIDPTR",
  "DAISHO_TOK_SIZEOF",
  "DAISHO_TOK_NAMESPACE",
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
  "DAISHO_TOK_ARROW",
  "DAISHO_TOK_DARROW",
  "DAISHO_TOK_RET",
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
  codepoint_t* content; // The token begins at tokenizer->start[token->start].
  size_t len;
#if DAISHO_SOURCEINFO
  size_t line;
  size_t col;
#endif
#ifdef DAISHO_TOKEN_EXTRA
  DAISHO_TOKEN_EXTRA
#endif
} daisho_token;

typedef struct {
  codepoint_t* start;
  size_t len;
  size_t pos;
#if DAISHO_SOURCEINFO
  size_t pos_line;
  size_t pos_col;
#endif
} daisho_tokenizer;

static inline void daisho_tokenizer_init(daisho_tokenizer* tokenizer, codepoint_t* start, size_t len) {
  tokenizer->start = start;
  tokenizer->len = len;
  tokenizer->pos = 0;
#if DAISHO_SOURCEINFO
  tokenizer->pos_line = 0;
  tokenizer->pos_col = 0;
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
  int smaut_state_13 = 0;
  int smaut_state_14 = 0;
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
  size_t smaut_munch_size_13 = 0;
  size_t smaut_munch_size_14 = 0;
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;

  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 10;
        else if (c == 35 /*'#'*/) trie_state = 108;
        else if (c == 36 /*'$'*/) trie_state = 110;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 40 /*'('*/) trie_state = 102;
        else if (c == 41 /*')'*/) trie_state = 103;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 101;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 100;
        else if (c == 47 /*'/'*/) trie_state = 5;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 99;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 109;
        else if (c == 70 /*'F'*/) trie_state = 70;
        else if (c == 83 /*'S'*/) trie_state = 79;
        else if (c == 86 /*'V'*/) trie_state = 87;
        else if (c == 91 /*'['*/) trie_state = 106;
        else if (c == 93 /*']'*/) trie_state = 107;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 111;
        else if (c == 97 /*'a'*/) trie_state = 53;
        else if (c == 99 /*'c'*/) trie_state = 72;
        else if (c == 102 /*'f'*/) trie_state = 39;
        else if (c == 105 /*'i'*/) trie_state = 42;
        else if (c == 115 /*'s'*/) trie_state = 83;
        else if (c == 116 /*'t'*/) trie_state = 49;
        else if (c == 117 /*'u'*/) trie_state = 60;
        else if (c == 119 /*'w'*/) trie_state = 44;
        else if (c == 123 /*'{'*/) trie_state = 104;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 105;
        else if (c == 126 /*'~'*/) trie_state = 11;
        else trie_state = -1;
      }
      else if (trie_state == 1) {
        if (c == 43 /*'+'*/) trie_state = 34;
        else if (c == 61 /*'='*/) trie_state = 21;
        else trie_state = -1;
      }
      else if (trie_state == 2) {
        if (c == 45 /*'-'*/) trie_state = 35;
        else if (c == 61 /*'='*/) trie_state = 22;
        else if (c == 62 /*'>'*/) trie_state = 112;
        else trie_state = -1;
      }
      else if (trie_state == 3) {
        if (c == 42 /*'*'*/) trie_state = 4;
        else if (c == 61 /*'='*/) trie_state = 23;
        else trie_state = -1;
      }
      else if (trie_state == 5) {
        if (c == 61 /*'='*/) trie_state = 24;
        else trie_state = -1;
      }
      else if (trie_state == 6) {
        if (c == 61 /*'='*/) trie_state = 25;
        else trie_state = -1;
      }
      else if (trie_state == 7) {
        if (c == 38 /*'&'*/) trie_state = 12;
        else if (c == 61 /*'='*/) trie_state = 26;
        else trie_state = -1;
      }
      else if (trie_state == 8) {
        if (c == 61 /*'='*/) trie_state = 27;
        else if (c == 124 /*'|'*/) trie_state = 13;
        else trie_state = -1;
      }
      else if (trie_state == 9) {
        if (c == 61 /*'='*/) trie_state = 28;
        else trie_state = -1;
      }
      else if (trie_state == 10) {
        if (c == 61 /*'='*/) trie_state = 16;
        else trie_state = -1;
      }
      else if (trie_state == 11) {
        if (c == 61 /*'='*/) trie_state = 29;
        else trie_state = -1;
      }
      else if (trie_state == 14) {
        if (c == 61 /*'='*/) trie_state = 15;
        else if (c == 62 /*'>'*/) trie_state = 113;
        else trie_state = -1;
      }
      else if (trie_state == 17) {
        if (c == 60 /*'<'*/) trie_state = 32;
        else if (c == 61 /*'='*/) trie_state = 18;
        else trie_state = -1;
      }
      else if (trie_state == 19) {
        if (c == 61 /*'='*/) trie_state = 20;
        else if (c == 62 /*'>'*/) trie_state = 30;
        else trie_state = -1;
      }
      else if (trie_state == 30) {
        if (c == 61 /*'='*/) trie_state = 31;
        else trie_state = -1;
      }
      else if (trie_state == 32) {
        if (c == 61 /*'='*/) trie_state = 33;
        else trie_state = -1;
      }
      else if (trie_state == 36) {
        if (c == 58 /*':'*/) trie_state = 38;
        else trie_state = -1;
      }
      else if (trie_state == 39) {
        if (c == 110 /*'n'*/) trie_state = 69;
        else if (c == 111 /*'o'*/) trie_state = 40;
        else trie_state = -1;
      }
      else if (trie_state == 40) {
        if (c == 114 /*'r'*/) trie_state = 41;
        else trie_state = -1;
      }
      else if (trie_state == 42) {
        if (c == 110 /*'n'*/) trie_state = 43;
        else trie_state = -1;
      }
      else if (trie_state == 44) {
        if (c == 104 /*'h'*/) trie_state = 45;
        else trie_state = -1;
      }
      else if (trie_state == 45) {
        if (c == 101 /*'e'*/) trie_state = 57;
        else if (c == 105 /*'i'*/) trie_state = 46;
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
        if (c == 104 /*'h'*/) trie_state = 50;
        else if (c == 114 /*'r'*/) trie_state = 65;
        else trie_state = -1;
      }
      else if (trie_state == 50) {
        if (c == 101 /*'e'*/) trie_state = 51;
        else trie_state = -1;
      }
      else if (trie_state == 51) {
        if (c == 110 /*'n'*/) trie_state = 52;
        else trie_state = -1;
      }
      else if (trie_state == 53) {
        if (c == 108 /*'l'*/) trie_state = 54;
        else trie_state = -1;
      }
      else if (trie_state == 54) {
        if (c == 115 /*'s'*/) trie_state = 55;
        else trie_state = -1;
      }
      else if (trie_state == 55) {
        if (c == 111 /*'o'*/) trie_state = 56;
        else trie_state = -1;
      }
      else if (trie_state == 57) {
        if (c == 114 /*'r'*/) trie_state = 58;
        else trie_state = -1;
      }
      else if (trie_state == 58) {
        if (c == 101 /*'e'*/) trie_state = 59;
        else trie_state = -1;
      }
      else if (trie_state == 60) {
        if (c == 110 /*'n'*/) trie_state = 61;
        else trie_state = -1;
      }
      else if (trie_state == 61) {
        if (c == 105 /*'i'*/) trie_state = 62;
        else trie_state = -1;
      }
      else if (trie_state == 62) {
        if (c == 111 /*'o'*/) trie_state = 63;
        else trie_state = -1;
      }
      else if (trie_state == 63) {
        if (c == 110 /*'n'*/) trie_state = 64;
        else trie_state = -1;
      }
      else if (trie_state == 65) {
        if (c == 97 /*'a'*/) trie_state = 66;
        else trie_state = -1;
      }
      else if (trie_state == 66) {
        if (c == 105 /*'i'*/) trie_state = 67;
        else trie_state = -1;
      }
      else if (trie_state == 67) {
        if (c == 116 /*'t'*/) trie_state = 68;
        else trie_state = -1;
      }
      else if (trie_state == 70) {
        if (c == 110 /*'n'*/) trie_state = 71;
        else trie_state = -1;
      }
      else if (trie_state == 72) {
        if (c == 102 /*'f'*/) trie_state = 77;
        else if (c == 116 /*'t'*/) trie_state = 73;
        else trie_state = -1;
      }
      else if (trie_state == 73) {
        if (c == 121 /*'y'*/) trie_state = 74;
        else trie_state = -1;
      }
      else if (trie_state == 74) {
        if (c == 112 /*'p'*/) trie_state = 75;
        else trie_state = -1;
      }
      else if (trie_state == 75) {
        if (c == 101 /*'e'*/) trie_state = 76;
        else trie_state = -1;
      }
      else if (trie_state == 77) {
        if (c == 110 /*'n'*/) trie_state = 78;
        else trie_state = -1;
      }
      else if (trie_state == 79) {
        if (c == 101 /*'e'*/) trie_state = 80;
        else trie_state = -1;
      }
      else if (trie_state == 80) {
        if (c == 108 /*'l'*/) trie_state = 81;
        else trie_state = -1;
      }
      else if (trie_state == 81) {
        if (c == 102 /*'f'*/) trie_state = 82;
        else trie_state = -1;
      }
      else if (trie_state == 83) {
        if (c == 101 /*'e'*/) trie_state = 84;
        else if (c == 105 /*'i'*/) trie_state = 94;
        else trie_state = -1;
      }
      else if (trie_state == 84) {
        if (c == 108 /*'l'*/) trie_state = 85;
        else trie_state = -1;
      }
      else if (trie_state == 85) {
        if (c == 102 /*'f'*/) trie_state = 86;
        else trie_state = -1;
      }
      else if (trie_state == 87) {
        if (c == 111 /*'o'*/) trie_state = 88;
        else trie_state = -1;
      }
      else if (trie_state == 88) {
        if (c == 105 /*'i'*/) trie_state = 89;
        else trie_state = -1;
      }
      else if (trie_state == 89) {
        if (c == 100 /*'d'*/) trie_state = 90;
        else trie_state = -1;
      }
      else if (trie_state == 90) {
        if (c == 80 /*'P'*/) trie_state = 91;
        else trie_state = -1;
      }
      else if (trie_state == 91) {
        if (c == 116 /*'t'*/) trie_state = 92;
        else trie_state = -1;
      }
      else if (trie_state == 92) {
        if (c == 114 /*'r'*/) trie_state = 93;
        else trie_state = -1;
      }
      else if (trie_state == 94) {
        if (c == 122 /*'z'*/) trie_state = 95;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 101 /*'e'*/) trie_state = 96;
        else trie_state = -1;
      }
      else if (trie_state == 96) {
        if (c == 111 /*'o'*/) trie_state = 97;
        else trie_state = -1;
      }
      else if (trie_state == 97) {
        if (c == 102 /*'f'*/) trie_state = 98;
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
        trie_tokenkind =  DAISHO_TOK_POW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 5) {
        trie_tokenkind =  DAISHO_TOK_DIV;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 6) {
        trie_tokenkind =  DAISHO_TOK_MOD;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 7) {
        trie_tokenkind =  DAISHO_TOK_AND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 8) {
        trie_tokenkind =  DAISHO_TOK_OR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 9) {
        trie_tokenkind =  DAISHO_TOK_XOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 10) {
        trie_tokenkind =  DAISHO_TOK_NOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 11) {
        trie_tokenkind =  DAISHO_TOK_BITNOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 12) {
        trie_tokenkind =  DAISHO_TOK_LOGAND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 13) {
        trie_tokenkind =  DAISHO_TOK_LOGOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 15) {
        trie_tokenkind =  DAISHO_TOK_DEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 16) {
        trie_tokenkind =  DAISHO_TOK_NEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 17) {
        trie_tokenkind =  DAISHO_TOK_LT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 18) {
        trie_tokenkind =  DAISHO_TOK_LEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 19) {
        trie_tokenkind =  DAISHO_TOK_GT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 20) {
        trie_tokenkind =  DAISHO_TOK_GEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 14) {
        trie_tokenkind =  DAISHO_TOK_EQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 21) {
        trie_tokenkind =  DAISHO_TOK_PLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 22) {
        trie_tokenkind =  DAISHO_TOK_MINEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 23) {
        trie_tokenkind =  DAISHO_TOK_MULEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 24) {
        trie_tokenkind =  DAISHO_TOK_DIVEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 25) {
        trie_tokenkind =  DAISHO_TOK_MODEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 26) {
        trie_tokenkind =  DAISHO_TOK_ANDEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 27) {
        trie_tokenkind =  DAISHO_TOK_OREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 28) {
        trie_tokenkind =  DAISHO_TOK_XOREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 29) {
        trie_tokenkind =  DAISHO_TOK_BNEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 31) {
        trie_tokenkind =  DAISHO_TOK_BSREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 33) {
        trie_tokenkind =  DAISHO_TOK_BSLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 34) {
        trie_tokenkind =  DAISHO_TOK_INCR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 35) {
        trie_tokenkind =  DAISHO_TOK_DECR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 36) {
        trie_tokenkind =  DAISHO_TOK_QUEST;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 37) {
        trie_tokenkind =  DAISHO_TOK_COLON;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 38) {
        trie_tokenkind =  DAISHO_TOK_NCOLL;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 41) {
        trie_tokenkind =  DAISHO_TOK_FOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 43) {
        trie_tokenkind =  DAISHO_TOK_IN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 48) {
        trie_tokenkind =  DAISHO_TOK_WHILE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 52) {
        trie_tokenkind =  DAISHO_TOK_THEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 56) {
        trie_tokenkind =  DAISHO_TOK_ALSO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 59) {
        trie_tokenkind =  DAISHO_TOK_WHERE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 64) {
        trie_tokenkind =  DAISHO_TOK_UNION;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 68) {
        trie_tokenkind =  DAISHO_TOK_TRAIT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 69) {
        trie_tokenkind =  DAISHO_TOK_FN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 71) {
        trie_tokenkind =  DAISHO_TOK_FNTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 76) {
        trie_tokenkind =  DAISHO_TOK_CTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 78) {
        trie_tokenkind =  DAISHO_TOK_CFN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 82) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 86) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 90) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 93) {
        trie_tokenkind =  DAISHO_TOK_VOIDPTR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
        trie_tokenkind =  DAISHO_TOK_SIZEOF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 99) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 100) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 101) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 102) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 103) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 104) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 106) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 107) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_DARROW;
        trie_munch_size = iidx + 1;
      }
    }

    // Transition STRUCT State Machine
    if (smaut_state_0 != -1) {
      all_dead = 0;

      if ((smaut_state_0 == 0) &
         (c == 99)) {
          smaut_state_0 = 1;
      }
      else if ((smaut_state_0 == 1) &
         (c == 108)) {
          smaut_state_0 = 2;
      }
      else if ((smaut_state_0 == 2) &
         (c == 97)) {
          smaut_state_0 = 3;
      }
      else if ((smaut_state_0 == 3) &
         (c == 115)) {
          smaut_state_0 = 4;
      }
      else if ((smaut_state_0 == 4) &
         (c == 115)) {
          smaut_state_0 = 5;
      }
      else if ((smaut_state_0 == 0) &
         (c == 115)) {
          smaut_state_0 = 6;
      }
      else if ((smaut_state_0 == 6) &
         (c == 116)) {
          smaut_state_0 = 7;
      }
      else if ((smaut_state_0 == 7) &
         (c == 114)) {
          smaut_state_0 = 8;
      }
      else if ((smaut_state_0 == 8) &
         (c == 117)) {
          smaut_state_0 = 9;
      }
      else if ((smaut_state_0 == 9) &
         (c == 99)) {
          smaut_state_0 = 10;
      }
      else if ((smaut_state_0 == 10) &
         (c == 116)) {
          smaut_state_0 = 11;
      }
      else if ((smaut_state_0 == 0) &
         (c == 116)) {
          smaut_state_0 = 13;
      }
      else if ((smaut_state_0 == 13) &
         (c == 121)) {
          smaut_state_0 = 14;
      }
      else if ((smaut_state_0 == 14) &
         (c == 112)) {
          smaut_state_0 = 15;
      }
      else if ((smaut_state_0 == 15) &
         (c == 101)) {
          smaut_state_0 = 16;
      }
      else {
        smaut_state_0 = -1;
      }

      // Check accept
      if ((smaut_state_0 == 5) | (smaut_state_0 == 11) | (smaut_state_0 == 16)) {
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

    // Transition NAMESPACE State Machine
    if (smaut_state_2 != -1) {
      all_dead = 0;

      if ((smaut_state_2 == 0) &
         (c == 110)) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 97)) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 109)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 101)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 115)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 112)) {
          smaut_state_2 = 6;
      }
      else if ((smaut_state_2 == 6) &
         (c == 97)) {
          smaut_state_2 = 7;
      }
      else if ((smaut_state_2 == 7) &
         (c == 99)) {
          smaut_state_2 = 8;
      }
      else if ((smaut_state_2 == 8) &
         (c == 101)) {
          smaut_state_2 = 9;
      }
      else if ((smaut_state_2 == 0) &
         (c == 109)) {
          smaut_state_2 = 10;
      }
      else if ((smaut_state_2 == 10) &
         (c == 111)) {
          smaut_state_2 = 11;
      }
      else if ((smaut_state_2 == 11) &
         (c == 100)) {
          smaut_state_2 = 12;
      }
      else if ((smaut_state_2 == 12) &
         (c == 117)) {
          smaut_state_2 = 13;
      }
      else if ((smaut_state_2 == 13) &
         (c == 108)) {
          smaut_state_2 = 14;
      }
      else if ((smaut_state_2 == 14) &
         (c == 101)) {
          smaut_state_2 = 15;
      }
      else if ((smaut_state_2 == 0) &
         (c == 112)) {
          smaut_state_2 = 16;
      }
      else if ((smaut_state_2 == 16) &
         (c == 97)) {
          smaut_state_2 = 17;
      }
      else if ((smaut_state_2 == 17) &
         (c == 99)) {
          smaut_state_2 = 18;
      }
      else if ((smaut_state_2 == 18) &
         (c == 107)) {
          smaut_state_2 = 19;
      }
      else if ((smaut_state_2 == 19) &
         (c == 97)) {
          smaut_state_2 = 20;
      }
      else if ((smaut_state_2 == 20) &
         (c == 103)) {
          smaut_state_2 = 21;
      }
      else if ((smaut_state_2 == 21) &
         (c == 101)) {
          smaut_state_2 = 22;
      }
      else {
        smaut_state_2 = -1;
      }

      // Check accept
      if ((smaut_state_2 == 9) | (smaut_state_2 == 15) | (smaut_state_2 == 22)) {
        smaut_munch_size_2 = iidx + 1;
      }
    }

    // Transition RET State Machine
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
         (c == 116)) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 117)) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 114)) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 5) &
         (c == 110)) {
          smaut_state_3 = 6;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 3) | (smaut_state_3 == 6)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition OP State Machine
    if (smaut_state_4 != -1) {
      all_dead = 0;

      if ((smaut_state_4 == 0) &
         (c == 111)) {
          smaut_state_4 = 1;
      }
      else if ((smaut_state_4 == 1) &
         (c == 112)) {
          smaut_state_4 = 2;
      }
      else if ((smaut_state_4 == 2) &
         (c == 101)) {
          smaut_state_4 = 3;
      }
      else if ((smaut_state_4 == 3) &
         (c == 114)) {
          smaut_state_4 = 4;
      }
      else if ((smaut_state_4 == 4) &
         (c == 97)) {
          smaut_state_4 = 5;
      }
      else if ((smaut_state_4 == 5) &
         (c == 116)) {
          smaut_state_4 = 6;
      }
      else if ((smaut_state_4 == 6) &
         (c == 111)) {
          smaut_state_4 = 7;
      }
      else if ((smaut_state_4 == 7) &
         (c == 114)) {
          smaut_state_4 = 8;
      }
      else {
        smaut_state_4 = -1;
      }

      // Check accept
      if ((smaut_state_4 == 2) | (smaut_state_4 == 8)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition REDEF State Machine
    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         (c == 114)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 1) &
         (c == 101)) {
          smaut_state_5 = 2;
      }
      else if ((smaut_state_5 == 2) &
         (c == 100)) {
          smaut_state_5 = 3;
      }
      else if ((smaut_state_5 == 3) &
         (c == 101)) {
          smaut_state_5 = 4;
      }
      else if ((smaut_state_5 == 4) &
         (c == 102)) {
          smaut_state_5 = 5;
      }
      else if ((smaut_state_5 == 5) &
         (c == 105)) {
          smaut_state_5 = 6;
      }
      else if ((smaut_state_5 == 6) &
         (c == 110)) {
          smaut_state_5 = 7;
      }
      else if ((smaut_state_5 == 7) &
         (c == 101)) {
          smaut_state_5 = 8;
      }
      else {
        smaut_state_5 = -1;
      }

      // Check accept
      if ((smaut_state_5 == 5) | (smaut_state_5 == 8)) {
        smaut_munch_size_5 = iidx + 1;
      }
    }

    // Transition TYPEIDENT State Machine
    if (smaut_state_6 != -1) {
      all_dead = 0;

      if ((smaut_state_6 == 0) &
         (((c >= 65) & (c <= 90)))) {
          smaut_state_6 = 1;
      }
      else if (((smaut_state_6 == 1) | (smaut_state_6 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
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

    // Transition VARIDENT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_7 = 2;
      }
      else {
        smaut_state_7 = -1;
      }

      // Check accept
      if ((smaut_state_7 == 1) | (smaut_state_7 == 2)) {
        smaut_munch_size_7 = iidx + 1;
      }
    }

    // Transition CIDENT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_8 = 2;
      }
      else {
        smaut_state_8 = -1;
      }

      // Check accept
      if ((smaut_state_8 == 1) | (smaut_state_8 == 2)) {
        smaut_munch_size_8 = iidx + 1;
      }
    }

    // Transition NUMLIT State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_9 = 1;
      }
      else if (((smaut_state_9 == 0) | (smaut_state_9 == 1) | (smaut_state_9 == 2)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 2) &
         (c == 46)) {
          smaut_state_9 = 3;
      }
      else if ((smaut_state_9 == 3) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_9 = 3;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if ((smaut_state_9 == 2) | (smaut_state_9 == 3)) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         (c == 34)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 1) &
         (c == 34)) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 1) &
         (c == 10)) {
          smaut_state_10 = 9;
      }
      else if ((smaut_state_10 == 1) &
         (c == 92)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 1) &
         (1)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 110)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 102)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 98)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 114)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 116)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 101)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 92)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 39)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 34)) {
          smaut_state_10 = 1;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if (smaut_state_10 == 2) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if (((smaut_state_11 == 0) | (smaut_state_11 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_11 = 1;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if (smaut_state_11 == 1) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 47)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 42)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (c == 42)) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 2) &
         (1)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 42)) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 3) &
         (c == 47)) {
          smaut_state_12 = 4;
      }
      else if ((smaut_state_12 == 3) &
         (1)) {
          smaut_state_12 = 2;
      }
      else {
        smaut_state_12 = -1;
      }

      // Check accept
      if (smaut_state_12 == 4) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == 47)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 47)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 2) &
         (!(c == 10))) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 2) &
         (c == 10)) {
          smaut_state_13 = 3;
      }
      else {
        smaut_state_13 = -1;
      }

      // Check accept
      if ((smaut_state_13 == 2) | (smaut_state_13 == 3)) {
        smaut_munch_size_13 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_14 != -1) {
      all_dead = 0;

      if ((smaut_state_14 == 0) &
         (c == 35)) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 1) &
         (c == 33)) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 2) &
         (!(c == 10))) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 2) &
         (c == 10)) {
          smaut_state_14 = 3;
      }
      else {
        smaut_state_14 = -1;
      }

      // Check accept
      if (smaut_state_14 == 3) {
        smaut_munch_size_14 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_14 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_14;
  }
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_CIDENT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_7;
  }
  if (smaut_munch_size_6 >= max_munch) {
    kind = DAISHO_TOK_TYPEIDENT;
    max_munch = smaut_munch_size_6;
  }
  if (smaut_munch_size_5 >= max_munch) {
    kind = DAISHO_TOK_REDEF;
    max_munch = smaut_munch_size_5;
  }
  if (smaut_munch_size_4 >= max_munch) {
    kind = DAISHO_TOK_OP;
    max_munch = smaut_munch_size_4;
  }
  if (smaut_munch_size_3 >= max_munch) {
    kind = DAISHO_TOK_RET;
    max_munch = smaut_munch_size_3;
  }
  if (smaut_munch_size_2 >= max_munch) {
    kind = DAISHO_TOK_NAMESPACE;
    max_munch = smaut_munch_size_2;
  }
  if (smaut_munch_size_1 >= max_munch) {
    kind = DAISHO_TOK_IMPL;
    max_munch = smaut_munch_size_1;
  }
  if (smaut_munch_size_0 >= max_munch) {
    kind = DAISHO_TOK_STRUCT;
    max_munch = smaut_munch_size_0;
  }
  if (trie_munch_size >= max_munch) {
    kind = trie_tokenkind;
    max_munch = trie_munch_size;
  }

  daisho_token ret;
  ret.kind = kind;
  ret.content = tokenizer->start + tokenizer->pos;
  ret.len = max_munch;

#if DAISHO_SOURCEINFO
  ret.line = tokenizer->pos_line;
  ret.col = tokenizer->pos_col;

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
  DAISHO_NODE_EMPTY,
  DAISHO_NODE_PROGRAM,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_NSLIST,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_NSDECLS,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_STRUCT,
  DAISHO_NODE_TMPLSTRUCT,
  DAISHO_NODE_UNION,
  DAISHO_NODE_TMPLUNION,
  DAISHO_NODE_TRAIT,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_TYPE,
  DAISHO_NODE_TMPLTYPE,
  DAISHO_NODE_TRAITTYPE,
  DAISHO_NODE_STRUCTTYPE,
  DAISHO_NODE_VOIDPTR,
  DAISHO_NODE_QUEST,
  DAISHO_NODE_COLON,
  DAISHO_NODE_FOR,
  DAISHO_NODE_WHILE,
  DAISHO_NODE_CAST,
  DAISHO_NODE_REF,
  DAISHO_NODE_DEREF,
  DAISHO_NODE_BLK,
  DAISHO_NODE_ARGLIST,
  DAISHO_NODE_ARROW,
  DAISHO_NODE_DARROW,
  DAISHO_NODE_LAMBDA,
  DAISHO_NODE_SIZEOF,
  DAISHO_NODE_EQ,
  DAISHO_NODE_PLEQ,
  DAISHO_NODE_MINEQ,
  DAISHO_NODE_MULEQ,
  DAISHO_NODE_DIVEQ,
  DAISHO_NODE_MODEQ,
  DAISHO_NODE_ANDEQ,
  DAISHO_NODE_OREQ,
  DAISHO_NODE_XOREQ,
  DAISHO_NODE_BNEQ,
  DAISHO_NODE_BSREQ,
  DAISHO_NODE_BSLEQ,
  DAISHO_NODE_TERN,
  DAISHO_NODE_IF,
  DAISHO_NODE_THEN,
  DAISHO_NODE_ALSO,
  DAISHO_NODE_LOGOR,
  DAISHO_NODE_LOGAND,
  DAISHO_NODE_OR,
  DAISHO_NODE_XOR,
  DAISHO_NODE_AND,
  DAISHO_NODE_DEQ,
  DAISHO_NODE_NEQ,
  DAISHO_NODE_LT,
  DAISHO_NODE_GT,
  DAISHO_NODE_LEQ,
  DAISHO_NODE_GEQ,
  DAISHO_NODE_BSL,
  DAISHO_NODE_BSR,
  DAISHO_NODE_STAR,
  DAISHO_NODE_MUL,
  DAISHO_NODE_DIV,
  DAISHO_NODE_MOD,
  DAISHO_NODE_POW,
  DAISHO_NODE_SUM,
  DAISHO_NODE_PLUS,
  DAISHO_NODE_MINUS,
  DAISHO_NODE_RET,
  DAISHO_NODE_GRAVE,
  DAISHO_NODE_SELF,
  DAISHO_NODE_SELFTYPE,
  DAISHO_NODE_VOIDTYPE,
  DAISHO_NODE_FNTYPE,
  DAISHO_NODE_OPEN,
  DAISHO_NODE_CLOSE,
  DAISHO_NODE_NUMLIT,
  DAISHO_NODE_STRLIT,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_TYPEIDENT,
  DAISHO_NODE_DTRAITIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 82
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_PROGRAM",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_NSLIST",
  "DAISHO_NODE_NAMESPACE",
  "DAISHO_NODE_NSDECLS",
  "DAISHO_NODE_MEMBERLIST",
  "DAISHO_NODE_STRUCT",
  "DAISHO_NODE_TMPLSTRUCT",
  "DAISHO_NODE_UNION",
  "DAISHO_NODE_TMPLUNION",
  "DAISHO_NODE_TRAIT",
  "DAISHO_NODE_TMPLTRAIT",
  "DAISHO_NODE_TYPE",
  "DAISHO_NODE_TMPLTYPE",
  "DAISHO_NODE_TRAITTYPE",
  "DAISHO_NODE_STRUCTTYPE",
  "DAISHO_NODE_VOIDPTR",
  "DAISHO_NODE_QUEST",
  "DAISHO_NODE_COLON",
  "DAISHO_NODE_FOR",
  "DAISHO_NODE_WHILE",
  "DAISHO_NODE_CAST",
  "DAISHO_NODE_REF",
  "DAISHO_NODE_DEREF",
  "DAISHO_NODE_BLK",
  "DAISHO_NODE_ARGLIST",
  "DAISHO_NODE_ARROW",
  "DAISHO_NODE_DARROW",
  "DAISHO_NODE_LAMBDA",
  "DAISHO_NODE_SIZEOF",
  "DAISHO_NODE_EQ",
  "DAISHO_NODE_PLEQ",
  "DAISHO_NODE_MINEQ",
  "DAISHO_NODE_MULEQ",
  "DAISHO_NODE_DIVEQ",
  "DAISHO_NODE_MODEQ",
  "DAISHO_NODE_ANDEQ",
  "DAISHO_NODE_OREQ",
  "DAISHO_NODE_XOREQ",
  "DAISHO_NODE_BNEQ",
  "DAISHO_NODE_BSREQ",
  "DAISHO_NODE_BSLEQ",
  "DAISHO_NODE_TERN",
  "DAISHO_NODE_IF",
  "DAISHO_NODE_THEN",
  "DAISHO_NODE_ALSO",
  "DAISHO_NODE_LOGOR",
  "DAISHO_NODE_LOGAND",
  "DAISHO_NODE_OR",
  "DAISHO_NODE_XOR",
  "DAISHO_NODE_AND",
  "DAISHO_NODE_DEQ",
  "DAISHO_NODE_NEQ",
  "DAISHO_NODE_LT",
  "DAISHO_NODE_GT",
  "DAISHO_NODE_LEQ",
  "DAISHO_NODE_GEQ",
  "DAISHO_NODE_BSL",
  "DAISHO_NODE_BSR",
  "DAISHO_NODE_STAR",
  "DAISHO_NODE_MUL",
  "DAISHO_NODE_DIV",
  "DAISHO_NODE_MOD",
  "DAISHO_NODE_POW",
  "DAISHO_NODE_SUM",
  "DAISHO_NODE_PLUS",
  "DAISHO_NODE_MINUS",
  "DAISHO_NODE_RET",
  "DAISHO_NODE_GRAVE",
  "DAISHO_NODE_SELF",
  "DAISHO_NODE_SELFTYPE",
  "DAISHO_NODE_VOIDTYPE",
  "DAISHO_NODE_FNTYPE",
  "DAISHO_NODE_OPEN",
  "DAISHO_NODE_CLOSE",
  "DAISHO_NODE_NUMLIT",
  "DAISHO_NODE_STRLIT",
  "DAISHO_NODE_TYPEMEMBER",
  "DAISHO_NODE_TYPEIDENT",
  "DAISHO_NODE_DTRAITIDENT",
  "DAISHO_NODE_VARIDENT",
};

struct daisho_astnode_t {
  daisho_astnode_t* parent;
  uint16_t num_children;
  uint16_t max_children;
  daisho_astnode_kind kind;

  // Store node number or tok repr.
  // if (tok_repr) then it's a codepoint string of size len_or_toknum.
  // if (!tok_repr && len_or_toknum) then len_or_toknum is a token offset.
  // if (!tok_repr && !len_or_toknum) then nothing is stored.
#if DAISHO_SOURCEINFO
  codepoint_t* tok_repr;
  size_t len_or_toknum;
#endif
  // Extra data in %extra directives:
  void* extra;
  void* symtab;
  ExprType* type; // The concrete type
  // End of extra data.
  daisho_astnode_t** children;
};

#if DAISHO_SOURCEINFO
#define PGEN_MIN1(a) a
#define PGEN_MIN2(a, b) PGEN_MIN(a, PGEN_MIN1(b))
#define PGEN_MIN3(a, b, c) PGEN_MIN(a, PGEN_MIN2(b, c))
#define PGEN_MIN4(a, b, c, d) PGEN_MIN(a, PGEN_MIN3(b, c, d))
#define PGEN_MIN5(a, b, c, d, e) PGEN_MIN(a, PGEN_MIN4(b, c, d, e))
#define PGEN_MAX1(a) a
#define PGEN_MAX2(a, b) PGEN_MAX(a, PGEN_MAX1(b))
#define PGEN_MAX3(a, b, c) PGEN_MAX(a, PGEN_MAX2(b, c))
#define PGEN_MAX4(a, b, c, d) PGEN_MAX(a, PGEN_MAX3(b, c, d))
#define PGEN_MAX5(a, b, c, d, e) PGEN_MAX(a, PGEN_MAX4(b, c, d, e))
#define PGEN_MAX(a, b) ((a) > (b) ? (a) : (b))
#define PGEN_MIN(a, b) ((a) ? ((a) > (b) ? (b) : (a)) : (b))
#endif

static inline daisho_astnode_t* daisho_astnode_list(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             size_t initial_size) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t),
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t*)ret;

  daisho_astnode_t **children;
  if (initial_size) {
    children = (daisho_astnode_t**)malloc(sizeof(daisho_astnode_t*) * initial_size);
    if (!children) PGEN_OOM();
    pgen_defer(alloc, free, children, alloc->rew);
  } else {
    children = NULL;
  }

  node->kind = kind;
  node->parent = NULL;
  node->max_children = initial_size;
  node->num_children = 0;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  // Extra initialization from %extrainit directives:
  node->extra = NULL;
  node->symtab = NULL;
  node->type = NULL;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_leaf(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t),
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t *children = NULL;
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 0;
  node->children = NULL;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  // Extra initialization from %extrainit directives:
  node->extra = NULL;
  node->symtab = NULL;
  node->type = NULL;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_1(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 1,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 1;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  children[0] = n0;
  n0->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_2(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 2,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 2;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  children[0] = n0;
  n0->parent = node;
  children[1] = n1;
  n1->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_3(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 3,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 3;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  children[0] = n0;
  n0->parent = node;
  children[1] = n1;
  n1->parent = node;
  children[2] = n2;
  n2->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_4(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 4,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 4;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  children[0] = n0;
  n0->parent = node;
  children[1] = n1;
  n1->parent = node;
  children[2] = n2;
  n2->parent = node;
  children[3] = n3;
  n3->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_5(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 5,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 5;
  node->children = children;
#if DAISHO_SOURCEINFO
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
#endif
  children[0] = n0;
  n0->parent = node;
  children[1] = n1;
  n1->parent = node;
  children[2] = n2;
  n2->parent = node;
  children[3] = n3;
  n3->parent = node;
  children[4] = n4;
  n4->parent = node;
  return node;
}

static inline void daisho_astnode_add(pgen_allocator* alloc, daisho_astnode_t *list, daisho_astnode_t *node) {
  if (list->max_children == list->num_children) {
    // Figure out the new size. Check for overflow where applicable.
    uint64_t new_max = (uint64_t)list->max_children * 2;
    if (new_max > UINT16_MAX || new_max > SIZE_MAX) PGEN_OOM();
    if (SIZE_MAX < UINT16_MAX && (size_t)new_max > SIZE_MAX / sizeof(daisho_astnode_t)) PGEN_OOM();
    size_t new_bytes = (size_t)new_max * sizeof(daisho_astnode_t);

    // Reallocate the list, and inform the allocator.
    void* old_ptr = list->children;
    void* new_ptr = realloc(list->children, new_bytes);
    if (!new_ptr) PGEN_OOM();
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

static inline daisho_astnode_t* daisho_astnode_repr(daisho_astnode_t* node, daisho_astnode_t* t) {
#if DAISHO_SOURCEINFO
  node->tok_repr = t->tok_repr;
  node->len_or_toknum = t->len_or_toknum;
#endif
  return node;
}

static inline daisho_astnode_t* daisho_astnode_srepr(pgen_allocator* allocator, daisho_astnode_t* node, char* s) {
#if DAISHO_SOURCEINFO
  size_t cpslen = strlen(s);
  codepoint_t* cps = (codepoint_t*)pgen_alloc(allocator, (cpslen + 1) * sizeof(codepoint_t), _Alignof(codepoint_t));
  for (size_t i = 0; i < cpslen; i++) cps[i] = (codepoint_t)s[i];
  cps[cpslen] = 0;
  node->tok_repr = cps;
  node->len_or_toknum = cpslen;
#endif
  return node;
}

#define rec(label)               pgen_parser_rewind_t _rew_##label = (pgen_parser_rewind_t){ctx->alloc->rew, ctx->pos};
#define rew(label)               daisho_parser_rewind(ctx, _rew_##label)
#define node(kindname, ...)          PGEN_CAT(daisho_astnode_fixed_, PGEN_NARG(__VA_ARGS__))(ctx->alloc, kind(kindname), __VA_ARGS__)
#define kind(name)               DAISHO_NODE_##name
#define list(kind)               daisho_astnode_list(ctx->alloc, DAISHO_NODE_##kind, 16)
#define leaf(kind)               daisho_astnode_leaf(ctx->alloc, DAISHO_NODE_##kind)
#define add(list, node)          daisho_astnode_add(ctx->alloc, list, node)
#define has(node)                (((uintptr_t)node <= (uintptr_t)SUCC) ? 0 : 1)
#define repr(node, t)            daisho_astnode_repr(node, t)
#define srepr(node, s)           daisho_astnode_srepr(ctx->alloc, node, (char*)s)
#define SUCC                     ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t))

static inline int daisho_node_print_content(daisho_astnode_t* node, daisho_token* tokens) {
#if DAISHO_SOURCEINFO
  int found = 0;
  codepoint_t* utf32 = NULL; size_t utf32len = 0;
  char* utf8 = NULL; size_t utf8len = 0;
  if (node->tok_repr) {
    utf32 = node->tok_repr;
    utf32len = node->len_or_toknum;
  } else {
    if (node->len_or_toknum) {
      utf32 = tokens[node->len_or_toknum].content;
      utf32len = tokens[node->len_or_toknum].len;
    }
  }
  if (utf32len) {
    int success = UTF8_encode(node->tok_repr, node->len_or_toknum, &utf8, &utf8len);
    if (success) return fwrite(utf8, utf8len, 1, stdout), free(utf8), 1;
  }
#endif
  return 0;
}

static inline int daisho_astnode_print_h(daisho_token* tokens, daisho_astnode_t *node, size_t depth, int fl) {
  #define indent() for (size_t i = 0; i < depth; i++) printf("  ")
  if (!node)
    return 0;
  else if (node == SUCC)
    puts("ERROR, CAPTURED SUCC."), exit(1);

  indent(); puts("{");
  depth++;
  indent(); printf("\"kind\": "); printf("\"%s\",\n", daisho_nodekind_name[node->kind] + 12);
  #if DAISHO_SOURCEINFO
  indent(); printf("\"content\": \"");
  daisho_node_print_content(node, tokens); printf("\",\n");
  #endif
  size_t cnum = node->num_children;
  if (cnum) {
    // indent(); printf("\"num_children\": %zu,\n", cnum);
    indent(); printf("\"children\": [");
    putchar('\n');
    for (size_t i = 0; i < cnum; i++)
      daisho_astnode_print_h(tokens, node->children[i], depth + 1, i == cnum - 1);
    indent();
    printf("]\n");
  }
  depth--;
  indent(); putchar('}'); if (fl != 1) putchar(','); putchar('\n');
  return 0;
#undef indent
}

static inline void daisho_astnode_print_json(daisho_token* tokens, daisho_astnode_t *node) {
  daisho_astnode_print_h(tokens, node, 0, 1);
}

/******************/
/* Mid Directives */
/******************/
#include <daisho/Daisho.h>
#include "../asthelpers.h"

static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_namespace(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplspec(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* nses = NULL;
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_0
  daisho_astnode_t* expr_ret_1 = NULL;
  daisho_astnode_t* expr_ret_0 = NULL;
  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_3 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
      // Capturing SHEBANG.
      expr_ret_3 = leaf(SHEBANG);
      #if DAISHO_SOURCEINFO
      expr_ret_3->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_3->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_3 = NULL;
    }

    // optional
    if (!expr_ret_3)
      expr_ret_3 = SUCC;
    expr_ret_2 = expr_ret_3;
    sh = expr_ret_3;
  }

  // ModExprList 1
  if (expr_ret_2)
  {
    daisho_astnode_t* expr_ret_4 = NULL;
    // CodeExpr
    #define ret expr_ret_4
    ret = SUCC;

    list(NSLIST);

    #undef ret
    expr_ret_2 = expr_ret_4;
    nses = expr_ret_4;
  }

  // ModExprList 2
  if (expr_ret_2)
  {
    daisho_astnode_t* expr_ret_5 = NULL;
    daisho_astnode_t* expr_ret_6 = SUCC;
    while (expr_ret_6)
    {
      rec(kleene_rew_5);
      daisho_astnode_t* expr_ret_7 = NULL;
      rec(mod_7);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_8 = NULL;
        expr_ret_8 = daisho_parse_namespace(ctx);
        expr_ret_7 = expr_ret_8;
        f = expr_ret_8;
      }

      // ModExprList 1
      if (expr_ret_7)
      {
        // CodeExpr
        #define ret expr_ret_7
        ret = SUCC;

        add(nses, f);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_7) rew(mod_7);
      expr_ret_6 = expr_ret_7;
    }

    expr_ret_5 = SUCC;
    expr_ret_2 = expr_ret_5;
  }

  // ModExprList 3
  if (expr_ret_2)
  {
    // CodeExpr
    #define ret expr_ret_2
    ret = SUCC;

    rule=node(PROGRAM, sh, nses);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2;
  if (!rule) rule = expr_ret_1;
  if (!expr_ret_1) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_namespace(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_9
  daisho_astnode_t* expr_ret_10 = NULL;
  daisho_astnode_t* expr_ret_9 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  rec(mod_11);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_12 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Capturing NAMESPACE.
      expr_ret_12 = leaf(NAMESPACE);
      #if DAISHO_SOURCEINFO
      expr_ret_12->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_12->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_12 = NULL;
    }

    expr_ret_11 = expr_ret_12;
    ns = expr_ret_12;
  }

  // ModExprList 1
  if (expr_ret_11)
  {
    daisho_astnode_t* expr_ret_13 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_13 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_13->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_13->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_13 = NULL;
    }

    expr_ret_11 = expr_ret_13;
    name = expr_ret_13;
  }

  // ModExprList 2
  if (expr_ret_11)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_11 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_11 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_11)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    // CodeExpr
    #define ret expr_ret_14
    ret = SUCC;

    list(NSDECLS);

    #undef ret
    expr_ret_11 = expr_ret_14;
    l = expr_ret_14;
  }

  // ModExprList 4
  if (expr_ret_11)
  {
    daisho_astnode_t* expr_ret_15 = NULL;
    expr_ret_15 = daisho_parse_topdecl(ctx);
    expr_ret_11 = expr_ret_15;
    t = expr_ret_15;
  }

  // ModExprList 5
  if (expr_ret_11)
  {
    // CodeExpr
    #define ret expr_ret_11
    ret = SUCC;

    add(l, t);

    #undef ret
  }

  // ModExprList 6
  if (expr_ret_11)
  {
    daisho_astnode_t* expr_ret_16 = NULL;
    daisho_astnode_t* expr_ret_17 = SUCC;
    while (expr_ret_17)
    {
      rec(kleene_rew_16);
      daisho_astnode_t* expr_ret_18 = NULL;
      rec(mod_18);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
          // Not capturing SEMI.
          expr_ret_18 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_18 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_18)
      {
        daisho_astnode_t* expr_ret_19 = NULL;
        expr_ret_19 = daisho_parse_topdecl(ctx);
        expr_ret_18 = expr_ret_19;
        t = expr_ret_19;
      }

      // ModExprList 2
      if (expr_ret_18)
      {
        // CodeExpr
        #define ret expr_ret_18
        ret = SUCC;

        add(l, t);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_18) rew(mod_18);
      expr_ret_17 = expr_ret_18;
    }

    expr_ret_16 = SUCC;
    expr_ret_11 = expr_ret_16;
  }

  // ModExprList 7
  if (expr_ret_11)
  {
    // CodeExpr
    #define ret expr_ret_11
    ret = SUCC;

    rule=node(NAMESPACE, name, l);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_11) rew(mod_11);
  expr_ret_10 = expr_ret_11;
  if (!rule) rule = expr_ret_10;
  if (!expr_ret_10) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_20
  daisho_astnode_t* expr_ret_21 = NULL;
  daisho_astnode_t* expr_ret_20 = NULL;
  daisho_astnode_t* expr_ret_22 = NULL;

  // SlashExpr 0
  if (!expr_ret_22)
  {
    daisho_astnode_t* expr_ret_23 = NULL;
    rec(mod_23);
    // ModExprList Forwarding
    expr_ret_23 = daisho_parse_fndecl(ctx);
    // ModExprList end
    if (!expr_ret_23) rew(mod_23);
    expr_ret_22 = expr_ret_23;
  }

  // SlashExpr 1
  if (!expr_ret_22)
  {
    daisho_astnode_t* expr_ret_24 = NULL;
    rec(mod_24);
    // ModExprList Forwarding
    expr_ret_24 = daisho_parse_structdecl(ctx);
    // ModExprList end
    if (!expr_ret_24) rew(mod_24);
    expr_ret_22 = expr_ret_24;
  }

  // SlashExpr 2
  if (!expr_ret_22)
  {
    daisho_astnode_t* expr_ret_25 = NULL;
    rec(mod_25);
    // ModExprList Forwarding
    expr_ret_25 = daisho_parse_uniondecl(ctx);
    // ModExprList end
    if (!expr_ret_25) rew(mod_25);
    expr_ret_22 = expr_ret_25;
  }

  // SlashExpr 3
  if (!expr_ret_22)
  {
    daisho_astnode_t* expr_ret_26 = NULL;
    rec(mod_26);
    // ModExprList Forwarding
    expr_ret_26 = daisho_parse_traitdecl(ctx);
    // ModExprList end
    if (!expr_ret_26) rew(mod_26);
    expr_ret_22 = expr_ret_26;
  }

  // SlashExpr 4
  if (!expr_ret_22)
  {
    daisho_astnode_t* expr_ret_27 = NULL;
    rec(mod_27);
    // ModExprList Forwarding
    expr_ret_27 = daisho_parse_impldecl(ctx);
    // ModExprList end
    if (!expr_ret_27) rew(mod_27);
    expr_ret_22 = expr_ret_27;
  }

  // SlashExpr end
  expr_ret_21 = expr_ret_22;

  if (!rule) rule = expr_ret_21;
  if (!expr_ret_21) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_28
  daisho_astnode_t* expr_ret_29 = NULL;
  daisho_astnode_t* expr_ret_28 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;
  rec(mod_30);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      // Not capturing STRUCT.
      expr_ret_30 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_30 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_31 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_31 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_31->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_31->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

    expr_ret_30 = expr_ret_31;
    id = expr_ret_31;
  }

  // ModExprList 2
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_32 = NULL;
    expr_ret_32 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_32)
      expr_ret_32 = SUCC;
    expr_ret_30 = expr_ret_32;
    tmpl = expr_ret_32;
  }

  // ModExprList 3
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_33 = NULL;
    daisho_astnode_t* expr_ret_34 = NULL;
    rec(mod_34);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_34 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_34 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_34)
    {
      expr_ret_34 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_34)
    {
      daisho_astnode_t* expr_ret_35 = NULL;
      daisho_astnode_t* expr_ret_36 = SUCC;
      while (expr_ret_36)
      {
        rec(kleene_rew_35);
        daisho_astnode_t* expr_ret_37 = NULL;
        rec(mod_37);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_37 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_37 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_37)
        {
          expr_ret_37 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_37) rew(mod_37);
        expr_ret_36 = expr_ret_37;
      }

      expr_ret_35 = SUCC;
      expr_ret_34 = expr_ret_35;
    }

    // ModExprList end
    if (!expr_ret_34) rew(mod_34);
    expr_ret_33 = expr_ret_34;
    // optional
    if (!expr_ret_33)
      expr_ret_33 = SUCC;
    expr_ret_30 = expr_ret_33;
    impl = expr_ret_33;
  }

  // ModExprList 4
  if (expr_ret_30)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_30 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_30 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_38 = NULL;
    // CodeExpr
    #define ret expr_ret_38
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_30 = expr_ret_38;
    members = expr_ret_38;
  }

  // ModExprList 6
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_39 = NULL;
    daisho_astnode_t* expr_ret_40 = SUCC;
    while (expr_ret_40)
    {
      rec(kleene_rew_39);
      daisho_astnode_t* expr_ret_41 = NULL;
      rec(mod_41);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_42 = NULL;
        expr_ret_42 = daisho_parse_typemember(ctx);
        expr_ret_41 = expr_ret_42;
        m = expr_ret_42;
      }

      // ModExprList 1
      if (expr_ret_41)
      {
        // CodeExpr
        #define ret expr_ret_41
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_41) rew(mod_41);
      expr_ret_40 = expr_ret_41;
    }

    expr_ret_39 = SUCC;
    expr_ret_30 = expr_ret_39;
  }

  // ModExprList 7
  if (expr_ret_30)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_30 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_30 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_30)
  {
    daisho_astnode_t* expr_ret_43 = NULL;
    // CodeExpr
    #define ret expr_ret_43
    ret = SUCC;

    n = node(STRUCT, id, members);
              rule = has(tmpl) ? node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_30 = expr_ret_43;
    n = expr_ret_43;
  }

  // ModExprList end
  if (!expr_ret_30) rew(mod_30);
  expr_ret_29 = expr_ret_30;
  if (!rule) rule = expr_ret_29;
  if (!expr_ret_29) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_44
  daisho_astnode_t* expr_ret_45 = NULL;
  daisho_astnode_t* expr_ret_44 = NULL;
  daisho_astnode_t* expr_ret_46 = NULL;
  rec(mod_46);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      // Not capturing UNION.
      expr_ret_46 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_46 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_47 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_47 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_47->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_47->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_47 = NULL;
    }

    expr_ret_46 = expr_ret_47;
    id = expr_ret_47;
  }

  // ModExprList 2
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_48 = NULL;
    expr_ret_48 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_48)
      expr_ret_48 = SUCC;
    expr_ret_46 = expr_ret_48;
    tmpl = expr_ret_48;
  }

  // ModExprList 3
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_49 = NULL;
    daisho_astnode_t* expr_ret_50 = NULL;
    rec(mod_50);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_50 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_50 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_50)
    {
      expr_ret_50 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_50)
    {
      daisho_astnode_t* expr_ret_51 = NULL;
      daisho_astnode_t* expr_ret_52 = SUCC;
      while (expr_ret_52)
      {
        rec(kleene_rew_51);
        daisho_astnode_t* expr_ret_53 = NULL;
        rec(mod_53);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_53 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_53 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_53)
        {
          expr_ret_53 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_53) rew(mod_53);
        expr_ret_52 = expr_ret_53;
      }

      expr_ret_51 = SUCC;
      expr_ret_50 = expr_ret_51;
    }

    // ModExprList end
    if (!expr_ret_50) rew(mod_50);
    expr_ret_49 = expr_ret_50;
    // optional
    if (!expr_ret_49)
      expr_ret_49 = SUCC;
    expr_ret_46 = expr_ret_49;
    impl = expr_ret_49;
  }

  // ModExprList 4
  if (expr_ret_46)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_46 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_46 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_54 = NULL;
    // CodeExpr
    #define ret expr_ret_54
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_46 = expr_ret_54;
    members = expr_ret_54;
  }

  // ModExprList 6
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_55 = NULL;
    daisho_astnode_t* expr_ret_56 = SUCC;
    while (expr_ret_56)
    {
      rec(kleene_rew_55);
      daisho_astnode_t* expr_ret_57 = NULL;
      rec(mod_57);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_58 = NULL;
        expr_ret_58 = daisho_parse_typemember(ctx);
        expr_ret_57 = expr_ret_58;
        m = expr_ret_58;
      }

      // ModExprList 1
      if (expr_ret_57)
      {
        // CodeExpr
        #define ret expr_ret_57
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_57) rew(mod_57);
      expr_ret_56 = expr_ret_57;
    }

    expr_ret_55 = SUCC;
    expr_ret_46 = expr_ret_55;
  }

  // ModExprList 7
  if (expr_ret_46)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_46 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_46 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_46)
  {
    daisho_astnode_t* expr_ret_59 = NULL;
    // CodeExpr
    #define ret expr_ret_59
    ret = SUCC;

    n = node(UNION, id, members);
              rule = has(tmpl) ? node(TMPLUNION, tmpl, n) : n;

    #undef ret
    expr_ret_46 = expr_ret_59;
    n = expr_ret_59;
  }

  // ModExprList end
  if (!expr_ret_46) rew(mod_46);
  expr_ret_45 = expr_ret_46;
  if (!rule) rule = expr_ret_45;
  if (!expr_ret_45) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_60
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_60 = NULL;
  daisho_astnode_t* expr_ret_62 = NULL;
  rec(mod_62);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      // Not capturing TRAIT.
      expr_ret_62 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_62 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_63 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_63 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_63->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_63->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

    expr_ret_62 = expr_ret_63;
    id = expr_ret_63;
  }

  // ModExprList 2
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_64 = NULL;
    expr_ret_64 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_64)
      expr_ret_64 = SUCC;
    expr_ret_62 = expr_ret_64;
    tmpl = expr_ret_64;
  }

  // ModExprList 3
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_65 = NULL;
    daisho_astnode_t* expr_ret_66 = NULL;
    rec(mod_66);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_66 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_66 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_66)
    {
      expr_ret_66 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_66)
    {
      daisho_astnode_t* expr_ret_67 = NULL;
      daisho_astnode_t* expr_ret_68 = SUCC;
      while (expr_ret_68)
      {
        rec(kleene_rew_67);
        daisho_astnode_t* expr_ret_69 = NULL;
        rec(mod_69);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_69 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_69 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_69)
        {
          expr_ret_69 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_69) rew(mod_69);
        expr_ret_68 = expr_ret_69;
      }

      expr_ret_67 = SUCC;
      expr_ret_66 = expr_ret_67;
    }

    // ModExprList end
    if (!expr_ret_66) rew(mod_66);
    expr_ret_65 = expr_ret_66;
    // optional
    if (!expr_ret_65)
      expr_ret_65 = SUCC;
    expr_ret_62 = expr_ret_65;
    impl = expr_ret_65;
  }

  // ModExprList 4
  if (expr_ret_62)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_62 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_62 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_70 = NULL;
    // CodeExpr
    #define ret expr_ret_70
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_62 = expr_ret_70;
    members = expr_ret_70;
  }

  // ModExprList 6
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_71 = NULL;
    daisho_astnode_t* expr_ret_72 = SUCC;
    while (expr_ret_72)
    {
      rec(kleene_rew_71);
      daisho_astnode_t* expr_ret_73 = NULL;
      rec(mod_73);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_74 = NULL;
        expr_ret_74 = daisho_parse_fnmember(ctx);
        expr_ret_73 = expr_ret_74;
        m = expr_ret_74;
      }

      // ModExprList 1
      if (expr_ret_73)
      {
        // CodeExpr
        #define ret expr_ret_73
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_73) rew(mod_73);
      expr_ret_72 = expr_ret_73;
    }

    expr_ret_71 = SUCC;
    expr_ret_62 = expr_ret_71;
  }

  // ModExprList 7
  if (expr_ret_62)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_62 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_62 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_75 = NULL;
    // CodeExpr
    #define ret expr_ret_75
    ret = SUCC;

    n = node(TRAIT, id, members);
              rule = has(tmpl) ? node(TMPLTRAIT, tmpl, n) : n;

    #undef ret
    expr_ret_62 = expr_ret_75;
    n = expr_ret_75;
  }

  // ModExprList end
  if (!expr_ret_62) rew(mod_62);
  expr_ret_61 = expr_ret_62;
  if (!rule) rule = expr_ret_61;
  if (!expr_ret_61) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_76
  daisho_astnode_t* expr_ret_77 = NULL;
  daisho_astnode_t* expr_ret_76 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  rec(mod_78);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Not capturing FN.
      expr_ret_78 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_78 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_78)
  {
    expr_ret_78 = daisho_parse_fnproto(ctx);
  }

  // ModExprList 2
  if (expr_ret_78)
  {
    daisho_astnode_t* expr_ret_79 = NULL;
    expr_ret_79 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_79)
      expr_ret_79 = SUCC;
    expr_ret_78 = expr_ret_79;
  }

  // ModExprList 3
  if (expr_ret_78)
  {
    expr_ret_78 = daisho_parse_expr(ctx);
  }

  // ModExprList end
  if (!expr_ret_78) rew(mod_78);
  expr_ret_77 = expr_ret_78;
  if (!rule) rule = expr_ret_77;
  if (!expr_ret_77) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_80
  daisho_astnode_t* expr_ret_81 = NULL;
  daisho_astnode_t* expr_ret_80 = NULL;
  daisho_astnode_t* expr_ret_82 = NULL;
  rec(mod_82);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_82 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_83 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_83 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_83->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_83->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_83 = NULL;
    }

    expr_ret_82 = expr_ret_83;
    tt = expr_ret_83;
  }

  // ModExprList 2
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_84 = NULL;
    expr_ret_84 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_84)
      expr_ret_84 = SUCC;
    expr_ret_82 = expr_ret_84;
  }

  // ModExprList 3
  if (expr_ret_82)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_82 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_85 = NULL;
    expr_ret_85 = daisho_parse_type(ctx);
    expr_ret_82 = expr_ret_85;
    ft = expr_ret_85;
  }

  // ModExprList 5
  if (expr_ret_82)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_82 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_86 = NULL;
    // CodeExpr
    #define ret expr_ret_86
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_82 = expr_ret_86;
    members = expr_ret_86;
  }

  // ModExprList 7
  if (expr_ret_82)
  {
    daisho_astnode_t* expr_ret_87 = NULL;
    daisho_astnode_t* expr_ret_88 = SUCC;
    while (expr_ret_88)
    {
      rec(kleene_rew_87);
      daisho_astnode_t* expr_ret_89 = NULL;
      rec(mod_89);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_90 = NULL;
        expr_ret_90 = daisho_parse_fnmember(ctx);
        expr_ret_89 = expr_ret_90;
        m = expr_ret_90;
      }

      // ModExprList 1
      if (expr_ret_89)
      {
        // CodeExpr
        #define ret expr_ret_89
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_89) rew(mod_89);
      expr_ret_88 = expr_ret_89;
    }

    expr_ret_87 = SUCC;
    expr_ret_82 = expr_ret_87;
  }

  // ModExprList 8
  if (expr_ret_82)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_82 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_82) rew(mod_82);
  expr_ret_81 = expr_ret_82;
  if (!rule) rule = expr_ret_81;
  if (!expr_ret_81) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_91
  daisho_astnode_t* expr_ret_92 = NULL;
  daisho_astnode_t* expr_ret_91 = NULL;
  daisho_astnode_t* expr_ret_93 = NULL;
  rec(mod_93);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_94 = NULL;
    expr_ret_94 = daisho_parse_type(ctx);
    expr_ret_93 = expr_ret_94;
    t = expr_ret_94;
  }

  // ModExprList 1
  if (expr_ret_93)
  {
    daisho_astnode_t* expr_ret_95 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_95 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_95->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_95->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

    expr_ret_93 = expr_ret_95;
    v = expr_ret_95;
  }

  // ModExprList 2
  if (expr_ret_93)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_93 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_93 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_93)
  {
    // CodeExpr
    #define ret expr_ret_93
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_93) rew(mod_93);
  expr_ret_92 = expr_ret_93;
  if (!rule) rule = expr_ret_92;
  if (!expr_ret_92) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_96
  daisho_astnode_t* expr_ret_97 = NULL;
  daisho_astnode_t* expr_ret_96 = NULL;
  daisho_astnode_t* expr_ret_98 = NULL;
  rec(mod_98);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_99 = NULL;
    daisho_astnode_t* expr_ret_100 = NULL;

    // SlashExpr 0
    if (!expr_ret_100)
    {
      daisho_astnode_t* expr_ret_101 = NULL;
      rec(mod_101);
      // ModExprList Forwarding
      expr_ret_101 = daisho_parse_fndecl(ctx);
      // ModExprList end
      if (!expr_ret_101) rew(mod_101);
      expr_ret_100 = expr_ret_101;
    }

    // SlashExpr 1
    if (!expr_ret_100)
    {
      daisho_astnode_t* expr_ret_102 = NULL;
      rec(mod_102);
      // ModExprList Forwarding
      expr_ret_102 = daisho_parse_fnproto(ctx);
      // ModExprList end
      if (!expr_ret_102) rew(mod_102);
      expr_ret_100 = expr_ret_102;
    }

    // SlashExpr end
    expr_ret_99 = expr_ret_100;

    expr_ret_98 = expr_ret_99;
    r = expr_ret_99;
  }

  // ModExprList 1
  if (expr_ret_98)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_98 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_98 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_98)
  {
    // CodeExpr
    #define ret expr_ret_98
    ret = SUCC;

    rule=r;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_98) rew(mod_98);
  expr_ret_97 = expr_ret_98;
  if (!rule) rule = expr_ret_97;
  if (!expr_ret_97) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  uint8_t depth = 0;

  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_103
  daisho_astnode_t* expr_ret_104 = NULL;
  daisho_astnode_t* expr_ret_103 = NULL;
  daisho_astnode_t* expr_ret_105 = NULL;

  // SlashExpr 0
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_106 = NULL;
    rec(mod_106);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_107 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_107 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_107->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_107->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_107 = NULL;
      }

      expr_ret_106 = expr_ret_107;
      v = expr_ret_107;
    }

    // ModExprList 1
    if (expr_ret_106)
    {
      rec(mexpr_state_108)
      daisho_astnode_t* expr_ret_108 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_108 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_108 = NULL;
      }

      // invert
      expr_ret_108 = expr_ret_108 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_108);
      expr_ret_106 = expr_ret_108;
    }

    // ModExprList 2
    if (expr_ret_106)
    {
      // CodeExpr
      #define ret expr_ret_106
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_106) rew(mod_106);
    expr_ret_105 = expr_ret_106;
  }

  // SlashExpr 1
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_109 = NULL;
    rec(mod_109);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_110 = NULL;
      expr_ret_110 = daisho_parse_voidptr(ctx);
      expr_ret_109 = expr_ret_110;
      v = expr_ret_110;
    }

    // ModExprList 1
    if (expr_ret_109)
    {
      daisho_astnode_t* expr_ret_111 = NULL;
      daisho_astnode_t* expr_ret_112 = SUCC;
      while (expr_ret_112)
      {
        rec(kleene_rew_111);
        daisho_astnode_t* expr_ret_113 = NULL;
        rec(mod_113);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_113 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_113 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_113)
        {
          // CodeExpr
          #define ret expr_ret_113
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_113) rew(mod_113);
        expr_ret_112 = expr_ret_113;
      }

      expr_ret_111 = SUCC;
      expr_ret_109 = expr_ret_111;
    }

    // ModExprList 2
    if (expr_ret_109)
    {
      // CodeExpr
      #define ret expr_ret_109
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_109) rew(mod_109);
    expr_ret_105 = expr_ret_109;
  }

  // SlashExpr 2
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_114 = NULL;
    rec(mod_114);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_115 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
        // Capturing SELFTYPE.
        expr_ret_115 = leaf(SELFTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_115->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_115->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_115 = NULL;
      }

      expr_ret_114 = expr_ret_115;
      s = expr_ret_115;
    }

    // ModExprList 1
    if (expr_ret_114)
    {
      daisho_astnode_t* expr_ret_116 = NULL;
      daisho_astnode_t* expr_ret_117 = SUCC;
      while (expr_ret_117)
      {
        rec(kleene_rew_116);
        daisho_astnode_t* expr_ret_118 = NULL;
        rec(mod_118);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_118 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_118 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_118)
        {
          // CodeExpr
          #define ret expr_ret_118
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_118) rew(mod_118);
        expr_ret_117 = expr_ret_118;
      }

      expr_ret_116 = SUCC;
      expr_ret_114 = expr_ret_116;
    }

    // ModExprList 2
    if (expr_ret_114)
    {
      // CodeExpr
      #define ret expr_ret_114
      ret = SUCC;

      rule=node(TYPE, s);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_114) rew(mod_114);
    expr_ret_105 = expr_ret_114;
  }

  // SlashExpr 3
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    rec(mod_119);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_120 = NULL;
      expr_ret_120 = daisho_parse_traittype(ctx);
      expr_ret_119 = expr_ret_120;
      t = expr_ret_120;
    }

    // ModExprList 1
    if (expr_ret_119)
    {
      daisho_astnode_t* expr_ret_121 = NULL;
      daisho_astnode_t* expr_ret_122 = SUCC;
      while (expr_ret_122)
      {
        rec(kleene_rew_121);
        daisho_astnode_t* expr_ret_123 = NULL;
        rec(mod_123);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_123 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_123 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_123)
        {
          // CodeExpr
          #define ret expr_ret_123
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_123) rew(mod_123);
        expr_ret_122 = expr_ret_123;
      }

      expr_ret_121 = SUCC;
      expr_ret_119 = expr_ret_121;
    }

    // ModExprList 2
    if (expr_ret_119)
    {
      // CodeExpr
      #define ret expr_ret_119
      ret = SUCC;

      rule=node(TYPE, t);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_119) rew(mod_119);
    expr_ret_105 = expr_ret_119;
  }

  // SlashExpr 4
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_124 = NULL;
    rec(mod_124);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_125 = NULL;
      expr_ret_125 = daisho_parse_structtype(ctx);
      expr_ret_124 = expr_ret_125;
      s = expr_ret_125;
    }

    // ModExprList 1
    if (expr_ret_124)
    {
      daisho_astnode_t* expr_ret_126 = NULL;
      daisho_astnode_t* expr_ret_127 = SUCC;
      while (expr_ret_127)
      {
        rec(kleene_rew_126);
        daisho_astnode_t* expr_ret_128 = NULL;
        rec(mod_128);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_128 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_128 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_128)
        {
          // CodeExpr
          #define ret expr_ret_128
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_128) rew(mod_128);
        expr_ret_127 = expr_ret_128;
      }

      expr_ret_126 = SUCC;
      expr_ret_124 = expr_ret_126;
    }

    // ModExprList 2
    if (expr_ret_124)
    {
      // CodeExpr
      #define ret expr_ret_124
      ret = SUCC;

      rule=node(TYPE, s);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_124) rew(mod_124);
    expr_ret_105 = expr_ret_124;
  }

  // SlashExpr 5
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_129 = NULL;
    rec(mod_129);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_130 = NULL;
      expr_ret_130 = daisho_parse_fntype(ctx);
      expr_ret_129 = expr_ret_130;
      f = expr_ret_130;
    }

    // ModExprList 1
    if (expr_ret_129)
    {
      daisho_astnode_t* expr_ret_131 = NULL;
      daisho_astnode_t* expr_ret_132 = SUCC;
      while (expr_ret_132)
      {
        rec(kleene_rew_131);
        daisho_astnode_t* expr_ret_133 = NULL;
        rec(mod_133);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_133 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_133 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_133)
        {
          // CodeExpr
          #define ret expr_ret_133
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_133) rew(mod_133);
        expr_ret_132 = expr_ret_133;
      }

      expr_ret_131 = SUCC;
      expr_ret_129 = expr_ret_131;
    }

    // ModExprList 2
    if (expr_ret_129)
    {
      // CodeExpr
      #define ret expr_ret_129
      ret = SUCC;

      rule=node(TYPE, f);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_129) rew(mod_129);
    expr_ret_105 = expr_ret_129;
  }

  // SlashExpr 6
  if (!expr_ret_105)
  {
    daisho_astnode_t* expr_ret_134 = NULL;
    rec(mod_134);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_135 = NULL;
      expr_ret_135 = daisho_parse_ctypedecl(ctx);
      expr_ret_134 = expr_ret_135;
      c = expr_ret_135;
    }

    // ModExprList 1
    if (expr_ret_134)
    {
      // CodeExpr
      #define ret expr_ret_134
      ret = SUCC;

      rule=node(TYPE, c);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_134) rew(mod_134);
    expr_ret_105 = expr_ret_134;
  }

  // SlashExpr end
  expr_ret_104 = expr_ret_105;

  if (!rule) rule = expr_ret_104;
  if (!expr_ret_104) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_136
  daisho_astnode_t* expr_ret_137 = NULL;
  daisho_astnode_t* expr_ret_136 = NULL;
  daisho_astnode_t* expr_ret_138 = NULL;

  // SlashExpr 0
  if (!expr_ret_138)
  {
    daisho_astnode_t* expr_ret_139 = NULL;
    rec(mod_139);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_140 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
        // Capturing VOIDPTR.
        expr_ret_140 = leaf(VOIDPTR);
        #if DAISHO_SOURCEINFO
        expr_ret_140->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_140->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_140 = NULL;
      }

      expr_ret_139 = expr_ret_140;
      v = expr_ret_140;
    }

    // ModExprList 1
    if (expr_ret_139)
    {
      // CodeExpr
      #define ret expr_ret_139
      ret = SUCC;

      rule=v;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_139) rew(mod_139);
    expr_ret_138 = expr_ret_139;
  }

  // SlashExpr 1
  if (!expr_ret_138)
  {
    daisho_astnode_t* expr_ret_141 = NULL;
    rec(mod_141);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_142 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_142 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_142->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_142->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_142 = NULL;
      }

      expr_ret_141 = expr_ret_142;
      v = expr_ret_142;
    }

    // ModExprList 1
    if (expr_ret_141)
    {
      daisho_astnode_t* expr_ret_143 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_143 = leaf(STAR);
        #if DAISHO_SOURCEINFO
        expr_ret_143->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_143->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_143 = NULL;
      }

      expr_ret_141 = expr_ret_143;
      s = expr_ret_143;
    }

    // ModExprList 2
    if (expr_ret_141)
    {
      // CodeExpr
      #define ret expr_ret_141
      ret = SUCC;

      rule=leaf(VOIDPTR);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_141) rew(mod_141);
    expr_ret_138 = expr_ret_141;
  }

  // SlashExpr end
  expr_ret_137 = expr_ret_138;

  if (!rule) rule = expr_ret_137;
  if (!expr_ret_137) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_144
  daisho_astnode_t* expr_ret_145 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
  daisho_astnode_t* expr_ret_146 = NULL;
  rec(mod_146);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_147 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_147 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_147->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_147->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_147 = NULL;
    }

    expr_ret_146 = expr_ret_147;
    i = expr_ret_147;
  }

  // ModExprList 1
  if (expr_ret_146)
  {
    daisho_astnode_t* expr_ret_148 = NULL;
    expr_ret_148 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_148)
      expr_ret_148 = SUCC;
    expr_ret_146 = expr_ret_148;
    t = expr_ret_148;
  }

  // ModExprList 2
  if (expr_ret_146)
  {
    // CodeExpr
    #define ret expr_ret_146
    ret = SUCC;

    ret = has(t) ? node(TMPLTYPE, t, i) : node(TYPE, i);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_146) rew(mod_146);
  expr_ret_145 = expr_ret_146;
  if (!rule) rule = expr_ret_145;
  if (!expr_ret_145) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_149
  daisho_astnode_t* expr_ret_150 = NULL;
  daisho_astnode_t* expr_ret_149 = NULL;
  daisho_astnode_t* expr_ret_151 = NULL;
  rec(mod_151);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_152 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_152 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_152->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_152->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_152 = NULL;
    }

    expr_ret_151 = expr_ret_152;
    s = expr_ret_152;
  }

  // ModExprList 1
  if (expr_ret_151)
  {
    daisho_astnode_t* expr_ret_153 = NULL;
    expr_ret_153 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_153)
      expr_ret_153 = SUCC;
    expr_ret_151 = expr_ret_153;
    t = expr_ret_153;
  }

  // ModExprList 2
  if (expr_ret_151)
  {
    // CodeExpr
    #define ret expr_ret_151
    ret = SUCC;

    ret = has(t) ? node(TMPLTYPE, t, s) : node(TYPE, s);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_151) rew(mod_151);
  expr_ret_150 = expr_ret_151;
  if (!rule) rule = expr_ret_150;
  if (!expr_ret_150) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_154
  daisho_astnode_t* expr_ret_155 = NULL;
  daisho_astnode_t* expr_ret_154 = NULL;
  daisho_astnode_t* expr_ret_156 = NULL;
  rec(mod_156);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      // Not capturing CTYPE.
      expr_ret_156 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_156 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_156)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_156 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_156 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_156) rew(mod_156);
  expr_ret_155 = expr_ret_156;
  if (!rule) rule = expr_ret_155;
  if (!expr_ret_155) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* arrow = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* tmp = NULL;
  #define rule expr_ret_157
  daisho_astnode_t* expr_ret_158 = NULL;
  daisho_astnode_t* expr_ret_157 = NULL;
  daisho_astnode_t* expr_ret_159 = NULL;

  // SlashExpr 0
  if (!expr_ret_159)
  {
    daisho_astnode_t* expr_ret_160 = NULL;
    rec(mod_160);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_160 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_160 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_160)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        // Not capturing LT.
        expr_ret_160 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_160 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_161 = NULL;
      // CodeExpr
      #define ret expr_ret_161
      ret = SUCC;

      ret=list(ARGLIST);

      #undef ret
      expr_ret_160 = expr_ret_161;
      argtypes = expr_ret_161;
    }

    // ModExprList 3
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_162 = NULL;
      daisho_astnode_t* expr_ret_163 = NULL;
      rec(mod_163);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_164 = NULL;
        expr_ret_164 = daisho_parse_type(ctx);
        expr_ret_163 = expr_ret_164;
        t = expr_ret_164;
      }

      // ModExprList 1
      if (expr_ret_163)
      {
        // CodeExpr
        #define ret expr_ret_163
        ret = SUCC;

        add(argtypes, t);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_163) rew(mod_163);
      expr_ret_162 = expr_ret_163;
      // optional
      if (!expr_ret_162)
        expr_ret_162 = SUCC;
      expr_ret_160 = expr_ret_162;
    }

    // ModExprList 4
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_165 = NULL;
      daisho_astnode_t* expr_ret_166 = SUCC;
      while (expr_ret_166)
      {
        rec(kleene_rew_165);
        daisho_astnode_t* expr_ret_167 = NULL;
        rec(mod_167);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_167 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_167 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_167)
        {
          daisho_astnode_t* expr_ret_168 = NULL;
          expr_ret_168 = daisho_parse_type(ctx);
          expr_ret_167 = expr_ret_168;
          t = expr_ret_168;
        }

        // ModExprList 2
        if (expr_ret_167)
        {
          // CodeExpr
          #define ret expr_ret_167
          ret = SUCC;

          add(argtypes, t);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_167) rew(mod_167);
        expr_ret_166 = expr_ret_167;
      }

      expr_ret_165 = SUCC;
      expr_ret_160 = expr_ret_165;
    }

    // ModExprList 5
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_169 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_169 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_169 = NULL;
      }

      // optional
      if (!expr_ret_169)
        expr_ret_169 = SUCC;
      expr_ret_160 = expr_ret_169;
    }

    // ModExprList 6
    if (expr_ret_160)
    {
      // CodeExpr
      #define ret expr_ret_160
      ret = SUCC;

      if (!argtypes->num_children) add(argtypes, leaf(VOIDTYPE));

      #undef ret
    }

    // ModExprList 7
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_170 = NULL;
      daisho_astnode_t* expr_ret_171 = NULL;
      rec(mod_171);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_172 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
          // Capturing ARROW.
          expr_ret_172 = leaf(ARROW);
          #if DAISHO_SOURCEINFO
          expr_ret_172->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_172->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_172 = NULL;
        }

        expr_ret_171 = expr_ret_172;
        arrow = expr_ret_172;
      }

      // ModExprList 1
      if (expr_ret_171)
      {
        daisho_astnode_t* expr_ret_173 = NULL;
        expr_ret_173 = daisho_parse_type(ctx);
        expr_ret_171 = expr_ret_173;
        rettype = expr_ret_173;
      }

      // ModExprList end
      if (!expr_ret_171) rew(mod_171);
      expr_ret_170 = expr_ret_171;
      // optional
      if (!expr_ret_170)
        expr_ret_170 = SUCC;
      expr_ret_160 = expr_ret_170;
    }

    // ModExprList 8
    if (expr_ret_160)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Not capturing GT.
        expr_ret_160 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_160 = NULL;
      }

    }

    // ModExprList 9
    if (expr_ret_160)
    {
      // CodeExpr
      #define ret expr_ret_160
      ret = SUCC;

      rule=node(FNTYPE, argtypes, !has(rettype) ? leaf(VOIDTYPE) : rettype);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_160) rew(mod_160);
    expr_ret_159 = expr_ret_160;
  }

  // SlashExpr 1
  if (!expr_ret_159)
  {
    daisho_astnode_t* expr_ret_174 = NULL;
    rec(mod_174);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_174 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_174 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_174)
    {
      daisho_astnode_t* expr_ret_175 = NULL;
      // CodeExpr
      #define ret expr_ret_175
      ret = SUCC;

      rule=node(FNTYPE,
                            (tmp=list(ARGLIST), add(tmp, leaf(VOIDTYPE)), tmp),
                             leaf(VOIDTYPE));

      #undef ret
      expr_ret_174 = expr_ret_175;
      tmp = expr_ret_175;
    }

    // ModExprList end
    if (!expr_ret_174) rew(mod_174);
    expr_ret_159 = expr_ret_174;
  }

  // SlashExpr end
  expr_ret_158 = expr_ret_159;

  if (!rule) rule = expr_ret_158;
  if (!expr_ret_158) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplspec(daisho_parser_ctx* ctx) {
  #define rule expr_ret_176
  daisho_astnode_t* expr_ret_177 = NULL;
  daisho_astnode_t* expr_ret_176 = NULL;
  daisho_astnode_t* expr_ret_178 = NULL;
  rec(mod_178);
  // ModExprList end
  if (!expr_ret_178) rew(mod_178);
  expr_ret_177 = expr_ret_178;
  if (!rule) rule = expr_ret_177;
  if (!expr_ret_177) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  #define rule expr_ret_179
  daisho_astnode_t* expr_ret_180 = NULL;
  daisho_astnode_t* expr_ret_179 = NULL;
  daisho_astnode_t* expr_ret_181 = NULL;
  rec(mod_181);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_181 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_181 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_181)
  {
    daisho_astnode_t* expr_ret_182 = NULL;
    expr_ret_182 = daisho_parse_tmplmember(ctx);
    // optional
    if (!expr_ret_182)
      expr_ret_182 = SUCC;
    expr_ret_181 = expr_ret_182;
  }

  // ModExprList 2
  if (expr_ret_181)
  {
    daisho_astnode_t* expr_ret_183 = NULL;
    daisho_astnode_t* expr_ret_184 = SUCC;
    while (expr_ret_184)
    {
      rec(kleene_rew_183);
      daisho_astnode_t* expr_ret_185 = NULL;
      rec(mod_185);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_185 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_185 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_185)
      {
        expr_ret_185 = daisho_parse_tmplmember(ctx);
      }

      // ModExprList end
      if (!expr_ret_185) rew(mod_185);
      expr_ret_184 = expr_ret_185;
    }

    expr_ret_183 = SUCC;
    expr_ret_181 = expr_ret_183;
  }

  // ModExprList 3
  if (expr_ret_181)
  {
    daisho_astnode_t* expr_ret_186 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_186 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_186 = NULL;
    }

    // optional
    if (!expr_ret_186)
      expr_ret_186 = SUCC;
    expr_ret_181 = expr_ret_186;
  }

  // ModExprList 4
  if (expr_ret_181)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_181 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_181 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_181) rew(mod_181);
  expr_ret_180 = expr_ret_181;
  if (!rule) rule = expr_ret_180;
  if (!expr_ret_180) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplmember(daisho_parser_ctx* ctx) {
  #define rule expr_ret_187
  daisho_astnode_t* expr_ret_188 = NULL;
  daisho_astnode_t* expr_ret_187 = NULL;
  daisho_astnode_t* expr_ret_189 = NULL;
  rec(mod_189);
  // ModExprList Forwarding
  expr_ret_189 = daisho_parse_type(ctx);
  // ModExprList end
  if (!expr_ret_189) rew(mod_189);
  expr_ret_188 = expr_ret_189;
  if (!rule) rule = expr_ret_188;
  if (!expr_ret_188) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  #define rule expr_ret_190
  daisho_astnode_t* expr_ret_191 = NULL;
  daisho_astnode_t* expr_ret_190 = NULL;
  daisho_astnode_t* expr_ret_192 = NULL;
  rec(mod_192);
  // ModExprList 0
  {
    expr_ret_192 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_192)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_192 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_192)
  {
    daisho_astnode_t* expr_ret_193 = NULL;
    expr_ret_193 = daisho_parse_fnarg(ctx);
    // optional
    if (!expr_ret_193)
      expr_ret_193 = SUCC;
    expr_ret_192 = expr_ret_193;
  }

  // ModExprList 3
  if (expr_ret_192)
  {
    daisho_astnode_t* expr_ret_194 = NULL;
    daisho_astnode_t* expr_ret_195 = SUCC;
    while (expr_ret_195)
    {
      rec(kleene_rew_194);
      daisho_astnode_t* expr_ret_196 = NULL;
      rec(mod_196);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_196 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_196 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_196)
      {
        expr_ret_196 = daisho_parse_fnarg(ctx);
      }

      // ModExprList end
      if (!expr_ret_196) rew(mod_196);
      expr_ret_195 = expr_ret_196;
    }

    expr_ret_194 = SUCC;
    expr_ret_192 = expr_ret_194;
  }

  // ModExprList 4
  if (expr_ret_192)
  {
    daisho_astnode_t* expr_ret_197 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_197 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_197 = NULL;
    }

    // optional
    if (!expr_ret_197)
      expr_ret_197 = SUCC;
    expr_ret_192 = expr_ret_197;
  }

  // ModExprList 5
  if (expr_ret_192)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_192 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_192) rew(mod_192);
  expr_ret_191 = expr_ret_192;
  if (!rule) rule = expr_ret_191;
  if (!expr_ret_191) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  #define rule expr_ret_198
  daisho_astnode_t* expr_ret_199 = NULL;
  daisho_astnode_t* expr_ret_198 = NULL;
  daisho_astnode_t* expr_ret_200 = NULL;
  rec(mod_200);
  // ModExprList 0
  {
    expr_ret_200 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_200)
  {
    daisho_astnode_t* expr_ret_201 = NULL;
    daisho_astnode_t* expr_ret_202 = NULL;
    rec(mod_202);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_202 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_202 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_202)
    {
      daisho_astnode_t* expr_ret_203 = NULL;
      expr_ret_203 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_203)
        expr_ret_203 = SUCC;
      expr_ret_202 = expr_ret_203;
    }

    // ModExprList end
    if (!expr_ret_202) rew(mod_202);
    expr_ret_201 = expr_ret_202;
    // optional
    if (!expr_ret_201)
      expr_ret_201 = SUCC;
    expr_ret_200 = expr_ret_201;
  }

  // ModExprList end
  if (!expr_ret_200) rew(mod_200);
  expr_ret_199 = expr_ret_200;
  if (!rule) rule = expr_ret_199;
  if (!expr_ret_199) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx) {
  #define rule expr_ret_204
  daisho_astnode_t* expr_ret_205 = NULL;
  daisho_astnode_t* expr_ret_204 = NULL;
  daisho_astnode_t* expr_ret_206 = NULL;
  rec(mod_206);
  // ModExprList Forwarding
  expr_ret_206 = daisho_parse_expr(ctx);
  // ModExprList end
  if (!expr_ret_206) rew(mod_206);
  expr_ret_205 = expr_ret_206;
  if (!rule) rule = expr_ret_205;
  if (!expr_ret_205) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_207
  daisho_astnode_t* expr_ret_208 = NULL;
  daisho_astnode_t* expr_ret_207 = NULL;
  daisho_astnode_t* expr_ret_209 = NULL;
  rec(mod_209);
  // ModExprList Forwarding
  expr_ret_209 = daisho_parse_forexpr(ctx);
  // ModExprList end
  if (!expr_ret_209) rew(mod_209);
  expr_ret_208 = expr_ret_209;
  if (!rule) rule = expr_ret_208;
  if (!expr_ret_208) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* sn = NULL;
  #define rule expr_ret_210
  daisho_astnode_t* expr_ret_211 = NULL;
  daisho_astnode_t* expr_ret_210 = NULL;
  daisho_astnode_t* expr_ret_212 = NULL;

  // SlashExpr 0
  if (!expr_ret_212)
  {
    daisho_astnode_t* expr_ret_213 = NULL;
    rec(mod_213);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_213 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_213 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_214 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_214 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_214 = NULL;
      }

      // optional
      if (!expr_ret_214)
        expr_ret_214 = SUCC;
      expr_ret_213 = expr_ret_214;
    }

    // ModExprList 2
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_215 = NULL;
      expr_ret_215 = daisho_parse_whileexpr(ctx);
      expr_ret_213 = expr_ret_215;
      n = expr_ret_215;
    }

    // ModExprList 3
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_216 = NULL;

      // SlashExpr 0
      if (!expr_ret_216)
      {
        daisho_astnode_t* expr_ret_217 = NULL;
        rec(mod_217);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_218 = NULL;

        // SlashExpr 0
        if (!expr_ret_218)
        {
          daisho_astnode_t* expr_ret_219 = NULL;
          rec(mod_219);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_219 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_219 = NULL;
          }

          // ModExprList end
          if (!expr_ret_219) rew(mod_219);
          expr_ret_218 = expr_ret_219;
        }

        // SlashExpr 1
        if (!expr_ret_218)
        {
          daisho_astnode_t* expr_ret_220 = NULL;
          rec(mod_220);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_220 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_220 = NULL;
          }

          // ModExprList end
          if (!expr_ret_220) rew(mod_220);
          expr_ret_218 = expr_ret_220;
        }

        // SlashExpr end
        expr_ret_217 = expr_ret_218;

        // ModExprList end
        if (!expr_ret_217) rew(mod_217);
        expr_ret_216 = expr_ret_217;
      }

      // SlashExpr 1
      if (!expr_ret_216)
      {
        daisho_astnode_t* expr_ret_221 = NULL;
        rec(mod_221);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_222 = NULL;
        rec(mod_222);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_222 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_222 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_222)
        {
          daisho_astnode_t* expr_ret_223 = NULL;
          expr_ret_223 = daisho_parse_whileexpr(ctx);
          expr_ret_222 = expr_ret_223;
          sn = expr_ret_223;
        }

        // ModExprList 2
        if (expr_ret_222)
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_222 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_222 = NULL;
          }

        }

        // ModExprList end
        if (!expr_ret_222) rew(mod_222);
        expr_ret_221 = expr_ret_222;
        // ModExprList end
        if (!expr_ret_221) rew(mod_221);
        expr_ret_216 = expr_ret_221;
      }

      // SlashExpr end
      expr_ret_213 = expr_ret_216;

    }

    // ModExprList 4
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_224 = NULL;
      expr_ret_224 = daisho_parse_whileexpr(ctx);
      expr_ret_213 = expr_ret_224;
      n = expr_ret_224;
    }

    // ModExprList 5
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_225 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_225 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_225 = NULL;
      }

      // optional
      if (!expr_ret_225)
        expr_ret_225 = SUCC;
      expr_ret_213 = expr_ret_225;
    }

    // ModExprList 6
    if (expr_ret_213)
    {
      daisho_astnode_t* expr_ret_226 = NULL;
      expr_ret_226 = daisho_parse_whileexpr(ctx);
      expr_ret_213 = expr_ret_226;
      n = expr_ret_226;
    }

    // ModExprList end
    if (!expr_ret_213) rew(mod_213);
    expr_ret_212 = expr_ret_213;
  }

  // SlashExpr 1
  if (!expr_ret_212)
  {
    daisho_astnode_t* expr_ret_227 = NULL;
    rec(mod_227);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_228 = NULL;
      expr_ret_228 = daisho_parse_whileexpr(ctx);
      expr_ret_227 = expr_ret_228;
      n = expr_ret_228;
    }

    // ModExprList 1
    if (expr_ret_227)
    {
      // CodeExpr
      #define ret expr_ret_227
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_227) rew(mod_227);
    expr_ret_212 = expr_ret_227;
  }

  // SlashExpr end
  expr_ret_211 = expr_ret_212;

  if (!rule) rule = expr_ret_211;
  if (!expr_ret_211) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_229
  daisho_astnode_t* expr_ret_230 = NULL;
  daisho_astnode_t* expr_ret_229 = NULL;
  daisho_astnode_t* expr_ret_231 = NULL;

  // SlashExpr 0
  if (!expr_ret_231)
  {
    daisho_astnode_t* expr_ret_232 = NULL;
    rec(mod_232);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
        // Not capturing WHILE.
        expr_ret_232 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_232 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_232)
    {
      daisho_astnode_t* expr_ret_233 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_233 = leaf(OPEN);
        #if DAISHO_SOURCEINFO
        expr_ret_233->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_233->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_233 = NULL;
      }

      // optional
      if (!expr_ret_233)
        expr_ret_233 = SUCC;
      expr_ret_232 = expr_ret_233;
      o = expr_ret_233;
    }

    // ModExprList 2
    if (expr_ret_232)
    {
      daisho_astnode_t* expr_ret_234 = NULL;
      expr_ret_234 = daisho_parse_ternexpr(ctx);
      expr_ret_232 = expr_ret_234;
      n = expr_ret_234;
    }

    // ModExprList 3
    if (expr_ret_232)
    {
      daisho_astnode_t* expr_ret_235 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_235 = leaf(CLOSE);
        #if DAISHO_SOURCEINFO
        expr_ret_235->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_235->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_235 = NULL;
      }

      // optional
      if (!expr_ret_235)
        expr_ret_235 = SUCC;
      expr_ret_232 = expr_ret_235;
      c = expr_ret_235;
    }

    // ModExprList 4
    if (expr_ret_232)
    {
      // CodeExpr
      #define ret expr_ret_232
      ret = SUCC;

      ret=o==c?SUCC:NULL;

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_232)
    {
      expr_ret_232 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_232) rew(mod_232);
    expr_ret_231 = expr_ret_232;
  }

  // SlashExpr 1
  if (!expr_ret_231)
  {
    daisho_astnode_t* expr_ret_236 = NULL;
    rec(mod_236);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_237 = NULL;
      expr_ret_237 = daisho_parse_ternexpr(ctx);
      expr_ret_236 = expr_ret_237;
      n = expr_ret_237;
    }

    // ModExprList 1
    if (expr_ret_236)
    {
      // CodeExpr
      #define ret expr_ret_236
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_236) rew(mod_236);
    expr_ret_231 = expr_ret_236;
  }

  // SlashExpr end
  expr_ret_230 = expr_ret_231;

  if (!rule) rule = expr_ret_230;
  if (!expr_ret_230) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* q = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_238
  daisho_astnode_t* expr_ret_239 = NULL;
  daisho_astnode_t* expr_ret_238 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
  rec(mod_240);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_241 = NULL;
    expr_ret_241 = daisho_parse_thenexpr(ctx);
    expr_ret_240 = expr_ret_241;
    n = expr_ret_241;
  }

  // ModExprList 1
  if (expr_ret_240)
  {
    daisho_astnode_t* expr_ret_242 = NULL;
    daisho_astnode_t* expr_ret_243 = NULL;
    rec(mod_243);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_244 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
        // Capturing QUEST.
        expr_ret_244 = leaf(QUEST);
        #if DAISHO_SOURCEINFO
        expr_ret_244->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_244->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_244 = NULL;
      }

      expr_ret_243 = expr_ret_244;
      q = expr_ret_244;
    }

    // ModExprList 1
    if (expr_ret_243)
    {
      daisho_astnode_t* expr_ret_245 = NULL;
      expr_ret_245 = daisho_parse_expr(ctx);
      expr_ret_243 = expr_ret_245;
      qe = expr_ret_245;
    }

    // ModExprList 2
    if (expr_ret_243)
    {
      daisho_astnode_t* expr_ret_246 = NULL;
      daisho_astnode_t* expr_ret_247 = NULL;
      rec(mod_247);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_248 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          // Capturing COLON.
          expr_ret_248 = leaf(COLON);
          #if DAISHO_SOURCEINFO
          expr_ret_248->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_248->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_248 = NULL;
        }

        expr_ret_247 = expr_ret_248;
        c = expr_ret_248;
      }

      // ModExprList 1
      if (expr_ret_247)
      {
        daisho_astnode_t* expr_ret_249 = NULL;
        expr_ret_249 = daisho_parse_expr(ctx);
        expr_ret_247 = expr_ret_249;
        ce = expr_ret_249;
      }

      // ModExprList end
      if (!expr_ret_247) rew(mod_247);
      expr_ret_246 = expr_ret_247;
      // optional
      if (!expr_ret_246)
        expr_ret_246 = SUCC;
      expr_ret_243 = expr_ret_246;
    }

    // ModExprList end
    if (!expr_ret_243) rew(mod_243);
    expr_ret_242 = expr_ret_243;
    // optional
    if (!expr_ret_242)
      expr_ret_242 = SUCC;
    expr_ret_240 = expr_ret_242;
  }

  // ModExprList 2
  if (expr_ret_240)
  {
    // CodeExpr
    #define ret expr_ret_240
    ret = SUCC;

    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, q, n, qe)
                    :            node(TERN, q, c, n, qe, ce);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_240) rew(mod_240);
  expr_ret_239 = expr_ret_240;
  if (!rule) rule = expr_ret_239;
  if (!expr_ret_239) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_250
  daisho_astnode_t* expr_ret_251 = NULL;
  daisho_astnode_t* expr_ret_250 = NULL;
  daisho_astnode_t* expr_ret_252 = NULL;
  rec(mod_252);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_253 = NULL;
    expr_ret_253 = daisho_parse_alsoexpr(ctx);
    expr_ret_252 = expr_ret_253;
    n = expr_ret_253;
  }

  // ModExprList 1
  if (expr_ret_252)
  {
    // CodeExpr
    #define ret expr_ret_252
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_252)
  {
    daisho_astnode_t* expr_ret_254 = NULL;
    daisho_astnode_t* expr_ret_255 = SUCC;
    while (expr_ret_255)
    {
      rec(kleene_rew_254);
      daisho_astnode_t* expr_ret_256 = NULL;
      rec(mod_256);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
          // Not capturing THEN.
          expr_ret_256 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_256 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_256)
      {
        daisho_astnode_t* expr_ret_257 = NULL;
        expr_ret_257 = daisho_parse_alsoexpr(ctx);
        expr_ret_256 = expr_ret_257;
        nn = expr_ret_257;
      }

      // ModExprList 2
      if (expr_ret_256)
      {
        // CodeExpr
        #define ret expr_ret_256
        ret = SUCC;

        rule=node(THEN, rule, nn);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_256) rew(mod_256);
      expr_ret_255 = expr_ret_256;
    }

    expr_ret_254 = SUCC;
    expr_ret_252 = expr_ret_254;
  }

  // ModExprList end
  if (!expr_ret_252) rew(mod_252);
  expr_ret_251 = expr_ret_252;
  if (!rule) rule = expr_ret_251;
  if (!expr_ret_251) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_258
  daisho_astnode_t* expr_ret_259 = NULL;
  daisho_astnode_t* expr_ret_258 = NULL;
  daisho_astnode_t* expr_ret_260 = NULL;
  rec(mod_260);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_261 = NULL;
    expr_ret_261 = daisho_parse_binop(ctx);
    expr_ret_260 = expr_ret_261;
    n = expr_ret_261;
  }

  // ModExprList 1
  if (expr_ret_260)
  {
    // CodeExpr
    #define ret expr_ret_260
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_260)
  {
    daisho_astnode_t* expr_ret_262 = NULL;
    daisho_astnode_t* expr_ret_263 = SUCC;
    while (expr_ret_263)
    {
      rec(kleene_rew_262);
      daisho_astnode_t* expr_ret_264 = NULL;
      rec(mod_264);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
          // Not capturing ALSO.
          expr_ret_264 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_264 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_264)
      {
        daisho_astnode_t* expr_ret_265 = NULL;
        expr_ret_265 = daisho_parse_binop(ctx);
        expr_ret_264 = expr_ret_265;
        nn = expr_ret_265;
      }

      // ModExprList 2
      if (expr_ret_264)
      {
        // CodeExpr
        #define ret expr_ret_264
        ret = SUCC;

        rule=node(ALSO, rule, nn);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_264) rew(mod_264);
      expr_ret_263 = expr_ret_264;
    }

    expr_ret_262 = SUCC;
    expr_ret_260 = expr_ret_262;
  }

  // ModExprList end
  if (!expr_ret_260) rew(mod_260);
  expr_ret_259 = expr_ret_260;
  if (!rule) rule = expr_ret_259;
  if (!expr_ret_259) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  #define rule expr_ret_266
  daisho_astnode_t* expr_ret_267 = NULL;
  daisho_astnode_t* expr_ret_266 = NULL;
  daisho_astnode_t* expr_ret_268 = NULL;
  rec(mod_268);
  // ModExprList Forwarding
  expr_ret_268 = daisho_parse_eqexpr(ctx);
  // ModExprList end
  if (!expr_ret_268) rew(mod_268);
  expr_ret_267 = expr_ret_268;
  if (!rule) rule = expr_ret_267;
  if (!expr_ret_267) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_269
  daisho_astnode_t* expr_ret_270 = NULL;
  daisho_astnode_t* expr_ret_269 = NULL;
  daisho_astnode_t* expr_ret_271 = NULL;
  rec(mod_271);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_272 = NULL;
    expr_ret_272 = daisho_parse_logorexpr(ctx);
    expr_ret_271 = expr_ret_272;
    n = expr_ret_272;
  }

  // ModExprList 1
  if (expr_ret_271)
  {
    // CodeExpr
    #define ret expr_ret_271
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_271)
  {
    daisho_astnode_t* expr_ret_273 = NULL;
    daisho_astnode_t* expr_ret_274 = SUCC;
    while (expr_ret_274)
    {
      rec(kleene_rew_273);
      daisho_astnode_t* expr_ret_275 = NULL;
      rec(mod_275);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_276 = NULL;
        daisho_astnode_t* expr_ret_277 = NULL;

        // SlashExpr 0
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_278 = NULL;
          rec(mod_278);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            // Capturing EQ.
            expr_ret_278 = leaf(EQ);
            #if DAISHO_SOURCEINFO
            expr_ret_278->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_278->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_278 = NULL;
          }

          // ModExprList end
          if (!expr_ret_278) rew(mod_278);
          expr_ret_277 = expr_ret_278;
        }

        // SlashExpr 1
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_279 = NULL;
          rec(mod_279);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            // Capturing PLEQ.
            expr_ret_279 = leaf(PLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_279->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_279->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_279 = NULL;
          }

          // ModExprList end
          if (!expr_ret_279) rew(mod_279);
          expr_ret_277 = expr_ret_279;
        }

        // SlashExpr 2
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_280 = NULL;
          rec(mod_280);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            // Capturing MINEQ.
            expr_ret_280 = leaf(MINEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_280->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_280->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_280 = NULL;
          }

          // ModExprList end
          if (!expr_ret_280) rew(mod_280);
          expr_ret_277 = expr_ret_280;
        }

        // SlashExpr 3
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_281 = NULL;
          rec(mod_281);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            // Capturing MULEQ.
            expr_ret_281 = leaf(MULEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_281->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_281->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_281 = NULL;
          }

          // ModExprList end
          if (!expr_ret_281) rew(mod_281);
          expr_ret_277 = expr_ret_281;
        }

        // SlashExpr 4
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_282 = NULL;
          rec(mod_282);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            // Capturing DIVEQ.
            expr_ret_282 = leaf(DIVEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_282->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_282->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_282 = NULL;
          }

          // ModExprList end
          if (!expr_ret_282) rew(mod_282);
          expr_ret_277 = expr_ret_282;
        }

        // SlashExpr 5
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_283 = NULL;
          rec(mod_283);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            // Capturing MODEQ.
            expr_ret_283 = leaf(MODEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_283->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_283->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_283 = NULL;
          }

          // ModExprList end
          if (!expr_ret_283) rew(mod_283);
          expr_ret_277 = expr_ret_283;
        }

        // SlashExpr 6
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_284 = NULL;
          rec(mod_284);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            // Capturing ANDEQ.
            expr_ret_284 = leaf(ANDEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_284->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_284->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_284 = NULL;
          }

          // ModExprList end
          if (!expr_ret_284) rew(mod_284);
          expr_ret_277 = expr_ret_284;
        }

        // SlashExpr 7
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_285 = NULL;
          rec(mod_285);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            // Capturing OREQ.
            expr_ret_285 = leaf(OREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_285->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_285->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_285 = NULL;
          }

          // ModExprList end
          if (!expr_ret_285) rew(mod_285);
          expr_ret_277 = expr_ret_285;
        }

        // SlashExpr 8
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_286 = NULL;
          rec(mod_286);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            // Capturing XOREQ.
            expr_ret_286 = leaf(XOREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_286->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_286->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_286 = NULL;
          }

          // ModExprList end
          if (!expr_ret_286) rew(mod_286);
          expr_ret_277 = expr_ret_286;
        }

        // SlashExpr 9
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_287 = NULL;
          rec(mod_287);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            // Capturing BNEQ.
            expr_ret_287 = leaf(BNEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_287->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_287->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_287 = NULL;
          }

          // ModExprList end
          if (!expr_ret_287) rew(mod_287);
          expr_ret_277 = expr_ret_287;
        }

        // SlashExpr 10
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_288 = NULL;
          rec(mod_288);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            // Capturing BSREQ.
            expr_ret_288 = leaf(BSREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_288->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_288->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_288 = NULL;
          }

          // ModExprList end
          if (!expr_ret_288) rew(mod_288);
          expr_ret_277 = expr_ret_288;
        }

        // SlashExpr 11
        if (!expr_ret_277)
        {
          daisho_astnode_t* expr_ret_289 = NULL;
          rec(mod_289);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            // Capturing BSLEQ.
            expr_ret_289 = leaf(BSLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_289->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_289->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_289 = NULL;
          }

          // ModExprList end
          if (!expr_ret_289) rew(mod_289);
          expr_ret_277 = expr_ret_289;
        }

        // SlashExpr end
        expr_ret_276 = expr_ret_277;

        expr_ret_275 = expr_ret_276;
        op = expr_ret_276;
      }

      // ModExprList 1
      if (expr_ret_275)
      {
        daisho_astnode_t* expr_ret_290 = NULL;
        expr_ret_290 = daisho_parse_logorexpr(ctx);
        expr_ret_275 = expr_ret_290;
        t = expr_ret_290;
      }

      // ModExprList 2
      if (expr_ret_275)
      {
        // CodeExpr
        #define ret expr_ret_275
        ret = SUCC;

        
                if      (op->kind == kind(EQ))    rule=node(EQ, rule,                   t );
                else if (op->kind == kind(PLEQ))  rule=node(EQ, rule, node(PLUS,  rule, t));
                else if (op->kind == kind(MINEQ)) rule=node(EQ, rule, node(MINUS, rule, t));
                else if (op->kind == kind(MULEQ)) rule=node(EQ, rule, node(MUL,   rule, t));
                else if (op->kind == kind(DIVEQ)) rule=node(EQ, rule, node(DIV,   rule, t));
                else if (op->kind == kind(MODEQ)) rule=node(EQ, rule, node(MOD,   rule, t));
                else if (op->kind == kind(ANDEQ)) rule=node(EQ, rule, node(AND,   rule, t));
                else if (op->kind == kind(OREQ))  rule=node(EQ, rule, node(OR,    rule, t));
                else if (op->kind == kind(XOREQ)) rule=node(EQ, rule, node(BNEQ,  rule, t));
                else if (op->kind == kind(BSREQ)) rule=node(EQ, rule, node(BSR,   rule, t));
                else if (op->kind == kind(BSLEQ)) rule=node(EQ, rule, node(BSL,   rule, t));
                else _DAI_UNREACHABLE()
              ;

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_275) rew(mod_275);
      expr_ret_274 = expr_ret_275;
    }

    expr_ret_273 = SUCC;
    expr_ret_271 = expr_ret_273;
  }

  // ModExprList end
  if (!expr_ret_271) rew(mod_271);
  expr_ret_270 = expr_ret_271;
  if (!rule) rule = expr_ret_270;
  if (!expr_ret_270) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_291
  daisho_astnode_t* expr_ret_292 = NULL;
  daisho_astnode_t* expr_ret_291 = NULL;
  daisho_astnode_t* expr_ret_293 = NULL;
  rec(mod_293);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_294 = NULL;
    expr_ret_294 = daisho_parse_logandexpr(ctx);
    expr_ret_293 = expr_ret_294;
    n = expr_ret_294;
  }

  // ModExprList 1
  if (expr_ret_293)
  {
    // CodeExpr
    #define ret expr_ret_293
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_293)
  {
    daisho_astnode_t* expr_ret_295 = NULL;
    daisho_astnode_t* expr_ret_296 = SUCC;
    while (expr_ret_296)
    {
      rec(kleene_rew_295);
      daisho_astnode_t* expr_ret_297 = NULL;
      rec(mod_297);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Not capturing LOGOR.
          expr_ret_297 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_297 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_297)
      {
        daisho_astnode_t* expr_ret_298 = NULL;
        expr_ret_298 = daisho_parse_logandexpr(ctx);
        expr_ret_297 = expr_ret_298;
        n = expr_ret_298;
      }

      // ModExprList 2
      if (expr_ret_297)
      {
        // CodeExpr
        #define ret expr_ret_297
        ret = SUCC;

        rule=node(LOGOR,  rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_297) rew(mod_297);
      expr_ret_296 = expr_ret_297;
    }

    expr_ret_295 = SUCC;
    expr_ret_293 = expr_ret_295;
  }

  // ModExprList end
  if (!expr_ret_293) rew(mod_293);
  expr_ret_292 = expr_ret_293;
  if (!rule) rule = expr_ret_292;
  if (!expr_ret_292) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_299
  daisho_astnode_t* expr_ret_300 = NULL;
  daisho_astnode_t* expr_ret_299 = NULL;
  daisho_astnode_t* expr_ret_301 = NULL;
  rec(mod_301);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_302 = NULL;
    expr_ret_302 = daisho_parse_binorexpr(ctx);
    expr_ret_301 = expr_ret_302;
    n = expr_ret_302;
  }

  // ModExprList 1
  if (expr_ret_301)
  {
    // CodeExpr
    #define ret expr_ret_301
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_301)
  {
    daisho_astnode_t* expr_ret_303 = NULL;
    daisho_astnode_t* expr_ret_304 = SUCC;
    while (expr_ret_304)
    {
      rec(kleene_rew_303);
      daisho_astnode_t* expr_ret_305 = NULL;
      rec(mod_305);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Not capturing LOGAND.
          expr_ret_305 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_305 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_305)
      {
        daisho_astnode_t* expr_ret_306 = NULL;
        expr_ret_306 = daisho_parse_binorexpr(ctx);
        expr_ret_305 = expr_ret_306;
        n = expr_ret_306;
      }

      // ModExprList 2
      if (expr_ret_305)
      {
        // CodeExpr
        #define ret expr_ret_305
        ret = SUCC;

        rule=node(LOGAND, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_305) rew(mod_305);
      expr_ret_304 = expr_ret_305;
    }

    expr_ret_303 = SUCC;
    expr_ret_301 = expr_ret_303;
  }

  // ModExprList end
  if (!expr_ret_301) rew(mod_301);
  expr_ret_300 = expr_ret_301;
  if (!rule) rule = expr_ret_300;
  if (!expr_ret_300) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_307
  daisho_astnode_t* expr_ret_308 = NULL;
  daisho_astnode_t* expr_ret_307 = NULL;
  daisho_astnode_t* expr_ret_309 = NULL;
  rec(mod_309);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_310 = NULL;
    expr_ret_310 = daisho_parse_binxorexpr(ctx);
    expr_ret_309 = expr_ret_310;
    n = expr_ret_310;
  }

  // ModExprList 1
  if (expr_ret_309)
  {
    // CodeExpr
    #define ret expr_ret_309
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_309)
  {
    daisho_astnode_t* expr_ret_311 = NULL;
    daisho_astnode_t* expr_ret_312 = SUCC;
    while (expr_ret_312)
    {
      rec(kleene_rew_311);
      daisho_astnode_t* expr_ret_313 = NULL;
      rec(mod_313);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Not capturing OR.
          expr_ret_313 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_313 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_313)
      {
        daisho_astnode_t* expr_ret_314 = NULL;
        expr_ret_314 = daisho_parse_binxorexpr(ctx);
        expr_ret_313 = expr_ret_314;
        n = expr_ret_314;
      }

      // ModExprList 2
      if (expr_ret_313)
      {
        // CodeExpr
        #define ret expr_ret_313
        ret = SUCC;

        rule=node(OR,     rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_313) rew(mod_313);
      expr_ret_312 = expr_ret_313;
    }

    expr_ret_311 = SUCC;
    expr_ret_309 = expr_ret_311;
  }

  // ModExprList end
  if (!expr_ret_309) rew(mod_309);
  expr_ret_308 = expr_ret_309;
  if (!rule) rule = expr_ret_308;
  if (!expr_ret_308) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_315
  daisho_astnode_t* expr_ret_316 = NULL;
  daisho_astnode_t* expr_ret_315 = NULL;
  daisho_astnode_t* expr_ret_317 = NULL;
  rec(mod_317);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_318 = NULL;
    expr_ret_318 = daisho_parse_binandexpr(ctx);
    expr_ret_317 = expr_ret_318;
    n = expr_ret_318;
  }

  // ModExprList 1
  if (expr_ret_317)
  {
    // CodeExpr
    #define ret expr_ret_317
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_317)
  {
    daisho_astnode_t* expr_ret_319 = NULL;
    daisho_astnode_t* expr_ret_320 = SUCC;
    while (expr_ret_320)
    {
      rec(kleene_rew_319);
      daisho_astnode_t* expr_ret_321 = NULL;
      rec(mod_321);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Not capturing XOR.
          expr_ret_321 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_321 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_321)
      {
        daisho_astnode_t* expr_ret_322 = NULL;
        expr_ret_322 = daisho_parse_binandexpr(ctx);
        expr_ret_321 = expr_ret_322;
        n = expr_ret_322;
      }

      // ModExprList 2
      if (expr_ret_321)
      {
        // CodeExpr
        #define ret expr_ret_321
        ret = SUCC;

        rule=node(XOR,    rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_321) rew(mod_321);
      expr_ret_320 = expr_ret_321;
    }

    expr_ret_319 = SUCC;
    expr_ret_317 = expr_ret_319;
  }

  // ModExprList end
  if (!expr_ret_317) rew(mod_317);
  expr_ret_316 = expr_ret_317;
  if (!rule) rule = expr_ret_316;
  if (!expr_ret_316) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_323
  daisho_astnode_t* expr_ret_324 = NULL;
  daisho_astnode_t* expr_ret_323 = NULL;
  daisho_astnode_t* expr_ret_325 = NULL;
  rec(mod_325);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_326 = NULL;
    expr_ret_326 = daisho_parse_deneqexpr(ctx);
    expr_ret_325 = expr_ret_326;
    n = expr_ret_326;
  }

  // ModExprList 1
  if (expr_ret_325)
  {
    // CodeExpr
    #define ret expr_ret_325
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_325)
  {
    daisho_astnode_t* expr_ret_327 = NULL;
    daisho_astnode_t* expr_ret_328 = SUCC;
    while (expr_ret_328)
    {
      rec(kleene_rew_327);
      daisho_astnode_t* expr_ret_329 = NULL;
      rec(mod_329);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Not capturing AND.
          expr_ret_329 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_329 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_329)
      {
        daisho_astnode_t* expr_ret_330 = NULL;
        expr_ret_330 = daisho_parse_deneqexpr(ctx);
        expr_ret_329 = expr_ret_330;
        n = expr_ret_330;
      }

      // ModExprList 2
      if (expr_ret_329)
      {
        // CodeExpr
        #define ret expr_ret_329
        ret = SUCC;

        rule=node(AND,    rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_329) rew(mod_329);
      expr_ret_328 = expr_ret_329;
    }

    expr_ret_327 = SUCC;
    expr_ret_325 = expr_ret_327;
  }

  // ModExprList end
  if (!expr_ret_325) rew(mod_325);
  expr_ret_324 = expr_ret_325;
  if (!rule) rule = expr_ret_324;
  if (!expr_ret_324) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_331
  daisho_astnode_t* expr_ret_332 = NULL;
  daisho_astnode_t* expr_ret_331 = NULL;
  daisho_astnode_t* expr_ret_333 = NULL;
  rec(mod_333);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_334 = NULL;
    expr_ret_334 = daisho_parse_cmpexpr(ctx);
    expr_ret_333 = expr_ret_334;
    n = expr_ret_334;
  }

  // ModExprList 1
  if (expr_ret_333)
  {
    // CodeExpr
    #define ret expr_ret_333
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_333)
  {
    daisho_astnode_t* expr_ret_335 = NULL;
    daisho_astnode_t* expr_ret_336 = SUCC;
    while (expr_ret_336)
    {
      rec(kleene_rew_335);
      daisho_astnode_t* expr_ret_337 = NULL;

      // SlashExpr 0
      if (!expr_ret_337)
      {
        daisho_astnode_t* expr_ret_338 = NULL;
        rec(mod_338);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Not capturing DEQ.
            expr_ret_338 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_338 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_338)
        {
          daisho_astnode_t* expr_ret_339 = NULL;
          expr_ret_339 = daisho_parse_cmpexpr(ctx);
          expr_ret_338 = expr_ret_339;
          n = expr_ret_339;
        }

        // ModExprList 2
        if (expr_ret_338)
        {
          // CodeExpr
          #define ret expr_ret_338
          ret = SUCC;

          rule=node(DEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_338) rew(mod_338);
        expr_ret_337 = expr_ret_338;
      }

      // SlashExpr 1
      if (!expr_ret_337)
      {
        daisho_astnode_t* expr_ret_340 = NULL;
        rec(mod_340);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Not capturing NEQ.
            expr_ret_340 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_340 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_340)
        {
          daisho_astnode_t* expr_ret_341 = NULL;
          expr_ret_341 = daisho_parse_cmpexpr(ctx);
          expr_ret_340 = expr_ret_341;
          n = expr_ret_341;
        }

        // ModExprList 2
        if (expr_ret_340)
        {
          // CodeExpr
          #define ret expr_ret_340
          ret = SUCC;

          rule=node(NEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_340) rew(mod_340);
        expr_ret_337 = expr_ret_340;
      }

      // SlashExpr end
      expr_ret_336 = expr_ret_337;

    }

    expr_ret_335 = SUCC;
    expr_ret_333 = expr_ret_335;
  }

  // ModExprList end
  if (!expr_ret_333) rew(mod_333);
  expr_ret_332 = expr_ret_333;
  if (!rule) rule = expr_ret_332;
  if (!expr_ret_332) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_342
  daisho_astnode_t* expr_ret_343 = NULL;
  daisho_astnode_t* expr_ret_342 = NULL;
  daisho_astnode_t* expr_ret_344 = NULL;
  rec(mod_344);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_345 = NULL;
    expr_ret_345 = daisho_parse_shfexpr(ctx);
    expr_ret_344 = expr_ret_345;
    n = expr_ret_345;
  }

  // ModExprList 1
  if (expr_ret_344)
  {
    // CodeExpr
    #define ret expr_ret_344
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_344)
  {
    daisho_astnode_t* expr_ret_346 = NULL;
    daisho_astnode_t* expr_ret_347 = SUCC;
    while (expr_ret_347)
    {
      rec(kleene_rew_346);
      daisho_astnode_t* expr_ret_348 = NULL;

      // SlashExpr 0
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_349 = NULL;
        rec(mod_349);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_349 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_349 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_349)
        {
          daisho_astnode_t* expr_ret_350 = NULL;
          expr_ret_350 = daisho_parse_shfexpr(ctx);
          expr_ret_349 = expr_ret_350;
          n = expr_ret_350;
        }

        // ModExprList 2
        if (expr_ret_349)
        {
          // CodeExpr
          #define ret expr_ret_349
          ret = SUCC;

          rule=node(LT,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_349) rew(mod_349);
        expr_ret_348 = expr_ret_349;
      }

      // SlashExpr 1
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_351 = NULL;
        rec(mod_351);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_351 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_351 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_351)
        {
          daisho_astnode_t* expr_ret_352 = NULL;
          expr_ret_352 = daisho_parse_shfexpr(ctx);
          expr_ret_351 = expr_ret_352;
          n = expr_ret_352;
        }

        // ModExprList 2
        if (expr_ret_351)
        {
          // CodeExpr
          #define ret expr_ret_351
          ret = SUCC;

          rule=node(GT,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_351) rew(mod_351);
        expr_ret_348 = expr_ret_351;
      }

      // SlashExpr 2
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_353 = NULL;
        rec(mod_353);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Not capturing LEQ.
            expr_ret_353 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_353 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_353)
        {
          daisho_astnode_t* expr_ret_354 = NULL;
          expr_ret_354 = daisho_parse_shfexpr(ctx);
          expr_ret_353 = expr_ret_354;
          n = expr_ret_354;
        }

        // ModExprList 2
        if (expr_ret_353)
        {
          // CodeExpr
          #define ret expr_ret_353
          ret = SUCC;

          rule=node(LEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_353) rew(mod_353);
        expr_ret_348 = expr_ret_353;
      }

      // SlashExpr 3
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_355 = NULL;
        rec(mod_355);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Not capturing GEQ.
            expr_ret_355 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_355 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_355)
        {
          daisho_astnode_t* expr_ret_356 = NULL;
          expr_ret_356 = daisho_parse_shfexpr(ctx);
          expr_ret_355 = expr_ret_356;
          n = expr_ret_356;
        }

        // ModExprList 2
        if (expr_ret_355)
        {
          // CodeExpr
          #define ret expr_ret_355
          ret = SUCC;

          rule=node(GEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_355) rew(mod_355);
        expr_ret_348 = expr_ret_355;
      }

      // SlashExpr end
      expr_ret_347 = expr_ret_348;

    }

    expr_ret_346 = SUCC;
    expr_ret_344 = expr_ret_346;
  }

  // ModExprList end
  if (!expr_ret_344) rew(mod_344);
  expr_ret_343 = expr_ret_344;
  if (!rule) rule = expr_ret_343;
  if (!expr_ret_343) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  #define rule expr_ret_357
  daisho_astnode_t* expr_ret_358 = NULL;
  daisho_astnode_t* expr_ret_357 = NULL;
  daisho_astnode_t* expr_ret_359 = NULL;
  rec(mod_359);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_360 = NULL;
    expr_ret_360 = daisho_parse_sumexpr(ctx);
    expr_ret_359 = expr_ret_360;
    n = expr_ret_360;
  }

  // ModExprList 1
  if (expr_ret_359)
  {
    // CodeExpr
    #define ret expr_ret_359
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_359)
  {
    daisho_astnode_t* expr_ret_361 = NULL;
    daisho_astnode_t* expr_ret_362 = SUCC;
    while (expr_ret_362)
    {
      rec(kleene_rew_361);
      daisho_astnode_t* expr_ret_363 = NULL;

      // SlashExpr 0
      if (!expr_ret_363)
      {
        daisho_astnode_t* expr_ret_364 = NULL;
        rec(mod_364);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_365 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_365 = leaf(LT);
            #if DAISHO_SOURCEINFO
            expr_ret_365->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_365->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_365 = NULL;
          }

          expr_ret_364 = expr_ret_365;
          l = expr_ret_365;
        }

        // ModExprList 1
        if (expr_ret_364)
        {
          daisho_astnode_t* expr_ret_366 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_366 = leaf(LT);
            #if DAISHO_SOURCEINFO
            expr_ret_366->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_366->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_366 = NULL;
          }

          expr_ret_364 = expr_ret_366;
          lt = expr_ret_366;
        }

        // ModExprList 2
        if (expr_ret_364)
        {
          daisho_astnode_t* expr_ret_367 = NULL;
          expr_ret_367 = daisho_parse_sumexpr(ctx);
          expr_ret_364 = expr_ret_367;
          n = expr_ret_367;
        }

        // ModExprList 3
        if (expr_ret_364)
        {
          // CodeExpr
          #define ret expr_ret_364
          ret = SUCC;

          rule=node(BSL, l, lt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_364) rew(mod_364);
        expr_ret_363 = expr_ret_364;
      }

      // SlashExpr 1
      if (!expr_ret_363)
      {
        daisho_astnode_t* expr_ret_368 = NULL;
        rec(mod_368);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_369 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_369 = leaf(GT);
            #if DAISHO_SOURCEINFO
            expr_ret_369->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_369->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_369 = NULL;
          }

          expr_ret_368 = expr_ret_369;
          g = expr_ret_369;
        }

        // ModExprList 1
        if (expr_ret_368)
        {
          daisho_astnode_t* expr_ret_370 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_370 = leaf(GT);
            #if DAISHO_SOURCEINFO
            expr_ret_370->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_370->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_370 = NULL;
          }

          expr_ret_368 = expr_ret_370;
          gt = expr_ret_370;
        }

        // ModExprList 2
        if (expr_ret_368)
        {
          daisho_astnode_t* expr_ret_371 = NULL;
          expr_ret_371 = daisho_parse_sumexpr(ctx);
          expr_ret_368 = expr_ret_371;
          n = expr_ret_371;
        }

        // ModExprList 3
        if (expr_ret_368)
        {
          // CodeExpr
          #define ret expr_ret_368
          ret = SUCC;

          rule=node(BSR, g, gt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_368) rew(mod_368);
        expr_ret_363 = expr_ret_368;
      }

      // SlashExpr end
      expr_ret_362 = expr_ret_363;

    }

    expr_ret_361 = SUCC;
    expr_ret_359 = expr_ret_361;
  }

  // ModExprList end
  if (!expr_ret_359) rew(mod_359);
  expr_ret_358 = expr_ret_359;
  if (!rule) rule = expr_ret_358;
  if (!expr_ret_358) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_372
  daisho_astnode_t* expr_ret_373 = NULL;
  daisho_astnode_t* expr_ret_372 = NULL;
  daisho_astnode_t* expr_ret_374 = NULL;
  rec(mod_374);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_375 = NULL;
    expr_ret_375 = daisho_parse_multexpr(ctx);
    expr_ret_374 = expr_ret_375;
    n = expr_ret_375;
  }

  // ModExprList 1
  if (expr_ret_374)
  {
    // CodeExpr
    #define ret expr_ret_374
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_374)
  {
    daisho_astnode_t* expr_ret_376 = NULL;
    daisho_astnode_t* expr_ret_377 = SUCC;
    while (expr_ret_377)
    {
      rec(kleene_rew_376);
      daisho_astnode_t* expr_ret_378 = NULL;

      // SlashExpr 0
      if (!expr_ret_378)
      {
        daisho_astnode_t* expr_ret_379 = NULL;
        rec(mod_379);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_380 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Capturing PLUS.
            expr_ret_380 = leaf(PLUS);
            #if DAISHO_SOURCEINFO
            expr_ret_380->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_380->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_380 = NULL;
          }

          expr_ret_379 = expr_ret_380;
          p = expr_ret_380;
        }

        // ModExprList 1
        if (expr_ret_379)
        {
          daisho_astnode_t* expr_ret_381 = NULL;
          expr_ret_381 = daisho_parse_multexpr(ctx);
          expr_ret_379 = expr_ret_381;
          n = expr_ret_381;
        }

        // ModExprList 2
        if (expr_ret_379)
        {
          // CodeExpr
          #define ret expr_ret_379
          ret = SUCC;

          rule=repr(node(PLUS, rule, n), p);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_379) rew(mod_379);
        expr_ret_378 = expr_ret_379;
      }

      // SlashExpr 1
      if (!expr_ret_378)
      {
        daisho_astnode_t* expr_ret_382 = NULL;
        rec(mod_382);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_383 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Capturing MINUS.
            expr_ret_383 = leaf(MINUS);
            #if DAISHO_SOURCEINFO
            expr_ret_383->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_383->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_383 = NULL;
          }

          expr_ret_382 = expr_ret_383;
          m = expr_ret_383;
        }

        // ModExprList 1
        if (expr_ret_382)
        {
          daisho_astnode_t* expr_ret_384 = NULL;
          expr_ret_384 = daisho_parse_multexpr(ctx);
          expr_ret_382 = expr_ret_384;
          n = expr_ret_384;
        }

        // ModExprList 2
        if (expr_ret_382)
        {
          // CodeExpr
          #define ret expr_ret_382
          ret = SUCC;

          rule=repr(node(MINUS, rule, n), m);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_382) rew(mod_382);
        expr_ret_378 = expr_ret_382;
      }

      // SlashExpr end
      expr_ret_377 = expr_ret_378;

    }

    expr_ret_376 = SUCC;
    expr_ret_374 = expr_ret_376;
  }

  // ModExprList end
  if (!expr_ret_374) rew(mod_374);
  expr_ret_373 = expr_ret_374;
  if (!rule) rule = expr_ret_373;
  if (!expr_ret_373) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_385
  daisho_astnode_t* expr_ret_386 = NULL;
  daisho_astnode_t* expr_ret_385 = NULL;
  daisho_astnode_t* expr_ret_387 = NULL;
  rec(mod_387);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_388 = NULL;
    expr_ret_388 = daisho_parse_powexpr(ctx);
    expr_ret_387 = expr_ret_388;
    n = expr_ret_388;
  }

  // ModExprList 1
  if (expr_ret_387)
  {
    // CodeExpr
    #define ret expr_ret_387
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_387)
  {
    daisho_astnode_t* expr_ret_389 = NULL;
    daisho_astnode_t* expr_ret_390 = SUCC;
    while (expr_ret_390)
    {
      rec(kleene_rew_389);
      daisho_astnode_t* expr_ret_391 = NULL;

      // SlashExpr 0
      if (!expr_ret_391)
      {
        daisho_astnode_t* expr_ret_392 = NULL;
        rec(mod_392);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_392 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_392 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_392)
        {
          daisho_astnode_t* expr_ret_393 = NULL;
          expr_ret_393 = daisho_parse_powexpr(ctx);
          expr_ret_392 = expr_ret_393;
          n = expr_ret_393;
        }

        // ModExprList 2
        if (expr_ret_392)
        {
          // CodeExpr
          #define ret expr_ret_392
          ret = SUCC;

          rule=node(STAR, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_392) rew(mod_392);
        expr_ret_391 = expr_ret_392;
      }

      // SlashExpr 1
      if (!expr_ret_391)
      {
        daisho_astnode_t* expr_ret_394 = NULL;
        rec(mod_394);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Not capturing DIV.
            expr_ret_394 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_394 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_394)
        {
          daisho_astnode_t* expr_ret_395 = NULL;
          expr_ret_395 = daisho_parse_powexpr(ctx);
          expr_ret_394 = expr_ret_395;
          n = expr_ret_395;
        }

        // ModExprList 2
        if (expr_ret_394)
        {
          // CodeExpr
          #define ret expr_ret_394
          ret = SUCC;

          rule=node(DIV,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_394) rew(mod_394);
        expr_ret_391 = expr_ret_394;
      }

      // SlashExpr 2
      if (!expr_ret_391)
      {
        daisho_astnode_t* expr_ret_396 = NULL;
        rec(mod_396);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Not capturing MOD.
            expr_ret_396 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_396 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_396)
        {
          daisho_astnode_t* expr_ret_397 = NULL;
          expr_ret_397 = daisho_parse_powexpr(ctx);
          expr_ret_396 = expr_ret_397;
          n = expr_ret_397;
        }

        // ModExprList 2
        if (expr_ret_396)
        {
          // CodeExpr
          #define ret expr_ret_396
          ret = SUCC;

          rule=node(MOD,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_396) rew(mod_396);
        expr_ret_391 = expr_ret_396;
      }

      // SlashExpr end
      expr_ret_390 = expr_ret_391;

    }

    expr_ret_389 = SUCC;
    expr_ret_387 = expr_ret_389;
  }

  // ModExprList end
  if (!expr_ret_387) rew(mod_387);
  expr_ret_386 = expr_ret_387;
  if (!rule) rule = expr_ret_386;
  if (!expr_ret_386) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_398
  daisho_astnode_t* expr_ret_399 = NULL;
  daisho_astnode_t* expr_ret_398 = NULL;
  daisho_astnode_t* expr_ret_400 = NULL;
  rec(mod_400);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_401 = NULL;
    expr_ret_401 = daisho_parse_callexpr(ctx);
    expr_ret_400 = expr_ret_401;
    n = expr_ret_401;
  }

  // ModExprList 1
  if (expr_ret_400)
  {
    // CodeExpr
    #define ret expr_ret_400
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_400)
  {
    daisho_astnode_t* expr_ret_402 = NULL;
    daisho_astnode_t* expr_ret_403 = SUCC;
    while (expr_ret_403)
    {
      rec(kleene_rew_402);
      daisho_astnode_t* expr_ret_404 = NULL;
      rec(mod_404);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_404 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_404 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_404)
      {
        // CodeExpr
        #define ret expr_ret_404
        ret = SUCC;

        rule=node(POW, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_404) rew(mod_404);
      expr_ret_403 = expr_ret_404;
    }

    expr_ret_402 = SUCC;
    expr_ret_400 = expr_ret_402;
  }

  // ModExprList end
  if (!expr_ret_400) rew(mod_400);
  expr_ret_399 = expr_ret_400;
  if (!rule) rule = expr_ret_399;
  if (!expr_ret_399) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_405
  daisho_astnode_t* expr_ret_406 = NULL;
  daisho_astnode_t* expr_ret_405 = NULL;
  daisho_astnode_t* expr_ret_407 = NULL;

  // SlashExpr 0
  if (!expr_ret_407)
  {
    daisho_astnode_t* expr_ret_408 = NULL;
    rec(mod_408);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_408 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_408 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_408)
    {
      daisho_astnode_t* expr_ret_409 = NULL;
      expr_ret_409 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_409)
        expr_ret_409 = SUCC;
      expr_ret_408 = expr_ret_409;
      t = expr_ret_409;
    }

    // ModExprList 2
    if (expr_ret_408)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_408 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_408 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_408)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_408 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_408 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_408) rew(mod_408);
    expr_ret_407 = expr_ret_408;
  }

  // SlashExpr 1
  if (!expr_ret_407)
  {
    daisho_astnode_t* expr_ret_410 = NULL;
    rec(mod_410);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_411 = NULL;
      expr_ret_411 = daisho_parse_castexpr(ctx);
      expr_ret_410 = expr_ret_411;
      n = expr_ret_411;
    }

    // ModExprList 1
    if (expr_ret_410)
    {
      // CodeExpr
      #define ret expr_ret_410
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_410) rew(mod_410);
    expr_ret_407 = expr_ret_410;
  }

  // SlashExpr end
  expr_ret_406 = expr_ret_407;

  if (!rule) rule = expr_ret_406;
  if (!expr_ret_406) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_412
  daisho_astnode_t* expr_ret_413 = NULL;
  daisho_astnode_t* expr_ret_412 = NULL;
  daisho_astnode_t* expr_ret_414 = NULL;
  rec(mod_414);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_415 = NULL;
    expr_ret_415 = daisho_parse_refexpr(ctx);
    expr_ret_414 = expr_ret_415;
    n = expr_ret_415;
  }

  // ModExprList 1
  if (expr_ret_414)
  {
    daisho_astnode_t* expr_ret_416 = NULL;
    daisho_astnode_t* expr_ret_417 = NULL;
    rec(mod_417);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_417 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_417 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_417)
    {
      daisho_astnode_t* expr_ret_418 = NULL;
      expr_ret_418 = daisho_parse_type(ctx);
      expr_ret_417 = expr_ret_418;
      t = expr_ret_418;
    }

    // ModExprList 2
    if (expr_ret_417)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_417 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_417 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_417) rew(mod_417);
    expr_ret_416 = expr_ret_417;
    // optional
    if (!expr_ret_416)
      expr_ret_416 = SUCC;
    expr_ret_414 = expr_ret_416;
  }

  // ModExprList 2
  if (expr_ret_414)
  {
    // CodeExpr
    #define ret expr_ret_414
    ret = SUCC;

    rule = has(t) ? node(CAST, t, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_414) rew(mod_414);
  expr_ret_413 = expr_ret_414;
  if (!rule) rule = expr_ret_413;
  if (!expr_ret_413) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_419
  daisho_astnode_t* expr_ret_420 = NULL;
  daisho_astnode_t* expr_ret_419 = NULL;
  daisho_astnode_t* expr_ret_421 = NULL;
  rec(mod_421);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_422 = NULL;
    expr_ret_422 = daisho_parse_derefexpr(ctx);
    expr_ret_421 = expr_ret_422;
    n = expr_ret_422;
  }

  // ModExprList 1
  if (expr_ret_421)
  {
    daisho_astnode_t* expr_ret_423 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_423 = leaf(REF);
      #if DAISHO_SOURCEINFO
      expr_ret_423->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_423->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_423 = NULL;
    }

    // optional
    if (!expr_ret_423)
      expr_ret_423 = SUCC;
    expr_ret_421 = expr_ret_423;
    r = expr_ret_423;
  }

  // ModExprList 2
  if (expr_ret_421)
  {
    // CodeExpr
    #define ret expr_ret_421
    ret = SUCC;

    rule=has(r) ? node(REF, r, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_421) rew(mod_421);
  expr_ret_420 = expr_ret_421;
  if (!rule) rule = expr_ret_420;
  if (!expr_ret_420) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_424
  daisho_astnode_t* expr_ret_425 = NULL;
  daisho_astnode_t* expr_ret_424 = NULL;
  daisho_astnode_t* expr_ret_426 = NULL;
  rec(mod_426);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_427 = NULL;
    expr_ret_427 = daisho_parse_postretexpr(ctx);
    expr_ret_426 = expr_ret_427;
    n = expr_ret_427;
  }

  // ModExprList 1
  if (expr_ret_426)
  {
    daisho_astnode_t* expr_ret_428 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
      // Capturing DEREF.
      expr_ret_428 = leaf(DEREF);
      #if DAISHO_SOURCEINFO
      expr_ret_428->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_428->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_428 = NULL;
    }

    // optional
    if (!expr_ret_428)
      expr_ret_428 = SUCC;
    expr_ret_426 = expr_ret_428;
    d = expr_ret_428;
  }

  // ModExprList 2
  if (expr_ret_426)
  {
    // CodeExpr
    #define ret expr_ret_426
    ret = SUCC;

    rule=has(d) ? node(REF, d, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_426) rew(mod_426);
  expr_ret_425 = expr_ret_426;
  if (!rule) rule = expr_ret_425;
  if (!expr_ret_425) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  #define rule expr_ret_429
  daisho_astnode_t* expr_ret_430 = NULL;
  daisho_astnode_t* expr_ret_429 = NULL;
  daisho_astnode_t* expr_ret_431 = NULL;
  rec(mod_431);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_432 = NULL;
    expr_ret_432 = daisho_parse_atomexpr(ctx);
    expr_ret_431 = expr_ret_432;
    n = expr_ret_432;
  }

  // ModExprList 1
  if (expr_ret_431)
  {
    daisho_astnode_t* expr_ret_433 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      // Capturing GRAVE.
      expr_ret_433 = leaf(GRAVE);
      #if DAISHO_SOURCEINFO
      expr_ret_433->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_433->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_433 = NULL;
    }

    // optional
    if (!expr_ret_433)
      expr_ret_433 = SUCC;
    expr_ret_431 = expr_ret_433;
    g = expr_ret_433;
  }

  // ModExprList 2
  if (expr_ret_431)
  {
    // CodeExpr
    #define ret expr_ret_431
    ret = SUCC;

    rule=has(g) ? node(RET, g, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_431) rew(mod_431);
  expr_ret_430 = expr_ret_431;
  if (!rule) rule = expr_ret_430;
  if (!expr_ret_430) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_434
  daisho_astnode_t* expr_ret_435 = NULL;
  daisho_astnode_t* expr_ret_434 = NULL;
  daisho_astnode_t* expr_ret_436 = NULL;

  // SlashExpr 0
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_437 = NULL;
    rec(mod_437);
    // ModExprList Forwarding
    expr_ret_437 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_437) rew(mod_437);
    expr_ret_436 = expr_ret_437;
  }

  // SlashExpr 1
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_438 = NULL;
    rec(mod_438);
    // ModExprList Forwarding
    expr_ret_438 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_438) rew(mod_438);
    expr_ret_436 = expr_ret_438;
  }

  // SlashExpr 2
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_439 = NULL;
    rec(mod_439);
    // ModExprList Forwarding
    expr_ret_439 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_439) rew(mod_439);
    expr_ret_436 = expr_ret_439;
  }

  // SlashExpr 3
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_440 = NULL;
    rec(mod_440);
    // ModExprList Forwarding
    expr_ret_440 = daisho_parse_listlit(ctx);
    // ModExprList end
    if (!expr_ret_440) rew(mod_440);
    expr_ret_436 = expr_ret_440;
  }

  // SlashExpr 4
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_441 = NULL;
    rec(mod_441);
    // ModExprList Forwarding
    expr_ret_441 = daisho_parse_tuplelit(ctx);
    // ModExprList end
    if (!expr_ret_441) rew(mod_441);
    expr_ret_436 = expr_ret_441;
  }

  // SlashExpr 5
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_442 = NULL;
    rec(mod_442);
    // ModExprList Forwarding
    expr_ret_442 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_442) rew(mod_442);
    expr_ret_436 = expr_ret_442;
  }

  // SlashExpr 6
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_443 = NULL;
    rec(mod_443);
    // ModExprList Forwarding
    expr_ret_443 = daisho_parse_cfuncexpr(ctx);
    // ModExprList end
    if (!expr_ret_443) rew(mod_443);
    expr_ret_436 = expr_ret_443;
  }

  // SlashExpr 7
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_444 = NULL;
    rec(mod_444);
    // ModExprList Forwarding
    expr_ret_444 = daisho_parse_preretexpr(ctx);
    // ModExprList end
    if (!expr_ret_444) rew(mod_444);
    expr_ret_436 = expr_ret_444;
  }

  // SlashExpr 8
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_445 = NULL;
    rec(mod_445);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_445 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_445->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_445->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_445 = NULL;
    }

    // ModExprList end
    if (!expr_ret_445) rew(mod_445);
    expr_ret_436 = expr_ret_445;
  }

  // SlashExpr 9
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_446 = NULL;
    rec(mod_446);
    // ModExprList Forwarding
    expr_ret_446 = daisho_parse_numlit(ctx);
    // ModExprList end
    if (!expr_ret_446) rew(mod_446);
    expr_ret_436 = expr_ret_446;
  }

  // SlashExpr 10
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_447 = NULL;
    rec(mod_447);
    // ModExprList Forwarding
    expr_ret_447 = daisho_parse_strlit(ctx);
    // ModExprList end
    if (!expr_ret_447) rew(mod_447);
    expr_ret_436 = expr_ret_447;
  }

  // SlashExpr 11
  if (!expr_ret_436)
  {
    daisho_astnode_t* expr_ret_448 = NULL;
    rec(mod_448);
    // ModExprList Forwarding
    expr_ret_448 = daisho_parse_sizeofexpr(ctx);
    // ModExprList end
    if (!expr_ret_448) rew(mod_448);
    expr_ret_436 = expr_ret_448;
  }

  // SlashExpr end
  expr_ret_435 = expr_ret_436;

  if (!rule) rule = expr_ret_435;
  if (!expr_ret_435) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_449
  daisho_astnode_t* expr_ret_450 = NULL;
  daisho_astnode_t* expr_ret_449 = NULL;
  daisho_astnode_t* expr_ret_451 = NULL;
  rec(mod_451);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_451 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_451 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_451)
  {
    // CodeExpr
    #define ret expr_ret_451
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_451)
  {
    daisho_astnode_t* expr_ret_452 = NULL;
    daisho_astnode_t* expr_ret_453 = SUCC;
    while (expr_ret_453)
    {
      rec(kleene_rew_452);
      daisho_astnode_t* expr_ret_454 = NULL;
      rec(mod_454);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_455 = NULL;
        expr_ret_455 = daisho_parse_expr(ctx);
        expr_ret_454 = expr_ret_455;
        e = expr_ret_455;
      }

      // ModExprList 1
      if (expr_ret_454)
      {
        // CodeExpr
        #define ret expr_ret_454
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_454) rew(mod_454);
      expr_ret_453 = expr_ret_454;
    }

    expr_ret_452 = SUCC;
    expr_ret_451 = expr_ret_452;
  }

  // ModExprList 3
  if (expr_ret_451)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_451 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_451 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_451) rew(mod_451);
  expr_ret_450 = expr_ret_451;
  if (!rule) rule = expr_ret_450;
  if (!expr_ret_450) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_456
  daisho_astnode_t* expr_ret_457 = NULL;
  daisho_astnode_t* expr_ret_456 = NULL;
  daisho_astnode_t* expr_ret_458 = NULL;
  rec(mod_458);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_459 = NULL;
    daisho_astnode_t* expr_ret_460 = NULL;
    rec(mod_460);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_460 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_460 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_460)
    {
      daisho_astnode_t* expr_ret_461 = NULL;
      expr_ret_461 = daisho_parse_expr(ctx);
      // optional
      if (!expr_ret_461)
        expr_ret_461 = SUCC;
      expr_ret_460 = expr_ret_461;
    }

    // ModExprList 2
    if (expr_ret_460)
    {
      daisho_astnode_t* expr_ret_462 = NULL;
      daisho_astnode_t* expr_ret_463 = SUCC;
      while (expr_ret_463)
      {
        rec(kleene_rew_462);
        daisho_astnode_t* expr_ret_464 = NULL;
        rec(mod_464);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_464 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_464 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_464)
        {
          expr_ret_464 = daisho_parse_expr(ctx);
        }

        // ModExprList end
        if (!expr_ret_464) rew(mod_464);
        expr_ret_463 = expr_ret_464;
      }

      expr_ret_462 = SUCC;
      expr_ret_460 = expr_ret_462;
    }

    // ModExprList 3
    if (expr_ret_460)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_460 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_460 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_460) rew(mod_460);
    expr_ret_459 = expr_ret_460;
    // optional
    if (!expr_ret_459)
      expr_ret_459 = SUCC;
    expr_ret_458 = expr_ret_459;
  }

  // ModExprList 1
  if (expr_ret_458)
  {
    daisho_astnode_t* expr_ret_465 = NULL;

    // SlashExpr 0
    if (!expr_ret_465)
    {
      daisho_astnode_t* expr_ret_466 = NULL;
      rec(mod_466);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_467 = NULL;
      rec(mod_467);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_467 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_467 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_467)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_467 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_467 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_467) rew(mod_467);
      expr_ret_466 = expr_ret_467;
      // ModExprList end
      if (!expr_ret_466) rew(mod_466);
      expr_ret_465 = expr_ret_466;
    }

    // SlashExpr 1
    if (!expr_ret_465)
    {
      daisho_astnode_t* expr_ret_468 = NULL;
      rec(mod_468);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_469 = NULL;
      rec(mod_469);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_469 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_469 = NULL;
      }

      // ModExprList end
      if (!expr_ret_469) rew(mod_469);
      expr_ret_468 = expr_ret_469;
      // ModExprList end
      if (!expr_ret_468) rew(mod_468);
      expr_ret_465 = expr_ret_468;
    }

    // SlashExpr end
    expr_ret_458 = expr_ret_465;

  }

  // ModExprList 2
  if (expr_ret_458)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_458 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_458 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_458)
  {
    expr_ret_458 = daisho_parse_expr(ctx);
  }

  // ModExprList end
  if (!expr_ret_458) rew(mod_458);
  expr_ret_457 = expr_ret_458;
  if (!rule) rule = expr_ret_457;
  if (!expr_ret_457) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  #define rule expr_ret_470
  daisho_astnode_t* expr_ret_471 = NULL;
  daisho_astnode_t* expr_ret_470 = NULL;
  daisho_astnode_t* expr_ret_472 = NULL;
  rec(mod_472);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_472 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_472 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_472)
  {
    daisho_astnode_t* expr_ret_473 = NULL;
    daisho_astnode_t* expr_ret_474 = NULL;
    rec(mod_474);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_475 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_475 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_475->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_475->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_475 = NULL;
      }

      expr_ret_474 = expr_ret_475;
      cnt = expr_ret_475;
    }

    // ModExprList 1
    if (expr_ret_474)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_474 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_474 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_474) rew(mod_474);
    expr_ret_473 = expr_ret_474;
    // optional
    if (!expr_ret_473)
      expr_ret_473 = SUCC;
    expr_ret_472 = expr_ret_473;
  }

  // ModExprList 2
  if (expr_ret_472)
  {
    expr_ret_472 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_472)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_472 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_472 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_472)
  {
    daisho_astnode_t* expr_ret_476 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_476 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_476->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_476->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_476 = NULL;
    }

    expr_ret_472 = expr_ret_476;
    item = expr_ret_476;
  }

  // ModExprList 5
  if (expr_ret_472)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_472 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_472 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_472)
  {
    expr_ret_472 = daisho_parse_expr(ctx);
  }

  // ModExprList 7
  if (expr_ret_472)
  {
    daisho_astnode_t* expr_ret_477 = NULL;
    daisho_astnode_t* expr_ret_478 = NULL;
    rec(mod_478);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        // Not capturing WHERE.
        expr_ret_478 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_478 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_478)
    {
      expr_ret_478 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_478) rew(mod_478);
    expr_ret_477 = expr_ret_478;
    // optional
    if (!expr_ret_477)
      expr_ret_477 = SUCC;
    expr_ret_472 = expr_ret_477;
  }

  // ModExprList 8
  if (expr_ret_472)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_472 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_472 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_472) rew(mod_472);
  expr_ret_471 = expr_ret_472;
  if (!rule) rule = expr_ret_471;
  if (!expr_ret_471) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_479
  daisho_astnode_t* expr_ret_480 = NULL;
  daisho_astnode_t* expr_ret_479 = NULL;
  daisho_astnode_t* expr_ret_481 = NULL;
  rec(mod_481);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_481 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_481 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_481)
  {
    daisho_astnode_t* expr_ret_482 = NULL;
    expr_ret_482 = daisho_parse_expr(ctx);
    expr_ret_481 = expr_ret_482;
    e = expr_ret_482;
  }

  // ModExprList 2
  if (expr_ret_481)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_481 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_481 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_481)
  {
    // CodeExpr
    #define ret expr_ret_481
    ret = SUCC;

    rule=e;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_481) rew(mod_481);
  expr_ret_480 = expr_ret_481;
  if (!rule) rule = expr_ret_480;
  if (!expr_ret_480) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_483
  daisho_astnode_t* expr_ret_484 = NULL;
  daisho_astnode_t* expr_ret_483 = NULL;
  daisho_astnode_t* expr_ret_485 = NULL;
  rec(mod_485);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_485 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_485 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_485)
  {
    daisho_astnode_t* expr_ret_486 = NULL;
    expr_ret_486 = daisho_parse_expr(ctx);
    expr_ret_485 = expr_ret_486;
    e = expr_ret_486;
  }

  // ModExprList 2
  if (expr_ret_485)
  {
    daisho_astnode_t* expr_ret_487 = NULL;

    // SlashExpr 0
    if (!expr_ret_487)
    {
      daisho_astnode_t* expr_ret_488 = NULL;
      rec(mod_488);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_489 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_489 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_489 = NULL;
        }

        // optional
        if (!expr_ret_489)
          expr_ret_489 = SUCC;
        expr_ret_488 = expr_ret_489;
      }

      // ModExprList 1
      if (expr_ret_488)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_488 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_488 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_488) rew(mod_488);
      expr_ret_487 = expr_ret_488;
    }

    // SlashExpr 1
    if (!expr_ret_487)
    {
      daisho_astnode_t* expr_ret_490 = NULL;
      rec(mod_490);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_491 = NULL;
        daisho_astnode_t* expr_ret_492 = SUCC;
        while (expr_ret_492)
        {
          rec(kleene_rew_491);
          daisho_astnode_t* expr_ret_493 = NULL;
          rec(mod_493);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
              expr_ret_493 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_493 = NULL;
            }

          }

          // ModExprList 1
          if (expr_ret_493)
          {
            daisho_astnode_t* expr_ret_494 = NULL;
            expr_ret_494 = daisho_parse_expr(ctx);
            expr_ret_493 = expr_ret_494;
            e = expr_ret_494;
          }

          // ModExprList end
          if (!expr_ret_493) rew(mod_493);
          expr_ret_492 = expr_ret_493;
        }

        expr_ret_491 = SUCC;
        expr_ret_490 = expr_ret_491;
      }

      // ModExprList 1
      if (expr_ret_490)
      {
        daisho_astnode_t* expr_ret_495 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_495 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_495 = NULL;
        }

        // optional
        if (!expr_ret_495)
          expr_ret_495 = SUCC;
        expr_ret_490 = expr_ret_495;
      }

      // ModExprList 2
      if (expr_ret_490)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_490 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_490 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_490) rew(mod_490);
      expr_ret_487 = expr_ret_490;
    }

    // SlashExpr end
    expr_ret_485 = expr_ret_487;

  }

  // ModExprList end
  if (!expr_ret_485) rew(mod_485);
  expr_ret_484 = expr_ret_485;
  if (!rule) rule = expr_ret_484;
  if (!expr_ret_484) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_496
  daisho_astnode_t* expr_ret_497 = NULL;
  daisho_astnode_t* expr_ret_496 = NULL;
  daisho_astnode_t* expr_ret_498 = NULL;
  rec(mod_498);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_498 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_498 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_498)
  {
    daisho_astnode_t* expr_ret_499 = NULL;
    expr_ret_499 = daisho_parse_expr(ctx);
    expr_ret_498 = expr_ret_499;
    e = expr_ret_499;
  }

  // ModExprList 2
  if (expr_ret_498)
  {
    daisho_astnode_t* expr_ret_500 = NULL;

    // SlashExpr 0
    if (!expr_ret_500)
    {
      daisho_astnode_t* expr_ret_501 = NULL;
      rec(mod_501);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_501 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_501 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_501)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_501 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_501 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_501) rew(mod_501);
      expr_ret_500 = expr_ret_501;
    }

    // SlashExpr 1
    if (!expr_ret_500)
    {
      daisho_astnode_t* expr_ret_502 = NULL;
      rec(mod_502);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_503 = NULL;
        daisho_astnode_t* expr_ret_504 = SUCC;
        while (expr_ret_504)
        {
          rec(kleene_rew_503);
          daisho_astnode_t* expr_ret_505 = NULL;
          rec(mod_505);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
              expr_ret_505 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_505 = NULL;
            }

          }

          // ModExprList 1
          if (expr_ret_505)
          {
            daisho_astnode_t* expr_ret_506 = NULL;
            expr_ret_506 = daisho_parse_expr(ctx);
            expr_ret_505 = expr_ret_506;
            e = expr_ret_506;
          }

          // ModExprList end
          if (!expr_ret_505) rew(mod_505);
          expr_ret_504 = expr_ret_505;
        }

        expr_ret_503 = SUCC;
        expr_ret_502 = expr_ret_503;
      }

      // ModExprList 1
      if (expr_ret_502)
      {
        daisho_astnode_t* expr_ret_507 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_507 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_507 = NULL;
        }

        // optional
        if (!expr_ret_507)
          expr_ret_507 = SUCC;
        expr_ret_502 = expr_ret_507;
      }

      // ModExprList 2
      if (expr_ret_502)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_502 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_502 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_502) rew(mod_502);
      expr_ret_500 = expr_ret_502;
    }

    // SlashExpr end
    expr_ret_498 = expr_ret_500;

  }

  // ModExprList end
  if (!expr_ret_498) rew(mod_498);
  expr_ret_497 = expr_ret_498;
  if (!rule) rule = expr_ret_497;
  if (!expr_ret_497) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_508
  daisho_astnode_t* expr_ret_509 = NULL;
  daisho_astnode_t* expr_ret_508 = NULL;
  daisho_astnode_t* expr_ret_510 = NULL;
  rec(mod_510);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
      // Not capturing CFN.
      expr_ret_510 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_510 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_510)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_510 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_510 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_510) rew(mod_510);
  expr_ret_509 = expr_ret_510;
  if (!rule) rule = expr_ret_509;
  if (!expr_ret_509) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_511
  daisho_astnode_t* expr_ret_512 = NULL;
  daisho_astnode_t* expr_ret_511 = NULL;
  daisho_astnode_t* expr_ret_513 = NULL;
  rec(mod_513);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_514 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_514 = leaf(RET);
      #if DAISHO_SOURCEINFO
      expr_ret_514->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_514->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_514 = NULL;
    }

    expr_ret_513 = expr_ret_514;
    r = expr_ret_514;
  }

  // ModExprList 1
  if (expr_ret_513)
  {
    daisho_astnode_t* expr_ret_515 = NULL;
    expr_ret_515 = daisho_parse_expr(ctx);
    expr_ret_513 = expr_ret_515;
    e = expr_ret_515;
  }

  // ModExprList 2
  if (expr_ret_513)
  {
    // CodeExpr
    #define ret expr_ret_513
    ret = SUCC;

    rule=node(RET, r, e);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_513) rew(mod_513);
  expr_ret_512 = expr_ret_513;
  if (!rule) rule = expr_ret_512;
  if (!expr_ret_512) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* pm = NULL;
  daisho_astnode_t* nl = NULL;
  #define rule expr_ret_516
  daisho_astnode_t* expr_ret_517 = NULL;
  daisho_astnode_t* expr_ret_516 = NULL;
  daisho_astnode_t* expr_ret_518 = NULL;
  rec(mod_518);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_519 = NULL;
    daisho_astnode_t* expr_ret_520 = NULL;

    // SlashExpr 0
    if (!expr_ret_520)
    {
      daisho_astnode_t* expr_ret_521 = NULL;
      rec(mod_521);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
        // Capturing PLUS.
        expr_ret_521 = leaf(PLUS);
        #if DAISHO_SOURCEINFO
        expr_ret_521->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_521->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_521 = NULL;
      }

      // ModExprList end
      if (!expr_ret_521) rew(mod_521);
      expr_ret_520 = expr_ret_521;
    }

    // SlashExpr 1
    if (!expr_ret_520)
    {
      daisho_astnode_t* expr_ret_522 = NULL;
      rec(mod_522);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
        // Capturing MINUS.
        expr_ret_522 = leaf(MINUS);
        #if DAISHO_SOURCEINFO
        expr_ret_522->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_522->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_522 = NULL;
      }

      // ModExprList end
      if (!expr_ret_522) rew(mod_522);
      expr_ret_520 = expr_ret_522;
    }

    // SlashExpr end
    expr_ret_519 = expr_ret_520;

    // optional
    if (!expr_ret_519)
      expr_ret_519 = SUCC;
    expr_ret_518 = expr_ret_519;
    pm = expr_ret_519;
  }

  // ModExprList 1
  if (expr_ret_518)
  {
    daisho_astnode_t* expr_ret_523 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_523 = leaf(NUMLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_523->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_523->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_523 = NULL;
    }

    expr_ret_518 = expr_ret_523;
    nl = expr_ret_523;
  }

  // ModExprList 2
  if (expr_ret_518)
  {
    // CodeExpr
    #define ret expr_ret_518
    ret = SUCC;

    rule = nl;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_518) rew(mod_518);
  expr_ret_517 = expr_ret_518;
  if (!rule) rule = expr_ret_517;
  if (!expr_ret_517) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_524
  daisho_astnode_t* expr_ret_525 = NULL;
  daisho_astnode_t* expr_ret_524 = NULL;
  daisho_astnode_t* expr_ret_526 = NULL;
  rec(mod_526);
  // ModExprList Forwarding
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_526 = leaf(STRLIT);
    #if DAISHO_SOURCEINFO
    expr_ret_526->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_526->len_or_toknum = ctx->tokens[ctx->pos].len;
    #endif
    ctx->pos++;
  } else {
    expr_ret_526 = NULL;
  }

  // ModExprList end
  if (!expr_ret_526) rew(mod_526);
  expr_ret_525 = expr_ret_526;
  if (!rule) rule = expr_ret_525;
  if (!expr_ret_525) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_527
  daisho_astnode_t* expr_ret_528 = NULL;
  daisho_astnode_t* expr_ret_527 = NULL;
  daisho_astnode_t* expr_ret_529 = NULL;
  rec(mod_529);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
      // Not capturing SIZEOF.
      expr_ret_529 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_529 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_529)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_529 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_529 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_529)
  {
    daisho_astnode_t* expr_ret_530 = NULL;

    // SlashExpr 0
    if (!expr_ret_530)
    {
      daisho_astnode_t* expr_ret_531 = NULL;
      rec(mod_531);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_532 = NULL;
      expr_ret_532 = daisho_parse_type(ctx);
      expr_ret_531 = expr_ret_532;
      t = expr_ret_532;
      // ModExprList end
      if (!expr_ret_531) rew(mod_531);
      expr_ret_530 = expr_ret_531;
    }

    // SlashExpr 1
    if (!expr_ret_530)
    {
      daisho_astnode_t* expr_ret_533 = NULL;
      rec(mod_533);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_534 = NULL;
      expr_ret_534 = daisho_parse_expr(ctx);
      expr_ret_533 = expr_ret_534;
      t = expr_ret_534;
      // ModExprList end
      if (!expr_ret_533) rew(mod_533);
      expr_ret_530 = expr_ret_533;
    }

    // SlashExpr end
    expr_ret_529 = expr_ret_530;

  }

  // ModExprList 3
  if (expr_ret_529)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_529 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_529 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_529)
  {
    // CodeExpr
    #define ret expr_ret_529
    ret = SUCC;

    rule=node(SIZEOF, t);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_529) rew(mod_529);
  expr_ret_528 = expr_ret_529;
  if (!rule) rule = expr_ret_528;
  if (!expr_ret_528) rule = NULL;
  return rule;
  #undef rule
}




#undef rec
#undef rew
#undef node
#undef kind
#undef list
#undef leaf
#undef add
#undef has
#undef repr
#undef srepr
#undef rret
#undef SUCC

#undef PGEN_MIN
#undef PGEN_MAX
#undef PGEN_MIN1
#undef PGEN_MAX1
#undef PGEN_MIN2
#undef PGEN_MAX2
#undef PGEN_MIN3
#undef PGEN_MAX3
#undef PGEN_MIN4
#undef PGEN_MAX4
#undef PGEN_MIN5
#undef PGEN_MAX5

#endif /* PGEN_DAISHO_ASTNODE_INCLUDE */

