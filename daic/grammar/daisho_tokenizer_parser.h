
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
// Tokens 1 through 82 are the ones you defined.
// This totals 84 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 84
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
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;

  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 10;
        else if (c == 35 /*'#'*/) trie_state = 112;
        else if (c == 36 /*'$'*/) trie_state = 114;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 40 /*'('*/) trie_state = 106;
        else if (c == 41 /*')'*/) trie_state = 107;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 105;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 104;
        else if (c == 47 /*'/'*/) trie_state = 5;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 103;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 113;
        else if (c == 70 /*'F'*/) trie_state = 70;
        else if (c == 83 /*'S'*/) trie_state = 79;
        else if (c == 86 /*'V'*/) trie_state = 87;
        else if (c == 91 /*'['*/) trie_state = 110;
        else if (c == 93 /*']'*/) trie_state = 111;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 115;
        else if (c == 97 /*'a'*/) trie_state = 53;
        else if (c == 99 /*'c'*/) trie_state = 72;
        else if (c == 102 /*'f'*/) trie_state = 39;
        else if (c == 105 /*'i'*/) trie_state = 42;
        else if (c == 110 /*'n'*/) trie_state = 94;
        else if (c == 115 /*'s'*/) trie_state = 83;
        else if (c == 116 /*'t'*/) trie_state = 49;
        else if (c == 117 /*'u'*/) trie_state = 60;
        else if (c == 119 /*'w'*/) trie_state = 44;
        else if (c == 123 /*'{'*/) trie_state = 108;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 109;
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
        else if (c == 62 /*'>'*/) trie_state = 116;
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
        else if (c == 62 /*'>'*/) trie_state = 117;
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
        if (c == 97 /*'a'*/) trie_state = 95;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 109 /*'m'*/) trie_state = 96;
        else trie_state = -1;
      }
      else if (trie_state == 96) {
        if (c == 101 /*'e'*/) trie_state = 97;
        else trie_state = -1;
      }
      else if (trie_state == 97) {
        if (c == 115 /*'s'*/) trie_state = 98;
        else trie_state = -1;
      }
      else if (trie_state == 98) {
        if (c == 112 /*'p'*/) trie_state = 99;
        else trie_state = -1;
      }
      else if (trie_state == 99) {
        if (c == 97 /*'a'*/) trie_state = 100;
        else trie_state = -1;
      }
      else if (trie_state == 100) {
        if (c == 99 /*'c'*/) trie_state = 101;
        else trie_state = -1;
      }
      else if (trie_state == 101) {
        if (c == 101 /*'e'*/) trie_state = 102;
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
      else if (trie_state == 102) {
        trie_tokenkind =  DAISHO_TOK_NAMESPACE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 103) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 104) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 106) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 107) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 114) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 115) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 116) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 117) {
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

    // Transition RET State Machine
    if (smaut_state_2 != -1) {
      all_dead = 0;

      if ((smaut_state_2 == 0) &
         (c == 114)) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 101)) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 116)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 117)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 114)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 110)) {
          smaut_state_2 = 6;
      }
      else {
        smaut_state_2 = -1;
      }

      // Check accept
      if ((smaut_state_2 == 3) | (smaut_state_2 == 6)) {
        smaut_munch_size_2 = iidx + 1;
      }
    }

    // Transition OP State Machine
    if (smaut_state_3 != -1) {
      all_dead = 0;

      if ((smaut_state_3 == 0) &
         (c == 111)) {
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 1) &
         (c == 112)) {
          smaut_state_3 = 2;
      }
      else if ((smaut_state_3 == 2) &
         (c == 101)) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 114)) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 97)) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 5) &
         (c == 116)) {
          smaut_state_3 = 6;
      }
      else if ((smaut_state_3 == 6) &
         (c == 111)) {
          smaut_state_3 = 7;
      }
      else if ((smaut_state_3 == 7) &
         (c == 114)) {
          smaut_state_3 = 8;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 2) | (smaut_state_3 == 8)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition REDEF State Machine
    if (smaut_state_4 != -1) {
      all_dead = 0;

      if ((smaut_state_4 == 0) &
         (c == 114)) {
          smaut_state_4 = 1;
      }
      else if ((smaut_state_4 == 1) &
         (c == 101)) {
          smaut_state_4 = 2;
      }
      else if ((smaut_state_4 == 2) &
         (c == 100)) {
          smaut_state_4 = 3;
      }
      else if ((smaut_state_4 == 3) &
         (c == 101)) {
          smaut_state_4 = 4;
      }
      else if ((smaut_state_4 == 4) &
         (c == 102)) {
          smaut_state_4 = 5;
      }
      else if ((smaut_state_4 == 5) &
         (c == 105)) {
          smaut_state_4 = 6;
      }
      else if ((smaut_state_4 == 6) &
         (c == 110)) {
          smaut_state_4 = 7;
      }
      else if ((smaut_state_4 == 7) &
         (c == 101)) {
          smaut_state_4 = 8;
      }
      else {
        smaut_state_4 = -1;
      }

      // Check accept
      if ((smaut_state_4 == 5) | (smaut_state_4 == 8)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition TYPEIDENT State Machine
    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         (((c >= 65) & (c <= 90)))) {
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

    // Transition VARIDENT State Machine
    if (smaut_state_6 != -1) {
      all_dead = 0;

      if ((smaut_state_6 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
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

    // Transition CIDENT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
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

    // Transition NUMLIT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 == 0) | (smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_8 = 2;
      }
      else if ((smaut_state_8 == 2) &
         (c == 46)) {
          smaut_state_8 = 3;
      }
      else if ((smaut_state_8 == 3) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_8 = 3;
      }
      else {
        smaut_state_8 = -1;
      }

      // Check accept
      if ((smaut_state_8 == 2) | (smaut_state_8 == 3)) {
        smaut_munch_size_8 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         (c == 34)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 1) &
         (c == 34)) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 1) &
         (c == 10)) {
          smaut_state_9 = 9;
      }
      else if ((smaut_state_9 == 1) &
         (c == 92)) {
          smaut_state_9 = 3;
      }
      else if ((smaut_state_9 == 1) &
         (1)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 110)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 102)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 98)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 114)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 116)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 101)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 92)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 39)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 34)) {
          smaut_state_9 = 1;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if (smaut_state_9 == 2) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if (((smaut_state_10 == 0) | (smaut_state_10 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_10 = 1;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if (smaut_state_10 == 1) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 47)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 42)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 2) &
         (c == 42)) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 2) &
         (1)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 3) &
         (c == 42)) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 3) &
         (c == 47)) {
          smaut_state_11 = 4;
      }
      else if ((smaut_state_11 == 3) &
         (1)) {
          smaut_state_11 = 2;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if (smaut_state_11 == 4) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 47)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 47)) {
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
      if ((smaut_state_12 == 2) | (smaut_state_12 == 3)) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == 35)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 33)) {
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
      if (smaut_state_13 == 3) {
        smaut_munch_size_13 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_CIDENT;
    max_munch = smaut_munch_size_7;
  }
  if (smaut_munch_size_6 >= max_munch) {
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_6;
  }
  if (smaut_munch_size_5 >= max_munch) {
    kind = DAISHO_TOK_TYPEIDENT;
    max_munch = smaut_munch_size_5;
  }
  if (smaut_munch_size_4 >= max_munch) {
    kind = DAISHO_TOK_REDEF;
    max_munch = smaut_munch_size_4;
  }
  if (smaut_munch_size_3 >= max_munch) {
    kind = DAISHO_TOK_OP;
    max_munch = smaut_munch_size_3;
  }
  if (smaut_munch_size_2 >= max_munch) {
    kind = DAISHO_TOK_RET;
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
  DAISHO_NODE_PROG,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_GLOBALSCOPE,
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

#define DAISHO_NUM_NODEKINDS 80
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_PROG",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_NAMESPACE",
  "DAISHO_NODE_GLOBALSCOPE",
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
#define rret(node)               do {rule=node;goto rule_end;} while(0)
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

static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx);
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


static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
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
    expr_ret_2 = daisho_parse_topdecl(ctx);
  }

  // ModExprList 2
  if (expr_ret_2)
  {
    daisho_astnode_t* expr_ret_4 = NULL;
    expr_ret_4 = SUCC;
    while (expr_ret_4)
    {
      daisho_astnode_t* expr_ret_5 = NULL;
      rec(mod_5);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
          // Not capturing SEMI.
          expr_ret_5 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_5 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_5)
      {
        expr_ret_5 = daisho_parse_topdecl(ctx);
      }

      // ModExprList end
      if (!expr_ret_5) rew(mod_5);
      expr_ret_4 = expr_ret_5 ? SUCC : NULL;
    }

    expr_ret_4 = SUCC;
    expr_ret_2 = expr_ret_4;
  }

  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2 ? SUCC : NULL;
  if (!rule) rule = expr_ret_1;
  if (!expr_ret_1) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_6

  daisho_astnode_t* expr_ret_7 = NULL;
  daisho_astnode_t* expr_ret_6 = NULL;
  daisho_astnode_t* expr_ret_8 = NULL;

  rec(slash_8);

  // SlashExpr 0
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_9 = NULL;
    rec(mod_9);
    // ModExprList Forwarding
    expr_ret_9 = daisho_parse_structdecl(ctx);
    // ModExprList end
    if (!expr_ret_9) rew(mod_9);
    expr_ret_8 = expr_ret_9;
  }

  // SlashExpr 1
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_10 = NULL;
    rec(mod_10);
    // ModExprList Forwarding
    expr_ret_10 = daisho_parse_uniondecl(ctx);
    // ModExprList end
    if (!expr_ret_10) rew(mod_10);
    expr_ret_8 = expr_ret_10;
  }

  // SlashExpr 2
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_11 = NULL;
    rec(mod_11);
    // ModExprList Forwarding
    expr_ret_11 = daisho_parse_traitdecl(ctx);
    // ModExprList end
    if (!expr_ret_11) rew(mod_11);
    expr_ret_8 = expr_ret_11;
  }

  // SlashExpr 3
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_12 = NULL;
    rec(mod_12);
    // ModExprList Forwarding
    expr_ret_12 = daisho_parse_fndecl(ctx);
    // ModExprList end
    if (!expr_ret_12) rew(mod_12);
    expr_ret_8 = expr_ret_12;
  }

  // SlashExpr 4
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_13 = NULL;
    rec(mod_13);
    // ModExprList Forwarding
    expr_ret_13 = daisho_parse_impldecl(ctx);
    // ModExprList end
    if (!expr_ret_13) rew(mod_13);
    expr_ret_8 = expr_ret_13;
  }

  // SlashExpr 5
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    rec(mod_14);
    // ModExprList Forwarding
    expr_ret_14 = daisho_parse_nsdecl(ctx);
    // ModExprList end
    if (!expr_ret_14) rew(mod_14);
    expr_ret_8 = expr_ret_14;
  }

  // SlashExpr end
  if (!expr_ret_8) rew(slash_8);
  expr_ret_7 = expr_ret_8;

  if (!rule) rule = expr_ret_7;
  if (!expr_ret_7) rule = NULL;
  rule_end:;
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
  #define rule expr_ret_15

  daisho_astnode_t* expr_ret_16 = NULL;
  daisho_astnode_t* expr_ret_15 = NULL;
  daisho_astnode_t* expr_ret_17 = NULL;
  rec(mod_17);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      // Not capturing STRUCT.
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_18 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_18 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_18->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_18->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_18 = NULL;
    }

    expr_ret_17 = expr_ret_18;
    id = expr_ret_18;
  }

  // ModExprList 2
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_19 = NULL;
    expr_ret_19 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_19)
      expr_ret_19 = SUCC;
    expr_ret_17 = expr_ret_19;
    tmpl = expr_ret_19;
  }

  // ModExprList 3
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_20 = NULL;
    daisho_astnode_t* expr_ret_21 = NULL;
    rec(mod_21);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_21 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_21 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_21)
    {
      expr_ret_21 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_21)
    {
      daisho_astnode_t* expr_ret_22 = NULL;
      expr_ret_22 = SUCC;
      while (expr_ret_22)
      {
        daisho_astnode_t* expr_ret_23 = NULL;
        rec(mod_23);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_23 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_23 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_23)
        {
          expr_ret_23 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_23) rew(mod_23);
        expr_ret_22 = expr_ret_23 ? SUCC : NULL;
      }

      expr_ret_22 = SUCC;
      expr_ret_21 = expr_ret_22;
    }

    // ModExprList end
    if (!expr_ret_21) rew(mod_21);
    expr_ret_20 = expr_ret_21 ? SUCC : NULL;
    // optional
    if (!expr_ret_20)
      expr_ret_20 = SUCC;
    expr_ret_17 = expr_ret_20;
    impl = expr_ret_20;
  }

  // ModExprList 4
  if (expr_ret_17)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_24 = NULL;
    // CodeExpr
    #define ret expr_ret_24
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_17 = expr_ret_24;
    members = expr_ret_24;
  }

  // ModExprList 6
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_25 = NULL;
    expr_ret_25 = SUCC;
    while (expr_ret_25)
    {
      daisho_astnode_t* expr_ret_26 = NULL;
      rec(mod_26);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_27 = NULL;
        expr_ret_27 = daisho_parse_typemember(ctx);
        expr_ret_26 = expr_ret_27;
        m = expr_ret_27;
      }

      // ModExprList 1
      if (expr_ret_26)
      {
        // CodeExpr
        #define ret expr_ret_26
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_26) rew(mod_26);
      expr_ret_25 = expr_ret_26 ? SUCC : NULL;
    }

    expr_ret_25 = SUCC;
    expr_ret_17 = expr_ret_25;
  }

  // ModExprList 7
  if (expr_ret_17)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_28 = NULL;
    // CodeExpr
    #define ret expr_ret_28
    ret = SUCC;

    n = node(STRUCT, id, members);
              rule = (tmpl != SUCC) ? node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_17 = expr_ret_28;
    n = expr_ret_28;
  }

  // ModExprList end
  if (!expr_ret_17) rew(mod_17);
  expr_ret_16 = expr_ret_17 ? SUCC : NULL;
  if (!rule) rule = expr_ret_16;
  if (!expr_ret_16) rule = NULL;
  rule_end:;
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
  #define rule expr_ret_29

  daisho_astnode_t* expr_ret_30 = NULL;
  daisho_astnode_t* expr_ret_29 = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
  rec(mod_31);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      // Not capturing UNION.
      expr_ret_31 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_32 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_32 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_32->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_32->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

    expr_ret_31 = expr_ret_32;
    id = expr_ret_32;
  }

  // ModExprList 2
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_33 = NULL;
    expr_ret_33 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_33)
      expr_ret_33 = SUCC;
    expr_ret_31 = expr_ret_33;
    tmpl = expr_ret_33;
  }

  // ModExprList 3
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_34 = NULL;
    daisho_astnode_t* expr_ret_35 = NULL;
    rec(mod_35);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_35 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_35 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_35)
    {
      expr_ret_35 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_35)
    {
      daisho_astnode_t* expr_ret_36 = NULL;
      expr_ret_36 = SUCC;
      while (expr_ret_36)
      {
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
        expr_ret_36 = expr_ret_37 ? SUCC : NULL;
      }

      expr_ret_36 = SUCC;
      expr_ret_35 = expr_ret_36;
    }

    // ModExprList end
    if (!expr_ret_35) rew(mod_35);
    expr_ret_34 = expr_ret_35 ? SUCC : NULL;
    // optional
    if (!expr_ret_34)
      expr_ret_34 = SUCC;
    expr_ret_31 = expr_ret_34;
    impl = expr_ret_34;
  }

  // ModExprList 4
  if (expr_ret_31)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_31 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_38 = NULL;
    // CodeExpr
    #define ret expr_ret_38
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_31 = expr_ret_38;
    members = expr_ret_38;
  }

  // ModExprList 6
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_39 = NULL;
    expr_ret_39 = SUCC;
    while (expr_ret_39)
    {
      daisho_astnode_t* expr_ret_40 = NULL;
      rec(mod_40);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_41 = NULL;
        expr_ret_41 = daisho_parse_typemember(ctx);
        expr_ret_40 = expr_ret_41;
        m = expr_ret_41;
      }

      // ModExprList 1
      if (expr_ret_40)
      {
        // CodeExpr
        #define ret expr_ret_40
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_40) rew(mod_40);
      expr_ret_39 = expr_ret_40 ? SUCC : NULL;
    }

    expr_ret_39 = SUCC;
    expr_ret_31 = expr_ret_39;
  }

  // ModExprList 7
  if (expr_ret_31)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_31 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_31)
  {
    daisho_astnode_t* expr_ret_42 = NULL;
    // CodeExpr
    #define ret expr_ret_42
    ret = SUCC;

    n = node(UNION, id, members);
              rule = (tmpl != SUCC) ? node(TMPLUNION, tmpl, n) : n;

    #undef ret
    expr_ret_31 = expr_ret_42;
    n = expr_ret_42;
  }

  // ModExprList end
  if (!expr_ret_31) rew(mod_31);
  expr_ret_30 = expr_ret_31 ? SUCC : NULL;
  if (!rule) rule = expr_ret_30;
  if (!expr_ret_30) rule = NULL;
  rule_end:;
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
  #define rule expr_ret_43

  daisho_astnode_t* expr_ret_44 = NULL;
  daisho_astnode_t* expr_ret_43 = NULL;
  daisho_astnode_t* expr_ret_45 = NULL;
  rec(mod_45);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      // Not capturing TRAIT.
      expr_ret_45 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_45 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_46 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_46 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_46->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_46->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_46 = NULL;
    }

    expr_ret_45 = expr_ret_46;
    id = expr_ret_46;
  }

  // ModExprList 2
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_47 = NULL;
    expr_ret_47 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_47)
      expr_ret_47 = SUCC;
    expr_ret_45 = expr_ret_47;
    tmpl = expr_ret_47;
  }

  // ModExprList 3
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_48 = NULL;
    daisho_astnode_t* expr_ret_49 = NULL;
    rec(mod_49);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_49 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_49 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_49)
    {
      expr_ret_49 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_49)
    {
      daisho_astnode_t* expr_ret_50 = NULL;
      expr_ret_50 = SUCC;
      while (expr_ret_50)
      {
        daisho_astnode_t* expr_ret_51 = NULL;
        rec(mod_51);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_51 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_51 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_51)
        {
          expr_ret_51 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_51) rew(mod_51);
        expr_ret_50 = expr_ret_51 ? SUCC : NULL;
      }

      expr_ret_50 = SUCC;
      expr_ret_49 = expr_ret_50;
    }

    // ModExprList end
    if (!expr_ret_49) rew(mod_49);
    expr_ret_48 = expr_ret_49 ? SUCC : NULL;
    // optional
    if (!expr_ret_48)
      expr_ret_48 = SUCC;
    expr_ret_45 = expr_ret_48;
    impl = expr_ret_48;
  }

  // ModExprList 4
  if (expr_ret_45)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_45 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_45 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_52 = NULL;
    // CodeExpr
    #define ret expr_ret_52
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_45 = expr_ret_52;
    members = expr_ret_52;
  }

  // ModExprList 6
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_53 = NULL;
    expr_ret_53 = SUCC;
    while (expr_ret_53)
    {
      daisho_astnode_t* expr_ret_54 = NULL;
      rec(mod_54);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_55 = NULL;
        expr_ret_55 = daisho_parse_fnmember(ctx);
        expr_ret_54 = expr_ret_55;
        m = expr_ret_55;
      }

      // ModExprList 1
      if (expr_ret_54)
      {
        // CodeExpr
        #define ret expr_ret_54
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_54) rew(mod_54);
      expr_ret_53 = expr_ret_54 ? SUCC : NULL;
    }

    expr_ret_53 = SUCC;
    expr_ret_45 = expr_ret_53;
  }

  // ModExprList 7
  if (expr_ret_45)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_45 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_45 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_45)
  {
    daisho_astnode_t* expr_ret_56 = NULL;
    // CodeExpr
    #define ret expr_ret_56
    ret = SUCC;

    n = node(TRAIT, id, members);
              rule = (tmpl != SUCC) ? node(TMPLTRAIT, tmpl, n) : n;

    #undef ret
    expr_ret_45 = expr_ret_56;
    n = expr_ret_56;
  }

  // ModExprList end
  if (!expr_ret_45) rew(mod_45);
  expr_ret_44 = expr_ret_45 ? SUCC : NULL;
  if (!rule) rule = expr_ret_44;
  if (!expr_ret_44) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_57

  daisho_astnode_t* expr_ret_58 = NULL;
  daisho_astnode_t* expr_ret_57 = NULL;
  daisho_astnode_t* expr_ret_59 = NULL;
  rec(mod_59);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Not capturing FN.
      expr_ret_59 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_59 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_59)
  {
    expr_ret_59 = daisho_parse_fnproto(ctx);
  }

  // ModExprList 2
  if (expr_ret_59)
  {
    daisho_astnode_t* expr_ret_60 = NULL;
    expr_ret_60 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_60)
      expr_ret_60 = SUCC;
    expr_ret_59 = expr_ret_60;
  }

  // ModExprList 3
  if (expr_ret_59)
  {
    expr_ret_59 = daisho_parse_expr(ctx);
  }

  // ModExprList end
  if (!expr_ret_59) rew(mod_59);
  expr_ret_58 = expr_ret_59 ? SUCC : NULL;
  if (!rule) rule = expr_ret_58;
  if (!expr_ret_58) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_61

  daisho_astnode_t* expr_ret_62 = NULL;
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_63 = NULL;
  rec(mod_63);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_63)
  {
    daisho_astnode_t* expr_ret_64 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_64 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_64->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_64->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_64 = NULL;
    }

    expr_ret_63 = expr_ret_64;
    tt = expr_ret_64;
  }

  // ModExprList 2
  if (expr_ret_63)
  {
    daisho_astnode_t* expr_ret_65 = NULL;
    expr_ret_65 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_65)
      expr_ret_65 = SUCC;
    expr_ret_63 = expr_ret_65;
  }

  // ModExprList 3
  if (expr_ret_63)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_63)
  {
    daisho_astnode_t* expr_ret_66 = NULL;
    expr_ret_66 = daisho_parse_type(ctx);
    expr_ret_63 = expr_ret_66;
    ft = expr_ret_66;
  }

  // ModExprList 5
  if (expr_ret_63)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_63)
  {
    daisho_astnode_t* expr_ret_67 = NULL;
    // CodeExpr
    #define ret expr_ret_67
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_63 = expr_ret_67;
    members = expr_ret_67;
  }

  // ModExprList 7
  if (expr_ret_63)
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
        expr_ret_70 = daisho_parse_fnmember(ctx);
        expr_ret_69 = expr_ret_70;
        m = expr_ret_70;
      }

      // ModExprList 1
      if (expr_ret_69)
      {
        // CodeExpr
        #define ret expr_ret_69
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_69) rew(mod_69);
      expr_ret_68 = expr_ret_69 ? SUCC : NULL;
    }

    expr_ret_68 = SUCC;
    expr_ret_63 = expr_ret_68;
  }

  // ModExprList 8
  if (expr_ret_63)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_63) rew(mod_63);
  expr_ret_62 = expr_ret_63 ? SUCC : NULL;
  if (!rule) rule = expr_ret_62;
  if (!expr_ret_62) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_71

  daisho_astnode_t* expr_ret_72 = NULL;
  daisho_astnode_t* expr_ret_71 = NULL;
  daisho_astnode_t* expr_ret_73 = NULL;
  rec(mod_73);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_74 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Capturing NAMESPACE.
      expr_ret_74 = leaf(NAMESPACE);
      #if DAISHO_SOURCEINFO
      expr_ret_74->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_74->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_74 = NULL;
    }

    expr_ret_73 = expr_ret_74;
    ns = expr_ret_74;
  }

  // ModExprList 1
  if (expr_ret_73)
  {
    daisho_astnode_t* expr_ret_75 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_75 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_75->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_75->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_75 = NULL;
    }

    expr_ret_73 = expr_ret_75;
    t = expr_ret_75;
  }

  // ModExprList 2
  if (expr_ret_73)
  {
    // CodeExpr
    #define ret expr_ret_73
    ret = SUCC;

    rule=node(NAMESPACE, t);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_73) rew(mod_73);
  expr_ret_72 = expr_ret_73 ? SUCC : NULL;
  if (!rule) rule = expr_ret_72;
  if (!expr_ret_72) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_76

  daisho_astnode_t* expr_ret_77 = NULL;
  daisho_astnode_t* expr_ret_76 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  rec(mod_78);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_79 = NULL;
    expr_ret_79 = daisho_parse_type(ctx);
    expr_ret_78 = expr_ret_79;
    t = expr_ret_79;
  }

  // ModExprList 1
  if (expr_ret_78)
  {
    daisho_astnode_t* expr_ret_80 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_80 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_80->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_80->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_80 = NULL;
    }

    expr_ret_78 = expr_ret_80;
    v = expr_ret_80;
  }

  // ModExprList 2
  if (expr_ret_78)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_78 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_78 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_78)
  {
    // CodeExpr
    #define ret expr_ret_78
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_78) rew(mod_78);
  expr_ret_77 = expr_ret_78 ? SUCC : NULL;
  if (!rule) rule = expr_ret_77;
  if (!expr_ret_77) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_81

  daisho_astnode_t* expr_ret_82 = NULL;
  daisho_astnode_t* expr_ret_81 = NULL;
  daisho_astnode_t* expr_ret_83 = NULL;
  rec(mod_83);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_84 = NULL;
    daisho_astnode_t* expr_ret_85 = NULL;

    rec(slash_85);

    // SlashExpr 0
    if (!expr_ret_85)
    {
      daisho_astnode_t* expr_ret_86 = NULL;
      rec(mod_86);
      // ModExprList Forwarding
      expr_ret_86 = daisho_parse_fndecl(ctx);
      // ModExprList end
      if (!expr_ret_86) rew(mod_86);
      expr_ret_85 = expr_ret_86;
    }

    // SlashExpr 1
    if (!expr_ret_85)
    {
      daisho_astnode_t* expr_ret_87 = NULL;
      rec(mod_87);
      // ModExprList Forwarding
      expr_ret_87 = daisho_parse_fnproto(ctx);
      // ModExprList end
      if (!expr_ret_87) rew(mod_87);
      expr_ret_85 = expr_ret_87;
    }

    // SlashExpr end
    if (!expr_ret_85) rew(slash_85);
    expr_ret_84 = expr_ret_85;

    expr_ret_83 = expr_ret_84;
    r = expr_ret_84;
  }

  // ModExprList 1
  if (expr_ret_83)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_83 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_83 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_83)
  {
    // CodeExpr
    #define ret expr_ret_83
    ret = SUCC;

    rule=r;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_83) rew(mod_83);
  expr_ret_82 = expr_ret_83 ? SUCC : NULL;
  if (!rule) rule = expr_ret_82;
  if (!expr_ret_82) rule = NULL;
  rule_end:;
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
  #define rule expr_ret_88

  daisho_astnode_t* expr_ret_89 = NULL;
  daisho_astnode_t* expr_ret_88 = NULL;
  daisho_astnode_t* expr_ret_90 = NULL;

  rec(slash_90);

  // SlashExpr 0
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_91 = NULL;
    rec(mod_91);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_92 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_92 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_92->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_92->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_92 = NULL;
      }

      expr_ret_91 = expr_ret_92;
      v = expr_ret_92;
    }

    // ModExprList 1
    if (expr_ret_91)
    {
      daisho_astnode_t* expr_ret_93 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_93 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_93 = NULL;
      }

      // invert
      expr_ret_93 = expr_ret_93 ? NULL : SUCC;
      expr_ret_91 = expr_ret_93;
    }

    // ModExprList 2
    if (expr_ret_91)
    {
      // CodeExpr
      #define ret expr_ret_91
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_91) rew(mod_91);
    expr_ret_90 = expr_ret_91 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_94 = NULL;
    rec(mod_94);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_95 = NULL;
      expr_ret_95 = daisho_parse_voidptr(ctx);
      expr_ret_94 = expr_ret_95;
      v = expr_ret_95;
    }

    // ModExprList 1
    if (expr_ret_94)
    {
      daisho_astnode_t* expr_ret_96 = NULL;
      expr_ret_96 = SUCC;
      while (expr_ret_96)
      {
        daisho_astnode_t* expr_ret_97 = NULL;
        rec(mod_97);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_97 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_97 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_97)
        {
          // CodeExpr
          #define ret expr_ret_97
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_97) rew(mod_97);
        expr_ret_96 = expr_ret_97 ? SUCC : NULL;
      }

      expr_ret_96 = SUCC;
      expr_ret_94 = expr_ret_96;
    }

    // ModExprList 2
    if (expr_ret_94)
    {
      // CodeExpr
      #define ret expr_ret_94
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_94) rew(mod_94);
    expr_ret_90 = expr_ret_94 ? SUCC : NULL;
  }

  // SlashExpr 2
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_98 = NULL;
    rec(mod_98);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_99 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
        // Capturing SELFTYPE.
        expr_ret_99 = leaf(SELFTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_99->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_99->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_99 = NULL;
      }

      expr_ret_98 = expr_ret_99;
      s = expr_ret_99;
    }

    // ModExprList 1
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
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_101 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_101 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_101)
        {
          // CodeExpr
          #define ret expr_ret_101
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_101) rew(mod_101);
        expr_ret_100 = expr_ret_101 ? SUCC : NULL;
      }

      expr_ret_100 = SUCC;
      expr_ret_98 = expr_ret_100;
    }

    // ModExprList 2
    if (expr_ret_98)
    {
      // CodeExpr
      #define ret expr_ret_98
      ret = SUCC;

      rule=node(TYPE, s);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_98) rew(mod_98);
    expr_ret_90 = expr_ret_98 ? SUCC : NULL;
  }

  // SlashExpr 3
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_102 = NULL;
    rec(mod_102);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_103 = NULL;
      expr_ret_103 = daisho_parse_traittype(ctx);
      expr_ret_102 = expr_ret_103;
      t = expr_ret_103;
    }

    // ModExprList 1
    if (expr_ret_102)
    {
      daisho_astnode_t* expr_ret_104 = NULL;
      expr_ret_104 = SUCC;
      while (expr_ret_104)
      {
        daisho_astnode_t* expr_ret_105 = NULL;
        rec(mod_105);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_105 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_105 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_105)
        {
          // CodeExpr
          #define ret expr_ret_105
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_105) rew(mod_105);
        expr_ret_104 = expr_ret_105 ? SUCC : NULL;
      }

      expr_ret_104 = SUCC;
      expr_ret_102 = expr_ret_104;
    }

    // ModExprList 2
    if (expr_ret_102)
    {
      // CodeExpr
      #define ret expr_ret_102
      ret = SUCC;

      rule=node(TYPE, t);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_102) rew(mod_102);
    expr_ret_90 = expr_ret_102 ? SUCC : NULL;
  }

  // SlashExpr 4
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_106 = NULL;
    rec(mod_106);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_107 = NULL;
      expr_ret_107 = daisho_parse_structtype(ctx);
      expr_ret_106 = expr_ret_107;
      s = expr_ret_107;
    }

    // ModExprList 1
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
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_109 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_109 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_109)
        {
          // CodeExpr
          #define ret expr_ret_109
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_109) rew(mod_109);
        expr_ret_108 = expr_ret_109 ? SUCC : NULL;
      }

      expr_ret_108 = SUCC;
      expr_ret_106 = expr_ret_108;
    }

    // ModExprList 2
    if (expr_ret_106)
    {
      // CodeExpr
      #define ret expr_ret_106
      ret = SUCC;

      rule=node(TYPE, t);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_106) rew(mod_106);
    expr_ret_90 = expr_ret_106 ? SUCC : NULL;
  }

  // SlashExpr 5
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_110 = NULL;
    rec(mod_110);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_111 = NULL;
      expr_ret_111 = daisho_parse_fntype(ctx);
      expr_ret_110 = expr_ret_111;
      f = expr_ret_111;
    }

    // ModExprList 1
    if (expr_ret_110)
    {
      daisho_astnode_t* expr_ret_112 = NULL;
      expr_ret_112 = SUCC;
      while (expr_ret_112)
      {
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
        expr_ret_112 = expr_ret_113 ? SUCC : NULL;
      }

      expr_ret_112 = SUCC;
      expr_ret_110 = expr_ret_112;
    }

    // ModExprList 2
    if (expr_ret_110)
    {
      // CodeExpr
      #define ret expr_ret_110
      ret = SUCC;

      rule=node(TYPE, f);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_110) rew(mod_110);
    expr_ret_90 = expr_ret_110 ? SUCC : NULL;
  }

  // SlashExpr 6
  if (!expr_ret_90)
  {
    daisho_astnode_t* expr_ret_114 = NULL;
    rec(mod_114);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_115 = NULL;
      expr_ret_115 = daisho_parse_ctypedecl(ctx);
      expr_ret_114 = expr_ret_115;
      c = expr_ret_115;
    }

    // ModExprList 1
    if (expr_ret_114)
    {
      // CodeExpr
      #define ret expr_ret_114
      ret = SUCC;

      rule=node(TYPE, c);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_114) rew(mod_114);
    expr_ret_90 = expr_ret_114 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_90) rew(slash_90);
  expr_ret_89 = expr_ret_90;

  if (!rule) rule = expr_ret_89;
  if (!expr_ret_89) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_116

  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_116 = NULL;
  daisho_astnode_t* expr_ret_118 = NULL;

  rec(slash_118);

  // SlashExpr 0
  if (!expr_ret_118)
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    rec(mod_119);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_120 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
        // Capturing VOIDPTR.
        expr_ret_120 = leaf(VOIDPTR);
        #if DAISHO_SOURCEINFO
        expr_ret_120->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_120->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_120 = NULL;
      }

      expr_ret_119 = expr_ret_120;
      v = expr_ret_120;
    }

    // ModExprList 1
    if (expr_ret_119)
    {
      // CodeExpr
      #define ret expr_ret_119
      ret = SUCC;

      rule=v;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_119) rew(mod_119);
    expr_ret_118 = expr_ret_119 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_118)
  {
    daisho_astnode_t* expr_ret_121 = NULL;
    rec(mod_121);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_122 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_122 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_122->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_122->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_122 = NULL;
      }

      expr_ret_121 = expr_ret_122;
      v = expr_ret_122;
    }

    // ModExprList 1
    if (expr_ret_121)
    {
      daisho_astnode_t* expr_ret_123 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_123 = leaf(STAR);
        #if DAISHO_SOURCEINFO
        expr_ret_123->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_123->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_123 = NULL;
      }

      expr_ret_121 = expr_ret_123;
      s = expr_ret_123;
    }

    // ModExprList 2
    if (expr_ret_121)
    {
      // CodeExpr
      #define ret expr_ret_121
      ret = SUCC;

      rule=leaf(VOIDPTR);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_121) rew(mod_121);
    expr_ret_118 = expr_ret_121 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_118) rew(slash_118);
  expr_ret_117 = expr_ret_118;

  if (!rule) rule = expr_ret_117;
  if (!expr_ret_117) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_124

  daisho_astnode_t* expr_ret_125 = NULL;
  daisho_astnode_t* expr_ret_124 = NULL;
  daisho_astnode_t* expr_ret_126 = NULL;
  rec(mod_126);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_127 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_127 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_127->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_127->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_127 = NULL;
    }

    expr_ret_126 = expr_ret_127;
    i = expr_ret_127;
  }

  // ModExprList 1
  if (expr_ret_126)
  {
    daisho_astnode_t* expr_ret_128 = NULL;
    expr_ret_128 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_128)
      expr_ret_128 = SUCC;
    expr_ret_126 = expr_ret_128;
    t = expr_ret_128;
  }

  // ModExprList 2
  if (expr_ret_126)
  {
    // CodeExpr
    #define ret expr_ret_126
    ret = SUCC;

    ret = t ? node(TMPLTYPE, t, i) : node(TYPE, i);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_126) rew(mod_126);
  expr_ret_125 = expr_ret_126 ? SUCC : NULL;
  if (!rule) rule = expr_ret_125;
  if (!expr_ret_125) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_129

  daisho_astnode_t* expr_ret_130 = NULL;
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_131 = NULL;
  rec(mod_131);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_132 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_132 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_132->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_132->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_132 = NULL;
    }

    expr_ret_131 = expr_ret_132;
    s = expr_ret_132;
  }

  // ModExprList 1
  if (expr_ret_131)
  {
    daisho_astnode_t* expr_ret_133 = NULL;
    expr_ret_133 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_133)
      expr_ret_133 = SUCC;
    expr_ret_131 = expr_ret_133;
    t = expr_ret_133;
  }

  // ModExprList 2
  if (expr_ret_131)
  {
    // CodeExpr
    #define ret expr_ret_131
    ret = SUCC;

    ret = t ? node(TMPLTYPE, t, s) : node(TYPE, s);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_131) rew(mod_131);
  expr_ret_130 = expr_ret_131 ? SUCC : NULL;
  if (!rule) rule = expr_ret_130;
  if (!expr_ret_130) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_134

  daisho_astnode_t* expr_ret_135 = NULL;
  daisho_astnode_t* expr_ret_134 = NULL;
  daisho_astnode_t* expr_ret_136 = NULL;
  rec(mod_136);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      // Not capturing CTYPE.
      expr_ret_136 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_136 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_136)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_136 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_136 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_136) rew(mod_136);
  expr_ret_135 = expr_ret_136 ? SUCC : NULL;
  if (!rule) rule = expr_ret_135;
  if (!expr_ret_135) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* arrow = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* tmp = NULL;
  #define rule expr_ret_137

  daisho_astnode_t* expr_ret_138 = NULL;
  daisho_astnode_t* expr_ret_137 = NULL;
  daisho_astnode_t* expr_ret_139 = NULL;

  rec(slash_139);

  // SlashExpr 0
  if (!expr_ret_139)
  {
    daisho_astnode_t* expr_ret_140 = NULL;
    rec(mod_140);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_140 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_140 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_140)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        // Not capturing LT.
        expr_ret_140 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_140 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_140)
    {
      daisho_astnode_t* expr_ret_141 = NULL;
      // CodeExpr
      #define ret expr_ret_141
      ret = SUCC;

      ret=list(ARGLIST);

      #undef ret
      expr_ret_140 = expr_ret_141;
      argtypes = expr_ret_141;
    }

    // ModExprList 3
    if (expr_ret_140)
    {
      daisho_astnode_t* expr_ret_142 = NULL;
      daisho_astnode_t* expr_ret_143 = NULL;
      rec(mod_143);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_144 = NULL;
        expr_ret_144 = daisho_parse_type(ctx);
        expr_ret_143 = expr_ret_144;
        t = expr_ret_144;
      }

      // ModExprList 1
      if (expr_ret_143)
      {
        // CodeExpr
        #define ret expr_ret_143
        ret = SUCC;

        add(argtypes, t);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_143) rew(mod_143);
      expr_ret_142 = expr_ret_143 ? SUCC : NULL;
      // optional
      if (!expr_ret_142)
        expr_ret_142 = SUCC;
      expr_ret_140 = expr_ret_142;
    }

    // ModExprList 4
    if (expr_ret_140)
    {
      daisho_astnode_t* expr_ret_145 = NULL;
      expr_ret_145 = SUCC;
      while (expr_ret_145)
      {
        daisho_astnode_t* expr_ret_146 = NULL;
        rec(mod_146);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_146 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_146 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_146)
        {
          daisho_astnode_t* expr_ret_147 = NULL;
          expr_ret_147 = daisho_parse_type(ctx);
          expr_ret_146 = expr_ret_147;
          t = expr_ret_147;
        }

        // ModExprList 2
        if (expr_ret_146)
        {
          // CodeExpr
          #define ret expr_ret_146
          ret = SUCC;

          add(argtypes, t);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_146) rew(mod_146);
        expr_ret_145 = expr_ret_146 ? SUCC : NULL;
      }

      expr_ret_145 = SUCC;
      expr_ret_140 = expr_ret_145;
    }

    // ModExprList 5
    if (expr_ret_140)
    {
      // CodeExpr
      #define ret expr_ret_140
      ret = SUCC;

      if (!argtypes->num_children) add(argtypes, node(TYPE, leaf(VOIDTYPE)));

      #undef ret
    }

    // ModExprList 6
    if (expr_ret_140)
    {
      daisho_astnode_t* expr_ret_148 = NULL;
      daisho_astnode_t* expr_ret_149 = NULL;
      rec(mod_149);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_150 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
          // Capturing ARROW.
          expr_ret_150 = leaf(ARROW);
          #if DAISHO_SOURCEINFO
          expr_ret_150->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_150->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_150 = NULL;
        }

        expr_ret_149 = expr_ret_150;
        arrow = expr_ret_150;
      }

      // ModExprList 1
      if (expr_ret_149)
      {
        daisho_astnode_t* expr_ret_151 = NULL;
        expr_ret_151 = daisho_parse_type(ctx);
        expr_ret_149 = expr_ret_151;
        rettype = expr_ret_151;
      }

      // ModExprList end
      if (!expr_ret_149) rew(mod_149);
      expr_ret_148 = expr_ret_149 ? SUCC : NULL;
      // optional
      if (!expr_ret_148)
        expr_ret_148 = SUCC;
      expr_ret_140 = expr_ret_148;
    }

    // ModExprList 7
    if (expr_ret_140)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Not capturing GT.
        expr_ret_140 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_140 = NULL;
      }

    }

    // ModExprList 8
    if (expr_ret_140)
    {
      // CodeExpr
      #define ret expr_ret_140
      ret = SUCC;

      rule=node(FNTYPE,
                         argtypes,
                         ((rettype==SUCC) | (rettype==NULL)) ? node(TYPE, leaf(VOIDTYPE)) : rettype);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_140) rew(mod_140);
    expr_ret_139 = expr_ret_140 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_139)
  {
    daisho_astnode_t* expr_ret_152 = NULL;
    rec(mod_152);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_152 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_152 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_152)
    {
      daisho_astnode_t* expr_ret_153 = NULL;
      // CodeExpr
      #define ret expr_ret_153
      ret = SUCC;

      rule=node(FNTYPE,
                            (tmp=list(ARGLIST), add(tmp, node(TYPE, leaf(VOIDTYPE))), tmp),
                             node(TYPE, leaf(VOIDTYPE)));

      #undef ret
      expr_ret_152 = expr_ret_153;
      tmp = expr_ret_153;
    }

    // ModExprList end
    if (!expr_ret_152) rew(mod_152);
    expr_ret_139 = expr_ret_152 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_139) rew(slash_139);
  expr_ret_138 = expr_ret_139;

  if (!rule) rule = expr_ret_138;
  if (!expr_ret_138) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplspec(daisho_parser_ctx* ctx) {
  #define rule expr_ret_154

  daisho_astnode_t* expr_ret_155 = NULL;
  daisho_astnode_t* expr_ret_154 = NULL;
  daisho_astnode_t* expr_ret_156 = NULL;
  rec(mod_156);
  // ModExprList end
  if (!expr_ret_156) rew(mod_156);
  expr_ret_155 = expr_ret_156 ? SUCC : NULL;
  if (!rule) rule = expr_ret_155;
  if (!expr_ret_155) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  #define rule expr_ret_157

  daisho_astnode_t* expr_ret_158 = NULL;
  daisho_astnode_t* expr_ret_157 = NULL;
  daisho_astnode_t* expr_ret_159 = NULL;
  rec(mod_159);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_159 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_159 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_159)
  {
    daisho_astnode_t* expr_ret_160 = NULL;
    expr_ret_160 = daisho_parse_tmplmember(ctx);
    // optional
    if (!expr_ret_160)
      expr_ret_160 = SUCC;
    expr_ret_159 = expr_ret_160;
  }

  // ModExprList 2
  if (expr_ret_159)
  {
    daisho_astnode_t* expr_ret_161 = NULL;
    expr_ret_161 = SUCC;
    while (expr_ret_161)
    {
      daisho_astnode_t* expr_ret_162 = NULL;
      rec(mod_162);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_162 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_162 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_162)
      {
        expr_ret_162 = daisho_parse_tmplmember(ctx);
      }

      // ModExprList end
      if (!expr_ret_162) rew(mod_162);
      expr_ret_161 = expr_ret_162 ? SUCC : NULL;
    }

    expr_ret_161 = SUCC;
    expr_ret_159 = expr_ret_161;
  }

  // ModExprList 3
  if (expr_ret_159)
  {
    daisho_astnode_t* expr_ret_163 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_163 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_163 = NULL;
    }

    // optional
    if (!expr_ret_163)
      expr_ret_163 = SUCC;
    expr_ret_159 = expr_ret_163;
  }

  // ModExprList 4
  if (expr_ret_159)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_159 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_159 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_159) rew(mod_159);
  expr_ret_158 = expr_ret_159 ? SUCC : NULL;
  if (!rule) rule = expr_ret_158;
  if (!expr_ret_158) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplmember(daisho_parser_ctx* ctx) {
  #define rule expr_ret_164

  daisho_astnode_t* expr_ret_165 = NULL;
  daisho_astnode_t* expr_ret_164 = NULL;
  daisho_astnode_t* expr_ret_166 = NULL;
  rec(mod_166);
  // ModExprList Forwarding
  expr_ret_166 = daisho_parse_type(ctx);
  // ModExprList end
  if (!expr_ret_166) rew(mod_166);
  expr_ret_165 = expr_ret_166;
  if (!rule) rule = expr_ret_165;
  if (!expr_ret_165) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  #define rule expr_ret_167

  daisho_astnode_t* expr_ret_168 = NULL;
  daisho_astnode_t* expr_ret_167 = NULL;
  daisho_astnode_t* expr_ret_169 = NULL;
  rec(mod_169);
  // ModExprList 0
  {
    expr_ret_169 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_169)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_169 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_169 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_169)
  {
    daisho_astnode_t* expr_ret_170 = NULL;
    expr_ret_170 = daisho_parse_fnarg(ctx);
    // optional
    if (!expr_ret_170)
      expr_ret_170 = SUCC;
    expr_ret_169 = expr_ret_170;
  }

  // ModExprList 3
  if (expr_ret_169)
  {
    daisho_astnode_t* expr_ret_171 = NULL;
    expr_ret_171 = SUCC;
    while (expr_ret_171)
    {
      daisho_astnode_t* expr_ret_172 = NULL;
      rec(mod_172);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_172 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_172 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_172)
      {
        expr_ret_172 = daisho_parse_fnarg(ctx);
      }

      // ModExprList end
      if (!expr_ret_172) rew(mod_172);
      expr_ret_171 = expr_ret_172 ? SUCC : NULL;
    }

    expr_ret_171 = SUCC;
    expr_ret_169 = expr_ret_171;
  }

  // ModExprList 4
  if (expr_ret_169)
  {
    daisho_astnode_t* expr_ret_173 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_173 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_173 = NULL;
    }

    // optional
    if (!expr_ret_173)
      expr_ret_173 = SUCC;
    expr_ret_169 = expr_ret_173;
  }

  // ModExprList 5
  if (expr_ret_169)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_169 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_169 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_169) rew(mod_169);
  expr_ret_168 = expr_ret_169 ? SUCC : NULL;
  if (!rule) rule = expr_ret_168;
  if (!expr_ret_168) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  #define rule expr_ret_174

  daisho_astnode_t* expr_ret_175 = NULL;
  daisho_astnode_t* expr_ret_174 = NULL;
  daisho_astnode_t* expr_ret_176 = NULL;
  rec(mod_176);
  // ModExprList 0
  {
    expr_ret_176 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_176)
  {
    daisho_astnode_t* expr_ret_177 = NULL;
    daisho_astnode_t* expr_ret_178 = NULL;
    rec(mod_178);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_178 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_178 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_178)
    {
      daisho_astnode_t* expr_ret_179 = NULL;
      expr_ret_179 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_179)
        expr_ret_179 = SUCC;
      expr_ret_178 = expr_ret_179;
    }

    // ModExprList end
    if (!expr_ret_178) rew(mod_178);
    expr_ret_177 = expr_ret_178 ? SUCC : NULL;
    // optional
    if (!expr_ret_177)
      expr_ret_177 = SUCC;
    expr_ret_176 = expr_ret_177;
  }

  // ModExprList end
  if (!expr_ret_176) rew(mod_176);
  expr_ret_175 = expr_ret_176 ? SUCC : NULL;
  if (!rule) rule = expr_ret_175;
  if (!expr_ret_175) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx) {
  #define rule expr_ret_180

  daisho_astnode_t* expr_ret_181 = NULL;
  daisho_astnode_t* expr_ret_180 = NULL;
  daisho_astnode_t* expr_ret_182 = NULL;
  rec(mod_182);
  // ModExprList Forwarding
  expr_ret_182 = daisho_parse_expr(ctx);
  // ModExprList end
  if (!expr_ret_182) rew(mod_182);
  expr_ret_181 = expr_ret_182;
  if (!rule) rule = expr_ret_181;
  if (!expr_ret_181) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_183

  daisho_astnode_t* expr_ret_184 = NULL;
  daisho_astnode_t* expr_ret_183 = NULL;
  daisho_astnode_t* expr_ret_185 = NULL;
  rec(mod_185);
  // ModExprList Forwarding
  expr_ret_185 = daisho_parse_forexpr(ctx);
  // ModExprList end
  if (!expr_ret_185) rew(mod_185);
  expr_ret_184 = expr_ret_185;
  if (!rule) rule = expr_ret_184;
  if (!expr_ret_184) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* sn = NULL;
  #define rule expr_ret_186

  daisho_astnode_t* expr_ret_187 = NULL;
  daisho_astnode_t* expr_ret_186 = NULL;
  daisho_astnode_t* expr_ret_188 = NULL;

  rec(slash_188);

  // SlashExpr 0
  if (!expr_ret_188)
  {
    daisho_astnode_t* expr_ret_189 = NULL;
    rec(mod_189);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_189 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_189 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_190 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_190 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_190 = NULL;
      }

      // optional
      if (!expr_ret_190)
        expr_ret_190 = SUCC;
      expr_ret_189 = expr_ret_190;
    }

    // ModExprList 2
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_191 = NULL;
      expr_ret_191 = daisho_parse_whileexpr(ctx);
      expr_ret_189 = expr_ret_191;
      n = expr_ret_191;
    }

    // ModExprList 3
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_192 = NULL;

      rec(slash_192);

      // SlashExpr 0
      if (!expr_ret_192)
      {
        daisho_astnode_t* expr_ret_193 = NULL;
        rec(mod_193);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_194 = NULL;

        rec(slash_194);

        // SlashExpr 0
        if (!expr_ret_194)
        {
          daisho_astnode_t* expr_ret_195 = NULL;
          rec(mod_195);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_195 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_195 = NULL;
          }

          // ModExprList end
          if (!expr_ret_195) rew(mod_195);
          expr_ret_194 = expr_ret_195;
        }

        // SlashExpr 1
        if (!expr_ret_194)
        {
          daisho_astnode_t* expr_ret_196 = NULL;
          rec(mod_196);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_196 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_196 = NULL;
          }

          // ModExprList end
          if (!expr_ret_196) rew(mod_196);
          expr_ret_194 = expr_ret_196;
        }

        // SlashExpr end
        if (!expr_ret_194) rew(slash_194);
        expr_ret_193 = expr_ret_194;

        // ModExprList end
        if (!expr_ret_193) rew(mod_193);
        expr_ret_192 = expr_ret_193;
      }

      // SlashExpr 1
      if (!expr_ret_192)
      {
        daisho_astnode_t* expr_ret_197 = NULL;
        rec(mod_197);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_198 = NULL;
        rec(mod_198);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_198 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_198 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_198)
        {
          daisho_astnode_t* expr_ret_199 = NULL;
          expr_ret_199 = daisho_parse_whileexpr(ctx);
          expr_ret_198 = expr_ret_199;
          sn = expr_ret_199;
        }

        // ModExprList 2
        if (expr_ret_198)
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_198 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_198 = NULL;
          }

        }

        // ModExprList end
        if (!expr_ret_198) rew(mod_198);
        expr_ret_197 = expr_ret_198 ? SUCC : NULL;
        // ModExprList end
        if (!expr_ret_197) rew(mod_197);
        expr_ret_192 = expr_ret_197;
      }

      // SlashExpr end
      if (!expr_ret_192) rew(slash_192);
      expr_ret_189 = expr_ret_192;

    }

    // ModExprList 4
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_200 = NULL;
      expr_ret_200 = daisho_parse_whileexpr(ctx);
      expr_ret_189 = expr_ret_200;
      n = expr_ret_200;
    }

    // ModExprList 5
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_201 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_201 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_201 = NULL;
      }

      // optional
      if (!expr_ret_201)
        expr_ret_201 = SUCC;
      expr_ret_189 = expr_ret_201;
    }

    // ModExprList 6
    if (expr_ret_189)
    {
      daisho_astnode_t* expr_ret_202 = NULL;
      expr_ret_202 = daisho_parse_whileexpr(ctx);
      expr_ret_189 = expr_ret_202;
      n = expr_ret_202;
    }

    // ModExprList end
    if (!expr_ret_189) rew(mod_189);
    expr_ret_188 = expr_ret_189 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_188)
  {
    daisho_astnode_t* expr_ret_203 = NULL;
    rec(mod_203);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_204 = NULL;
      expr_ret_204 = daisho_parse_whileexpr(ctx);
      expr_ret_203 = expr_ret_204;
      n = expr_ret_204;
    }

    // ModExprList 1
    if (expr_ret_203)
    {
      // CodeExpr
      #define ret expr_ret_203
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_203) rew(mod_203);
    expr_ret_188 = expr_ret_203 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_188) rew(slash_188);
  expr_ret_187 = expr_ret_188;

  if (!rule) rule = expr_ret_187;
  if (!expr_ret_187) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_205

  daisho_astnode_t* expr_ret_206 = NULL;
  daisho_astnode_t* expr_ret_205 = NULL;
  daisho_astnode_t* expr_ret_207 = NULL;

  rec(slash_207);

  // SlashExpr 0
  if (!expr_ret_207)
  {
    daisho_astnode_t* expr_ret_208 = NULL;
    rec(mod_208);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
        // Not capturing WHILE.
        expr_ret_208 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_208 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_208)
    {
      daisho_astnode_t* expr_ret_209 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_209 = leaf(OPEN);
        #if DAISHO_SOURCEINFO
        expr_ret_209->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_209->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_209 = NULL;
      }

      // optional
      if (!expr_ret_209)
        expr_ret_209 = SUCC;
      expr_ret_208 = expr_ret_209;
      o = expr_ret_209;
    }

    // ModExprList 2
    if (expr_ret_208)
    {
      daisho_astnode_t* expr_ret_210 = NULL;
      expr_ret_210 = daisho_parse_ternexpr(ctx);
      expr_ret_208 = expr_ret_210;
      n = expr_ret_210;
    }

    // ModExprList 3
    if (expr_ret_208)
    {
      daisho_astnode_t* expr_ret_211 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_211 = leaf(CLOSE);
        #if DAISHO_SOURCEINFO
        expr_ret_211->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_211->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_211 = NULL;
      }

      // optional
      if (!expr_ret_211)
        expr_ret_211 = SUCC;
      expr_ret_208 = expr_ret_211;
      c = expr_ret_211;
    }

    // ModExprList 4
    if (expr_ret_208)
    {
      // CodeExpr
      #define ret expr_ret_208
      ret = SUCC;

      ret=o==c?SUCC:NULL;

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_208)
    {
      expr_ret_208 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_208) rew(mod_208);
    expr_ret_207 = expr_ret_208 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_207)
  {
    daisho_astnode_t* expr_ret_212 = NULL;
    rec(mod_212);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_213 = NULL;
      expr_ret_213 = daisho_parse_ternexpr(ctx);
      expr_ret_212 = expr_ret_213;
      n = expr_ret_213;
    }

    // ModExprList 1
    if (expr_ret_212)
    {
      // CodeExpr
      #define ret expr_ret_212
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_212) rew(mod_212);
    expr_ret_207 = expr_ret_212 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_207) rew(slash_207);
  expr_ret_206 = expr_ret_207;

  if (!rule) rule = expr_ret_206;
  if (!expr_ret_206) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* q = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_214

  daisho_astnode_t* expr_ret_215 = NULL;
  daisho_astnode_t* expr_ret_214 = NULL;
  daisho_astnode_t* expr_ret_216 = NULL;
  rec(mod_216);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_217 = NULL;
    expr_ret_217 = daisho_parse_thenexpr(ctx);
    expr_ret_216 = expr_ret_217;
    n = expr_ret_217;
  }

  // ModExprList 1
  if (expr_ret_216)
  {
    daisho_astnode_t* expr_ret_218 = NULL;
    daisho_astnode_t* expr_ret_219 = NULL;
    rec(mod_219);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_220 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
        // Capturing QUEST.
        expr_ret_220 = leaf(QUEST);
        #if DAISHO_SOURCEINFO
        expr_ret_220->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_220->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_220 = NULL;
      }

      expr_ret_219 = expr_ret_220;
      q = expr_ret_220;
    }

    // ModExprList 1
    if (expr_ret_219)
    {
      daisho_astnode_t* expr_ret_221 = NULL;
      expr_ret_221 = daisho_parse_expr(ctx);
      expr_ret_219 = expr_ret_221;
      qe = expr_ret_221;
    }

    // ModExprList 2
    if (expr_ret_219)
    {
      daisho_astnode_t* expr_ret_222 = NULL;
      daisho_astnode_t* expr_ret_223 = NULL;
      rec(mod_223);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_224 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          // Capturing COLON.
          expr_ret_224 = leaf(COLON);
          #if DAISHO_SOURCEINFO
          expr_ret_224->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_224->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_224 = NULL;
        }

        expr_ret_223 = expr_ret_224;
        c = expr_ret_224;
      }

      // ModExprList 1
      if (expr_ret_223)
      {
        daisho_astnode_t* expr_ret_225 = NULL;
        expr_ret_225 = daisho_parse_expr(ctx);
        expr_ret_223 = expr_ret_225;
        ce = expr_ret_225;
      }

      // ModExprList end
      if (!expr_ret_223) rew(mod_223);
      expr_ret_222 = expr_ret_223 ? SUCC : NULL;
      // optional
      if (!expr_ret_222)
        expr_ret_222 = SUCC;
      expr_ret_219 = expr_ret_222;
    }

    // ModExprList end
    if (!expr_ret_219) rew(mod_219);
    expr_ret_218 = expr_ret_219 ? SUCC : NULL;
    // optional
    if (!expr_ret_218)
      expr_ret_218 = SUCC;
    expr_ret_216 = expr_ret_218;
  }

  // ModExprList 2
  if (expr_ret_216)
  {
    // CodeExpr
    #define ret expr_ret_216
    ret = SUCC;

    rule = !qe ? n
                    : !ce ? node(IF, q, n, qe)
                    :       node(TERN, q, c, n, qe, ce);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_216) rew(mod_216);
  expr_ret_215 = expr_ret_216 ? SUCC : NULL;
  if (!rule) rule = expr_ret_215;
  if (!expr_ret_215) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_226

  daisho_astnode_t* expr_ret_227 = NULL;
  daisho_astnode_t* expr_ret_226 = NULL;
  daisho_astnode_t* expr_ret_228 = NULL;
  rec(mod_228);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_229 = NULL;
    expr_ret_229 = daisho_parse_alsoexpr(ctx);
    expr_ret_228 = expr_ret_229;
    n = expr_ret_229;
  }

  // ModExprList 1
  if (expr_ret_228)
  {
    // CodeExpr
    #define ret expr_ret_228
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_228)
  {
    daisho_astnode_t* expr_ret_230 = NULL;
    expr_ret_230 = SUCC;
    while (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_231 = NULL;
      rec(mod_231);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
          // Not capturing THEN.
          expr_ret_231 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_231 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_231)
      {
        daisho_astnode_t* expr_ret_232 = NULL;
        expr_ret_232 = daisho_parse_alsoexpr(ctx);
        expr_ret_231 = expr_ret_232;
        nn = expr_ret_232;
      }

      // ModExprList 2
      if (expr_ret_231)
      {
        // CodeExpr
        #define ret expr_ret_231
        ret = SUCC;

        rule=node(THEN, rule, nn);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_231) rew(mod_231);
      expr_ret_230 = expr_ret_231 ? SUCC : NULL;
    }

    expr_ret_230 = SUCC;
    expr_ret_228 = expr_ret_230;
  }

  // ModExprList end
  if (!expr_ret_228) rew(mod_228);
  expr_ret_227 = expr_ret_228 ? SUCC : NULL;
  if (!rule) rule = expr_ret_227;
  if (!expr_ret_227) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_233

  daisho_astnode_t* expr_ret_234 = NULL;
  daisho_astnode_t* expr_ret_233 = NULL;
  daisho_astnode_t* expr_ret_235 = NULL;
  rec(mod_235);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_236 = NULL;
    expr_ret_236 = daisho_parse_binop(ctx);
    expr_ret_235 = expr_ret_236;
    n = expr_ret_236;
  }

  // ModExprList 1
  if (expr_ret_235)
  {
    // CodeExpr
    #define ret expr_ret_235
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_235)
  {
    daisho_astnode_t* expr_ret_237 = NULL;
    expr_ret_237 = SUCC;
    while (expr_ret_237)
    {
      daisho_astnode_t* expr_ret_238 = NULL;
      rec(mod_238);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
          // Not capturing ALSO.
          expr_ret_238 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_238 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_238)
      {
        daisho_astnode_t* expr_ret_239 = NULL;
        expr_ret_239 = daisho_parse_binop(ctx);
        expr_ret_238 = expr_ret_239;
        nn = expr_ret_239;
      }

      // ModExprList 2
      if (expr_ret_238)
      {
        // CodeExpr
        #define ret expr_ret_238
        ret = SUCC;

        rule=node(ALSO, rule, nn);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_238) rew(mod_238);
      expr_ret_237 = expr_ret_238 ? SUCC : NULL;
    }

    expr_ret_237 = SUCC;
    expr_ret_235 = expr_ret_237;
  }

  // ModExprList end
  if (!expr_ret_235) rew(mod_235);
  expr_ret_234 = expr_ret_235 ? SUCC : NULL;
  if (!rule) rule = expr_ret_234;
  if (!expr_ret_234) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  #define rule expr_ret_240

  daisho_astnode_t* expr_ret_241 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
  daisho_astnode_t* expr_ret_242 = NULL;
  rec(mod_242);
  // ModExprList Forwarding
  expr_ret_242 = daisho_parse_eqexpr(ctx);
  // ModExprList end
  if (!expr_ret_242) rew(mod_242);
  expr_ret_241 = expr_ret_242;
  if (!rule) rule = expr_ret_241;
  if (!expr_ret_241) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_243

  daisho_astnode_t* expr_ret_244 = NULL;
  daisho_astnode_t* expr_ret_243 = NULL;
  daisho_astnode_t* expr_ret_245 = NULL;
  rec(mod_245);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_246 = NULL;
    expr_ret_246 = daisho_parse_logorexpr(ctx);
    expr_ret_245 = expr_ret_246;
    n = expr_ret_246;
  }

  // ModExprList 1
  if (expr_ret_245)
  {
    // CodeExpr
    #define ret expr_ret_245
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_245)
  {
    daisho_astnode_t* expr_ret_247 = NULL;
    expr_ret_247 = SUCC;
    while (expr_ret_247)
    {
      daisho_astnode_t* expr_ret_248 = NULL;
      rec(mod_248);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_249 = NULL;
        daisho_astnode_t* expr_ret_250 = NULL;

        rec(slash_250);

        // SlashExpr 0
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_251 = NULL;
          rec(mod_251);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            // Capturing EQ.
            expr_ret_251 = leaf(EQ);
            #if DAISHO_SOURCEINFO
            expr_ret_251->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_251->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_251 = NULL;
          }

          // ModExprList end
          if (!expr_ret_251) rew(mod_251);
          expr_ret_250 = expr_ret_251;
        }

        // SlashExpr 1
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_252 = NULL;
          rec(mod_252);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            // Capturing PLEQ.
            expr_ret_252 = leaf(PLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_252->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_252->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_252 = NULL;
          }

          // ModExprList end
          if (!expr_ret_252) rew(mod_252);
          expr_ret_250 = expr_ret_252;
        }

        // SlashExpr 2
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_253 = NULL;
          rec(mod_253);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            // Capturing MINEQ.
            expr_ret_253 = leaf(MINEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_253->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_253->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_253 = NULL;
          }

          // ModExprList end
          if (!expr_ret_253) rew(mod_253);
          expr_ret_250 = expr_ret_253;
        }

        // SlashExpr 3
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_254 = NULL;
          rec(mod_254);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            // Capturing MULEQ.
            expr_ret_254 = leaf(MULEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_254->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_254->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_254 = NULL;
          }

          // ModExprList end
          if (!expr_ret_254) rew(mod_254);
          expr_ret_250 = expr_ret_254;
        }

        // SlashExpr 4
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_255 = NULL;
          rec(mod_255);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            // Capturing DIVEQ.
            expr_ret_255 = leaf(DIVEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_255->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_255->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_255 = NULL;
          }

          // ModExprList end
          if (!expr_ret_255) rew(mod_255);
          expr_ret_250 = expr_ret_255;
        }

        // SlashExpr 5
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_256 = NULL;
          rec(mod_256);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            // Capturing MODEQ.
            expr_ret_256 = leaf(MODEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_256->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_256->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_256 = NULL;
          }

          // ModExprList end
          if (!expr_ret_256) rew(mod_256);
          expr_ret_250 = expr_ret_256;
        }

        // SlashExpr 6
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_257 = NULL;
          rec(mod_257);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            // Capturing ANDEQ.
            expr_ret_257 = leaf(ANDEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_257->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_257->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_257 = NULL;
          }

          // ModExprList end
          if (!expr_ret_257) rew(mod_257);
          expr_ret_250 = expr_ret_257;
        }

        // SlashExpr 7
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_258 = NULL;
          rec(mod_258);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            // Capturing OREQ.
            expr_ret_258 = leaf(OREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_258->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_258->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_258 = NULL;
          }

          // ModExprList end
          if (!expr_ret_258) rew(mod_258);
          expr_ret_250 = expr_ret_258;
        }

        // SlashExpr 8
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_259 = NULL;
          rec(mod_259);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            // Capturing XOREQ.
            expr_ret_259 = leaf(XOREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_259->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_259->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_259 = NULL;
          }

          // ModExprList end
          if (!expr_ret_259) rew(mod_259);
          expr_ret_250 = expr_ret_259;
        }

        // SlashExpr 9
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_260 = NULL;
          rec(mod_260);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            // Capturing BNEQ.
            expr_ret_260 = leaf(BNEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_260->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_260->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_260 = NULL;
          }

          // ModExprList end
          if (!expr_ret_260) rew(mod_260);
          expr_ret_250 = expr_ret_260;
        }

        // SlashExpr 10
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_261 = NULL;
          rec(mod_261);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            // Capturing BSREQ.
            expr_ret_261 = leaf(BSREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_261->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_261->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_261 = NULL;
          }

          // ModExprList end
          if (!expr_ret_261) rew(mod_261);
          expr_ret_250 = expr_ret_261;
        }

        // SlashExpr 11
        if (!expr_ret_250)
        {
          daisho_astnode_t* expr_ret_262 = NULL;
          rec(mod_262);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            // Capturing BSLEQ.
            expr_ret_262 = leaf(BSLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_262->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_262->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_262 = NULL;
          }

          // ModExprList end
          if (!expr_ret_262) rew(mod_262);
          expr_ret_250 = expr_ret_262;
        }

        // SlashExpr end
        if (!expr_ret_250) rew(slash_250);
        expr_ret_249 = expr_ret_250;

        expr_ret_248 = expr_ret_249;
        op = expr_ret_249;
      }

      // ModExprList 1
      if (expr_ret_248)
      {
        daisho_astnode_t* expr_ret_263 = NULL;
        expr_ret_263 = daisho_parse_logorexpr(ctx);
        expr_ret_248 = expr_ret_263;
        t = expr_ret_263;
      }

      // ModExprList 2
      if (expr_ret_248)
      {
        // CodeExpr
        #define ret expr_ret_248
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
                else
                    __DAI_UNREACHABLE()
              ;

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_248) rew(mod_248);
      expr_ret_247 = expr_ret_248 ? SUCC : NULL;
    }

    expr_ret_247 = SUCC;
    expr_ret_245 = expr_ret_247;
  }

  // ModExprList end
  if (!expr_ret_245) rew(mod_245);
  expr_ret_244 = expr_ret_245 ? SUCC : NULL;
  if (!rule) rule = expr_ret_244;
  if (!expr_ret_244) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_264

  daisho_astnode_t* expr_ret_265 = NULL;
  daisho_astnode_t* expr_ret_264 = NULL;
  daisho_astnode_t* expr_ret_266 = NULL;
  rec(mod_266);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_267 = NULL;
    expr_ret_267 = daisho_parse_logandexpr(ctx);
    expr_ret_266 = expr_ret_267;
    n = expr_ret_267;
  }

  // ModExprList 1
  if (expr_ret_266)
  {
    // CodeExpr
    #define ret expr_ret_266
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_266)
  {
    daisho_astnode_t* expr_ret_268 = NULL;
    expr_ret_268 = SUCC;
    while (expr_ret_268)
    {
      daisho_astnode_t* expr_ret_269 = NULL;
      rec(mod_269);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Not capturing LOGOR.
          expr_ret_269 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_269 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_269)
      {
        daisho_astnode_t* expr_ret_270 = NULL;
        expr_ret_270 = daisho_parse_logandexpr(ctx);
        expr_ret_269 = expr_ret_270;
        n = expr_ret_270;
      }

      // ModExprList 2
      if (expr_ret_269)
      {
        // CodeExpr
        #define ret expr_ret_269
        ret = SUCC;

        rule=node(LOGOR,  rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_269) rew(mod_269);
      expr_ret_268 = expr_ret_269 ? SUCC : NULL;
    }

    expr_ret_268 = SUCC;
    expr_ret_266 = expr_ret_268;
  }

  // ModExprList end
  if (!expr_ret_266) rew(mod_266);
  expr_ret_265 = expr_ret_266 ? SUCC : NULL;
  if (!rule) rule = expr_ret_265;
  if (!expr_ret_265) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_271

  daisho_astnode_t* expr_ret_272 = NULL;
  daisho_astnode_t* expr_ret_271 = NULL;
  daisho_astnode_t* expr_ret_273 = NULL;
  rec(mod_273);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_274 = NULL;
    expr_ret_274 = daisho_parse_binorexpr(ctx);
    expr_ret_273 = expr_ret_274;
    n = expr_ret_274;
  }

  // ModExprList 1
  if (expr_ret_273)
  {
    // CodeExpr
    #define ret expr_ret_273
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_273)
  {
    daisho_astnode_t* expr_ret_275 = NULL;
    expr_ret_275 = SUCC;
    while (expr_ret_275)
    {
      daisho_astnode_t* expr_ret_276 = NULL;
      rec(mod_276);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Not capturing LOGAND.
          expr_ret_276 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_276 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_276)
      {
        daisho_astnode_t* expr_ret_277 = NULL;
        expr_ret_277 = daisho_parse_binorexpr(ctx);
        expr_ret_276 = expr_ret_277;
        n = expr_ret_277;
      }

      // ModExprList 2
      if (expr_ret_276)
      {
        // CodeExpr
        #define ret expr_ret_276
        ret = SUCC;

        rule=node(LOGAND, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_276) rew(mod_276);
      expr_ret_275 = expr_ret_276 ? SUCC : NULL;
    }

    expr_ret_275 = SUCC;
    expr_ret_273 = expr_ret_275;
  }

  // ModExprList end
  if (!expr_ret_273) rew(mod_273);
  expr_ret_272 = expr_ret_273 ? SUCC : NULL;
  if (!rule) rule = expr_ret_272;
  if (!expr_ret_272) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_278

  daisho_astnode_t* expr_ret_279 = NULL;
  daisho_astnode_t* expr_ret_278 = NULL;
  daisho_astnode_t* expr_ret_280 = NULL;
  rec(mod_280);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_281 = NULL;
    expr_ret_281 = daisho_parse_binxorexpr(ctx);
    expr_ret_280 = expr_ret_281;
    n = expr_ret_281;
  }

  // ModExprList 1
  if (expr_ret_280)
  {
    // CodeExpr
    #define ret expr_ret_280
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_280)
  {
    daisho_astnode_t* expr_ret_282 = NULL;
    expr_ret_282 = SUCC;
    while (expr_ret_282)
    {
      daisho_astnode_t* expr_ret_283 = NULL;
      rec(mod_283);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Not capturing OR.
          expr_ret_283 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_283 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_283)
      {
        daisho_astnode_t* expr_ret_284 = NULL;
        expr_ret_284 = daisho_parse_binxorexpr(ctx);
        expr_ret_283 = expr_ret_284;
        n = expr_ret_284;
      }

      // ModExprList 2
      if (expr_ret_283)
      {
        // CodeExpr
        #define ret expr_ret_283
        ret = SUCC;

        rule=node(OR,     rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_283) rew(mod_283);
      expr_ret_282 = expr_ret_283 ? SUCC : NULL;
    }

    expr_ret_282 = SUCC;
    expr_ret_280 = expr_ret_282;
  }

  // ModExprList end
  if (!expr_ret_280) rew(mod_280);
  expr_ret_279 = expr_ret_280 ? SUCC : NULL;
  if (!rule) rule = expr_ret_279;
  if (!expr_ret_279) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_285

  daisho_astnode_t* expr_ret_286 = NULL;
  daisho_astnode_t* expr_ret_285 = NULL;
  daisho_astnode_t* expr_ret_287 = NULL;
  rec(mod_287);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_288 = NULL;
    expr_ret_288 = daisho_parse_binandexpr(ctx);
    expr_ret_287 = expr_ret_288;
    n = expr_ret_288;
  }

  // ModExprList 1
  if (expr_ret_287)
  {
    // CodeExpr
    #define ret expr_ret_287
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_287)
  {
    daisho_astnode_t* expr_ret_289 = NULL;
    expr_ret_289 = SUCC;
    while (expr_ret_289)
    {
      daisho_astnode_t* expr_ret_290 = NULL;
      rec(mod_290);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Not capturing XOR.
          expr_ret_290 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_290 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_290)
      {
        daisho_astnode_t* expr_ret_291 = NULL;
        expr_ret_291 = daisho_parse_binandexpr(ctx);
        expr_ret_290 = expr_ret_291;
        n = expr_ret_291;
      }

      // ModExprList 2
      if (expr_ret_290)
      {
        // CodeExpr
        #define ret expr_ret_290
        ret = SUCC;

        rule=node(XOR,    rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_290) rew(mod_290);
      expr_ret_289 = expr_ret_290 ? SUCC : NULL;
    }

    expr_ret_289 = SUCC;
    expr_ret_287 = expr_ret_289;
  }

  // ModExprList end
  if (!expr_ret_287) rew(mod_287);
  expr_ret_286 = expr_ret_287 ? SUCC : NULL;
  if (!rule) rule = expr_ret_286;
  if (!expr_ret_286) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_292

  daisho_astnode_t* expr_ret_293 = NULL;
  daisho_astnode_t* expr_ret_292 = NULL;
  daisho_astnode_t* expr_ret_294 = NULL;
  rec(mod_294);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_295 = NULL;
    expr_ret_295 = daisho_parse_deneqexpr(ctx);
    expr_ret_294 = expr_ret_295;
    n = expr_ret_295;
  }

  // ModExprList 1
  if (expr_ret_294)
  {
    // CodeExpr
    #define ret expr_ret_294
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_294)
  {
    daisho_astnode_t* expr_ret_296 = NULL;
    expr_ret_296 = SUCC;
    while (expr_ret_296)
    {
      daisho_astnode_t* expr_ret_297 = NULL;
      rec(mod_297);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Not capturing AND.
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
        expr_ret_298 = daisho_parse_deneqexpr(ctx);
        expr_ret_297 = expr_ret_298;
        n = expr_ret_298;
      }

      // ModExprList 2
      if (expr_ret_297)
      {
        // CodeExpr
        #define ret expr_ret_297
        ret = SUCC;

        rule=node(AND,    rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_297) rew(mod_297);
      expr_ret_296 = expr_ret_297 ? SUCC : NULL;
    }

    expr_ret_296 = SUCC;
    expr_ret_294 = expr_ret_296;
  }

  // ModExprList end
  if (!expr_ret_294) rew(mod_294);
  expr_ret_293 = expr_ret_294 ? SUCC : NULL;
  if (!rule) rule = expr_ret_293;
  if (!expr_ret_293) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_299

  daisho_astnode_t* expr_ret_300 = NULL;
  daisho_astnode_t* expr_ret_299 = NULL;
  daisho_astnode_t* expr_ret_301 = NULL;
  rec(mod_301);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_302 = NULL;
    expr_ret_302 = daisho_parse_cmpexpr(ctx);
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
    expr_ret_303 = SUCC;
    while (expr_ret_303)
    {
      daisho_astnode_t* expr_ret_304 = NULL;

      rec(slash_304);

      // SlashExpr 0
      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_305 = NULL;
        rec(mod_305);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Not capturing DEQ.
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
          expr_ret_306 = daisho_parse_cmpexpr(ctx);
          expr_ret_305 = expr_ret_306;
          n = expr_ret_306;
        }

        // ModExprList 2
        if (expr_ret_305)
        {
          // CodeExpr
          #define ret expr_ret_305
          ret = SUCC;

          rule=node(DEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_305) rew(mod_305);
        expr_ret_304 = expr_ret_305 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_307 = NULL;
        rec(mod_307);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Not capturing NEQ.
            expr_ret_307 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_307 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_307)
        {
          daisho_astnode_t* expr_ret_308 = NULL;
          expr_ret_308 = daisho_parse_cmpexpr(ctx);
          expr_ret_307 = expr_ret_308;
          n = expr_ret_308;
        }

        // ModExprList 2
        if (expr_ret_307)
        {
          // CodeExpr
          #define ret expr_ret_307
          ret = SUCC;

          rule=node(NEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_307) rew(mod_307);
        expr_ret_304 = expr_ret_307 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_304) rew(slash_304);
      expr_ret_303 = expr_ret_304;

    }

    expr_ret_303 = SUCC;
    expr_ret_301 = expr_ret_303;
  }

  // ModExprList end
  if (!expr_ret_301) rew(mod_301);
  expr_ret_300 = expr_ret_301 ? SUCC : NULL;
  if (!rule) rule = expr_ret_300;
  if (!expr_ret_300) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_309

  daisho_astnode_t* expr_ret_310 = NULL;
  daisho_astnode_t* expr_ret_309 = NULL;
  daisho_astnode_t* expr_ret_311 = NULL;
  rec(mod_311);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_312 = NULL;
    expr_ret_312 = daisho_parse_shfexpr(ctx);
    expr_ret_311 = expr_ret_312;
    n = expr_ret_312;
  }

  // ModExprList 1
  if (expr_ret_311)
  {
    // CodeExpr
    #define ret expr_ret_311
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_311)
  {
    daisho_astnode_t* expr_ret_313 = NULL;
    expr_ret_313 = SUCC;
    while (expr_ret_313)
    {
      daisho_astnode_t* expr_ret_314 = NULL;

      rec(slash_314);

      // SlashExpr 0
      if (!expr_ret_314)
      {
        daisho_astnode_t* expr_ret_315 = NULL;
        rec(mod_315);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_315 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_315 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_315)
        {
          daisho_astnode_t* expr_ret_316 = NULL;
          expr_ret_316 = daisho_parse_shfexpr(ctx);
          expr_ret_315 = expr_ret_316;
          n = expr_ret_316;
        }

        // ModExprList 2
        if (expr_ret_315)
        {
          // CodeExpr
          #define ret expr_ret_315
          ret = SUCC;

          rule=node(LT,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_315) rew(mod_315);
        expr_ret_314 = expr_ret_315 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_314)
      {
        daisho_astnode_t* expr_ret_317 = NULL;
        rec(mod_317);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_317 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_317 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_317)
        {
          daisho_astnode_t* expr_ret_318 = NULL;
          expr_ret_318 = daisho_parse_shfexpr(ctx);
          expr_ret_317 = expr_ret_318;
          n = expr_ret_318;
        }

        // ModExprList 2
        if (expr_ret_317)
        {
          // CodeExpr
          #define ret expr_ret_317
          ret = SUCC;

          rule=node(GT,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_317) rew(mod_317);
        expr_ret_314 = expr_ret_317 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_314)
      {
        daisho_astnode_t* expr_ret_319 = NULL;
        rec(mod_319);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Not capturing LEQ.
            expr_ret_319 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_319 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_319)
        {
          daisho_astnode_t* expr_ret_320 = NULL;
          expr_ret_320 = daisho_parse_shfexpr(ctx);
          expr_ret_319 = expr_ret_320;
          n = expr_ret_320;
        }

        // ModExprList 2
        if (expr_ret_319)
        {
          // CodeExpr
          #define ret expr_ret_319
          ret = SUCC;

          rule=node(LEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_319) rew(mod_319);
        expr_ret_314 = expr_ret_319 ? SUCC : NULL;
      }

      // SlashExpr 3
      if (!expr_ret_314)
      {
        daisho_astnode_t* expr_ret_321 = NULL;
        rec(mod_321);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Not capturing GEQ.
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
          expr_ret_322 = daisho_parse_shfexpr(ctx);
          expr_ret_321 = expr_ret_322;
          n = expr_ret_322;
        }

        // ModExprList 2
        if (expr_ret_321)
        {
          // CodeExpr
          #define ret expr_ret_321
          ret = SUCC;

          rule=node(GEQ, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_321) rew(mod_321);
        expr_ret_314 = expr_ret_321 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_314) rew(slash_314);
      expr_ret_313 = expr_ret_314;

    }

    expr_ret_313 = SUCC;
    expr_ret_311 = expr_ret_313;
  }

  // ModExprList end
  if (!expr_ret_311) rew(mod_311);
  expr_ret_310 = expr_ret_311 ? SUCC : NULL;
  if (!rule) rule = expr_ret_310;
  if (!expr_ret_310) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  #define rule expr_ret_323

  daisho_astnode_t* expr_ret_324 = NULL;
  daisho_astnode_t* expr_ret_323 = NULL;
  daisho_astnode_t* expr_ret_325 = NULL;
  rec(mod_325);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_326 = NULL;
    expr_ret_326 = daisho_parse_powexpr(ctx);
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
    expr_ret_327 = SUCC;
    while (expr_ret_327)
    {
      daisho_astnode_t* expr_ret_328 = NULL;

      rec(slash_328);

      // SlashExpr 0
      if (!expr_ret_328)
      {
        daisho_astnode_t* expr_ret_329 = NULL;
        rec(mod_329);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_330 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_330 = leaf(LT);
            #if DAISHO_SOURCEINFO
            expr_ret_330->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_330->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_330 = NULL;
          }

          expr_ret_329 = expr_ret_330;
          l = expr_ret_330;
        }

        // ModExprList 1
        if (expr_ret_329)
        {
          daisho_astnode_t* expr_ret_331 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_331 = leaf(LT);
            #if DAISHO_SOURCEINFO
            expr_ret_331->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_331->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_331 = NULL;
          }

          expr_ret_329 = expr_ret_331;
          lt = expr_ret_331;
        }

        // ModExprList 2
        if (expr_ret_329)
        {
          daisho_astnode_t* expr_ret_332 = NULL;
          expr_ret_332 = daisho_parse_powexpr(ctx);
          expr_ret_329 = expr_ret_332;
          n = expr_ret_332;
        }

        // ModExprList 3
        if (expr_ret_329)
        {
          // CodeExpr
          #define ret expr_ret_329
          ret = SUCC;

          rule=node(BSL, l, lt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_329) rew(mod_329);
        expr_ret_328 = expr_ret_329 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_328)
      {
        daisho_astnode_t* expr_ret_333 = NULL;
        rec(mod_333);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_334 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_334 = leaf(GT);
            #if DAISHO_SOURCEINFO
            expr_ret_334->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_334->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_334 = NULL;
          }

          expr_ret_333 = expr_ret_334;
          g = expr_ret_334;
        }

        // ModExprList 1
        if (expr_ret_333)
        {
          daisho_astnode_t* expr_ret_335 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_335 = leaf(GT);
            #if DAISHO_SOURCEINFO
            expr_ret_335->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_335->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_335 = NULL;
          }

          expr_ret_333 = expr_ret_335;
          gt = expr_ret_335;
        }

        // ModExprList 2
        if (expr_ret_333)
        {
          daisho_astnode_t* expr_ret_336 = NULL;
          expr_ret_336 = daisho_parse_powexpr(ctx);
          expr_ret_333 = expr_ret_336;
          n = expr_ret_336;
        }

        // ModExprList 3
        if (expr_ret_333)
        {
          // CodeExpr
          #define ret expr_ret_333
          ret = SUCC;

          rule=node(BSR, g, gt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_333) rew(mod_333);
        expr_ret_328 = expr_ret_333 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_328) rew(slash_328);
      expr_ret_327 = expr_ret_328;

    }

    expr_ret_327 = SUCC;
    expr_ret_325 = expr_ret_327;
  }

  // ModExprList end
  if (!expr_ret_325) rew(mod_325);
  expr_ret_324 = expr_ret_325 ? SUCC : NULL;
  if (!rule) rule = expr_ret_324;
  if (!expr_ret_324) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_337

  daisho_astnode_t* expr_ret_338 = NULL;
  daisho_astnode_t* expr_ret_337 = NULL;
  daisho_astnode_t* expr_ret_339 = NULL;
  rec(mod_339);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_340 = NULL;
    expr_ret_340 = daisho_parse_multexpr(ctx);
    expr_ret_339 = expr_ret_340;
    n = expr_ret_340;
  }

  // ModExprList 1
  if (expr_ret_339)
  {
    // CodeExpr
    #define ret expr_ret_339
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_339)
  {
    daisho_astnode_t* expr_ret_341 = NULL;
    expr_ret_341 = SUCC;
    while (expr_ret_341)
    {
      daisho_astnode_t* expr_ret_342 = NULL;
      rec(mod_342);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_342 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_342 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_342)
      {
        // CodeExpr
        #define ret expr_ret_342
        ret = SUCC;

        rule=node(POW, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_342) rew(mod_342);
      expr_ret_341 = expr_ret_342 ? SUCC : NULL;
    }

    expr_ret_341 = SUCC;
    expr_ret_339 = expr_ret_341;
  }

  // ModExprList end
  if (!expr_ret_339) rew(mod_339);
  expr_ret_338 = expr_ret_339 ? SUCC : NULL;
  if (!rule) rule = expr_ret_338;
  if (!expr_ret_338) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_343

  daisho_astnode_t* expr_ret_344 = NULL;
  daisho_astnode_t* expr_ret_343 = NULL;
  daisho_astnode_t* expr_ret_345 = NULL;
  rec(mod_345);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_346 = NULL;
    expr_ret_346 = daisho_parse_sumexpr(ctx);
    expr_ret_345 = expr_ret_346;
    n = expr_ret_346;
  }

  // ModExprList 1
  if (expr_ret_345)
  {
    // CodeExpr
    #define ret expr_ret_345
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_345)
  {
    daisho_astnode_t* expr_ret_347 = NULL;
    expr_ret_347 = SUCC;
    while (expr_ret_347)
    {
      daisho_astnode_t* expr_ret_348 = NULL;

      rec(slash_348);

      // SlashExpr 0
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_349 = NULL;
        rec(mod_349);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
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
          expr_ret_350 = daisho_parse_sumexpr(ctx);
          expr_ret_349 = expr_ret_350;
          n = expr_ret_350;
        }

        // ModExprList 2
        if (expr_ret_349)
        {
          // CodeExpr
          #define ret expr_ret_349
          ret = SUCC;

          rule=node(STAR, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_349) rew(mod_349);
        expr_ret_348 = expr_ret_349 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_351 = NULL;
        rec(mod_351);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Not capturing DIV.
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
          expr_ret_352 = daisho_parse_sumexpr(ctx);
          expr_ret_351 = expr_ret_352;
          n = expr_ret_352;
        }

        // ModExprList 2
        if (expr_ret_351)
        {
          // CodeExpr
          #define ret expr_ret_351
          ret = SUCC;

          rule=node(DIV,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_351) rew(mod_351);
        expr_ret_348 = expr_ret_351 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_348)
      {
        daisho_astnode_t* expr_ret_353 = NULL;
        rec(mod_353);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Not capturing MOD.
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
          expr_ret_354 = daisho_parse_sumexpr(ctx);
          expr_ret_353 = expr_ret_354;
          n = expr_ret_354;
        }

        // ModExprList 2
        if (expr_ret_353)
        {
          // CodeExpr
          #define ret expr_ret_353
          ret = SUCC;

          rule=node(MOD,  rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_353) rew(mod_353);
        expr_ret_348 = expr_ret_353 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_348) rew(slash_348);
      expr_ret_347 = expr_ret_348;

    }

    expr_ret_347 = SUCC;
    expr_ret_345 = expr_ret_347;
  }

  // ModExprList end
  if (!expr_ret_345) rew(mod_345);
  expr_ret_344 = expr_ret_345 ? SUCC : NULL;
  if (!rule) rule = expr_ret_344;
  if (!expr_ret_344) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_355

  daisho_astnode_t* expr_ret_356 = NULL;
  daisho_astnode_t* expr_ret_355 = NULL;
  daisho_astnode_t* expr_ret_357 = NULL;
  rec(mod_357);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_358 = NULL;
    expr_ret_358 = daisho_parse_callexpr(ctx);
    expr_ret_357 = expr_ret_358;
    n = expr_ret_358;
  }

  // ModExprList 1
  if (expr_ret_357)
  {
    // CodeExpr
    #define ret expr_ret_357
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_357)
  {
    daisho_astnode_t* expr_ret_359 = NULL;
    expr_ret_359 = SUCC;
    while (expr_ret_359)
    {
      daisho_astnode_t* expr_ret_360 = NULL;

      rec(slash_360);

      // SlashExpr 0
      if (!expr_ret_360)
      {
        daisho_astnode_t* expr_ret_361 = NULL;
        rec(mod_361);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_362 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Capturing PLUS.
            expr_ret_362 = leaf(PLUS);
            #if DAISHO_SOURCEINFO
            expr_ret_362->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_362->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_362 = NULL;
          }

          expr_ret_361 = expr_ret_362;
          p = expr_ret_362;
        }

        // ModExprList 1
        if (expr_ret_361)
        {
          daisho_astnode_t* expr_ret_363 = NULL;
          expr_ret_363 = daisho_parse_callexpr(ctx);
          expr_ret_361 = expr_ret_363;
          n = expr_ret_363;
        }

        // ModExprList 2
        if (expr_ret_361)
        {
          // CodeExpr
          #define ret expr_ret_361
          ret = SUCC;

          rule=repr(node(PLUS, rule, n), p);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_361) rew(mod_361);
        expr_ret_360 = expr_ret_361 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_360)
      {
        daisho_astnode_t* expr_ret_364 = NULL;
        rec(mod_364);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_365 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Capturing MINUS.
            expr_ret_365 = leaf(MINUS);
            #if DAISHO_SOURCEINFO
            expr_ret_365->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_365->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_365 = NULL;
          }

          expr_ret_364 = expr_ret_365;
          m = expr_ret_365;
        }

        // ModExprList 1
        if (expr_ret_364)
        {
          daisho_astnode_t* expr_ret_366 = NULL;
          expr_ret_366 = daisho_parse_callexpr(ctx);
          expr_ret_364 = expr_ret_366;
          n = expr_ret_366;
        }

        // ModExprList 2
        if (expr_ret_364)
        {
          // CodeExpr
          #define ret expr_ret_364
          ret = SUCC;

          rule=repr(node(MINUS, rule, n), m);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_364) rew(mod_364);
        expr_ret_360 = expr_ret_364 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_360) rew(slash_360);
      expr_ret_359 = expr_ret_360;

    }

    expr_ret_359 = SUCC;
    expr_ret_357 = expr_ret_359;
  }

  // ModExprList end
  if (!expr_ret_357) rew(mod_357);
  expr_ret_356 = expr_ret_357 ? SUCC : NULL;
  if (!rule) rule = expr_ret_356;
  if (!expr_ret_356) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_367

  daisho_astnode_t* expr_ret_368 = NULL;
  daisho_astnode_t* expr_ret_367 = NULL;
  daisho_astnode_t* expr_ret_369 = NULL;

  rec(slash_369);

  // SlashExpr 0
  if (!expr_ret_369)
  {
    daisho_astnode_t* expr_ret_370 = NULL;
    rec(mod_370);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_370 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_370 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_370)
    {
      daisho_astnode_t* expr_ret_371 = NULL;
      expr_ret_371 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_371)
        expr_ret_371 = SUCC;
      expr_ret_370 = expr_ret_371;
      t = expr_ret_371;
    }

    // ModExprList 2
    if (expr_ret_370)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_370 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_370 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_370)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_370 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_370 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_370) rew(mod_370);
    expr_ret_369 = expr_ret_370 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_369)
  {
    daisho_astnode_t* expr_ret_372 = NULL;
    rec(mod_372);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_373 = NULL;
      expr_ret_373 = daisho_parse_castexpr(ctx);
      expr_ret_372 = expr_ret_373;
      n = expr_ret_373;
    }

    // ModExprList 1
    if (expr_ret_372)
    {
      // CodeExpr
      #define ret expr_ret_372
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_372) rew(mod_372);
    expr_ret_369 = expr_ret_372 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_369) rew(slash_369);
  expr_ret_368 = expr_ret_369;

  if (!rule) rule = expr_ret_368;
  if (!expr_ret_368) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_374

  daisho_astnode_t* expr_ret_375 = NULL;
  daisho_astnode_t* expr_ret_374 = NULL;
  daisho_astnode_t* expr_ret_376 = NULL;
  rec(mod_376);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_377 = NULL;
    expr_ret_377 = daisho_parse_refexpr(ctx);
    expr_ret_376 = expr_ret_377;
    n = expr_ret_377;
  }

  // ModExprList 1
  if (expr_ret_376)
  {
    daisho_astnode_t* expr_ret_378 = NULL;
    daisho_astnode_t* expr_ret_379 = NULL;
    rec(mod_379);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_379 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_379 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_379)
    {
      daisho_astnode_t* expr_ret_380 = NULL;
      expr_ret_380 = daisho_parse_type(ctx);
      expr_ret_379 = expr_ret_380;
      t = expr_ret_380;
    }

    // ModExprList 2
    if (expr_ret_379)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_379 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_379 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_379) rew(mod_379);
    expr_ret_378 = expr_ret_379 ? SUCC : NULL;
    // optional
    if (!expr_ret_378)
      expr_ret_378 = SUCC;
    expr_ret_376 = expr_ret_378;
  }

  // ModExprList 2
  if (expr_ret_376)
  {
    // CodeExpr
    #define ret expr_ret_376
    ret = SUCC;

    rule = t ? node(CAST, t, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_376) rew(mod_376);
  expr_ret_375 = expr_ret_376 ? SUCC : NULL;
  if (!rule) rule = expr_ret_375;
  if (!expr_ret_375) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_381

  daisho_astnode_t* expr_ret_382 = NULL;
  daisho_astnode_t* expr_ret_381 = NULL;
  daisho_astnode_t* expr_ret_383 = NULL;
  rec(mod_383);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_384 = NULL;
    expr_ret_384 = daisho_parse_derefexpr(ctx);
    expr_ret_383 = expr_ret_384;
    n = expr_ret_384;
  }

  // ModExprList 1
  if (expr_ret_383)
  {
    daisho_astnode_t* expr_ret_385 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_385 = leaf(REF);
      #if DAISHO_SOURCEINFO
      expr_ret_385->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_385->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_385 = NULL;
    }

    // optional
    if (!expr_ret_385)
      expr_ret_385 = SUCC;
    expr_ret_383 = expr_ret_385;
    r = expr_ret_385;
  }

  // ModExprList 2
  if (expr_ret_383)
  {
    // CodeExpr
    #define ret expr_ret_383
    ret = SUCC;

    rule=(r != SUCC) ? node(REF, r, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_383) rew(mod_383);
  expr_ret_382 = expr_ret_383 ? SUCC : NULL;
  if (!rule) rule = expr_ret_382;
  if (!expr_ret_382) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_386

  daisho_astnode_t* expr_ret_387 = NULL;
  daisho_astnode_t* expr_ret_386 = NULL;
  daisho_astnode_t* expr_ret_388 = NULL;
  rec(mod_388);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_389 = NULL;
    expr_ret_389 = daisho_parse_postretexpr(ctx);
    expr_ret_388 = expr_ret_389;
    n = expr_ret_389;
  }

  // ModExprList 1
  if (expr_ret_388)
  {
    daisho_astnode_t* expr_ret_390 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
      // Capturing DEREF.
      expr_ret_390 = leaf(DEREF);
      #if DAISHO_SOURCEINFO
      expr_ret_390->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_390->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_390 = NULL;
    }

    // optional
    if (!expr_ret_390)
      expr_ret_390 = SUCC;
    expr_ret_388 = expr_ret_390;
    d = expr_ret_390;
  }

  // ModExprList 2
  if (expr_ret_388)
  {
    // CodeExpr
    #define ret expr_ret_388
    ret = SUCC;

    rule=(d != SUCC) ? node(REF, d, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_388) rew(mod_388);
  expr_ret_387 = expr_ret_388 ? SUCC : NULL;
  if (!rule) rule = expr_ret_387;
  if (!expr_ret_387) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  #define rule expr_ret_391

  daisho_astnode_t* expr_ret_392 = NULL;
  daisho_astnode_t* expr_ret_391 = NULL;
  daisho_astnode_t* expr_ret_393 = NULL;
  rec(mod_393);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_394 = NULL;
    expr_ret_394 = daisho_parse_atomexpr(ctx);
    expr_ret_393 = expr_ret_394;
    n = expr_ret_394;
  }

  // ModExprList 1
  if (expr_ret_393)
  {
    daisho_astnode_t* expr_ret_395 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      // Capturing GRAVE.
      expr_ret_395 = leaf(GRAVE);
      #if DAISHO_SOURCEINFO
      expr_ret_395->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_395->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_395 = NULL;
    }

    // optional
    if (!expr_ret_395)
      expr_ret_395 = SUCC;
    expr_ret_393 = expr_ret_395;
    g = expr_ret_395;
  }

  // ModExprList 2
  if (expr_ret_393)
  {
    // CodeExpr
    #define ret expr_ret_393
    ret = SUCC;

    rule=(g != SUCC) ? node(RET, g, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_393) rew(mod_393);
  expr_ret_392 = expr_ret_393 ? SUCC : NULL;
  if (!rule) rule = expr_ret_392;
  if (!expr_ret_392) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_396

  daisho_astnode_t* expr_ret_397 = NULL;
  daisho_astnode_t* expr_ret_396 = NULL;
  daisho_astnode_t* expr_ret_398 = NULL;

  rec(slash_398);

  // SlashExpr 0
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_399 = NULL;
    rec(mod_399);
    // ModExprList Forwarding
    expr_ret_399 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_399) rew(mod_399);
    expr_ret_398 = expr_ret_399;
  }

  // SlashExpr 1
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_400 = NULL;
    rec(mod_400);
    // ModExprList Forwarding
    expr_ret_400 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_400) rew(mod_400);
    expr_ret_398 = expr_ret_400;
  }

  // SlashExpr 2
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_401 = NULL;
    rec(mod_401);
    // ModExprList Forwarding
    expr_ret_401 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_401) rew(mod_401);
    expr_ret_398 = expr_ret_401;
  }

  // SlashExpr 3
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_402 = NULL;
    rec(mod_402);
    // ModExprList Forwarding
    expr_ret_402 = daisho_parse_listlit(ctx);
    // ModExprList end
    if (!expr_ret_402) rew(mod_402);
    expr_ret_398 = expr_ret_402;
  }

  // SlashExpr 4
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_403 = NULL;
    rec(mod_403);
    // ModExprList Forwarding
    expr_ret_403 = daisho_parse_tuplelit(ctx);
    // ModExprList end
    if (!expr_ret_403) rew(mod_403);
    expr_ret_398 = expr_ret_403;
  }

  // SlashExpr 5
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_404 = NULL;
    rec(mod_404);
    // ModExprList Forwarding
    expr_ret_404 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_404) rew(mod_404);
    expr_ret_398 = expr_ret_404;
  }

  // SlashExpr 6
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_405 = NULL;
    rec(mod_405);
    // ModExprList Forwarding
    expr_ret_405 = daisho_parse_cfuncexpr(ctx);
    // ModExprList end
    if (!expr_ret_405) rew(mod_405);
    expr_ret_398 = expr_ret_405;
  }

  // SlashExpr 7
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_406 = NULL;
    rec(mod_406);
    // ModExprList Forwarding
    expr_ret_406 = daisho_parse_preretexpr(ctx);
    // ModExprList end
    if (!expr_ret_406) rew(mod_406);
    expr_ret_398 = expr_ret_406;
  }

  // SlashExpr 8
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_407 = NULL;
    rec(mod_407);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_407 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_407->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_407->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_407 = NULL;
    }

    // ModExprList end
    if (!expr_ret_407) rew(mod_407);
    expr_ret_398 = expr_ret_407;
  }

  // SlashExpr 9
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_408 = NULL;
    rec(mod_408);
    // ModExprList Forwarding
    expr_ret_408 = daisho_parse_numlit(ctx);
    // ModExprList end
    if (!expr_ret_408) rew(mod_408);
    expr_ret_398 = expr_ret_408;
  }

  // SlashExpr 10
  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_409 = NULL;
    rec(mod_409);
    // ModExprList Forwarding
    expr_ret_409 = daisho_parse_strlit(ctx);
    // ModExprList end
    if (!expr_ret_409) rew(mod_409);
    expr_ret_398 = expr_ret_409;
  }

  // SlashExpr end
  if (!expr_ret_398) rew(slash_398);
  expr_ret_397 = expr_ret_398;

  if (!rule) rule = expr_ret_397;
  if (!expr_ret_397) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_410

  daisho_astnode_t* expr_ret_411 = NULL;
  daisho_astnode_t* expr_ret_410 = NULL;
  daisho_astnode_t* expr_ret_412 = NULL;
  rec(mod_412);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_412 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_412 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_412)
  {
    // CodeExpr
    #define ret expr_ret_412
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_412)
  {
    daisho_astnode_t* expr_ret_413 = NULL;
    expr_ret_413 = SUCC;
    while (expr_ret_413)
    {
      daisho_astnode_t* expr_ret_414 = NULL;
      rec(mod_414);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_415 = NULL;
        expr_ret_415 = daisho_parse_expr(ctx);
        expr_ret_414 = expr_ret_415;
        e = expr_ret_415;
      }

      // ModExprList 1
      if (expr_ret_414)
      {
        // CodeExpr
        #define ret expr_ret_414
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_414) rew(mod_414);
      expr_ret_413 = expr_ret_414 ? SUCC : NULL;
    }

    expr_ret_413 = SUCC;
    expr_ret_412 = expr_ret_413;
  }

  // ModExprList 3
  if (expr_ret_412)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_412 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_412 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_412) rew(mod_412);
  expr_ret_411 = expr_ret_412 ? SUCC : NULL;
  if (!rule) rule = expr_ret_411;
  if (!expr_ret_411) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_416

  daisho_astnode_t* expr_ret_417 = NULL;
  daisho_astnode_t* expr_ret_416 = NULL;
  daisho_astnode_t* expr_ret_418 = NULL;
  rec(mod_418);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_419 = NULL;
    daisho_astnode_t* expr_ret_420 = NULL;
    rec(mod_420);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_420 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_420 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_420)
    {
      daisho_astnode_t* expr_ret_421 = NULL;
      expr_ret_421 = daisho_parse_expr(ctx);
      // optional
      if (!expr_ret_421)
        expr_ret_421 = SUCC;
      expr_ret_420 = expr_ret_421;
    }

    // ModExprList 2
    if (expr_ret_420)
    {
      daisho_astnode_t* expr_ret_422 = NULL;
      expr_ret_422 = SUCC;
      while (expr_ret_422)
      {
        daisho_astnode_t* expr_ret_423 = NULL;
        rec(mod_423);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_423 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_423 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_423)
        {
          expr_ret_423 = daisho_parse_expr(ctx);
        }

        // ModExprList end
        if (!expr_ret_423) rew(mod_423);
        expr_ret_422 = expr_ret_423 ? SUCC : NULL;
      }

      expr_ret_422 = SUCC;
      expr_ret_420 = expr_ret_422;
    }

    // ModExprList 3
    if (expr_ret_420)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_420 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_420 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_420) rew(mod_420);
    expr_ret_419 = expr_ret_420 ? SUCC : NULL;
    // optional
    if (!expr_ret_419)
      expr_ret_419 = SUCC;
    expr_ret_418 = expr_ret_419;
  }

  // ModExprList 1
  if (expr_ret_418)
  {
    daisho_astnode_t* expr_ret_424 = NULL;

    rec(slash_424);

    // SlashExpr 0
    if (!expr_ret_424)
    {
      daisho_astnode_t* expr_ret_425 = NULL;
      rec(mod_425);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_426 = NULL;
      rec(mod_426);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_426 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_426 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_426)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_426 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_426 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_426) rew(mod_426);
      expr_ret_425 = expr_ret_426 ? SUCC : NULL;
      // ModExprList end
      if (!expr_ret_425) rew(mod_425);
      expr_ret_424 = expr_ret_425;
    }

    // SlashExpr 1
    if (!expr_ret_424)
    {
      daisho_astnode_t* expr_ret_427 = NULL;
      rec(mod_427);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_428 = NULL;
      rec(mod_428);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_428 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_428 = NULL;
      }

      // ModExprList end
      if (!expr_ret_428) rew(mod_428);
      expr_ret_427 = expr_ret_428;
      // ModExprList end
      if (!expr_ret_427) rew(mod_427);
      expr_ret_424 = expr_ret_427;
    }

    // SlashExpr end
    if (!expr_ret_424) rew(slash_424);
    expr_ret_418 = expr_ret_424;

  }

  // ModExprList 2
  if (expr_ret_418)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_418 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_418 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_418)
  {
    expr_ret_418 = daisho_parse_expr(ctx);
  }

  // ModExprList end
  if (!expr_ret_418) rew(mod_418);
  expr_ret_417 = expr_ret_418 ? SUCC : NULL;
  if (!rule) rule = expr_ret_417;
  if (!expr_ret_417) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  #define rule expr_ret_429

  daisho_astnode_t* expr_ret_430 = NULL;
  daisho_astnode_t* expr_ret_429 = NULL;
  daisho_astnode_t* expr_ret_431 = NULL;
  rec(mod_431);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_431 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_431 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_431)
  {
    daisho_astnode_t* expr_ret_432 = NULL;
    daisho_astnode_t* expr_ret_433 = NULL;
    rec(mod_433);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_434 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_434 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_434->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_434->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_434 = NULL;
      }

      expr_ret_433 = expr_ret_434;
      cnt = expr_ret_434;
    }

    // ModExprList 1
    if (expr_ret_433)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_433 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_433 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_433) rew(mod_433);
    expr_ret_432 = expr_ret_433 ? SUCC : NULL;
    // optional
    if (!expr_ret_432)
      expr_ret_432 = SUCC;
    expr_ret_431 = expr_ret_432;
  }

  // ModExprList 2
  if (expr_ret_431)
  {
    expr_ret_431 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_431)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_431 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_431 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_431)
  {
    daisho_astnode_t* expr_ret_435 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_435 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_435->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_435->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_435 = NULL;
    }

    expr_ret_431 = expr_ret_435;
    item = expr_ret_435;
  }

  // ModExprList 5
  if (expr_ret_431)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_431 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_431 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_431)
  {
    expr_ret_431 = daisho_parse_expr(ctx);
  }

  // ModExprList 7
  if (expr_ret_431)
  {
    daisho_astnode_t* expr_ret_436 = NULL;
    daisho_astnode_t* expr_ret_437 = NULL;
    rec(mod_437);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        // Not capturing WHERE.
        expr_ret_437 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_437 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_437)
    {
      expr_ret_437 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_437) rew(mod_437);
    expr_ret_436 = expr_ret_437 ? SUCC : NULL;
    // optional
    if (!expr_ret_436)
      expr_ret_436 = SUCC;
    expr_ret_431 = expr_ret_436;
  }

  // ModExprList 8
  if (expr_ret_431)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_431 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_431 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_431) rew(mod_431);
  expr_ret_430 = expr_ret_431 ? SUCC : NULL;
  if (!rule) rule = expr_ret_430;
  if (!expr_ret_430) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_438

  daisho_astnode_t* expr_ret_439 = NULL;
  daisho_astnode_t* expr_ret_438 = NULL;
  daisho_astnode_t* expr_ret_440 = NULL;
  rec(mod_440);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_440 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_440 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_440)
  {
    daisho_astnode_t* expr_ret_441 = NULL;
    expr_ret_441 = daisho_parse_expr(ctx);
    expr_ret_440 = expr_ret_441;
    e = expr_ret_441;
  }

  // ModExprList 2
  if (expr_ret_440)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_440 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_440 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_440)
  {
    // CodeExpr
    #define ret expr_ret_440
    ret = SUCC;

    rule=e;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_440) rew(mod_440);
  expr_ret_439 = expr_ret_440 ? SUCC : NULL;
  if (!rule) rule = expr_ret_439;
  if (!expr_ret_439) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_442

  daisho_astnode_t* expr_ret_443 = NULL;
  daisho_astnode_t* expr_ret_442 = NULL;
  daisho_astnode_t* expr_ret_444 = NULL;
  rec(mod_444);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_444 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_444 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_444)
  {
    daisho_astnode_t* expr_ret_445 = NULL;
    expr_ret_445 = daisho_parse_expr(ctx);
    expr_ret_444 = expr_ret_445;
    e = expr_ret_445;
  }

  // ModExprList 2
  if (expr_ret_444)
  {
    daisho_astnode_t* expr_ret_446 = NULL;

    rec(slash_446);

    // SlashExpr 0
    if (!expr_ret_446)
    {
      daisho_astnode_t* expr_ret_447 = NULL;
      rec(mod_447);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_448 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_448 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_448 = NULL;
        }

        // optional
        if (!expr_ret_448)
          expr_ret_448 = SUCC;
        expr_ret_447 = expr_ret_448;
      }

      // ModExprList 1
      if (expr_ret_447)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_447 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_447 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_447) rew(mod_447);
      expr_ret_446 = expr_ret_447 ? SUCC : NULL;
    }

    // SlashExpr 1
    if (!expr_ret_446)
    {
      daisho_astnode_t* expr_ret_449 = NULL;
      rec(mod_449);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_450 = NULL;
        expr_ret_450 = SUCC;
        while (expr_ret_450)
        {
          daisho_astnode_t* expr_ret_451 = NULL;
          rec(mod_451);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
              expr_ret_451 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_451 = NULL;
            }

          }

          // ModExprList 1
          if (expr_ret_451)
          {
            daisho_astnode_t* expr_ret_452 = NULL;
            expr_ret_452 = daisho_parse_expr(ctx);
            expr_ret_451 = expr_ret_452;
            e = expr_ret_452;
          }

          // ModExprList end
          if (!expr_ret_451) rew(mod_451);
          expr_ret_450 = expr_ret_451 ? SUCC : NULL;
        }

        expr_ret_450 = SUCC;
        expr_ret_449 = expr_ret_450;
      }

      // ModExprList 1
      if (expr_ret_449)
      {
        daisho_astnode_t* expr_ret_453 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_453 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_453 = NULL;
        }

        // optional
        if (!expr_ret_453)
          expr_ret_453 = SUCC;
        expr_ret_449 = expr_ret_453;
      }

      // ModExprList 2
      if (expr_ret_449)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_449 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_449 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_449) rew(mod_449);
      expr_ret_446 = expr_ret_449 ? SUCC : NULL;
    }

    // SlashExpr end
    if (!expr_ret_446) rew(slash_446);
    expr_ret_444 = expr_ret_446;

  }

  // ModExprList end
  if (!expr_ret_444) rew(mod_444);
  expr_ret_443 = expr_ret_444 ? SUCC : NULL;
  if (!rule) rule = expr_ret_443;
  if (!expr_ret_443) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_454

  daisho_astnode_t* expr_ret_455 = NULL;
  daisho_astnode_t* expr_ret_454 = NULL;
  daisho_astnode_t* expr_ret_456 = NULL;
  rec(mod_456);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_456 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_456 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_456)
  {
    daisho_astnode_t* expr_ret_457 = NULL;
    expr_ret_457 = daisho_parse_expr(ctx);
    expr_ret_456 = expr_ret_457;
    e = expr_ret_457;
  }

  // ModExprList 2
  if (expr_ret_456)
  {
    daisho_astnode_t* expr_ret_458 = NULL;

    rec(slash_458);

    // SlashExpr 0
    if (!expr_ret_458)
    {
      daisho_astnode_t* expr_ret_459 = NULL;
      rec(mod_459);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_459 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_459 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_459)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_459 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_459 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_459) rew(mod_459);
      expr_ret_458 = expr_ret_459 ? SUCC : NULL;
    }

    // SlashExpr 1
    if (!expr_ret_458)
    {
      daisho_astnode_t* expr_ret_460 = NULL;
      rec(mod_460);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_461 = NULL;
        expr_ret_461 = SUCC;
        while (expr_ret_461)
        {
          daisho_astnode_t* expr_ret_462 = NULL;
          rec(mod_462);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
              expr_ret_462 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_462 = NULL;
            }

          }

          // ModExprList 1
          if (expr_ret_462)
          {
            daisho_astnode_t* expr_ret_463 = NULL;
            expr_ret_463 = daisho_parse_expr(ctx);
            expr_ret_462 = expr_ret_463;
            e = expr_ret_463;
          }

          // ModExprList end
          if (!expr_ret_462) rew(mod_462);
          expr_ret_461 = expr_ret_462 ? SUCC : NULL;
        }

        expr_ret_461 = SUCC;
        expr_ret_460 = expr_ret_461;
      }

      // ModExprList 1
      if (expr_ret_460)
      {
        daisho_astnode_t* expr_ret_464 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_464 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_464 = NULL;
        }

        // optional
        if (!expr_ret_464)
          expr_ret_464 = SUCC;
        expr_ret_460 = expr_ret_464;
      }

      // ModExprList 2
      if (expr_ret_460)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_460 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_460 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_460) rew(mod_460);
      expr_ret_458 = expr_ret_460 ? SUCC : NULL;
    }

    // SlashExpr end
    if (!expr_ret_458) rew(slash_458);
    expr_ret_456 = expr_ret_458;

  }

  // ModExprList end
  if (!expr_ret_456) rew(mod_456);
  expr_ret_455 = expr_ret_456 ? SUCC : NULL;
  if (!rule) rule = expr_ret_455;
  if (!expr_ret_455) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_465

  daisho_astnode_t* expr_ret_466 = NULL;
  daisho_astnode_t* expr_ret_465 = NULL;
  daisho_astnode_t* expr_ret_467 = NULL;
  rec(mod_467);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
      // Not capturing CFN.
      expr_ret_467 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_467 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_467)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_467 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_467 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_467) rew(mod_467);
  expr_ret_466 = expr_ret_467 ? SUCC : NULL;
  if (!rule) rule = expr_ret_466;
  if (!expr_ret_466) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_468

  daisho_astnode_t* expr_ret_469 = NULL;
  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_470 = NULL;
  rec(mod_470);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_471 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_471 = leaf(RET);
      #if DAISHO_SOURCEINFO
      expr_ret_471->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_471->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_471 = NULL;
    }

    expr_ret_470 = expr_ret_471;
    r = expr_ret_471;
  }

  // ModExprList 1
  if (expr_ret_470)
  {
    daisho_astnode_t* expr_ret_472 = NULL;
    expr_ret_472 = daisho_parse_expr(ctx);
    expr_ret_470 = expr_ret_472;
    e = expr_ret_472;
  }

  // ModExprList 2
  if (expr_ret_470)
  {
    // CodeExpr
    #define ret expr_ret_470
    ret = SUCC;

    rule=node(RET, r, e);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_470) rew(mod_470);
  expr_ret_469 = expr_ret_470 ? SUCC : NULL;
  if (!rule) rule = expr_ret_469;
  if (!expr_ret_469) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* pm = NULL;
  daisho_astnode_t* nl = NULL;
  #define rule expr_ret_473

  daisho_astnode_t* expr_ret_474 = NULL;
  daisho_astnode_t* expr_ret_473 = NULL;
  daisho_astnode_t* expr_ret_475 = NULL;
  rec(mod_475);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_476 = NULL;
    daisho_astnode_t* expr_ret_477 = NULL;

    rec(slash_477);

    // SlashExpr 0
    if (!expr_ret_477)
    {
      daisho_astnode_t* expr_ret_478 = NULL;
      rec(mod_478);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
        // Capturing PLUS.
        expr_ret_478 = leaf(PLUS);
        #if DAISHO_SOURCEINFO
        expr_ret_478->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_478->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_478 = NULL;
      }

      // ModExprList end
      if (!expr_ret_478) rew(mod_478);
      expr_ret_477 = expr_ret_478;
    }

    // SlashExpr 1
    if (!expr_ret_477)
    {
      daisho_astnode_t* expr_ret_479 = NULL;
      rec(mod_479);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
        // Capturing MINUS.
        expr_ret_479 = leaf(MINUS);
        #if DAISHO_SOURCEINFO
        expr_ret_479->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_479->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_479 = NULL;
      }

      // ModExprList end
      if (!expr_ret_479) rew(mod_479);
      expr_ret_477 = expr_ret_479;
    }

    // SlashExpr end
    if (!expr_ret_477) rew(slash_477);
    expr_ret_476 = expr_ret_477;

    // optional
    if (!expr_ret_476)
      expr_ret_476 = SUCC;
    expr_ret_475 = expr_ret_476;
    pm = expr_ret_476;
  }

  // ModExprList 1
  if (expr_ret_475)
  {
    daisho_astnode_t* expr_ret_480 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_480 = leaf(NUMLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_480->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_480->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_480 = NULL;
    }

    expr_ret_475 = expr_ret_480;
    nl = expr_ret_480;
  }

  // ModExprList 2
  if (expr_ret_475)
  {
    // CodeExpr
    #define ret expr_ret_475
    ret = SUCC;

    rule = nl;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_475) rew(mod_475);
  expr_ret_474 = expr_ret_475 ? SUCC : NULL;
  if (!rule) rule = expr_ret_474;
  if (!expr_ret_474) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_481

  daisho_astnode_t* expr_ret_482 = NULL;
  daisho_astnode_t* expr_ret_481 = NULL;
  daisho_astnode_t* expr_ret_483 = NULL;
  rec(mod_483);
  // ModExprList Forwarding
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_483 = leaf(STRLIT);
    #if DAISHO_SOURCEINFO
    expr_ret_483->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_483->len_or_toknum = ctx->tokens[ctx->pos].len;
    #endif
    ctx->pos++;
  } else {
    expr_ret_483 = NULL;
  }

  // ModExprList end
  if (!expr_ret_483) rew(mod_483);
  expr_ret_482 = expr_ret_483;
  if (!rule) rule = expr_ret_482;
  if (!expr_ret_482) rule = NULL;
  rule_end:;
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

