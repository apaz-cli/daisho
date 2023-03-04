
/* START OF UTF8 LIBRARY */

#ifndef UTF8_INCLUDED
#define UTF8_INCLUDED
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

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
  c = state->inp[state->idx++];
  return c;
}

static inline char UTF8_contByte(UTF8Decoder *state) {
  char c;
  c = UTF8_nextByte(state);
  return ((c & 0xC0) == 0x80) ? (c & 0x3F) : UTF8_ERR;
}

/* Extract the next unicode code point. Returns the codepoint, UTF8_END, or
 * UTF8_ERR. */
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

/*
 * Encodes the codepoint as utf8 into the buffer, and returns the number of
 * characters written. If the codepoint is invalid, nothing is written and zero
 * is returned.
 */
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
 * length to retlen. The result is not null terminated.
 * Returns 1 on success, 0 on failure. Cleans up the buffer and does not store
 * to retstr or retlen on failure.
 */
static inline int UTF8_encode(codepoint_t *codepoints, size_t len,
                              char **retstr, size_t *retlen) {
  char buf4[4];
  size_t characters_used, used, i, j;
  char *out_buf, *new_obuf;

  if ((!codepoints) | (!len))
    return 0;
  if (!(out_buf = (char *)malloc(len * sizeof(codepoint_t) + 1)))
    return 0;

  characters_used = 0;
  for (i = 0; i < len; i++) {
    if (!(used = UTF8_encodeNext(codepoints[i], buf4)))
      return free(out_buf), 0;
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

  if (cp == UTF8_ERR) {
    free(cpbuf);
    return 0;
  }

  *retcps = cpbuf;
  *retlen = cps_read;
  return 1;
}

#endif /* UTF8_INCLUDED */

/* END OF UTF8 LIBRARY */


#ifndef PGEN_INTERACTIVE
#define PGEN_INTERACTIVE 1

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
#define PGEN_NUM_ARENAS 256
#define PGEN_NUM_FREELIST 256

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
  pgen_arena_t arenas[PGEN_NUM_ARENAS];
  pgen_freelist_t freelist;
} pgen_allocator;

static inline pgen_allocator pgen_allocator_new(void) {
  pgen_allocator alloc;

  alloc.rew.arena_idx = 0;
  alloc.rew.filled = 0;

  for (size_t i = 0; i < PGEN_NUM_ARENAS; i++) {
    alloc.arenas[i].freefn = NULL;
    alloc.arenas[i].buf = NULL;
    alloc.arenas[i].cap = 0;
  }

  alloc.freelist.entries = (pgen_freelist_entry_t *)malloc(
      sizeof(pgen_freelist_entry_t) * PGEN_NUM_FREELIST);
  if (alloc.freelist.entries) {
    alloc.freelist.cap = PGEN_NUM_FREELIST;
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
  for (size_t i = 0; i < PGEN_NUM_ARENAS; i++) {
    if (!allocator->arenas[i].buf) {
      allocator->arenas[i] = arena;
      return 1;
    }
  }
  return 0;
}

static inline void pgen_allocator_destroy(pgen_allocator *allocator) {
  // Free all the buffers
  for (size_t i = 0; i < PGEN_NUM_ARENAS; i++) {
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

#define PGEN_ALLOC(allocator, type)                                         \
  (type *)pgen_alloc(allocator, sizeof(type), _Alignof(type))
static void *_aa_last;
#define PGEN_ALLOC_ASSIGN(allocator, type, value)                              \
  (_aa_last = PGEN_ALLOC(allocator, type), (*(type *)_aa_last = value), *(type *)_aa_last)
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
      if (allocator->rew.arena_idx + 1 >= PGEN_NUM_ARENAS)
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
  allocator->rew.filled = (uint32_t)bufnext;

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

  if (!freefn | !ptr)
    return;

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
  allocator->freelist.len = (uint32_t)next_len;

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
    allocator->freelist.len = (uint32_t)i;
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
#ifndef DAIC_TYPES_INCLUDE
#include "../types.h"
#endif
struct PreMonoSymtab;
typedef struct PreMonoSymtab PreMonoSymtab;
struct PreExprType;
typedef struct PreExprType PreExprType;

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
  DAISHO_TOK_EXCL,
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
  DAISHO_TOK_IF,
  DAISHO_TOK_ELSE,
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
  DAISHO_TOK_NATIVE,
  DAISHO_TOK_SEMI,
  DAISHO_TOK_DOT,
  DAISHO_TOK_COMMA,
  DAISHO_TOK_APOSTROPHE,
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
  DAISHO_TOK_NUMLIT,
  DAISHO_TOK_STRLIT,
  DAISHO_TOK_FSTRLITSTART,
  DAISHO_TOK_FSTRLITMID,
  DAISHO_TOK_FSTRLITEND,
  DAISHO_TOK_CHARLIT,
  DAISHO_TOK_WS,
  DAISHO_TOK_MLCOM,
  DAISHO_TOK_SLCOM,
  DAISHO_TOK_SHEBANG,
} daisho_token_kind;

// The 0th token is beginning of stream.
// The 1st token isend of stream.
// Tokens 1 through 90 are the ones you defined.
// This totals 92 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 92
static const char* daisho_tokenkind_name[DAISHO_NUM_TOKENKINDS] = {
  "STREAMBEGIN",
  "STREAMEND",
  "PLUS",
  "MINUS",
  "STAR",
  "POW",
  "DIV",
  "MOD",
  "AND",
  "OR",
  "XOR",
  "EXCL",
  "BITNOT",
  "LOGAND",
  "LOGOR",
  "DEQ",
  "NEQ",
  "LT",
  "LEQ",
  "GT",
  "GEQ",
  "EQ",
  "PLEQ",
  "MINEQ",
  "MULEQ",
  "DIVEQ",
  "MODEQ",
  "ANDEQ",
  "OREQ",
  "XOREQ",
  "BNEQ",
  "BSREQ",
  "BSLEQ",
  "INCR",
  "DECR",
  "QUEST",
  "COLON",
  "NCOLL",
  "IF",
  "ELSE",
  "FOR",
  "IN",
  "WHILE",
  "THEN",
  "ALSO",
  "WHERE",
  "STRUCT",
  "UNION",
  "TRAIT",
  "IMPL",
  "FN",
  "FNTYPE",
  "CTYPE",
  "CFN",
  "SELFTYPE",
  "SELFVAR",
  "VOIDTYPE",
  "VOIDPTR",
  "SIZEOF",
  "NAMESPACE",
  "NATIVE",
  "SEMI",
  "DOT",
  "COMMA",
  "APOSTROPHE",
  "OPEN",
  "CLOSE",
  "LCBRACK",
  "RCBRACK",
  "LSBRACK",
  "RSBRACK",
  "HASH",
  "REF",
  "DEREF",
  "GRAVE",
  "ARROW",
  "DARROW",
  "RET",
  "OP",
  "REDEF",
  "TYPEIDENT",
  "VARIDENT",
  "NUMLIT",
  "STRLIT",
  "FSTRLITSTART",
  "FSTRLITMID",
  "FSTRLITEND",
  "CHARLIT",
  "WS",
  "MLCOM",
  "SLCOM",
  "SHEBANG",
};

typedef struct {
  daisho_token_kind kind;
  codepoint_t* content; // The token begins at tokenizer->start[token->start].
  size_t len;
  size_t line;
  size_t col;
#ifdef DAISHO_TOKEN_EXTRA
  DAISHO_TOKEN_EXTRA
#endif
} daisho_token;

typedef struct {
  codepoint_t* start;
  size_t len;
  size_t pos;
  size_t pos_line;
  size_t pos_col;
} daisho_tokenizer;

static inline void daisho_tokenizer_init(daisho_tokenizer* tokenizer, codepoint_t* start, size_t len) {
  tokenizer->start = start;
  tokenizer->len = len;
  tokenizer->pos = 0;
  tokenizer->pos_line = 1;
  tokenizer->pos_col = 0;
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
  int smaut_state_15 = 0;
  int smaut_state_16 = 0;
  int smaut_state_17 = 0;
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
  size_t smaut_munch_size_15 = 0;
  size_t smaut_munch_size_16 = 0;
  size_t smaut_munch_size_17 = 0;
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;

  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 10;
        else if (c == 35 /*'#'*/) trie_state = 123;
        else if (c == 36 /*'$'*/) trie_state = 125;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 39 /*'''*/) trie_state = 116;
        else if (c == 40 /*'('*/) trie_state = 117;
        else if (c == 41 /*')'*/) trie_state = 118;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 115;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 114;
        else if (c == 47 /*'/'*/) trie_state = 5;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 113;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 124;
        else if (c == 70 /*'F'*/) trie_state = 75;
        else if (c == 83 /*'S'*/) trie_state = 84;
        else if (c == 86 /*'V'*/) trie_state = 92;
        else if (c == 91 /*'['*/) trie_state = 121;
        else if (c == 93 /*']'*/) trie_state = 122;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 126;
        else if (c == 97 /*'a'*/) trie_state = 58;
        else if (c == 99 /*'c'*/) trie_state = 77;
        else if (c == 101 /*'e'*/) trie_state = 41;
        else if (c == 102 /*'f'*/) trie_state = 45;
        else if (c == 105 /*'i'*/) trie_state = 39;
        else if (c == 110 /*'n'*/) trie_state = 104;
        else if (c == 115 /*'s'*/) trie_state = 88;
        else if (c == 116 /*'t'*/) trie_state = 54;
        else if (c == 117 /*'u'*/) trie_state = 65;
        else if (c == 119 /*'w'*/) trie_state = 49;
        else if (c == 123 /*'{'*/) trie_state = 119;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 120;
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
        else if (c == 62 /*'>'*/) trie_state = 127;
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
        else if (c == 62 /*'>'*/) trie_state = 128;
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
        if (c == 102 /*'f'*/) trie_state = 40;
        else if (c == 110 /*'n'*/) trie_state = 48;
        else trie_state = -1;
      }
      else if (trie_state == 41) {
        if (c == 108 /*'l'*/) trie_state = 42;
        else trie_state = -1;
      }
      else if (trie_state == 42) {
        if (c == 115 /*'s'*/) trie_state = 43;
        else trie_state = -1;
      }
      else if (trie_state == 43) {
        if (c == 101 /*'e'*/) trie_state = 44;
        else trie_state = -1;
      }
      else if (trie_state == 45) {
        if (c == 110 /*'n'*/) trie_state = 74;
        else if (c == 111 /*'o'*/) trie_state = 46;
        else trie_state = -1;
      }
      else if (trie_state == 46) {
        if (c == 114 /*'r'*/) trie_state = 47;
        else trie_state = -1;
      }
      else if (trie_state == 49) {
        if (c == 104 /*'h'*/) trie_state = 50;
        else trie_state = -1;
      }
      else if (trie_state == 50) {
        if (c == 101 /*'e'*/) trie_state = 62;
        else if (c == 105 /*'i'*/) trie_state = 51;
        else trie_state = -1;
      }
      else if (trie_state == 51) {
        if (c == 108 /*'l'*/) trie_state = 52;
        else trie_state = -1;
      }
      else if (trie_state == 52) {
        if (c == 101 /*'e'*/) trie_state = 53;
        else trie_state = -1;
      }
      else if (trie_state == 54) {
        if (c == 104 /*'h'*/) trie_state = 55;
        else if (c == 114 /*'r'*/) trie_state = 70;
        else trie_state = -1;
      }
      else if (trie_state == 55) {
        if (c == 101 /*'e'*/) trie_state = 56;
        else trie_state = -1;
      }
      else if (trie_state == 56) {
        if (c == 110 /*'n'*/) trie_state = 57;
        else trie_state = -1;
      }
      else if (trie_state == 58) {
        if (c == 108 /*'l'*/) trie_state = 59;
        else trie_state = -1;
      }
      else if (trie_state == 59) {
        if (c == 115 /*'s'*/) trie_state = 60;
        else trie_state = -1;
      }
      else if (trie_state == 60) {
        if (c == 111 /*'o'*/) trie_state = 61;
        else trie_state = -1;
      }
      else if (trie_state == 62) {
        if (c == 114 /*'r'*/) trie_state = 63;
        else trie_state = -1;
      }
      else if (trie_state == 63) {
        if (c == 101 /*'e'*/) trie_state = 64;
        else trie_state = -1;
      }
      else if (trie_state == 65) {
        if (c == 110 /*'n'*/) trie_state = 66;
        else trie_state = -1;
      }
      else if (trie_state == 66) {
        if (c == 105 /*'i'*/) trie_state = 67;
        else trie_state = -1;
      }
      else if (trie_state == 67) {
        if (c == 111 /*'o'*/) trie_state = 68;
        else trie_state = -1;
      }
      else if (trie_state == 68) {
        if (c == 110 /*'n'*/) trie_state = 69;
        else trie_state = -1;
      }
      else if (trie_state == 70) {
        if (c == 97 /*'a'*/) trie_state = 71;
        else trie_state = -1;
      }
      else if (trie_state == 71) {
        if (c == 105 /*'i'*/) trie_state = 72;
        else trie_state = -1;
      }
      else if (trie_state == 72) {
        if (c == 116 /*'t'*/) trie_state = 73;
        else trie_state = -1;
      }
      else if (trie_state == 75) {
        if (c == 110 /*'n'*/) trie_state = 76;
        else trie_state = -1;
      }
      else if (trie_state == 77) {
        if (c == 102 /*'f'*/) trie_state = 82;
        else if (c == 116 /*'t'*/) trie_state = 78;
        else trie_state = -1;
      }
      else if (trie_state == 78) {
        if (c == 121 /*'y'*/) trie_state = 79;
        else trie_state = -1;
      }
      else if (trie_state == 79) {
        if (c == 112 /*'p'*/) trie_state = 80;
        else trie_state = -1;
      }
      else if (trie_state == 80) {
        if (c == 101 /*'e'*/) trie_state = 81;
        else trie_state = -1;
      }
      else if (trie_state == 82) {
        if (c == 110 /*'n'*/) trie_state = 83;
        else trie_state = -1;
      }
      else if (trie_state == 84) {
        if (c == 101 /*'e'*/) trie_state = 85;
        else trie_state = -1;
      }
      else if (trie_state == 85) {
        if (c == 108 /*'l'*/) trie_state = 86;
        else trie_state = -1;
      }
      else if (trie_state == 86) {
        if (c == 102 /*'f'*/) trie_state = 87;
        else trie_state = -1;
      }
      else if (trie_state == 88) {
        if (c == 101 /*'e'*/) trie_state = 89;
        else if (c == 105 /*'i'*/) trie_state = 99;
        else trie_state = -1;
      }
      else if (trie_state == 89) {
        if (c == 108 /*'l'*/) trie_state = 90;
        else trie_state = -1;
      }
      else if (trie_state == 90) {
        if (c == 102 /*'f'*/) trie_state = 91;
        else trie_state = -1;
      }
      else if (trie_state == 92) {
        if (c == 111 /*'o'*/) trie_state = 93;
        else trie_state = -1;
      }
      else if (trie_state == 93) {
        if (c == 105 /*'i'*/) trie_state = 94;
        else trie_state = -1;
      }
      else if (trie_state == 94) {
        if (c == 100 /*'d'*/) trie_state = 95;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 80 /*'P'*/) trie_state = 96;
        else trie_state = -1;
      }
      else if (trie_state == 96) {
        if (c == 116 /*'t'*/) trie_state = 97;
        else trie_state = -1;
      }
      else if (trie_state == 97) {
        if (c == 114 /*'r'*/) trie_state = 98;
        else trie_state = -1;
      }
      else if (trie_state == 99) {
        if (c == 122 /*'z'*/) trie_state = 100;
        else trie_state = -1;
      }
      else if (trie_state == 100) {
        if (c == 101 /*'e'*/) trie_state = 101;
        else trie_state = -1;
      }
      else if (trie_state == 101) {
        if (c == 111 /*'o'*/) trie_state = 102;
        else trie_state = -1;
      }
      else if (trie_state == 102) {
        if (c == 102 /*'f'*/) trie_state = 103;
        else trie_state = -1;
      }
      else if (trie_state == 104) {
        if (c == 97 /*'a'*/) trie_state = 105;
        else trie_state = -1;
      }
      else if (trie_state == 105) {
        if (c == 109 /*'m'*/) trie_state = 106;
        else trie_state = -1;
      }
      else if (trie_state == 106) {
        if (c == 101 /*'e'*/) trie_state = 107;
        else trie_state = -1;
      }
      else if (trie_state == 107) {
        if (c == 115 /*'s'*/) trie_state = 108;
        else trie_state = -1;
      }
      else if (trie_state == 108) {
        if (c == 112 /*'p'*/) trie_state = 109;
        else trie_state = -1;
      }
      else if (trie_state == 109) {
        if (c == 97 /*'a'*/) trie_state = 110;
        else trie_state = -1;
      }
      else if (trie_state == 110) {
        if (c == 99 /*'c'*/) trie_state = 111;
        else trie_state = -1;
      }
      else if (trie_state == 111) {
        if (c == 101 /*'e'*/) trie_state = 112;
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
        trie_tokenkind =  DAISHO_TOK_EXCL;
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
      else if (trie_state == 40) {
        trie_tokenkind =  DAISHO_TOK_IF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 44) {
        trie_tokenkind =  DAISHO_TOK_ELSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 47) {
        trie_tokenkind =  DAISHO_TOK_FOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 48) {
        trie_tokenkind =  DAISHO_TOK_IN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 53) {
        trie_tokenkind =  DAISHO_TOK_WHILE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 57) {
        trie_tokenkind =  DAISHO_TOK_THEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 61) {
        trie_tokenkind =  DAISHO_TOK_ALSO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 64) {
        trie_tokenkind =  DAISHO_TOK_WHERE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 69) {
        trie_tokenkind =  DAISHO_TOK_UNION;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 73) {
        trie_tokenkind =  DAISHO_TOK_TRAIT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 74) {
        trie_tokenkind =  DAISHO_TOK_FN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 76) {
        trie_tokenkind =  DAISHO_TOK_FNTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 81) {
        trie_tokenkind =  DAISHO_TOK_CTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 83) {
        trie_tokenkind =  DAISHO_TOK_CFN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 87) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 91) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 95) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
        trie_tokenkind =  DAISHO_TOK_VOIDPTR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 103) {
        trie_tokenkind =  DAISHO_TOK_SIZEOF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_NAMESPACE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 114) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 115) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 116) {
        trie_tokenkind =  DAISHO_TOK_APOSTROPHE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 117) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 118) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 119) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 120) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 121) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 122) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 123) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 124) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 125) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 126) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 127) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 128) {
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

    // Transition NATIVE State Machine
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
         (c == 116)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 105)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 118)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 101)) {
          smaut_state_2 = 6;
      }
      else if ((smaut_state_2 == 0) &
         (c == 99)) {
          smaut_state_2 = 7;
      }
      else if ((smaut_state_2 == 7) &
         (c == 99)) {
          smaut_state_2 = 8;
      }
      else if ((smaut_state_2 == 8) &
         (c == 111)) {
          smaut_state_2 = 9;
      }
      else if ((smaut_state_2 == 9) &
         (c == 100)) {
          smaut_state_2 = 10;
      }
      else if ((smaut_state_2 == 10) &
         (c == 101)) {
          smaut_state_2 = 11;
      }
      else {
        smaut_state_2 = -1;
      }

      // Check accept
      if ((smaut_state_2 == 6) | (smaut_state_2 == 11)) {
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
         ((c >= 65) & (c <= 90))) {
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

    // Transition NUMLIT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 >= 0) & (smaut_state_8 <= 2)) &
         ((c >= 48) & (c <= 57))) {
          smaut_state_8 = 2;
      }
      else if ((smaut_state_8 == 2) &
         (c == 46)) {
          smaut_state_8 = 3;
      }
      else if ((smaut_state_8 == 3) &
         ((c >= 48) & (c <= 57))) {
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
         (c == 123)) {
          smaut_state_9 = -1;
      }
      else if ((smaut_state_9 == 1) &
         (c == 10)) {
          smaut_state_9 = -1;
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
      else if ((smaut_state_9 == 3) &
         (c == 123)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 3) &
         (c == 125)) {
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

    // Transition FSTRLITSTART State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         (c == 34)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 1) &
         (c == 123)) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 1) &
         (c == 34)) {
          smaut_state_10 = -1;
      }
      else if ((smaut_state_10 == 1) &
         (c == 10)) {
          smaut_state_10 = -1;
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
      else if ((smaut_state_10 == 3) &
         (c == 123)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 125)) {
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

    // Transition FSTRLITMID State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 125)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 123)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 1) &
         (c == 34)) {
          smaut_state_11 = -1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 10)) {
          smaut_state_11 = -1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 92)) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 1) &
         (1)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 110)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 102)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 98)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 114)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 116)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 101)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 92)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 39)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 34)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 123)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 125)) {
          smaut_state_11 = 1;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if (smaut_state_11 == 2) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition FSTRLITEND State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 125)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 34)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 1) &
         (c == 123)) {
          smaut_state_12 = -1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 10)) {
          smaut_state_12 = -1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 92)) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 1) &
         (1)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 110)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 102)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 98)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 114)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 116)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 101)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 92)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 39)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 34)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 123)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 125)) {
          smaut_state_12 = 1;
      }
      else {
        smaut_state_12 = -1;
      }

      // Check accept
      if (smaut_state_12 == 2) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    // Transition CHARLIT State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == 39)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 10)) {
          smaut_state_13 = -1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 92)) {
          smaut_state_13 = 4;
      }
      else if ((smaut_state_13 == 1) &
         (1)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 110)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 102)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 98)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 114)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 116)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 101)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 92)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 4) &
         (c == 39)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 2) &
         (c == 39)) {
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

    // Transition WS State Machine
    if (smaut_state_14 != -1) {
      all_dead = 0;

      if (((smaut_state_14 == 0) | (smaut_state_14 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_14 = 1;
      }
      else {
        smaut_state_14 = -1;
      }

      // Check accept
      if (smaut_state_14 == 1) {
        smaut_munch_size_14 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_15 != -1) {
      all_dead = 0;

      if ((smaut_state_15 == 0) &
         (c == 47)) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 1) &
         (c == 42)) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 2) &
         (c == 42)) {
          smaut_state_15 = 3;
      }
      else if ((smaut_state_15 == 2) &
         (1)) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 3) &
         (c == 42)) {
          smaut_state_15 = 3;
      }
      else if ((smaut_state_15 == 3) &
         (c == 47)) {
          smaut_state_15 = 4;
      }
      else if ((smaut_state_15 == 3) &
         (1)) {
          smaut_state_15 = 2;
      }
      else {
        smaut_state_15 = -1;
      }

      // Check accept
      if (smaut_state_15 == 4) {
        smaut_munch_size_15 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_16 != -1) {
      all_dead = 0;

      if ((smaut_state_16 == 0) &
         (c == 47)) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 1) &
         (c == 47)) {
          smaut_state_16 = 2;
      }
      else if ((smaut_state_16 == 2) &
         (!(c == 10))) {
          smaut_state_16 = 2;
      }
      else if ((smaut_state_16 == 2) &
         (c == 10)) {
          smaut_state_16 = 3;
      }
      else {
        smaut_state_16 = -1;
      }

      // Check accept
      if ((smaut_state_16 == 2) | (smaut_state_16 == 3)) {
        smaut_munch_size_16 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_17 != -1) {
      all_dead = 0;

      if ((smaut_state_17 == 0) &
         (c == 35)) {
          smaut_state_17 = 1;
      }
      else if ((smaut_state_17 == 1) &
         (c == 33)) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 2) &
         (!(c == 10))) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 2) &
         (c == 10)) {
          smaut_state_17 = 3;
      }
      else {
        smaut_state_17 = -1;
      }

      // Check accept
      if (smaut_state_17 == 3) {
        smaut_munch_size_17 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_17 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_17;
  }
  if (smaut_munch_size_16 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_16;
  }
  if (smaut_munch_size_15 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_15;
  }
  if (smaut_munch_size_14 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_14;
  }
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_CHARLIT;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITEND;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITMID;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITSTART;
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
    kind = DAISHO_TOK_NATIVE;
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

  tokenizer->pos += max_munch;
  return ret;
}

#endif /* DAISHO_TOKENIZER_INCLUDE */

#ifndef PGEN_DAISHO_ASTNODE_INCLUDE
#define PGEN_DAISHO_ASTNODE_INCLUDE

struct daisho_parse_err;
typedef struct daisho_parse_err daisho_parse_err;
struct daisho_parse_err {
  const char* msg;
  int severity;
  size_t line;
  size_t col;
};

#ifndef DAISHO_MAX_PARSER_ERRORS
#define DAISHO_MAX_PARSER_ERRORS 20
#endif
typedef struct {
  daisho_token* tokens;
  size_t len;
  size_t pos;
  int exit;
  pgen_allocator *alloc;
  size_t num_errors;
  daisho_parse_err errlist[DAISHO_MAX_PARSER_ERRORS];
} daisho_parser_ctx;

static inline void daisho_parser_ctx_init(daisho_parser_ctx* parser,
                                       pgen_allocator* allocator,
                                       daisho_token* tokens, size_t num_tokens) {
  parser->tokens = tokens;
  parser->len = num_tokens;
  parser->pos = 0;
  parser->exit = 0;
  parser->alloc = allocator;
  parser->num_errors = 0;
  size_t to_zero = sizeof(daisho_parse_err) * DAISHO_MAX_PARSER_ERRORS;
  memset(&parser->errlist, 0, to_zero);
}
static inline void freemsg(const char* msg, void* extra) {
  (void)extra;
  free((void*)msg);
}

static inline daisho_parse_err* daisho_report_parse_error(daisho_parser_ctx* ctx,
              const char* msg, void (*msgfree)(const char* msg, void* extra), int severity) {
  if (ctx->num_errors >= DAISHO_MAX_PARSER_ERRORS) {
    ctx->exit = 1;
    return NULL;
  }
  daisho_parse_err* err = &ctx->errlist[ctx->num_errors++];
  err->msg = (const char*)msg;
  err->severity = severity;
  if (ctx->pos < ctx->len) {
    size_t toknum = ctx->pos + (ctx->pos != ctx->len - 1);
    daisho_token tok = ctx->tokens[toknum];
    err->line = tok.line;
    err->col = tok.col;
  } else {
    err->line = 0;
    err->col = 0;
  }

  if (severity == 3)
    ctx->exit = 1;
  return err;
}

typedef enum {
  DAISHO_NODE_PLUS,
  DAISHO_NODE_MINUS,
  DAISHO_NODE_STAR,
  DAISHO_NODE_POW,
  DAISHO_NODE_DIV,
  DAISHO_NODE_MOD,
  DAISHO_NODE_AND,
  DAISHO_NODE_OR,
  DAISHO_NODE_XOR,
  DAISHO_NODE_EXCL,
  DAISHO_NODE_BITNOT,
  DAISHO_NODE_LOGAND,
  DAISHO_NODE_LOGOR,
  DAISHO_NODE_DEQ,
  DAISHO_NODE_NEQ,
  DAISHO_NODE_LT,
  DAISHO_NODE_LEQ,
  DAISHO_NODE_GT,
  DAISHO_NODE_GEQ,
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
  DAISHO_NODE_INCR,
  DAISHO_NODE_DECR,
  DAISHO_NODE_QUEST,
  DAISHO_NODE_COLON,
  DAISHO_NODE_NCOLL,
  DAISHO_NODE_IF,
  DAISHO_NODE_ELSE,
  DAISHO_NODE_FOR,
  DAISHO_NODE_IN,
  DAISHO_NODE_WHILE,
  DAISHO_NODE_THEN,
  DAISHO_NODE_ALSO,
  DAISHO_NODE_WHERE,
  DAISHO_NODE_STRUCT,
  DAISHO_NODE_UNION,
  DAISHO_NODE_TRAIT,
  DAISHO_NODE_IMPL,
  DAISHO_NODE_FN,
  DAISHO_NODE_FNTYPE,
  DAISHO_NODE_CTYPE,
  DAISHO_NODE_CFN,
  DAISHO_NODE_SELFTYPE,
  DAISHO_NODE_SELFVAR,
  DAISHO_NODE_VOIDTYPE,
  DAISHO_NODE_VOIDPTR,
  DAISHO_NODE_SIZEOF,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_NATIVE,
  DAISHO_NODE_SEMI,
  DAISHO_NODE_DOT,
  DAISHO_NODE_COMMA,
  DAISHO_NODE_APOSTROPHE,
  DAISHO_NODE_OPEN,
  DAISHO_NODE_CLOSE,
  DAISHO_NODE_LCBRACK,
  DAISHO_NODE_RCBRACK,
  DAISHO_NODE_LSBRACK,
  DAISHO_NODE_RSBRACK,
  DAISHO_NODE_HASH,
  DAISHO_NODE_REF,
  DAISHO_NODE_DEREF,
  DAISHO_NODE_GRAVE,
  DAISHO_NODE_ARROW,
  DAISHO_NODE_DARROW,
  DAISHO_NODE_RET,
  DAISHO_NODE_OP,
  DAISHO_NODE_REDEF,
  DAISHO_NODE_TYPEIDENT,
  DAISHO_NODE_VARIDENT,
  DAISHO_NODE_NUMLIT,
  DAISHO_NODE_STRLIT,
  DAISHO_NODE_FSTRLITSTART,
  DAISHO_NODE_FSTRLITMID,
  DAISHO_NODE_FSTRLITEND,
  DAISHO_NODE_CHARLIT,
  DAISHO_NODE_WS,
  DAISHO_NODE_MLCOM,
  DAISHO_NODE_SLCOM,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_BASETYPE,
  DAISHO_NODE_CURRENT_NS,
  DAISHO_NODE_NSACCESS,
  DAISHO_NODE_RECOVERY,
  DAISHO_NODE_PROGRAM,
  DAISHO_NODE_NSLIST,
  DAISHO_NODE_NSDECLS,
  DAISHO_NODE_GLOBAL,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_FNHEAD,
  DAISHO_NODE_FNDECL,
  DAISHO_NODE_FNPROTO,
  DAISHO_NODE_TMPLEXPAND,
  DAISHO_NODE_NOEXPAND,
  DAISHO_NODE_COMPENUMERATE,
  DAISHO_NODE_COMPCOND,
  DAISHO_NODE_LISTCOMP,
  DAISHO_NODE_TERN,
  DAISHO_NODE_MUL,
  DAISHO_NODE_BSR,
  DAISHO_NODE_BSL,
  DAISHO_NODE_BLOCK,
  DAISHO_NODE_VARDECL,
  DAISHO_NODE_CAST,
  DAISHO_NODE_CALL,
  DAISHO_NODE_LAMBDA,
  DAISHO_NODE_FOREACH,
  DAISHO_NODE_ACCESS,
  DAISHO_NODE_LISTLIT,
  DAISHO_NODE_TUPLELIT,
  DAISHO_NODE_FNARG,
  DAISHO_NODE_PROTOARG,
  DAISHO_NODE_EXPANDLIST,
  DAISHO_NODE_ARGLIST,
  DAISHO_NODE_TYPELIST,
  DAISHO_NODE_EXPRLIST,
  DAISHO_NODE_PROTOLIST,
  DAISHO_NODE_TYPE,
  DAISHO_NODE_PTRTYPE,
  DAISHO_NODE_TUPLETYPE,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_DTRAITIDENT,
  DAISHO_NODE_SSTR,
  DAISHO_NODE_FSTR,
  DAISHO_NODE_FSTRFRAG,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 136
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "PLUS",
  "MINUS",
  "STAR",
  "POW",
  "DIV",
  "MOD",
  "AND",
  "OR",
  "XOR",
  "EXCL",
  "BITNOT",
  "LOGAND",
  "LOGOR",
  "DEQ",
  "NEQ",
  "LT",
  "LEQ",
  "GT",
  "GEQ",
  "EQ",
  "PLEQ",
  "MINEQ",
  "MULEQ",
  "DIVEQ",
  "MODEQ",
  "ANDEQ",
  "OREQ",
  "XOREQ",
  "BNEQ",
  "BSREQ",
  "BSLEQ",
  "INCR",
  "DECR",
  "QUEST",
  "COLON",
  "NCOLL",
  "IF",
  "ELSE",
  "FOR",
  "IN",
  "WHILE",
  "THEN",
  "ALSO",
  "WHERE",
  "STRUCT",
  "UNION",
  "TRAIT",
  "IMPL",
  "FN",
  "FNTYPE",
  "CTYPE",
  "CFN",
  "SELFTYPE",
  "SELFVAR",
  "VOIDTYPE",
  "VOIDPTR",
  "SIZEOF",
  "NAMESPACE",
  "NATIVE",
  "SEMI",
  "DOT",
  "COMMA",
  "APOSTROPHE",
  "OPEN",
  "CLOSE",
  "LCBRACK",
  "RCBRACK",
  "LSBRACK",
  "RSBRACK",
  "HASH",
  "REF",
  "DEREF",
  "GRAVE",
  "ARROW",
  "DARROW",
  "RET",
  "OP",
  "REDEF",
  "TYPEIDENT",
  "VARIDENT",
  "NUMLIT",
  "STRLIT",
  "FSTRLITSTART",
  "FSTRLITMID",
  "FSTRLITEND",
  "CHARLIT",
  "WS",
  "MLCOM",
  "SLCOM",
  "SHEBANG",
  "BASETYPE",
  "CURRENT_NS",
  "NSACCESS",
  "RECOVERY",
  "PROGRAM",
  "NSLIST",
  "NSDECLS",
  "GLOBAL",
  "MEMBERLIST",
  "TMPLTRAIT",
  "FNHEAD",
  "FNDECL",
  "FNPROTO",
  "TMPLEXPAND",
  "NOEXPAND",
  "COMPENUMERATE",
  "COMPCOND",
  "LISTCOMP",
  "TERN",
  "MUL",
  "BSR",
  "BSL",
  "BLOCK",
  "VARDECL",
  "CAST",
  "CALL",
  "LAMBDA",
  "FOREACH",
  "ACCESS",
  "LISTLIT",
  "TUPLELIT",
  "FNARG",
  "PROTOARG",
  "EXPANDLIST",
  "ARGLIST",
  "TYPELIST",
  "EXPRLIST",
  "PROTOLIST",
  "TYPE",
  "PTRTYPE",
  "TUPLETYPE",
  "TYPEMEMBER",
  "DTRAITIDENT",
  "SSTR",
  "FSTR",
  "FSTRFRAG",
};

struct daisho_astnode_t {
  daisho_astnode_t* parent;
  uint16_t num_children;
  uint16_t max_children;
  daisho_astnode_kind kind;

  codepoint_t* tok_repr;
  size_t repr_len;
  // Extra data in %extra directives:
  PreMonoSymtab* presymtab; // Anything in the scope created by this expression
  PreExprType* pretype; // The concrete type of this expression
  // End of extra data.
  daisho_astnode_t** children;
};

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
  node->max_children = (uint16_t)initial_size;
  node->num_children = 0;
  node->children = children;
  node->tok_repr = NULL;
  node->repr_len = 0;
  // Extra initialization from %extrainit directives:
  node->presymtab = NULL;
  node->pretype = NULL;
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
  node->tok_repr = NULL;
  node->repr_len = 0;
  // Extra initialization from %extrainit directives:
  node->presymtab = NULL;
  node->pretype = NULL;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_1(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0) {
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (n0 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p)\n", daisho_nodekind_name[kind], (void*)n0), exit(1);
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
  node->tok_repr = NULL;
  node->repr_len = 0;
  children[0] = n0;
  n0->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_2(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1) {
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (n0 == SUCC) | (n1 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1), exit(1);
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
  node->tok_repr = NULL;
  node->repr_len = 0;
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2), exit(1);
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
  node->tok_repr = NULL;
  node->repr_len = 0;
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (!n3) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC) | (n3 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2, (void*)n3), exit(1);
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
  node->tok_repr = NULL;
  node->repr_len = 0;
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (!n3) | (!n4) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC) | (n3 == SUCC) | (n4 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2, (void*)n3, (void*)n4), exit(1);
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
  node->tok_repr = NULL;
  node->repr_len = 0;
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
    list->max_children = (uint16_t)new_max;
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
  node->tok_repr = t->tok_repr;
  node->repr_len = t->repr_len;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_cprepr(daisho_astnode_t* node, codepoint_t* cps, size_t repr_len) {
  node->tok_repr = cps;
  node->repr_len = repr_len;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_srepr(pgen_allocator* allocator, daisho_astnode_t* node, char* s) {
  size_t cpslen = strlen(s);
  codepoint_t* cps = (codepoint_t*)pgen_alloc(allocator, (cpslen + 1) * sizeof(codepoint_t), _Alignof(codepoint_t));
  for (size_t i = 0; i < cpslen; i++) cps[i] = (codepoint_t)s[i];
  cps[cpslen] = 0;
  node->tok_repr = cps;
  node->repr_len = cpslen;
  return node;
}

static inline int daisho_node_print_content(daisho_astnode_t* node, daisho_token* tokens) {
  int found = 0;
  codepoint_t* utf32 = NULL; size_t utf32len = 0;
  char* utf8 = NULL; size_t utf8len = 0;
  if (node->tok_repr && node->repr_len) {
    utf32 = node->tok_repr;
    utf32len = node->repr_len;
    int success = UTF8_encode(node->tok_repr, node->repr_len, &utf8, &utf8len);
    if (success) {
      for (size_t i = 0; i < utf8len; i++)
        if (utf8[i] == '\n') fputc('\\', stdout), fputc('n', stdout);
        else fputc(utf8[i], stdout);
      return free(utf8), 1;
    }
  }
  return 0;
}

static inline int daisho_astnode_print_h(daisho_token* tokens, daisho_astnode_t *node, size_t depth, int fl) {
  #define indent() for (size_t i = 0; i < depth; i++) printf("  ")
  if (!node)
    return 0;
  else if (node == (daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t))
    puts("ERROR, CAPTURED SUCC."), exit(1);

  indent(); puts("{");
  depth++;
  indent(); printf("\"kind\": "); printf("\"%s\",\n", daisho_nodekind_name[node->kind]);
  if (!(!node->tok_repr & !node->repr_len)) {
    indent();
    printf("\"content\": \"");
    daisho_node_print_content(node, tokens);
    printf("\",\n");
  }
  size_t cnum = node->num_children;
  if (cnum) {
    indent(); printf("\"num_children\": %zu,\n", cnum);
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

#define SUCC                     (daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t)

#define rec(label)               pgen_parser_rewind_t _rew_##label = (pgen_parser_rewind_t){ctx->alloc->rew, ctx->pos};
#define rew(label)               daisho_parser_rewind(ctx, _rew_##label)
#define node(kindname, ...)      PGEN_CAT(daisho_astnode_fixed_, PGEN_NARG(__VA_ARGS__))(ctx->alloc, kind(kindname), __VA_ARGS__)
#define kind(name)               DAISHO_NODE_##name
#define list(kind)               daisho_astnode_list(ctx->alloc, DAISHO_NODE_##kind, 16)
#define leaf(kind)               daisho_astnode_leaf(ctx->alloc, DAISHO_NODE_##kind)
#define add(list, node)          daisho_astnode_add(ctx->alloc, list, node)
#define has(node)                (((uintptr_t)node <= (uintptr_t)SUCC) ? 0 : 1)
#define repr(node, t)            daisho_astnode_repr(node, t)
#define srepr(node, s)           daisho_astnode_srepr(ctx->alloc, node, (char*)s)
#define cprepr(node, cps, len)   daisho_astnode_cprepr(node, cps, len)
#define expect(kind, cap)        ((ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == daisho_TOK_##kind) ? ctx->pos++, (cap ? cprepr(leaf(kind), NULL, ctx->pos-1) : SUCC) : NULL)

#define LB {
#define RB }

#define INFO(msg)                daisho_report_parse_error(ctx, (const char*)msg, NULL,   0)
#define WARNING(msg)             daisho_report_parse_error(ctx, (const char*)msg, NULL,   1)
#define ERROR(msg)               daisho_report_parse_error(ctx, (const char*)msg, NULL,   2)
#define FATAL(msg)               daisho_report_parse_error(ctx, (const char*)msg, NULL,   3)
#define INFO_F(msg, freefn)      daisho_report_parse_error(ctx, (const char*)msg, freefn, 0)
#define WARNING_F(msg, freefn)   daisho_report_parse_error(ctx, (const char*)msg, freefn, 1)
#define ERROR_F(msg, freefn)     daisho_report_parse_error(ctx, (const char*)msg, freefn, 2)
#define FATAL_F(msg, freefn)     daisho_report_parse_error(ctx, (const char*)msg, freefn, 3)

/******************/
/* Mid Directives */
/******************/
#include <daisho/Daisho.h>
static inline int cpstr_equals(codepoint_t* s1, size_t l1, codepoint_t* s2, size_t l2) {
if (l1 != l2) return 0;
if (s1 == s2) return 1;
for (size_t i = 0; i < l1; i++) if (s1[i] != s2[i]) return 0;
return 1;
}

#define PGEN_INTERACTIVE_WIDTH 12
typedef struct {
  const char* rule_name;
  size_t pos;
} intr_entry;

static struct {
  intr_entry rules[500];
  size_t size;
  int status;
  int first;
} intr_stack;

#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
static inline void intr_display(daisho_parser_ctx* ctx, const char* last) {
  if (!intr_stack.first) intr_stack.first = 1;
  else getchar();

  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  size_t width = w.ws_col;
  size_t leftwidth = (width - (1 + 3 + 1)) / 2;
  size_t rightwidth = leftwidth + (leftwidth % 2);
  size_t height = w.ws_row - 4;

// Clear screen, cursor to top left
  printf("\x1b[2J\x1b[H");

  // Write first line in color.
  if (intr_stack.status == -1) {
    printf("\x1b[31m"); // Red
    printf("Failed: %s\n", last);
  } else if (intr_stack.status == 0) {
    printf("\x1b[34m"); // Blue
    printf("Entering: %s\n", last);
  } else if (intr_stack.status == 1) {
    printf("\x1b[32m"); // Green
    printf("Accepted: %s\n", last);
  } else {
    printf("\x1b[33m"); // Green
    printf("SUCCED: %s\n", last), exit(1);
  }
  printf("\x1b[0m"); // Clear Formatting

  // Write labels and line.
  for (size_t i = 0; i < width; i++)
    putchar('-');

  // Write following lines
  for (size_t i = height; i --> 0;) {
    putchar(' ');

    // Print rule stack
    if (i < intr_stack.size) {
      int d = intr_stack.size - height;      size_t disp = d > 0 ? i + d : i;      printf("%-12s", intr_stack.rules[disp].rule_name);
    } else {
      for (size_t sp = 0; sp < 12; sp++)
        putchar(' ');
    }

    printf(" | "); // Middle bar

    // Print tokens
    size_t remaining_tokens = ctx->len - ctx->pos;
    if (i < remaining_tokens) {
      const char* name = daisho_tokenkind_name[ctx->tokens[ctx->pos + i].kind];
      size_t remaining = rightwidth - strlen(name);
      printf("%s", name);
      for (size_t sp = 0; sp < remaining; sp++)
        putchar(' ');
    }

    putchar(' ');
    putchar('\n');
  }
}

static inline void intr_enter(daisho_parser_ctx* ctx, const char* name, size_t pos) {
  intr_stack.rules[intr_stack.size++] = (intr_entry){name, pos};
  intr_stack.status = 0;
  intr_display(ctx, name);
}

static inline void intr_accept(daisho_parser_ctx* ctx, const char* accpeting) {
  intr_stack.size--;
  intr_stack.status = 1;
  intr_display(ctx, accpeting);
}

static inline void intr_reject(daisho_parser_ctx* ctx, const char* rejecting) {
  intr_stack.size--;
  intr_stack.status = -1;
  intr_display(ctx, rejecting);
}
static inline void intr_succ(daisho_parser_ctx* ctx, const char* succing) {
  intr_stack.size--;
  intr_stack.status = 2;
  intr_display(ctx, succing);
}
static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_namespace(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_preifexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_notexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nsexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* nses = NULL;
  daisho_astnode_t* nsn = NULL;
  daisho_astnode_t* cn = NULL;
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* current = NULL;
  #define rule expr_ret_0
  daisho_astnode_t* expr_ret_0 = NULL;
  daisho_astnode_t* expr_ret_1 = NULL;
  intr_enter(ctx, "program", ctx->pos);
  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList 0
  daisho_astnode_t* expr_ret_3 = NULL;
  intr_enter(ctx, "SHEBANG", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
    // Not capturing SHEBANG.
    expr_ret_3 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_3 = NULL;
  }

  if (expr_ret_3) intr_accept(ctx, "SHEBANG"); else intr_reject(ctx, "SHEBANG");
  // optional
  if (!expr_ret_3)
    expr_ret_3 = SUCC;
  expr_ret_2 = expr_ret_3;
  sh = expr_ret_3;
  // ModExprList 1
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_4 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_4
    ret = SUCC;
    #line 17 "daisho.peg"
    ret=list(NSLIST);
    #line 3475 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_2 = expr_ret_4;
    nses = expr_ret_4;
  }

  // ModExprList 2
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_5 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_5
    ret = SUCC;
    #line 17 "daisho.peg"
    ;
    #line 3492 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_2 = expr_ret_5;
    nsn = expr_ret_5;
  }

  // ModExprList 3
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_6 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_6
    ret = SUCC;
    #line 17 "daisho.peg"
    ;
    #line 3509 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_2 = expr_ret_6;
    cn = expr_ret_6;
  }

  // ModExprList 4
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_7 = NULL;
    daisho_astnode_t* expr_ret_8 = SUCC;
    while (expr_ret_8)
    {
      rec(kleene_rew_7);
      daisho_astnode_t* expr_ret_9 = NULL;
      rec(mod_9);
      // ModExprList 0
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_9
      ret = SUCC;
      #line 18 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 3533 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList 1
      if (expr_ret_9) {
        daisho_astnode_t* expr_ret_10 = NULL;
        expr_ret_10 = daisho_parse_namespace(ctx);
        if (ctx->exit) return NULL;
        expr_ret_9 = expr_ret_10;
        ns = expr_ret_10;
      }

      // ModExprList 2
      if (expr_ret_9) {
        daisho_astnode_t* expr_ret_11 = NULL;
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_11
        ret = SUCC;
        #line 18 "daisho.peg"
        
                // The top level declarations of all namespaces are combined.
                int found = 0;
                for (size_t i = 0; i < nses->num_children; i++) {
                  current = nses->children[i];
                  if (cpstr_equals(current->children[0]->tok_repr,
                                   current->children[0]->repr_len,
                                   ns->children[0]->tok_repr,
                                   ns->children[0]->repr_len)) {
                    for (size_t j = 0; j < ns->children[1]->num_children; j++)
                      add(current->children[1], ns->children[1]->children[j]);
                    found = 1;
                    break;
                  }
                }
                if (!found)
                  add(nses, ns);
              ;
        #line 3572 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
        expr_ret_9 = expr_ret_11;
        current = expr_ret_11;
      }

      // ModExprList end
      if (!expr_ret_9) rew(mod_9);
      expr_ret_8 = expr_ret_9;
    }

    expr_ret_7 = SUCC;
    expr_ret_2 = expr_ret_7;
  }

  // ModExprList 5
  if (expr_ret_2) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_2
    ret = SUCC;
    #line 36 "daisho.peg"
    rule=(!has(sh)) ? node(PROGRAM, nses)
                              : node(PROGRAM, nses, sh);
    #line 3598 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2;
  if (!rule) rule = expr_ret_1;
  if (!expr_ret_1) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "program");
  else if (rule) intr_accept(ctx, "program");
  else intr_reject(ctx, "program");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_namespace(daisho_parser_ctx* ctx) {
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* l = NULL;
  #define rule expr_ret_12
  daisho_astnode_t* expr_ret_12 = NULL;
  daisho_astnode_t* expr_ret_13 = NULL;
  intr_enter(ctx, "namespace", ctx->pos);
  daisho_astnode_t* expr_ret_14 = NULL;
  rec(mod_14);
  // ModExprList 0
  daisho_astnode_t* expr_ret_15 = NULL;

  // SlashExpr 0
  if (!expr_ret_15) {
    daisho_astnode_t* expr_ret_16 = NULL;
    rec(mod_16);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_17 = NULL;
    rec(mod_17);
    // ModExprList 0
    intr_enter(ctx, "NAMESPACE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

    if (expr_ret_17) intr_accept(ctx, "NAMESPACE"); else intr_reject(ctx, "NAMESPACE");
    // ModExprList 1
    if (expr_ret_17) {
      daisho_astnode_t* expr_ret_18 = NULL;
      intr_enter(ctx, "TYPEIDENT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_18 = leaf(TYPEIDENT);
        expr_ret_18->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_18->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_18 = NULL;
      }

      if (expr_ret_18) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
      expr_ret_17 = expr_ret_18;
      name = expr_ret_18;
    }

    // ModExprList 2
    if (expr_ret_17) {
      expr_ret_17 = daisho_parse_wsemi(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList end
    if (!expr_ret_17) rew(mod_17);
    expr_ret_16 = expr_ret_17;
    // ModExprList end
    if (!expr_ret_16) rew(mod_16);
    expr_ret_15 = expr_ret_16;
  }

  // SlashExpr 1
  if (!expr_ret_15) {
    daisho_astnode_t* expr_ret_19 = NULL;
    rec(mod_19);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_20 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_20
    ret = SUCC;
    #line 40 "daisho.peg"
    ret=srepr(leaf(TYPEIDENT), "GLOBAL");
    #line 3692 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_19 = expr_ret_20;
    name = expr_ret_20;
    // ModExprList end
    if (!expr_ret_19) rew(mod_19);
    expr_ret_15 = expr_ret_19;
  }

  // SlashExpr end
  expr_ret_14 = expr_ret_15;

  // ModExprList 1
  if (expr_ret_14) {
    daisho_astnode_t* expr_ret_21 = NULL;
    expr_ret_21 = daisho_parse_topdecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_14 = expr_ret_21;
    t = expr_ret_21;
  }

  // ModExprList 2
  if (expr_ret_14) {
    daisho_astnode_t* expr_ret_22 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_22
    ret = SUCC;
    #line 41 "daisho.peg"
    ret = list(NSDECLS);
    #line 3724 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_14 = expr_ret_22;
    l = expr_ret_22;
  }

  // ModExprList 3
  if (expr_ret_14) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_14
    ret = SUCC;
    #line 41 "daisho.peg"
    add(l, t);
    #line 3740 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_14) {
    daisho_astnode_t* expr_ret_23 = NULL;
    daisho_astnode_t* expr_ret_24 = SUCC;
    while (expr_ret_24)
    {
      rec(kleene_rew_23);
      daisho_astnode_t* expr_ret_25 = NULL;
      rec(mod_25);
      // ModExprList 0
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_25
      ret = SUCC;
      #line 42 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 3762 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList 1
      if (expr_ret_25) {
        daisho_astnode_t* expr_ret_26 = NULL;

        // SlashExpr 0
        if (!expr_ret_26) {
          daisho_astnode_t* expr_ret_27 = NULL;
          rec(mod_27);
          // ModExprList Forwarding
          intr_enter(ctx, "SEMI", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_27 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_27 = NULL;
          }

          if (expr_ret_27) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
          // ModExprList end
          if (!expr_ret_27) rew(mod_27);
          expr_ret_26 = expr_ret_27;
        }

        // SlashExpr 1
        if (!expr_ret_26) {
          daisho_astnode_t* expr_ret_28 = NULL;
          rec(mod_28);
          // ModExprList 0
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_28
          ret = SUCC;
          #line 43 "daisho.peg"
          t=NULL;
          #line 3801 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
          // ModExprList 1
          if (expr_ret_28) {
            daisho_astnode_t* expr_ret_29 = NULL;
            expr_ret_29 = daisho_parse_topdecl(ctx);
            if (ctx->exit) return NULL;
            expr_ret_28 = expr_ret_29;
            t = expr_ret_29;
          }

          // ModExprList 2
          if (expr_ret_28) {
            // CodeExpr
            intr_enter(ctx, "CodeExpr", ctx->pos);
            #define ret expr_ret_28
            ret = SUCC;
            #line 43 "daisho.peg"
            add(l, t);
            #line 3822 "daisho_tokenizer_parser.h"

            if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
            #undef ret
          }

          // ModExprList end
          if (!expr_ret_28) rew(mod_28);
          expr_ret_26 = expr_ret_28;
        }

        // SlashExpr end
        expr_ret_25 = expr_ret_26;

      }

      // ModExprList end
      if (!expr_ret_25) rew(mod_25);
      expr_ret_24 = expr_ret_25;
    }

    expr_ret_23 = SUCC;
    expr_ret_14 = expr_ret_23;
  }

  // ModExprList 5
  if (expr_ret_14) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_14
    ret = SUCC;
    #line 44 "daisho.peg"
    rule = node(NAMESPACE, name, l);
    #line 3855 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_14) rew(mod_14);
  expr_ret_13 = expr_ret_14;
  if (!rule) rule = expr_ret_13;
  if (!expr_ret_13) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "namespace");
  else if (rule) intr_accept(ctx, "namespace");
  else intr_reject(ctx, "namespace");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_30
  daisho_astnode_t* expr_ret_30 = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
  intr_enter(ctx, "topdecl", ctx->pos);
  daisho_astnode_t* expr_ret_32 = NULL;

  // SlashExpr 0
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_33 = NULL;
    rec(mod_33);
    // ModExprList Forwarding
    expr_ret_33 = daisho_parse_structdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_33) rew(mod_33);
    expr_ret_32 = expr_ret_33;
  }

  // SlashExpr 1
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_34 = NULL;
    rec(mod_34);
    // ModExprList Forwarding
    expr_ret_34 = daisho_parse_uniondecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_34) rew(mod_34);
    expr_ret_32 = expr_ret_34;
  }

  // SlashExpr 2
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_35 = NULL;
    rec(mod_35);
    // ModExprList Forwarding
    expr_ret_35 = daisho_parse_traitdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_35) rew(mod_35);
    expr_ret_32 = expr_ret_35;
  }

  // SlashExpr 3
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_36 = NULL;
    rec(mod_36);
    // ModExprList Forwarding
    expr_ret_36 = daisho_parse_impldecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_36) rew(mod_36);
    expr_ret_32 = expr_ret_36;
  }

  // SlashExpr 4
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_37 = NULL;
    rec(mod_37);
    // ModExprList Forwarding
    expr_ret_37 = daisho_parse_ctypedecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_37) rew(mod_37);
    expr_ret_32 = expr_ret_37;
  }

  // SlashExpr 5
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_38 = NULL;
    rec(mod_38);
    // ModExprList Forwarding
    expr_ret_38 = daisho_parse_cfndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_38) rew(mod_38);
    expr_ret_32 = expr_ret_38;
  }

  // SlashExpr 6
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_39 = NULL;
    rec(mod_39);
    // ModExprList Forwarding
    expr_ret_39 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_39) rew(mod_39);
    expr_ret_32 = expr_ret_39;
  }

  // SlashExpr 7
  if (!expr_ret_32) {
    daisho_astnode_t* expr_ret_40 = NULL;
    rec(mod_40);
    // ModExprList Forwarding
    expr_ret_40 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_40) rew(mod_40);
    expr_ret_32 = expr_ret_40;
  }

  // SlashExpr end
  expr_ret_31 = expr_ret_32;

  if (!rule) rule = expr_ret_31;
  if (!expr_ret_31) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "topdecl");
  else if (rule) intr_accept(ctx, "topdecl");
  else intr_reject(ctx, "topdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* il = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_41
  daisho_astnode_t* expr_ret_41 = NULL;
  daisho_astnode_t* expr_ret_42 = NULL;
  intr_enter(ctx, "structdecl", ctx->pos);
  daisho_astnode_t* expr_ret_43 = NULL;
  rec(mod_43);
  // ModExprList 0
  intr_enter(ctx, "STRUCT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
    // Not capturing STRUCT.
    expr_ret_43 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_43 = NULL;
  }

  if (expr_ret_43) intr_accept(ctx, "STRUCT"); else intr_reject(ctx, "STRUCT");
  // ModExprList 1
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_44 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_44 = leaf(TYPEIDENT);
      expr_ret_44->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_44->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_44 = NULL;
    }

    if (expr_ret_44) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_43 = expr_ret_44;
    id = expr_ret_44;
  }

  // ModExprList 2
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_45 = NULL;
    expr_ret_45 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_43 = expr_ret_45;
    tmpl = expr_ret_45;
  }

  // ModExprList 3
  if (expr_ret_43) {
    intr_enter(ctx, "IMPL", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) intr_accept(ctx, "IMPL"); else intr_reject(ctx, "IMPL");
  }

  // ModExprList 4
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_46 = NULL;
    expr_ret_46 = daisho_parse_typelist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_43 = expr_ret_46;
    il = expr_ret_46;
  }

  // ModExprList 5
  if (expr_ret_43) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 6
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_47 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_47
    ret = SUCC;
    #line 102 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4085 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_43 = expr_ret_47;
    members = expr_ret_47;
  }

  // ModExprList 7
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_48 = NULL;
    daisho_astnode_t* expr_ret_49 = SUCC;
    while (expr_ret_49)
    {
      rec(kleene_rew_48);
      daisho_astnode_t* expr_ret_50 = NULL;
      rec(mod_50);
      // ModExprList 0
      daisho_astnode_t* expr_ret_51 = NULL;
      expr_ret_51 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_50 = expr_ret_51;
      m = expr_ret_51;
      // ModExprList 1
      if (expr_ret_50) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_50
        ret = SUCC;
        #line 103 "daisho.peg"
        add(members, m);
        #line 4116 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_50) rew(mod_50);
      expr_ret_49 = expr_ret_50;
    }

    expr_ret_48 = SUCC;
    expr_ret_43 = expr_ret_48;
  }

  // ModExprList 8
  if (expr_ret_43) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 9
  if (expr_ret_43) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_43
    ret = SUCC;
    #line 105 "daisho.peg"
    rule = node(STRUCT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4153 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_43) rew(mod_43);
  expr_ret_42 = expr_ret_43;
  if (!rule) rule = expr_ret_42;
  if (!expr_ret_42) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "structdecl");
  else if (rule) intr_accept(ctx, "structdecl");
  else intr_reject(ctx, "structdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_52
  daisho_astnode_t* expr_ret_52 = NULL;
  daisho_astnode_t* expr_ret_53 = NULL;
  intr_enter(ctx, "uniondecl", ctx->pos);
  daisho_astnode_t* expr_ret_54 = NULL;
  rec(mod_54);
  // ModExprList 0
  intr_enter(ctx, "UNION", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_54 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_54 = NULL;
  }

  if (expr_ret_54) intr_accept(ctx, "UNION"); else intr_reject(ctx, "UNION");
  // ModExprList 1
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_55 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_55 = leaf(TYPEIDENT);
      expr_ret_55->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_55->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_55 = NULL;
    }

    if (expr_ret_55) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_54 = expr_ret_55;
    id = expr_ret_55;
  }

  // ModExprList 2
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_56 = NULL;
    expr_ret_56 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_54 = expr_ret_56;
    tmpl = expr_ret_56;
  }

  // ModExprList 3
  if (expr_ret_54) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_54 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_54 = NULL;
    }

    if (expr_ret_54) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 4
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_57 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_57
    ret = SUCC;
    #line 108 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4244 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_54 = expr_ret_57;
    members = expr_ret_57;
  }

  // ModExprList 5
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_58 = NULL;
    daisho_astnode_t* expr_ret_59 = SUCC;
    while (expr_ret_59)
    {
      rec(kleene_rew_58);
      daisho_astnode_t* expr_ret_60 = NULL;
      rec(mod_60);
      // ModExprList 0
      daisho_astnode_t* expr_ret_61 = NULL;
      expr_ret_61 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_60 = expr_ret_61;
      m = expr_ret_61;
      // ModExprList 1
      if (expr_ret_60) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_60
        ret = SUCC;
        #line 109 "daisho.peg"
        add(members, m);
        #line 4275 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_60) rew(mod_60);
      expr_ret_59 = expr_ret_60;
    }

    expr_ret_58 = SUCC;
    expr_ret_54 = expr_ret_58;
  }

  // ModExprList 6
  if (expr_ret_54) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_54 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_54 = NULL;
    }

    if (expr_ret_54) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 7
  if (expr_ret_54) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_54
    ret = SUCC;
    #line 111 "daisho.peg"
    rule = node(UNION, id, tmpl, members);
    #line 4312 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_54) rew(mod_54);
  expr_ret_53 = expr_ret_54;
  if (!rule) rule = expr_ret_53;
  if (!expr_ret_53) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "uniondecl");
  else if (rule) intr_accept(ctx, "uniondecl");
  else intr_reject(ctx, "uniondecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* il = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_62
  daisho_astnode_t* expr_ret_62 = NULL;
  daisho_astnode_t* expr_ret_63 = NULL;
  intr_enter(ctx, "traitdecl", ctx->pos);
  daisho_astnode_t* expr_ret_64 = NULL;
  rec(mod_64);
  // ModExprList 0
  intr_enter(ctx, "TRAIT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
    expr_ret_64 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_64 = NULL;
  }

  if (expr_ret_64) intr_accept(ctx, "TRAIT"); else intr_reject(ctx, "TRAIT");
  // ModExprList 1
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_65 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_65 = leaf(TYPEIDENT);
      expr_ret_65->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_65->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_65 = NULL;
    }

    if (expr_ret_65) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_64 = expr_ret_65;
    id = expr_ret_65;
  }

  // ModExprList 2
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_66 = NULL;
    expr_ret_66 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_64 = expr_ret_66;
    tmpl = expr_ret_66;
  }

  // ModExprList 3
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_67 = NULL;
    daisho_astnode_t* expr_ret_68 = NULL;
    rec(mod_68);
    // ModExprList 0
    intr_enter(ctx, "IMPL", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_68 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_68 = NULL;
    }

    if (expr_ret_68) intr_accept(ctx, "IMPL"); else intr_reject(ctx, "IMPL");
    // ModExprList 1
    if (expr_ret_68) {
      daisho_astnode_t* expr_ret_69 = NULL;
      expr_ret_69 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_68 = expr_ret_69;
      il = expr_ret_69;
    }

    // ModExprList end
    if (!expr_ret_68) rew(mod_68);
    expr_ret_67 = expr_ret_68;
    // optional
    if (!expr_ret_67)
      expr_ret_67 = SUCC;
    expr_ret_64 = expr_ret_67;
  }

  // ModExprList 4
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_70 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_70
    ret = SUCC;
    #line 114 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4424 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_64 = expr_ret_70;
    members = expr_ret_70;
  }

  // ModExprList 5
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_71 = NULL;
    daisho_astnode_t* expr_ret_72 = NULL;
    rec(mod_72);
    // ModExprList 0
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_72 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_72 = NULL;
    }

    if (expr_ret_72) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
    // ModExprList 1
    if (expr_ret_72) {
      daisho_astnode_t* expr_ret_73 = NULL;
      daisho_astnode_t* expr_ret_74 = SUCC;
      while (expr_ret_74)
      {
        rec(kleene_rew_73);
        daisho_astnode_t* expr_ret_75 = NULL;
        rec(mod_75);
        // ModExprList 0
        daisho_astnode_t* expr_ret_76 = NULL;
        expr_ret_76 = daisho_parse_fnmember(ctx);
        if (ctx->exit) return NULL;
        expr_ret_75 = expr_ret_76;
        m = expr_ret_76;
        // ModExprList 1
        if (expr_ret_75) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_75
          ret = SUCC;
          #line 115 "daisho.peg"
          add(members, m);
          #line 4471 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_75) rew(mod_75);
        expr_ret_74 = expr_ret_75;
      }

      expr_ret_73 = SUCC;
      expr_ret_72 = expr_ret_73;
    }

    // ModExprList 2
    if (expr_ret_72) {
      intr_enter(ctx, "RCBRACK", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
        // Not capturing RCBRACK.
        expr_ret_72 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_72 = NULL;
      }

      if (expr_ret_72) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
    }

    // ModExprList end
    if (!expr_ret_72) rew(mod_72);
    expr_ret_71 = expr_ret_72;
    // optional
    if (!expr_ret_71)
      expr_ret_71 = SUCC;
    expr_ret_64 = expr_ret_71;
  }

  // ModExprList 6
  if (expr_ret_64) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_64
    ret = SUCC;
    #line 116 "daisho.peg"
    rule = node(TRAIT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4517 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_64) rew(mod_64);
  expr_ret_63 = expr_ret_64;
  if (!rule) rule = expr_ret_63;
  if (!expr_ret_63) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "traitdecl");
  else if (rule) intr_accept(ctx, "traitdecl");
  else intr_reject(ctx, "traitdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_77
  daisho_astnode_t* expr_ret_77 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  intr_enter(ctx, "impldecl", ctx->pos);
  daisho_astnode_t* expr_ret_79 = NULL;
  rec(mod_79);
  // ModExprList 0
  intr_enter(ctx, "IMPL", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_79 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_79 = NULL;
  }

  if (expr_ret_79) intr_accept(ctx, "IMPL"); else intr_reject(ctx, "IMPL");
  // ModExprList 1
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_80 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_80 = leaf(TYPEIDENT);
      expr_ret_80->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_80->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_80 = NULL;
    }

    if (expr_ret_80) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_79 = expr_ret_80;
    id = expr_ret_80;
  }

  // ModExprList 2
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_81 = NULL;
    expr_ret_81 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_79 = expr_ret_81;
    tmpl = expr_ret_81;
  }

  // ModExprList 3
  if (expr_ret_79) {
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

    if (expr_ret_79) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_82 = NULL;
    expr_ret_82 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_79 = expr_ret_82;
    ft = expr_ret_82;
  }

  // ModExprList 5
  if (expr_ret_79) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

    if (expr_ret_79) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 6
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_83 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_83
    ret = SUCC;
    #line 119 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4632 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_79 = expr_ret_83;
    members = expr_ret_83;
  }

  // ModExprList 7
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_84 = NULL;
    daisho_astnode_t* expr_ret_85 = SUCC;
    while (expr_ret_85)
    {
      rec(kleene_rew_84);
      daisho_astnode_t* expr_ret_86 = NULL;
      rec(mod_86);
      // ModExprList 0
      daisho_astnode_t* expr_ret_87 = NULL;
      expr_ret_87 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_86 = expr_ret_87;
      m = expr_ret_87;
      // ModExprList 1
      if (expr_ret_86) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_86
        ret = SUCC;
        #line 120 "daisho.peg"
        add(members, m);
        #line 4663 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_86) rew(mod_86);
      expr_ret_85 = expr_ret_86;
    }

    expr_ret_84 = SUCC;
    expr_ret_79 = expr_ret_84;
  }

  // ModExprList 8
  if (expr_ret_79) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

    if (expr_ret_79) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 9
  if (expr_ret_79) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_79
    ret = SUCC;
    #line 122 "daisho.peg"
    rule = node(IMPL, id, tmpl, ft, members);
    #line 4700 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_79) rew(mod_79);
  expr_ret_78 = expr_ret_79;
  if (!rule) rule = expr_ret_78;
  if (!expr_ret_78) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "impldecl");
  else if (rule) intr_accept(ctx, "impldecl");
  else intr_reject(ctx, "impldecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_88
  daisho_astnode_t* expr_ret_88 = NULL;
  daisho_astnode_t* expr_ret_89 = NULL;
  intr_enter(ctx, "ctypedecl", ctx->pos);
  daisho_astnode_t* expr_ret_90 = NULL;
  rec(mod_90);
  // ModExprList 0
  intr_enter(ctx, "CTYPE", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_90 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_90 = NULL;
  }

  if (expr_ret_90) intr_accept(ctx, "CTYPE"); else intr_reject(ctx, "CTYPE");
  // ModExprList 1
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_91 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_91 = leaf(TYPEIDENT);
      expr_ret_91->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_91->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

    if (expr_ret_91) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_90 = expr_ret_91;
    id = expr_ret_91;
  }

  // ModExprList 2
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_92 = NULL;
    expr_ret_92 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_90 = expr_ret_92;
    c = expr_ret_92;
  }

  // ModExprList 3
  if (expr_ret_90) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_90
    ret = SUCC;
    #line 125 "daisho.peg"
    rule = node(CTYPE, id, c);
    #line 4774 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_90) rew(mod_90);
  expr_ret_89 = expr_ret_90;
  if (!rule) rule = expr_ret_89;
  if (!expr_ret_89) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ctypedecl");
  else if (rule) intr_accept(ctx, "ctypedecl");
  else intr_reject(ctx, "ctypedecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* ci = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_93
  daisho_astnode_t* expr_ret_93 = NULL;
  daisho_astnode_t* expr_ret_94 = NULL;
  intr_enter(ctx, "cfndecl", ctx->pos);
  daisho_astnode_t* expr_ret_95 = NULL;
  rec(mod_95);
  // ModExprList 0
  intr_enter(ctx, "CFN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_95 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_95 = NULL;
  }

  if (expr_ret_95) intr_accept(ctx, "CFN"); else intr_reject(ctx, "CFN");
  // ModExprList 1
  if (expr_ret_95) {
    daisho_astnode_t* expr_ret_96 = NULL;
    expr_ret_96 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_95 = expr_ret_96;
    rett = expr_ret_96;
  }

  // ModExprList 2
  if (expr_ret_95) {
    daisho_astnode_t* expr_ret_97 = NULL;
    expr_ret_97 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_95 = expr_ret_97;
    ci = expr_ret_97;
  }

  // ModExprList 3
  if (expr_ret_95) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_95 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

    if (expr_ret_95) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 4
  if (expr_ret_95) {
    daisho_astnode_t* expr_ret_98 = NULL;
    expr_ret_98 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_95 = expr_ret_98;
    al = expr_ret_98;
  }

  // ModExprList 5
  if (expr_ret_95) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_95 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

    if (expr_ret_95) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 6
  if (expr_ret_95) {
    expr_ret_95 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 7
  if (expr_ret_95) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_95
    ret = SUCC;
    #line 131 "daisho.peg"
    rule = node(CFN, rett, ci, al);
    #line 4882 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_95) rew(mod_95);
  expr_ret_94 = expr_ret_95;
  if (!rule) rule = expr_ret_94;
  if (!expr_ret_94) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "cfndecl");
  else if (rule) intr_accept(ctx, "cfndecl");
  else intr_reject(ctx, "cfndecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_99
  daisho_astnode_t* expr_ret_99 = NULL;
  daisho_astnode_t* expr_ret_100 = NULL;
  intr_enter(ctx, "fndecl", ctx->pos);
  daisho_astnode_t* expr_ret_101 = NULL;
  rec(mod_101);
  // ModExprList 0
  daisho_astnode_t* expr_ret_102 = NULL;
  intr_enter(ctx, "FN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_102 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_102 = NULL;
  }

  if (expr_ret_102) intr_accept(ctx, "FN"); else intr_reject(ctx, "FN");
  // optional
  if (!expr_ret_102)
    expr_ret_102 = SUCC;
  expr_ret_101 = expr_ret_102;
  // ModExprList 1
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_103 = NULL;
    expr_ret_103 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_101 = expr_ret_103;
    rett = expr_ret_103;
  }

  // ModExprList 2
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_104 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_104 = leaf(VARIDENT);
      expr_ret_104->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_104->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

    if (expr_ret_104) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_101 = expr_ret_104;
    name = expr_ret_104;
  }

  // ModExprList 3
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_105 = NULL;
    expr_ret_105 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_101 = expr_ret_105;
    tmpl = expr_ret_105;
  }

  // ModExprList 4
  if (expr_ret_101) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_101 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_101 = NULL;
    }

    if (expr_ret_101) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 5
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_106 = NULL;
    expr_ret_106 = daisho_parse_arglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_101 = expr_ret_106;
    al = expr_ret_106;
  }

  // ModExprList 6
  if (expr_ret_101) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_101 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_101 = NULL;
    }

    if (expr_ret_101) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 7
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_107 = NULL;
    intr_enter(ctx, "EQ", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_107 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_107 = NULL;
    }

    if (expr_ret_107) intr_accept(ctx, "EQ"); else intr_reject(ctx, "EQ");
    // optional
    if (!expr_ret_107)
      expr_ret_107 = SUCC;
    expr_ret_101 = expr_ret_107;
  }

  // ModExprList 8
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_108 = NULL;
    expr_ret_108 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_101 = expr_ret_108;
    e = expr_ret_108;
  }

  // ModExprList 9
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_109 = NULL;
    expr_ret_109 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_109)
      expr_ret_109 = SUCC;
    expr_ret_101 = expr_ret_109;
  }

  // ModExprList 10
  if (expr_ret_101) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_101
    ret = SUCC;
    #line 137 "daisho.peg"
    rule=node(FNDECL, rett, name, tmpl, al, e);
    #line 5049 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_101) rew(mod_101);
  expr_ret_100 = expr_ret_101;
  if (!rule) rule = expr_ret_100;
  if (!expr_ret_100) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fndecl");
  else if (rule) intr_accept(ctx, "fndecl");
  else intr_reject(ctx, "fndecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_110
  daisho_astnode_t* expr_ret_110 = NULL;
  daisho_astnode_t* expr_ret_111 = NULL;
  intr_enter(ctx, "fnproto", ctx->pos);
  daisho_astnode_t* expr_ret_112 = NULL;
  rec(mod_112);
  // ModExprList 0
  daisho_astnode_t* expr_ret_113 = NULL;
  intr_enter(ctx, "FN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_113 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_113 = NULL;
  }

  if (expr_ret_113) intr_accept(ctx, "FN"); else intr_reject(ctx, "FN");
  // optional
  if (!expr_ret_113)
    expr_ret_113 = SUCC;
  expr_ret_112 = expr_ret_113;
  // ModExprList 1
  if (expr_ret_112) {
    daisho_astnode_t* expr_ret_114 = NULL;
    expr_ret_114 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_112 = expr_ret_114;
    rett = expr_ret_114;
  }

  // ModExprList 2
  if (expr_ret_112) {
    daisho_astnode_t* expr_ret_115 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_115 = leaf(VARIDENT);
      expr_ret_115->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_115->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_115 = NULL;
    }

    if (expr_ret_115) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_112 = expr_ret_115;
    name = expr_ret_115;
  }

  // ModExprList 3
  if (expr_ret_112) {
    daisho_astnode_t* expr_ret_116 = NULL;
    expr_ret_116 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_112 = expr_ret_116;
    tmpl = expr_ret_116;
  }

  // ModExprList 4
  if (expr_ret_112) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_112 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_112 = NULL;
    }

    if (expr_ret_112) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 5
  if (expr_ret_112) {
    daisho_astnode_t* expr_ret_117 = NULL;
    expr_ret_117 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_112 = expr_ret_117;
    al = expr_ret_117;
  }

  // ModExprList 6
  if (expr_ret_112) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_112 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_112 = NULL;
    }

    if (expr_ret_112) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 7
  if (expr_ret_112) {
    daisho_astnode_t* expr_ret_118 = NULL;
    expr_ret_118 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_118)
      expr_ret_118 = SUCC;
    expr_ret_112 = expr_ret_118;
  }

  // ModExprList 8
  if (expr_ret_112) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_112
    ret = SUCC;
    #line 143 "daisho.peg"
    rule=node(FNPROTO, rett, name, tmpl, al);
    #line 5187 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_112) rew(mod_112);
  expr_ret_111 = expr_ret_112;
  if (!rule) rule = expr_ret_111;
  if (!expr_ret_111) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnproto");
  else if (rule) intr_accept(ctx, "fnproto");
  else intr_reject(ctx, "fnproto");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_119
  daisho_astnode_t* expr_ret_119 = NULL;
  daisho_astnode_t* expr_ret_120 = NULL;
  intr_enter(ctx, "fnmember", ctx->pos);
  daisho_astnode_t* expr_ret_121 = NULL;

  // SlashExpr 0
  if (!expr_ret_121) {
    daisho_astnode_t* expr_ret_122 = NULL;
    rec(mod_122);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_123 = NULL;
    expr_ret_123 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_122 = expr_ret_123;
    rule = expr_ret_123;
    // ModExprList end
    if (!expr_ret_122) rew(mod_122);
    expr_ret_121 = expr_ret_122;
  }

  // SlashExpr 1
  if (!expr_ret_121) {
    daisho_astnode_t* expr_ret_124 = NULL;
    rec(mod_124);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_125 = NULL;
    expr_ret_125 = daisho_parse_fnproto(ctx);
    if (ctx->exit) return NULL;
    expr_ret_124 = expr_ret_125;
    rule = expr_ret_125;
    // ModExprList end
    if (!expr_ret_124) rew(mod_124);
    expr_ret_121 = expr_ret_124;
  }

  // SlashExpr end
  expr_ret_120 = expr_ret_121;

  if (!rule) rule = expr_ret_120;
  if (!expr_ret_120) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnmember");
  else if (rule) intr_accept(ctx, "fnmember");
  else intr_reject(ctx, "fnmember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_126
  daisho_astnode_t* expr_ret_126 = NULL;
  daisho_astnode_t* expr_ret_127 = NULL;
  intr_enter(ctx, "typemember", ctx->pos);
  daisho_astnode_t* expr_ret_128 = NULL;
  rec(mod_128);
  // ModExprList 0
  daisho_astnode_t* expr_ret_129 = NULL;
  expr_ret_129 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_128 = expr_ret_129;
  t = expr_ret_129;
  // ModExprList 1
  if (expr_ret_128) {
    daisho_astnode_t* expr_ret_130 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_130 = leaf(VARIDENT);
      expr_ret_130->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_130->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_130 = NULL;
    }

    if (expr_ret_130) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_128 = expr_ret_130;
    v = expr_ret_130;
  }

  // ModExprList 2
  if (expr_ret_128) {
    expr_ret_128 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 3
  if (expr_ret_128) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_128
    ret = SUCC;
    #line 149 "daisho.peg"
    rule=node(TYPEMEMBER, t, v);
    #line 5303 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_128) rew(mod_128);
  expr_ret_127 = expr_ret_128;
  if (!rule) rule = expr_ret_127;
  if (!expr_ret_127) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "typemember");
  else if (rule) intr_accept(ctx, "typemember");
  else intr_reject(ctx, "typemember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_131
  daisho_astnode_t* expr_ret_131 = NULL;
  daisho_astnode_t* expr_ret_132 = NULL;
  intr_enter(ctx, "tmplexpand", ctx->pos);
  daisho_astnode_t* expr_ret_133 = NULL;

  // SlashExpr 0
  if (!expr_ret_133) {
    daisho_astnode_t* expr_ret_134 = NULL;
    rec(mod_134);
    // ModExprList 0
    intr_enter(ctx, "LT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_134 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_134 = NULL;
    }

    if (expr_ret_134) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
    // ModExprList 1
    if (expr_ret_134) {
      daisho_astnode_t* expr_ret_135 = NULL;
      expr_ret_135 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_134 = expr_ret_135;
      rule = expr_ret_135;
    }

    // ModExprList 2
    if (expr_ret_134) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_134
      ret = SUCC;
      #line 151 "daisho.peg"
      rule->kind = kind(TMPLEXPAND);
      #line 5361 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 3
    if (expr_ret_134) {
      intr_enter(ctx, "GT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Capturing GT.
        expr_ret_134 = leaf(GT);
        expr_ret_134->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_134->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_134 = NULL;
      }

      if (expr_ret_134) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
    }

    // ModExprList end
    if (!expr_ret_134) rew(mod_134);
    expr_ret_133 = expr_ret_134;
  }

  // SlashExpr 1
  if (!expr_ret_133) {
    daisho_astnode_t* expr_ret_136 = NULL;
    rec(mod_136);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_136
    ret = SUCC;
    #line 152 "daisho.peg"
    rule=leaf(NOEXPAND);
    #line 5399 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_136) rew(mod_136);
    expr_ret_133 = expr_ret_136;
  }

  // SlashExpr end
  expr_ret_132 = expr_ret_133;

  if (!rule) rule = expr_ret_132;
  if (!expr_ret_132) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tmplexpand");
  else if (rule) intr_accept(ctx, "tmplexpand");
  else intr_reject(ctx, "tmplexpand");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx) {
  #define rule expr_ret_137
  daisho_astnode_t* expr_ret_137 = NULL;
  daisho_astnode_t* expr_ret_138 = NULL;
  intr_enter(ctx, "returntype", ctx->pos);
  daisho_astnode_t* expr_ret_139 = NULL;
  rec(mod_139);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_140 = NULL;

  // SlashExpr 0
  if (!expr_ret_140) {
    daisho_astnode_t* expr_ret_141 = NULL;
    rec(mod_141);
    // ModExprList Forwarding
    expr_ret_141 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_141) rew(mod_141);
    expr_ret_140 = expr_ret_141;
  }

  // SlashExpr 1
  if (!expr_ret_140) {
    daisho_astnode_t* expr_ret_142 = NULL;
    rec(mod_142);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_142
    ret = SUCC;
    #line 154 "daisho.peg"
    ret=leaf(VOIDTYPE);
    #line 5453 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_142) rew(mod_142);
    expr_ret_140 = expr_ret_142;
  }

  // SlashExpr end
  expr_ret_139 = expr_ret_140;

  // ModExprList end
  if (!expr_ret_139) rew(mod_139);
  expr_ret_138 = expr_ret_139;
  if (!rule) rule = expr_ret_138;
  if (!expr_ret_138) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "returntype");
  else if (rule) intr_accept(ctx, "returntype");
  else intr_reject(ctx, "returntype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_143
  daisho_astnode_t* expr_ret_143 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
  intr_enter(ctx, "type", ctx->pos);
  daisho_astnode_t* expr_ret_145 = NULL;
  rec(mod_145);
  // ModExprList 0
  rec(mexpr_state_146)
  daisho_astnode_t* expr_ret_146 = NULL;
  daisho_astnode_t* expr_ret_147 = NULL;

  // SlashExpr 0
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_148 = NULL;
    rec(mod_148);
    // ModExprList Forwarding
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_148 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_148 = NULL;
    }

    if (expr_ret_148) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList end
    if (!expr_ret_148) rew(mod_148);
    expr_ret_147 = expr_ret_148;
  }

  // SlashExpr 1
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_149 = NULL;
    rec(mod_149);
    // ModExprList Forwarding
    intr_enter(ctx, "SELFTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Not capturing SELFTYPE.
      expr_ret_149 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_149 = NULL;
    }

    if (expr_ret_149) intr_accept(ctx, "SELFTYPE"); else intr_reject(ctx, "SELFTYPE");
    // ModExprList end
    if (!expr_ret_149) rew(mod_149);
    expr_ret_147 = expr_ret_149;
  }

  // SlashExpr 2
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_150 = NULL;
    rec(mod_150);
    // ModExprList Forwarding
    intr_enter(ctx, "VOIDTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Not capturing VOIDTYPE.
      expr_ret_150 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_150 = NULL;
    }

    if (expr_ret_150) intr_accept(ctx, "VOIDTYPE"); else intr_reject(ctx, "VOIDTYPE");
    // ModExprList end
    if (!expr_ret_150) rew(mod_150);
    expr_ret_147 = expr_ret_150;
  }

  // SlashExpr 3
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_151 = NULL;
    rec(mod_151);
    // ModExprList Forwarding
    intr_enter(ctx, "VOIDPTR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Not capturing VOIDPTR.
      expr_ret_151 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_151 = NULL;
    }

    if (expr_ret_151) intr_accept(ctx, "VOIDPTR"); else intr_reject(ctx, "VOIDPTR");
    // ModExprList end
    if (!expr_ret_151) rew(mod_151);
    expr_ret_147 = expr_ret_151;
  }

  // SlashExpr 4
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_152 = NULL;
    rec(mod_152);
    // ModExprList Forwarding
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_152 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_152 = NULL;
    }

    if (expr_ret_152) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    // ModExprList end
    if (!expr_ret_152) rew(mod_152);
    expr_ret_147 = expr_ret_152;
  }

  // SlashExpr end
  expr_ret_146 = expr_ret_147;

  // rewind
  rew(mexpr_state_146);
  expr_ret_145 = expr_ret_146;
  // ModExprList 1
  if (expr_ret_145) {
    daisho_astnode_t* expr_ret_153 = NULL;
    expr_ret_153 = daisho_parse_fntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_145 = expr_ret_153;
    rule = expr_ret_153;
  }

  // ModExprList end
  if (!expr_ret_145) rew(mod_145);
  expr_ret_144 = expr_ret_145;
  if (!rule) rule = expr_ret_144;
  if (!expr_ret_144) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "type");
  else if (rule) intr_accept(ctx, "type");
  else intr_reject(ctx, "type");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* from = NULL;
  daisho_astnode_t* to = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_154
  daisho_astnode_t* expr_ret_154 = NULL;
  daisho_astnode_t* expr_ret_155 = NULL;
  intr_enter(ctx, "fntype", ctx->pos);
  daisho_astnode_t* expr_ret_156 = NULL;
  rec(mod_156);
  // ModExprList 0
  daisho_astnode_t* expr_ret_157 = NULL;
  // CodeExpr
  intr_enter(ctx, "CodeExpr", ctx->pos);
  #define ret expr_ret_157
  ret = SUCC;
  #line 183 "daisho.peg"
  ;
  #line 5635 "daisho_tokenizer_parser.h"

  if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
  #undef ret
  expr_ret_156 = expr_ret_157;
  from = expr_ret_157;
  // ModExprList 1
  if (expr_ret_156) {
    daisho_astnode_t* expr_ret_158 = NULL;
    expr_ret_158 = daisho_parse_ptrtype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_156 = expr_ret_158;
    to = expr_ret_158;
  }

  // ModExprList 2
  if (expr_ret_156) {
    daisho_astnode_t* expr_ret_159 = NULL;
    daisho_astnode_t* expr_ret_160 = SUCC;
    while (expr_ret_160)
    {
      rec(kleene_rew_159);
      daisho_astnode_t* expr_ret_161 = NULL;
      rec(mod_161);
      // ModExprList 0
      intr_enter(ctx, "ARROW", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_161 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_161 = NULL;
      }

      if (expr_ret_161) intr_accept(ctx, "ARROW"); else intr_reject(ctx, "ARROW");
      // ModExprList 1
      if (expr_ret_161) {
        daisho_astnode_t* expr_ret_162 = NULL;
        expr_ret_162 = daisho_parse_ptrtype(ctx);
        if (ctx->exit) return NULL;
        expr_ret_161 = expr_ret_162;
        n = expr_ret_162;
      }

      // ModExprList 2
      if (expr_ret_161) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_161
        ret = SUCC;
        #line 185 "daisho.peg"
        if (!has(from)) from = list(TYPELIST);
        #line 5687 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 3
      if (expr_ret_161) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_161
        ret = SUCC;
        #line 186 "daisho.peg"
        add(from, to); to = n;
        #line 5701 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_161) rew(mod_161);
      expr_ret_160 = expr_ret_161;
    }

    expr_ret_159 = SUCC;
    expr_ret_156 = expr_ret_159;
  }

  // ModExprList 3
  if (expr_ret_156) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_156
    ret = SUCC;
    #line 187 "daisho.peg"
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #line 5724 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_156) rew(mod_156);
  expr_ret_155 = expr_ret_156;
  if (!rule) rule = expr_ret_155;
  if (!expr_ret_155) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fntype");
  else if (rule) intr_accept(ctx, "fntype");
  else intr_reject(ctx, "fntype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_163
  daisho_astnode_t* expr_ret_163 = NULL;
  daisho_astnode_t* expr_ret_164 = NULL;
  intr_enter(ctx, "ptrtype", ctx->pos);
  daisho_astnode_t* expr_ret_165 = NULL;
  rec(mod_165);
  // ModExprList 0
  daisho_astnode_t* expr_ret_166 = NULL;
  expr_ret_166 = daisho_parse_basetype(ctx);
  if (ctx->exit) return NULL;
  expr_ret_165 = expr_ret_166;
  rule = expr_ret_166;
  // ModExprList 1
  if (expr_ret_165) {
    daisho_astnode_t* expr_ret_167 = NULL;
    daisho_astnode_t* expr_ret_168 = SUCC;
    while (expr_ret_168)
    {
      rec(kleene_rew_167);
      daisho_astnode_t* expr_ret_169 = NULL;
      rec(mod_169);
      // ModExprList 0
      intr_enter(ctx, "STAR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_169 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_169 = NULL;
      }

      if (expr_ret_169) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
      // ModExprList 1
      if (expr_ret_169) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_169
        ret = SUCC;
        #line 189 "daisho.peg"
        rule=node(PTRTYPE, rule);
        #line 5784 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_169) rew(mod_169);
      expr_ret_168 = expr_ret_169;
    }

    expr_ret_167 = SUCC;
    expr_ret_165 = expr_ret_167;
  }

  // ModExprList end
  if (!expr_ret_165) rew(mod_165);
  expr_ret_164 = expr_ret_165;
  if (!rule) rule = expr_ret_164;
  if (!expr_ret_164) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ptrtype");
  else if (rule) intr_accept(ctx, "ptrtype");
  else intr_reject(ctx, "ptrtype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* nns = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_170
  daisho_astnode_t* expr_ret_170 = NULL;
  daisho_astnode_t* expr_ret_171 = NULL;
  intr_enter(ctx, "basetype", ctx->pos);
  daisho_astnode_t* expr_ret_172 = NULL;

  // SlashExpr 0
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_173 = NULL;
    rec(mod_173);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_173 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_173 = NULL;
    }

    if (expr_ret_173) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_173) {
      daisho_astnode_t* expr_ret_174 = NULL;
      expr_ret_174 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_173 = expr_ret_174;
      rule = expr_ret_174;
    }

    // ModExprList 2
    if (expr_ret_173) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_173 = leaf(CLOSE);
        expr_ret_173->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_173->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_173 = NULL;
      }

      if (expr_ret_173) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList end
    if (!expr_ret_173) rew(mod_173);
    expr_ret_172 = expr_ret_173;
  }

  // SlashExpr 1
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_175 = NULL;
    rec(mod_175);
    // ModExprList Forwarding
    expr_ret_175 = daisho_parse_tupletype(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_175) rew(mod_175);
    expr_ret_172 = expr_ret_175;
  }

  // SlashExpr 2
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_176 = NULL;
    rec(mod_176);
    // ModExprList Forwarding
    intr_enter(ctx, "SELFTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Capturing SELFTYPE.
      expr_ret_176 = leaf(SELFTYPE);
      expr_ret_176->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_176->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_176 = NULL;
    }

    if (expr_ret_176) intr_accept(ctx, "SELFTYPE"); else intr_reject(ctx, "SELFTYPE");
    // ModExprList end
    if (!expr_ret_176) rew(mod_176);
    expr_ret_172 = expr_ret_176;
  }

  // SlashExpr 3
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_177 = NULL;
    rec(mod_177);
    // ModExprList 0
    daisho_astnode_t* expr_ret_178 = NULL;
    intr_enter(ctx, "VOIDTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_178 = leaf(VOIDTYPE);
      expr_ret_178->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_178->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_178 = NULL;
    }

    if (expr_ret_178) intr_accept(ctx, "VOIDTYPE"); else intr_reject(ctx, "VOIDTYPE");
    expr_ret_177 = expr_ret_178;
    v = expr_ret_178;
    // ModExprList 1
    if (expr_ret_177) {
      rec(mexpr_state_179)
      daisho_astnode_t* expr_ret_179 = NULL;
      intr_enter(ctx, "STAR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_179 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_179 = NULL;
      }

      if (expr_ret_179) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
      // invert
      expr_ret_179 = expr_ret_179 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_179);
      expr_ret_177 = expr_ret_179;
    }

    // ModExprList 2
    if (expr_ret_177) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_177
      ret = SUCC;
      #line 196 "daisho.peg"
      rule=v;
      #line 5952 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_177) rew(mod_177);
    expr_ret_172 = expr_ret_177;
  }

  // SlashExpr 4
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_180 = NULL;
    rec(mod_180);
    // ModExprList Forwarding
    expr_ret_180 = daisho_parse_voidptr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_180) rew(mod_180);
    expr_ret_172 = expr_ret_180;
  }

  // SlashExpr 5
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_181 = NULL;
    rec(mod_181);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_182 = NULL;
    rec(mod_182);
    // ModExprList 0
    daisho_astnode_t* expr_ret_183 = NULL;
    daisho_astnode_t* expr_ret_184 = NULL;
    rec(mod_184);
    // ModExprList 0
    daisho_astnode_t* expr_ret_185 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_185 = leaf(TYPEIDENT);
      expr_ret_185->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_185->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_185 = NULL;
    }

    if (expr_ret_185) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_184 = expr_ret_185;
    nns = expr_ret_185;
    // ModExprList 1
    if (expr_ret_184) {
      intr_enter(ctx, "DOT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_184 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_184 = NULL;
      }

      if (expr_ret_184) intr_accept(ctx, "DOT"); else intr_reject(ctx, "DOT");
    }

    // ModExprList 2
    if (expr_ret_184) {
      daisho_astnode_t* expr_ret_186 = NULL;
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_186
      ret = SUCC;
      #line 198 "daisho.peg"
      ret=nns;
      #line 6025 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      expr_ret_184 = expr_ret_186;
      ns = expr_ret_186;
    }

    // ModExprList end
    if (!expr_ret_184) rew(mod_184);
    expr_ret_183 = expr_ret_184;
    // optional
    if (!expr_ret_183)
      expr_ret_183 = SUCC;
    expr_ret_182 = expr_ret_183;
    ns = expr_ret_183;
    // ModExprList 1
    if (expr_ret_182) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_182
      ret = SUCC;
      #line 199 "daisho.peg"
      if (!has(ns)) ns = leaf(CURRENT_NS);
      #line 6049 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 2
    if (expr_ret_182) {
      daisho_astnode_t* expr_ret_187 = NULL;
      intr_enter(ctx, "TYPEIDENT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_187 = leaf(TYPEIDENT);
        expr_ret_187->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_187->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_187 = NULL;
      }

      if (expr_ret_187) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
      expr_ret_182 = expr_ret_187;
      s = expr_ret_187;
    }

    // ModExprList 3
    if (expr_ret_182) {
      daisho_astnode_t* expr_ret_188 = NULL;
      expr_ret_188 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_182 = expr_ret_188;
      t = expr_ret_188;
    }

    // ModExprList 4
    if (expr_ret_182) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_182
      ret = SUCC;
      #line 201 "daisho.peg"
      rule=node(BASETYPE, ns, s, t);
      #line 6091 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_182) rew(mod_182);
    expr_ret_181 = expr_ret_182;
    // ModExprList end
    if (!expr_ret_181) rew(mod_181);
    expr_ret_172 = expr_ret_181;
  }

  // SlashExpr end
  expr_ret_171 = expr_ret_172;

  if (!rule) rule = expr_ret_171;
  if (!expr_ret_171) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "basetype");
  else if (rule) intr_accept(ctx, "basetype");
  else intr_reject(ctx, "basetype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_189
  daisho_astnode_t* expr_ret_189 = NULL;
  daisho_astnode_t* expr_ret_190 = NULL;
  intr_enter(ctx, "tupletype", ctx->pos);
  daisho_astnode_t* expr_ret_191 = NULL;

  // SlashExpr 0
  if (!expr_ret_191) {
    daisho_astnode_t* expr_ret_192 = NULL;
    rec(mod_192);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_192 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

    if (expr_ret_192) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_192) {
      daisho_astnode_t* expr_ret_193 = NULL;
      expr_ret_193 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_192 = expr_ret_193;
      t = expr_ret_193;
    }

    // ModExprList 2
    if (expr_ret_192) {
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_192 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_192 = NULL;
      }

      if (expr_ret_192) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    }

    // ModExprList 3
    if (expr_ret_192) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_192 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_192 = NULL;
      }

      if (expr_ret_192) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList 4
    if (expr_ret_192) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_192
      ret = SUCC;
      #line 203 "daisho.peg"
      rule=node(TUPLETYPE, t);
      #line 6185 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_192) rew(mod_192);
    expr_ret_191 = expr_ret_192;
  }

  // SlashExpr 1
  if (!expr_ret_191) {
    daisho_astnode_t* expr_ret_194 = NULL;
    rec(mod_194);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_194 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_194 = NULL;
    }

    if (expr_ret_194) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_194) {
      daisho_astnode_t* expr_ret_195 = NULL;
      expr_ret_195 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_194 = expr_ret_195;
      rule = expr_ret_195;
    }

    // ModExprList 2
    if (expr_ret_194) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_194 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_194 = NULL;
      }

      if (expr_ret_194) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList 3
    if (expr_ret_194) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_194
      ret = SUCC;
      #line 204 "daisho.peg"
      rule->kind = kind(TUPLETYPE);
      #line 6242 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_194) rew(mod_194);
    expr_ret_191 = expr_ret_194;
  }

  // SlashExpr end
  expr_ret_190 = expr_ret_191;

  if (!rule) rule = expr_ret_190;
  if (!expr_ret_190) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tupletype");
  else if (rule) intr_accept(ctx, "tupletype");
  else intr_reject(ctx, "tupletype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_196
  daisho_astnode_t* expr_ret_196 = NULL;
  daisho_astnode_t* expr_ret_197 = NULL;
  intr_enter(ctx, "voidptr", ctx->pos);
  daisho_astnode_t* expr_ret_198 = NULL;

  // SlashExpr 0
  if (!expr_ret_198) {
    daisho_astnode_t* expr_ret_199 = NULL;
    rec(mod_199);
    // ModExprList 0
    daisho_astnode_t* expr_ret_200 = NULL;
    intr_enter(ctx, "VOIDPTR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_200 = leaf(VOIDPTR);
      expr_ret_200->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_200->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_200 = NULL;
    }

    if (expr_ret_200) intr_accept(ctx, "VOIDPTR"); else intr_reject(ctx, "VOIDPTR");
    expr_ret_199 = expr_ret_200;
    v = expr_ret_200;
    // ModExprList 1
    if (expr_ret_199) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_199
      ret = SUCC;
      #line 206 "daisho.peg"
      rule=v;
      #line 6302 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_199) rew(mod_199);
    expr_ret_198 = expr_ret_199;
  }

  // SlashExpr 1
  if (!expr_ret_198) {
    daisho_astnode_t* expr_ret_201 = NULL;
    rec(mod_201);
    // ModExprList 0
    daisho_astnode_t* expr_ret_202 = NULL;
    intr_enter(ctx, "VOIDTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_202 = leaf(VOIDTYPE);
      expr_ret_202->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_202->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_202 = NULL;
    }

    if (expr_ret_202) intr_accept(ctx, "VOIDTYPE"); else intr_reject(ctx, "VOIDTYPE");
    expr_ret_201 = expr_ret_202;
    v = expr_ret_202;
    // ModExprList 1
    if (expr_ret_201) {
      daisho_astnode_t* expr_ret_203 = NULL;
      intr_enter(ctx, "STAR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_203 = leaf(STAR);
        expr_ret_203->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_203->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_203 = NULL;
      }

      if (expr_ret_203) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
      expr_ret_201 = expr_ret_203;
      s = expr_ret_203;
    }

    // ModExprList 2
    if (expr_ret_201) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_201
      ret = SUCC;
      #line 207 "daisho.peg"
      rule=leaf(VOIDPTR);
      #line 6360 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_201) rew(mod_201);
    expr_ret_198 = expr_ret_201;
  }

  // SlashExpr end
  expr_ret_197 = expr_ret_198;

  if (!rule) rule = expr_ret_197;
  if (!expr_ret_197) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "voidptr");
  else if (rule) intr_accept(ctx, "voidptr");
  else intr_reject(ctx, "voidptr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_204
  daisho_astnode_t* expr_ret_204 = NULL;
  daisho_astnode_t* expr_ret_205 = NULL;
  intr_enter(ctx, "typelist", ctx->pos);
  daisho_astnode_t* expr_ret_206 = NULL;
  rec(mod_206);
  // ModExprList 0
  daisho_astnode_t* expr_ret_207 = NULL;
  expr_ret_207 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_207)
    expr_ret_207 = SUCC;
  expr_ret_206 = expr_ret_207;
  // ModExprList 1
  if (expr_ret_206) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_206
    ret = SUCC;
    #line 277 "daisho.peg"
    rule=list(TYPELIST);
    #line 6407 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_206) {
    daisho_astnode_t* expr_ret_208 = NULL;
    expr_ret_208 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_208)
      expr_ret_208 = SUCC;
    expr_ret_206 = expr_ret_208;
    t = expr_ret_208;
  }

  // ModExprList 3
  if (expr_ret_206) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_206
    ret = SUCC;
    #line 278 "daisho.peg"
    if has(t) add(rule, t);
    #line 6433 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_206) {
    daisho_astnode_t* expr_ret_209 = NULL;
    daisho_astnode_t* expr_ret_210 = SUCC;
    while (expr_ret_210)
    {
      rec(kleene_rew_209);
      daisho_astnode_t* expr_ret_211 = NULL;
      rec(mod_211);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_211 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_211 = NULL;
      }

      if (expr_ret_211) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_211) {
        daisho_astnode_t* expr_ret_212 = NULL;
        expr_ret_212 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_211 = expr_ret_212;
        t = expr_ret_212;
      }

      // ModExprList 2
      if (expr_ret_211) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_211
        ret = SUCC;
        #line 279 "daisho.peg"
        add(rule, t);
        #line 6476 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_211) rew(mod_211);
      expr_ret_210 = expr_ret_211;
    }

    expr_ret_209 = SUCC;
    expr_ret_206 = expr_ret_209;
  }

  // ModExprList 5
  if (expr_ret_206) {
    daisho_astnode_t* expr_ret_213 = NULL;
    expr_ret_213 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_213)
      expr_ret_213 = SUCC;
    expr_ret_206 = expr_ret_213;
  }

  // ModExprList end
  if (!expr_ret_206) rew(mod_206);
  expr_ret_205 = expr_ret_206;
  if (!rule) rule = expr_ret_205;
  if (!expr_ret_205) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "typelist");
  else if (rule) intr_accept(ctx, "typelist");
  else intr_reject(ctx, "typelist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_214
  daisho_astnode_t* expr_ret_214 = NULL;
  daisho_astnode_t* expr_ret_215 = NULL;
  intr_enter(ctx, "exprlist", ctx->pos);
  daisho_astnode_t* expr_ret_216 = NULL;
  rec(mod_216);
  // ModExprList 0
  daisho_astnode_t* expr_ret_217 = NULL;
  expr_ret_217 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_217)
    expr_ret_217 = SUCC;
  expr_ret_216 = expr_ret_217;
  // ModExprList 1
  if (expr_ret_216) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_216
    ret = SUCC;
    #line 281 "daisho.peg"
    rule=list(EXPRLIST);
    #line 6538 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_216) {
    daisho_astnode_t* expr_ret_218 = NULL;
    expr_ret_218 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_218)
      expr_ret_218 = SUCC;
    expr_ret_216 = expr_ret_218;
    e = expr_ret_218;
  }

  // ModExprList 3
  if (expr_ret_216) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_216
    ret = SUCC;
    #line 282 "daisho.peg"
    if has(e) add(rule, e);
    #line 6564 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_216) {
    daisho_astnode_t* expr_ret_219 = NULL;
    daisho_astnode_t* expr_ret_220 = SUCC;
    while (expr_ret_220)
    {
      rec(kleene_rew_219);
      daisho_astnode_t* expr_ret_221 = NULL;
      rec(mod_221);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_221 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_221 = NULL;
      }

      if (expr_ret_221) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_221) {
        daisho_astnode_t* expr_ret_222 = NULL;
        expr_ret_222 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_221 = expr_ret_222;
        e = expr_ret_222;
      }

      // ModExprList 2
      if (expr_ret_221) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_221
        ret = SUCC;
        #line 283 "daisho.peg"
        add(rule, e);
        #line 6607 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_221) rew(mod_221);
      expr_ret_220 = expr_ret_221;
    }

    expr_ret_219 = SUCC;
    expr_ret_216 = expr_ret_219;
  }

  // ModExprList 5
  if (expr_ret_216) {
    daisho_astnode_t* expr_ret_223 = NULL;
    expr_ret_223 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_223)
      expr_ret_223 = SUCC;
    expr_ret_216 = expr_ret_223;
  }

  // ModExprList end
  if (!expr_ret_216) rew(mod_216);
  expr_ret_215 = expr_ret_216;
  if (!rule) rule = expr_ret_215;
  if (!expr_ret_215) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "exprlist");
  else if (rule) intr_accept(ctx, "exprlist");
  else intr_reject(ctx, "exprlist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_224
  daisho_astnode_t* expr_ret_224 = NULL;
  daisho_astnode_t* expr_ret_225 = NULL;
  intr_enter(ctx, "fnarg", ctx->pos);
  daisho_astnode_t* expr_ret_226 = NULL;
  rec(mod_226);
  // ModExprList 0
  daisho_astnode_t* expr_ret_227 = NULL;
  expr_ret_227 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_226 = expr_ret_227;
  t = expr_ret_227;
  // ModExprList 1
  if (expr_ret_226) {
    daisho_astnode_t* expr_ret_228 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_228 = leaf(VARIDENT);
      expr_ret_228->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_228->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_228 = NULL;
    }

    if (expr_ret_228) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_226 = expr_ret_228;
    i = expr_ret_228;
  }

  // ModExprList 2
  if (expr_ret_226) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_226
    ret = SUCC;
    #line 286 "daisho.peg"
    rule=node(FNARG, t, i);
    #line 6687 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_226) rew(mod_226);
  expr_ret_225 = expr_ret_226;
  if (!rule) rule = expr_ret_225;
  if (!expr_ret_225) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnarg");
  else if (rule) intr_accept(ctx, "fnarg");
  else intr_reject(ctx, "fnarg");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_229
  daisho_astnode_t* expr_ret_229 = NULL;
  daisho_astnode_t* expr_ret_230 = NULL;
  intr_enter(ctx, "arglist", ctx->pos);
  daisho_astnode_t* expr_ret_231 = NULL;
  rec(mod_231);
  // ModExprList 0
  daisho_astnode_t* expr_ret_232 = NULL;
  expr_ret_232 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_232)
    expr_ret_232 = SUCC;
  expr_ret_231 = expr_ret_232;
  // ModExprList 1
  if (expr_ret_231) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_231
    ret = SUCC;
    #line 287 "daisho.peg"
    rule=list(ARGLIST);
    #line 6729 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_231) {
    daisho_astnode_t* expr_ret_233 = NULL;
    expr_ret_233 = daisho_parse_fnarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_233)
      expr_ret_233 = SUCC;
    expr_ret_231 = expr_ret_233;
    a = expr_ret_233;
  }

  // ModExprList 3
  if (expr_ret_231) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_231
    ret = SUCC;
    #line 288 "daisho.peg"
    if has(a) add(rule, a);
    #line 6755 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_231) {
    daisho_astnode_t* expr_ret_234 = NULL;
    daisho_astnode_t* expr_ret_235 = SUCC;
    while (expr_ret_235)
    {
      rec(kleene_rew_234);
      daisho_astnode_t* expr_ret_236 = NULL;
      rec(mod_236);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_236 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_236 = NULL;
      }

      if (expr_ret_236) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_236) {
        daisho_astnode_t* expr_ret_237 = NULL;
        expr_ret_237 = daisho_parse_fnarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_236 = expr_ret_237;
        a = expr_ret_237;
      }

      // ModExprList 2
      if (expr_ret_236) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_236
        ret = SUCC;
        #line 289 "daisho.peg"
        add(rule, a);
        #line 6798 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_236) rew(mod_236);
      expr_ret_235 = expr_ret_236;
    }

    expr_ret_234 = SUCC;
    expr_ret_231 = expr_ret_234;
  }

  // ModExprList 5
  if (expr_ret_231) {
    daisho_astnode_t* expr_ret_238 = NULL;
    expr_ret_238 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_238)
      expr_ret_238 = SUCC;
    expr_ret_231 = expr_ret_238;
  }

  // ModExprList end
  if (!expr_ret_231) rew(mod_231);
  expr_ret_230 = expr_ret_231;
  if (!rule) rule = expr_ret_230;
  if (!expr_ret_230) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "arglist");
  else if (rule) intr_accept(ctx, "arglist");
  else intr_reject(ctx, "arglist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_239
  daisho_astnode_t* expr_ret_239 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
  intr_enter(ctx, "protoarg", ctx->pos);
  daisho_astnode_t* expr_ret_241 = NULL;
  rec(mod_241);
  // ModExprList 0
  daisho_astnode_t* expr_ret_242 = NULL;
  expr_ret_242 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_241 = expr_ret_242;
  t = expr_ret_242;
  // ModExprList 1
  if (expr_ret_241) {
    daisho_astnode_t* expr_ret_243 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Not capturing VARIDENT.
      expr_ret_243 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_243 = NULL;
    }

    if (expr_ret_243) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    // optional
    if (!expr_ret_243)
      expr_ret_243 = SUCC;
    expr_ret_241 = expr_ret_243;
    i = expr_ret_243;
  }

  // ModExprList 2
  if (expr_ret_241) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_241
    ret = SUCC;
    #line 292 "daisho.peg"
    rule=node(PROTOARG, t);
    #line 6879 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_241) rew(mod_241);
  expr_ret_240 = expr_ret_241;
  if (!rule) rule = expr_ret_240;
  if (!expr_ret_240) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "protoarg");
  else if (rule) intr_accept(ctx, "protoarg");
  else intr_reject(ctx, "protoarg");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_244
  daisho_astnode_t* expr_ret_244 = NULL;
  daisho_astnode_t* expr_ret_245 = NULL;
  intr_enter(ctx, "protoarglist", ctx->pos);
  daisho_astnode_t* expr_ret_246 = NULL;
  rec(mod_246);
  // ModExprList 0
  daisho_astnode_t* expr_ret_247 = NULL;
  expr_ret_247 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_247)
    expr_ret_247 = SUCC;
  expr_ret_246 = expr_ret_247;
  // ModExprList 1
  if (expr_ret_246) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_246
    ret = SUCC;
    #line 294 "daisho.peg"
    rule=list(PROTOLIST);
    #line 6921 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_246) {
    daisho_astnode_t* expr_ret_248 = NULL;
    expr_ret_248 = daisho_parse_protoarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_248)
      expr_ret_248 = SUCC;
    expr_ret_246 = expr_ret_248;
    p = expr_ret_248;
  }

  // ModExprList 3
  if (expr_ret_246) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_246
    ret = SUCC;
    #line 295 "daisho.peg"
    if has(p) add(rule, p);
    #line 6947 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_246) {
    daisho_astnode_t* expr_ret_249 = NULL;
    daisho_astnode_t* expr_ret_250 = SUCC;
    while (expr_ret_250)
    {
      rec(kleene_rew_249);
      daisho_astnode_t* expr_ret_251 = NULL;
      rec(mod_251);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_251 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_251 = NULL;
      }

      if (expr_ret_251) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_251) {
        daisho_astnode_t* expr_ret_252 = NULL;
        expr_ret_252 = daisho_parse_protoarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_251 = expr_ret_252;
        p = expr_ret_252;
      }

      // ModExprList 2
      if (expr_ret_251) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_251
        ret = SUCC;
        #line 296 "daisho.peg"
        add(rule, p);
        #line 6990 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_251) rew(mod_251);
      expr_ret_250 = expr_ret_251;
    }

    expr_ret_249 = SUCC;
    expr_ret_246 = expr_ret_249;
  }

  // ModExprList 5
  if (expr_ret_246) {
    daisho_astnode_t* expr_ret_253 = NULL;
    expr_ret_253 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_253)
      expr_ret_253 = SUCC;
    expr_ret_246 = expr_ret_253;
  }

  // ModExprList end
  if (!expr_ret_246) rew(mod_246);
  expr_ret_245 = expr_ret_246;
  if (!rule) rule = expr_ret_245;
  if (!expr_ret_245) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "protoarglist");
  else if (rule) intr_accept(ctx, "protoarglist");
  else intr_reject(ctx, "protoarglist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_254
  daisho_astnode_t* expr_ret_254 = NULL;
  daisho_astnode_t* expr_ret_255 = NULL;
  intr_enter(ctx, "expr", ctx->pos);
  daisho_astnode_t* expr_ret_256 = NULL;
  rec(mod_256);
  // ModExprList 0
  rec(mexpr_state_257)
  daisho_astnode_t* expr_ret_257 = NULL;
  intr_enter(ctx, "SEMI", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Not capturing SEMI.
    expr_ret_257 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_257 = NULL;
  }

  if (expr_ret_257) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
  // invert
  expr_ret_257 = expr_ret_257 ? NULL : SUCC;
  // rewind
  rew(mexpr_state_257);
  expr_ret_256 = expr_ret_257;
  // ModExprList 1
  if (expr_ret_256) {
    rec(mexpr_state_258)
    daisho_astnode_t* expr_ret_258 = NULL;
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_258 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_258 = NULL;
    }

    if (expr_ret_258) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    // invert
    expr_ret_258 = expr_ret_258 ? NULL : SUCC;
    // rewind
    rew(mexpr_state_258);
    expr_ret_256 = expr_ret_258;
  }

  // ModExprList 2
  if (expr_ret_256) {
    daisho_astnode_t* expr_ret_259 = NULL;
    expr_ret_259 = daisho_parse_preretexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_256 = expr_ret_259;
    rule = expr_ret_259;
  }

  // ModExprList end
  if (!expr_ret_256) rew(mod_256);
  expr_ret_255 = expr_ret_256;
  if (!rule) rule = expr_ret_255;
  if (!expr_ret_255) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "expr");
  else if (rule) intr_accept(ctx, "expr");
  else intr_reject(ctx, "expr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_260
  daisho_astnode_t* expr_ret_260 = NULL;
  daisho_astnode_t* expr_ret_261 = NULL;
  intr_enter(ctx, "preretexpr", ctx->pos);
  daisho_astnode_t* expr_ret_262 = NULL;

  // SlashExpr 0
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_263 = NULL;
    rec(mod_263);
    // ModExprList 0
    intr_enter(ctx, "RET", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Not capturing RET.
      expr_ret_263 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_263 = NULL;
    }

    if (expr_ret_263) intr_accept(ctx, "RET"); else intr_reject(ctx, "RET");
    // ModExprList 1
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_264 = NULL;
      expr_ret_264 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_263 = expr_ret_264;
      n = expr_ret_264;
    }

    // ModExprList 2
    if (expr_ret_263) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_263
      ret = SUCC;
      #line 344 "daisho.peg"
      rule=node(RET, n);
      #line 7136 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_263) rew(mod_263);
    expr_ret_262 = expr_ret_263;
  }

  // SlashExpr 1
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_265 = NULL;
    rec(mod_265);
    // ModExprList 0
    daisho_astnode_t* expr_ret_266 = NULL;
    expr_ret_266 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_265 = expr_ret_266;
    rule = expr_ret_266;
    // ModExprList 1
    if (expr_ret_265) {
      daisho_astnode_t* expr_ret_267 = NULL;
      daisho_astnode_t* expr_ret_268 = NULL;
      rec(mod_268);
      // ModExprList 0
      intr_enter(ctx, "GRAVE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Not capturing GRAVE.
        expr_ret_268 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_268 = NULL;
      }

      if (expr_ret_268) intr_accept(ctx, "GRAVE"); else intr_reject(ctx, "GRAVE");
      // ModExprList 1
      if (expr_ret_268) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_268
        ret = SUCC;
        #line 345 "daisho.peg"
        rule = node(RET, rule);
        #line 7181 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_268) rew(mod_268);
      expr_ret_267 = expr_ret_268;
      // optional
      if (!expr_ret_267)
        expr_ret_267 = SUCC;
      expr_ret_265 = expr_ret_267;
    }

    // ModExprList end
    if (!expr_ret_265) rew(mod_265);
    expr_ret_262 = expr_ret_265;
  }

  // SlashExpr end
  expr_ret_261 = expr_ret_262;

  if (!rule) rule = expr_ret_261;
  if (!expr_ret_261) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "preretexpr");
  else if (rule) intr_accept(ctx, "preretexpr");
  else intr_reject(ctx, "preretexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_269
  daisho_astnode_t* expr_ret_269 = NULL;
  daisho_astnode_t* expr_ret_270 = NULL;
  intr_enter(ctx, "forexpr", ctx->pos);
  daisho_astnode_t* expr_ret_271 = NULL;

  // SlashExpr 0
  if (!expr_ret_271) {
    daisho_astnode_t* expr_ret_272 = NULL;
    rec(mod_272);
    // ModExprList 0
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_272 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_272 = NULL;
    }

    if (expr_ret_272) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
    // ModExprList 1
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_273 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_273 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_273 = NULL;
      }

      if (expr_ret_273) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_273)
        expr_ret_273 = SUCC;
      expr_ret_272 = expr_ret_273;
      o = expr_ret_273;
    }

    // ModExprList 2
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_274 = NULL;
      expr_ret_274 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_272 = expr_ret_274;
      f = expr_ret_274;
    }

    // ModExprList 3
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_275 = NULL;

      // SlashExpr 0
      if (!expr_ret_275) {
        daisho_astnode_t* expr_ret_276 = NULL;
        rec(mod_276);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_277 = NULL;

        // SlashExpr 0
        if (!expr_ret_277) {
          daisho_astnode_t* expr_ret_278 = NULL;
          rec(mod_278);
          // ModExprList Forwarding
          intr_enter(ctx, "COLON", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_278 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_278 = NULL;
          }

          if (expr_ret_278) intr_accept(ctx, "COLON"); else intr_reject(ctx, "COLON");
          // ModExprList end
          if (!expr_ret_278) rew(mod_278);
          expr_ret_277 = expr_ret_278;
        }

        // SlashExpr 1
        if (!expr_ret_277) {
          daisho_astnode_t* expr_ret_279 = NULL;
          rec(mod_279);
          // ModExprList Forwarding
          intr_enter(ctx, "IN", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_279 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_279 = NULL;
          }

          if (expr_ret_279) intr_accept(ctx, "IN"); else intr_reject(ctx, "IN");
          // ModExprList end
          if (!expr_ret_279) rew(mod_279);
          expr_ret_277 = expr_ret_279;
        }

        // SlashExpr end
        expr_ret_276 = expr_ret_277;

        // ModExprList end
        if (!expr_ret_276) rew(mod_276);
        expr_ret_275 = expr_ret_276;
      }

      // SlashExpr 1
      if (!expr_ret_275) {
        daisho_astnode_t* expr_ret_280 = NULL;
        rec(mod_280);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_281 = NULL;
        rec(mod_281);
        // ModExprList 0
        expr_ret_281 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_281) {
          daisho_astnode_t* expr_ret_282 = NULL;
          expr_ret_282 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_281 = expr_ret_282;
          s = expr_ret_282;
        }

        // ModExprList 2
        if (expr_ret_281) {
          expr_ret_281 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_281) rew(mod_281);
        expr_ret_280 = expr_ret_281;
        // ModExprList end
        if (!expr_ret_280) rew(mod_280);
        expr_ret_275 = expr_ret_280;
      }

      // SlashExpr end
      expr_ret_272 = expr_ret_275;

    }

    // ModExprList 4
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_283 = NULL;
      expr_ret_283 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_272 = expr_ret_283;
      t = expr_ret_283;
    }

    // ModExprList 5
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_284 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_284 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_284 = NULL;
      }

      if (expr_ret_284) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_284)
        expr_ret_284 = SUCC;
      expr_ret_272 = expr_ret_284;
      c = expr_ret_284;
    }

    // ModExprList 6
    if (expr_ret_272) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_272
      ret = SUCC;
      #line 349 "daisho.peg"
      if (has(o) != has(c)) WARNING("For expression parens mismatch.");
      #line 7404 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 7
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_285 = NULL;
      expr_ret_285 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_272 = expr_ret_285;
      e = expr_ret_285;
    }

    // ModExprList 8
    if (expr_ret_272) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_272
      ret = SUCC;
      #line 351 "daisho.peg"
      rule = has(s) ? node(FOR, f, s, t, e)
                    :          node(FOREACH, f, t, e);
      #line 7428 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_272) rew(mod_272);
    expr_ret_271 = expr_ret_272;
  }

  // SlashExpr 1
  if (!expr_ret_271) {
    daisho_astnode_t* expr_ret_286 = NULL;
    rec(mod_286);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_287 = NULL;
    expr_ret_287 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_286 = expr_ret_287;
    rule = expr_ret_287;
    // ModExprList end
    if (!expr_ret_286) rew(mod_286);
    expr_ret_271 = expr_ret_286;
  }

  // SlashExpr end
  expr_ret_270 = expr_ret_271;

  if (!rule) rule = expr_ret_270;
  if (!expr_ret_270) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "forexpr");
  else if (rule) intr_accept(ctx, "forexpr");
  else intr_reject(ctx, "forexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_288
  daisho_astnode_t* expr_ret_288 = NULL;
  daisho_astnode_t* expr_ret_289 = NULL;
  intr_enter(ctx, "whileexpr", ctx->pos);
  daisho_astnode_t* expr_ret_290 = NULL;

  // SlashExpr 0
  if (!expr_ret_290) {
    daisho_astnode_t* expr_ret_291 = NULL;
    rec(mod_291);
    // ModExprList 0
    intr_enter(ctx, "WHILE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_291 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_291 = NULL;
    }

    if (expr_ret_291) intr_accept(ctx, "WHILE"); else intr_reject(ctx, "WHILE");
    // ModExprList 1
    if (expr_ret_291) {
      daisho_astnode_t* expr_ret_292 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_292 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_292 = NULL;
      }

      if (expr_ret_292) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_292)
        expr_ret_292 = SUCC;
      expr_ret_291 = expr_ret_292;
      o = expr_ret_292;
    }

    // ModExprList 2
    if (expr_ret_291) {
      daisho_astnode_t* expr_ret_293 = NULL;
      expr_ret_293 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_291 = expr_ret_293;
      n = expr_ret_293;
    }

    // ModExprList 3
    if (expr_ret_291) {
      daisho_astnode_t* expr_ret_294 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_294 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_294 = NULL;
      }

      if (expr_ret_294) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_294)
        expr_ret_294 = SUCC;
      expr_ret_291 = expr_ret_294;
      c = expr_ret_294;
    }

    // ModExprList 4
    if (expr_ret_291) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_291
      ret = SUCC;
      #line 356 "daisho.peg"
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #line 7549 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_291) {
      daisho_astnode_t* expr_ret_295 = NULL;
      expr_ret_295 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_291 = expr_ret_295;
      e = expr_ret_295;
    }

    // ModExprList 6
    if (expr_ret_291) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_291
      ret = SUCC;
      #line 357 "daisho.peg"
      rule=node(WHILE, n, e);
      #line 7572 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_291) rew(mod_291);
    expr_ret_290 = expr_ret_291;
  }

  // SlashExpr 1
  if (!expr_ret_290) {
    daisho_astnode_t* expr_ret_296 = NULL;
    rec(mod_296);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_297 = NULL;
    expr_ret_297 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_296 = expr_ret_297;
    rule = expr_ret_297;
    // ModExprList end
    if (!expr_ret_296) rew(mod_296);
    expr_ret_290 = expr_ret_296;
  }

  // SlashExpr end
  expr_ret_289 = expr_ret_290;

  if (!rule) rule = expr_ret_289;
  if (!expr_ret_289) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "whileexpr");
  else if (rule) intr_accept(ctx, "whileexpr");
  else intr_reject(ctx, "whileexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preifexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* ee = NULL;
  #define rule expr_ret_298
  daisho_astnode_t* expr_ret_298 = NULL;
  daisho_astnode_t* expr_ret_299 = NULL;
  intr_enter(ctx, "preifexpr", ctx->pos);
  daisho_astnode_t* expr_ret_300 = NULL;

  // SlashExpr 0
  if (!expr_ret_300) {
    daisho_astnode_t* expr_ret_301 = NULL;
    rec(mod_301);
    // ModExprList 0
    intr_enter(ctx, "IF", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_301 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_301 = NULL;
    }

    if (expr_ret_301) intr_accept(ctx, "IF"); else intr_reject(ctx, "IF");
    // ModExprList 1
    if (expr_ret_301) {
      daisho_astnode_t* expr_ret_302 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_302 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_302 = NULL;
      }

      if (expr_ret_302) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_302)
        expr_ret_302 = SUCC;
      expr_ret_301 = expr_ret_302;
      o = expr_ret_302;
    }

    // ModExprList 2
    if (expr_ret_301) {
      daisho_astnode_t* expr_ret_303 = NULL;
      expr_ret_303 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_301 = expr_ret_303;
      n = expr_ret_303;
    }

    // ModExprList 3
    if (expr_ret_301) {
      daisho_astnode_t* expr_ret_304 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_304 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_304 = NULL;
      }

      if (expr_ret_304) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_304)
        expr_ret_304 = SUCC;
      expr_ret_301 = expr_ret_304;
      c = expr_ret_304;
    }

    // ModExprList 4
    if (expr_ret_301) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_301
      ret = SUCC;
      #line 361 "daisho.peg"
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #line 7694 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_301) {
      daisho_astnode_t* expr_ret_305 = NULL;
      expr_ret_305 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_301 = expr_ret_305;
      e = expr_ret_305;
    }

    // ModExprList 6
    if (expr_ret_301) {
      daisho_astnode_t* expr_ret_306 = NULL;
      daisho_astnode_t* expr_ret_307 = NULL;
      rec(mod_307);
      // ModExprList 0
      intr_enter(ctx, "ELSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_307 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_307 = NULL;
      }

      if (expr_ret_307) intr_accept(ctx, "ELSE"); else intr_reject(ctx, "ELSE");
      // ModExprList 1
      if (expr_ret_307) {
        daisho_astnode_t* expr_ret_308 = NULL;
        expr_ret_308 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_307 = expr_ret_308;
        ee = expr_ret_308;
      }

      // ModExprList end
      if (!expr_ret_307) rew(mod_307);
      expr_ret_306 = expr_ret_307;
      // optional
      if (!expr_ret_306)
        expr_ret_306 = SUCC;
      expr_ret_301 = expr_ret_306;
    }

    // ModExprList 7
    if (expr_ret_301) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_301
      ret = SUCC;
      #line 364 "daisho.peg"
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #line 7752 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_301) rew(mod_301);
    expr_ret_300 = expr_ret_301;
  }

  // SlashExpr 1
  if (!expr_ret_300) {
    daisho_astnode_t* expr_ret_309 = NULL;
    rec(mod_309);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_310 = NULL;
    expr_ret_310 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_309 = expr_ret_310;
    rule = expr_ret_310;
    // ModExprList end
    if (!expr_ret_309) rew(mod_309);
    expr_ret_300 = expr_ret_309;
  }

  // SlashExpr end
  expr_ret_299 = expr_ret_300;

  if (!rule) rule = expr_ret_299;
  if (!expr_ret_299) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "preifexpr");
  else if (rule) intr_accept(ctx, "preifexpr");
  else intr_reject(ctx, "preifexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_311
  daisho_astnode_t* expr_ret_311 = NULL;
  daisho_astnode_t* expr_ret_312 = NULL;
  intr_enter(ctx, "ternexpr", ctx->pos);
  daisho_astnode_t* expr_ret_313 = NULL;
  rec(mod_313);
  // ModExprList 0
  daisho_astnode_t* expr_ret_314 = NULL;
  expr_ret_314 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_313 = expr_ret_314;
  n = expr_ret_314;
  // ModExprList 1
  if (expr_ret_313) {
    daisho_astnode_t* expr_ret_315 = NULL;
    daisho_astnode_t* expr_ret_316 = NULL;
    rec(mod_316);
    // ModExprList 0
    intr_enter(ctx, "QUEST", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_316 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_316 = NULL;
    }

    if (expr_ret_316) intr_accept(ctx, "QUEST"); else intr_reject(ctx, "QUEST");
    // ModExprList 1
    if (expr_ret_316) {
      daisho_astnode_t* expr_ret_317 = NULL;
      expr_ret_317 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_316 = expr_ret_317;
      qe = expr_ret_317;
    }

    // ModExprList 2
    if (expr_ret_316) {
      daisho_astnode_t* expr_ret_318 = NULL;
      daisho_astnode_t* expr_ret_319 = NULL;
      rec(mod_319);
      // ModExprList 0
      intr_enter(ctx, "COLON", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_319 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_319 = NULL;
      }

      if (expr_ret_319) intr_accept(ctx, "COLON"); else intr_reject(ctx, "COLON");
      // ModExprList 1
      if (expr_ret_319) {
        daisho_astnode_t* expr_ret_320 = NULL;
        expr_ret_320 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_319 = expr_ret_320;
        ce = expr_ret_320;
      }

      // ModExprList end
      if (!expr_ret_319) rew(mod_319);
      expr_ret_318 = expr_ret_319;
      // optional
      if (!expr_ret_318)
        expr_ret_318 = SUCC;
      expr_ret_316 = expr_ret_318;
    }

    // ModExprList end
    if (!expr_ret_316) rew(mod_316);
    expr_ret_315 = expr_ret_316;
    // optional
    if (!expr_ret_315)
      expr_ret_315 = SUCC;
    expr_ret_313 = expr_ret_315;
  }

  // ModExprList 2
  if (expr_ret_313) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_313
    ret = SUCC;
    #line 369 "daisho.peg"
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #line 7884 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_313) rew(mod_313);
  expr_ret_312 = expr_ret_313;
  if (!rule) rule = expr_ret_312;
  if (!expr_ret_312) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ternexpr");
  else if (rule) intr_accept(ctx, "ternexpr");
  else intr_reject(ctx, "ternexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_321
  daisho_astnode_t* expr_ret_321 = NULL;
  daisho_astnode_t* expr_ret_322 = NULL;
  intr_enter(ctx, "thenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_323 = NULL;
  rec(mod_323);
  // ModExprList 0
  daisho_astnode_t* expr_ret_324 = NULL;
  expr_ret_324 = daisho_parse_alsoexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_323 = expr_ret_324;
  rule = expr_ret_324;
  // ModExprList 1
  if (expr_ret_323) {
    daisho_astnode_t* expr_ret_325 = NULL;
    daisho_astnode_t* expr_ret_326 = SUCC;
    while (expr_ret_326)
    {
      rec(kleene_rew_325);
      daisho_astnode_t* expr_ret_327 = NULL;
      rec(mod_327);
      // ModExprList 0
      intr_enter(ctx, "THEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_327 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_327 = NULL;
      }

      if (expr_ret_327) intr_accept(ctx, "THEN"); else intr_reject(ctx, "THEN");
      // ModExprList 1
      if (expr_ret_327) {
        daisho_astnode_t* expr_ret_328 = NULL;
        expr_ret_328 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_327 = expr_ret_328;
        nn = expr_ret_328;
      }

      // ModExprList 2
      if (expr_ret_327) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_327
        ret = SUCC;
        #line 373 "daisho.peg"
        rule=node(THEN, rule, nn);
        #line 7954 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_327) rew(mod_327);
      expr_ret_326 = expr_ret_327;
    }

    expr_ret_325 = SUCC;
    expr_ret_323 = expr_ret_325;
  }

  // ModExprList end
  if (!expr_ret_323) rew(mod_323);
  expr_ret_322 = expr_ret_323;
  if (!rule) rule = expr_ret_322;
  if (!expr_ret_322) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "thenexpr");
  else if (rule) intr_accept(ctx, "thenexpr");
  else intr_reject(ctx, "thenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_329
  daisho_astnode_t* expr_ret_329 = NULL;
  daisho_astnode_t* expr_ret_330 = NULL;
  intr_enter(ctx, "alsoexpr", ctx->pos);
  daisho_astnode_t* expr_ret_331 = NULL;
  rec(mod_331);
  // ModExprList 0
  daisho_astnode_t* expr_ret_332 = NULL;
  expr_ret_332 = daisho_parse_ceqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_331 = expr_ret_332;
  rule = expr_ret_332;
  // ModExprList 1
  if (expr_ret_331) {
    daisho_astnode_t* expr_ret_333 = NULL;
    daisho_astnode_t* expr_ret_334 = SUCC;
    while (expr_ret_334)
    {
      rec(kleene_rew_333);
      daisho_astnode_t* expr_ret_335 = NULL;
      rec(mod_335);
      // ModExprList 0
      intr_enter(ctx, "ALSO", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_335 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_335 = NULL;
      }

      if (expr_ret_335) intr_accept(ctx, "ALSO"); else intr_reject(ctx, "ALSO");
      // ModExprList 1
      if (expr_ret_335) {
        daisho_astnode_t* expr_ret_336 = NULL;
        expr_ret_336 = daisho_parse_ceqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_335 = expr_ret_336;
        nn = expr_ret_336;
      }

      // ModExprList 2
      if (expr_ret_335) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_335
        ret = SUCC;
        #line 375 "daisho.peg"
        rule=node(ALSO, rule, nn);
        #line 8033 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_335) rew(mod_335);
      expr_ret_334 = expr_ret_335;
    }

    expr_ret_333 = SUCC;
    expr_ret_331 = expr_ret_333;
  }

  // ModExprList end
  if (!expr_ret_331) rew(mod_331);
  expr_ret_330 = expr_ret_331;
  if (!rule) rule = expr_ret_330;
  if (!expr_ret_330) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "alsoexpr");
  else if (rule) intr_accept(ctx, "alsoexpr");
  else intr_reject(ctx, "alsoexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_337
  daisho_astnode_t* expr_ret_337 = NULL;
  daisho_astnode_t* expr_ret_338 = NULL;
  intr_enter(ctx, "ceqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_339 = NULL;
  rec(mod_339);
  // ModExprList 0
  daisho_astnode_t* expr_ret_340 = NULL;
  expr_ret_340 = daisho_parse_logorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_339 = expr_ret_340;
  rule = expr_ret_340;
  // ModExprList 1
  if (expr_ret_339) {
    daisho_astnode_t* expr_ret_341 = NULL;
    daisho_astnode_t* expr_ret_342 = SUCC;
    while (expr_ret_342)
    {
      rec(kleene_rew_341);
      daisho_astnode_t* expr_ret_343 = NULL;
      rec(mod_343);
      // ModExprList 0
      daisho_astnode_t* expr_ret_344 = NULL;
      daisho_astnode_t* expr_ret_345 = NULL;

      // SlashExpr 0
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_346 = NULL;
        rec(mod_346);
        // ModExprList Forwarding
        intr_enter(ctx, "EQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_346 = leaf(EQ);
          expr_ret_346->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_346->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_346 = NULL;
        }

        if (expr_ret_346) intr_accept(ctx, "EQ"); else intr_reject(ctx, "EQ");
        // ModExprList end
        if (!expr_ret_346) rew(mod_346);
        expr_ret_345 = expr_ret_346;
      }

      // SlashExpr 1
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_347 = NULL;
        rec(mod_347);
        // ModExprList Forwarding
        intr_enter(ctx, "PLEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_347 = leaf(PLEQ);
          expr_ret_347->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_347->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_347 = NULL;
        }

        if (expr_ret_347) intr_accept(ctx, "PLEQ"); else intr_reject(ctx, "PLEQ");
        // ModExprList end
        if (!expr_ret_347) rew(mod_347);
        expr_ret_345 = expr_ret_347;
      }

      // SlashExpr 2
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_348 = NULL;
        rec(mod_348);
        // ModExprList Forwarding
        intr_enter(ctx, "MINEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_348 = leaf(MINEQ);
          expr_ret_348->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_348->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_348 = NULL;
        }

        if (expr_ret_348) intr_accept(ctx, "MINEQ"); else intr_reject(ctx, "MINEQ");
        // ModExprList end
        if (!expr_ret_348) rew(mod_348);
        expr_ret_345 = expr_ret_348;
      }

      // SlashExpr 3
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_349 = NULL;
        rec(mod_349);
        // ModExprList Forwarding
        intr_enter(ctx, "MULEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_349 = leaf(MULEQ);
          expr_ret_349->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_349->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_349 = NULL;
        }

        if (expr_ret_349) intr_accept(ctx, "MULEQ"); else intr_reject(ctx, "MULEQ");
        // ModExprList end
        if (!expr_ret_349) rew(mod_349);
        expr_ret_345 = expr_ret_349;
      }

      // SlashExpr 4
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_350 = NULL;
        rec(mod_350);
        // ModExprList Forwarding
        intr_enter(ctx, "DIVEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_350 = leaf(DIVEQ);
          expr_ret_350->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_350->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_350 = NULL;
        }

        if (expr_ret_350) intr_accept(ctx, "DIVEQ"); else intr_reject(ctx, "DIVEQ");
        // ModExprList end
        if (!expr_ret_350) rew(mod_350);
        expr_ret_345 = expr_ret_350;
      }

      // SlashExpr 5
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_351 = NULL;
        rec(mod_351);
        // ModExprList Forwarding
        intr_enter(ctx, "MODEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_351 = leaf(MODEQ);
          expr_ret_351->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_351->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_351 = NULL;
        }

        if (expr_ret_351) intr_accept(ctx, "MODEQ"); else intr_reject(ctx, "MODEQ");
        // ModExprList end
        if (!expr_ret_351) rew(mod_351);
        expr_ret_345 = expr_ret_351;
      }

      // SlashExpr 6
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_352 = NULL;
        rec(mod_352);
        // ModExprList Forwarding
        intr_enter(ctx, "ANDEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_352 = leaf(ANDEQ);
          expr_ret_352->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_352->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_352 = NULL;
        }

        if (expr_ret_352) intr_accept(ctx, "ANDEQ"); else intr_reject(ctx, "ANDEQ");
        // ModExprList end
        if (!expr_ret_352) rew(mod_352);
        expr_ret_345 = expr_ret_352;
      }

      // SlashExpr 7
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_353 = NULL;
        rec(mod_353);
        // ModExprList Forwarding
        intr_enter(ctx, "OREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_353 = leaf(OREQ);
          expr_ret_353->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_353->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_353 = NULL;
        }

        if (expr_ret_353) intr_accept(ctx, "OREQ"); else intr_reject(ctx, "OREQ");
        // ModExprList end
        if (!expr_ret_353) rew(mod_353);
        expr_ret_345 = expr_ret_353;
      }

      // SlashExpr 8
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_354 = NULL;
        rec(mod_354);
        // ModExprList Forwarding
        intr_enter(ctx, "XOREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_354 = leaf(XOREQ);
          expr_ret_354->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_354->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_354 = NULL;
        }

        if (expr_ret_354) intr_accept(ctx, "XOREQ"); else intr_reject(ctx, "XOREQ");
        // ModExprList end
        if (!expr_ret_354) rew(mod_354);
        expr_ret_345 = expr_ret_354;
      }

      // SlashExpr 9
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_355 = NULL;
        rec(mod_355);
        // ModExprList Forwarding
        intr_enter(ctx, "BNEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_355 = leaf(BNEQ);
          expr_ret_355->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_355->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_355 = NULL;
        }

        if (expr_ret_355) intr_accept(ctx, "BNEQ"); else intr_reject(ctx, "BNEQ");
        // ModExprList end
        if (!expr_ret_355) rew(mod_355);
        expr_ret_345 = expr_ret_355;
      }

      // SlashExpr 10
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_356 = NULL;
        rec(mod_356);
        // ModExprList Forwarding
        intr_enter(ctx, "BSREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_356 = leaf(BSREQ);
          expr_ret_356->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_356->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_356 = NULL;
        }

        if (expr_ret_356) intr_accept(ctx, "BSREQ"); else intr_reject(ctx, "BSREQ");
        // ModExprList end
        if (!expr_ret_356) rew(mod_356);
        expr_ret_345 = expr_ret_356;
      }

      // SlashExpr 11
      if (!expr_ret_345) {
        daisho_astnode_t* expr_ret_357 = NULL;
        rec(mod_357);
        // ModExprList Forwarding
        intr_enter(ctx, "BSLEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_357 = leaf(BSLEQ);
          expr_ret_357->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_357->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_357 = NULL;
        }

        if (expr_ret_357) intr_accept(ctx, "BSLEQ"); else intr_reject(ctx, "BSLEQ");
        // ModExprList end
        if (!expr_ret_357) rew(mod_357);
        expr_ret_345 = expr_ret_357;
      }

      // SlashExpr end
      expr_ret_344 = expr_ret_345;

      expr_ret_343 = expr_ret_344;
      op = expr_ret_344;
      // ModExprList 1
      if (expr_ret_343) {
        daisho_astnode_t* expr_ret_358 = NULL;
        expr_ret_358 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_343 = expr_ret_358;
        t = expr_ret_358;
      }

      // ModExprList 2
      if (expr_ret_343) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_343
        ret = SUCC;
        #line 381 "daisho.peg"
        
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
        #line 8388 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_343) rew(mod_343);
      expr_ret_342 = expr_ret_343;
    }

    expr_ret_341 = SUCC;
    expr_ret_339 = expr_ret_341;
  }

  // ModExprList end
  if (!expr_ret_339) rew(mod_339);
  expr_ret_338 = expr_ret_339;
  if (!rule) rule = expr_ret_338;
  if (!expr_ret_338) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ceqexpr");
  else if (rule) intr_accept(ctx, "ceqexpr");
  else intr_reject(ctx, "ceqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_359
  daisho_astnode_t* expr_ret_359 = NULL;
  daisho_astnode_t* expr_ret_360 = NULL;
  intr_enter(ctx, "logorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_361 = NULL;
  rec(mod_361);
  // ModExprList 0
  daisho_astnode_t* expr_ret_362 = NULL;
  expr_ret_362 = daisho_parse_logandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_361 = expr_ret_362;
  rule = expr_ret_362;
  // ModExprList 1
  if (expr_ret_361) {
    daisho_astnode_t* expr_ret_363 = NULL;
    daisho_astnode_t* expr_ret_364 = SUCC;
    while (expr_ret_364)
    {
      rec(kleene_rew_363);
      daisho_astnode_t* expr_ret_365 = NULL;
      rec(mod_365);
      // ModExprList 0
      intr_enter(ctx, "LOGOR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Not capturing LOGOR.
        expr_ret_365 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_365 = NULL;
      }

      if (expr_ret_365) intr_accept(ctx, "LOGOR"); else intr_reject(ctx, "LOGOR");
      // ModExprList 1
      if (expr_ret_365) {
        daisho_astnode_t* expr_ret_366 = NULL;
        expr_ret_366 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_365 = expr_ret_366;
        n = expr_ret_366;
      }

      // ModExprList 2
      if (expr_ret_365) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_365
        ret = SUCC;
        #line 396 "daisho.peg"
        rule=node(LOGOR,  rule, n);
        #line 8467 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_365) rew(mod_365);
      expr_ret_364 = expr_ret_365;
    }

    expr_ret_363 = SUCC;
    expr_ret_361 = expr_ret_363;
  }

  // ModExprList end
  if (!expr_ret_361) rew(mod_361);
  expr_ret_360 = expr_ret_361;
  if (!rule) rule = expr_ret_360;
  if (!expr_ret_360) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "logorexpr");
  else if (rule) intr_accept(ctx, "logorexpr");
  else intr_reject(ctx, "logorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_367
  daisho_astnode_t* expr_ret_367 = NULL;
  daisho_astnode_t* expr_ret_368 = NULL;
  intr_enter(ctx, "logandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_369 = NULL;
  rec(mod_369);
  // ModExprList 0
  daisho_astnode_t* expr_ret_370 = NULL;
  expr_ret_370 = daisho_parse_binorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_369 = expr_ret_370;
  rule = expr_ret_370;
  // ModExprList 1
  if (expr_ret_369) {
    daisho_astnode_t* expr_ret_371 = NULL;
    daisho_astnode_t* expr_ret_372 = SUCC;
    while (expr_ret_372)
    {
      rec(kleene_rew_371);
      daisho_astnode_t* expr_ret_373 = NULL;
      rec(mod_373);
      // ModExprList 0
      intr_enter(ctx, "LOGAND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Not capturing LOGAND.
        expr_ret_373 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_373 = NULL;
      }

      if (expr_ret_373) intr_accept(ctx, "LOGAND"); else intr_reject(ctx, "LOGAND");
      // ModExprList 1
      if (expr_ret_373) {
        daisho_astnode_t* expr_ret_374 = NULL;
        expr_ret_374 = daisho_parse_binorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_373 = expr_ret_374;
        n = expr_ret_374;
      }

      // ModExprList 2
      if (expr_ret_373) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_373
        ret = SUCC;
        #line 397 "daisho.peg"
        rule=node(LOGAND, rule, n);
        #line 8546 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_373) rew(mod_373);
      expr_ret_372 = expr_ret_373;
    }

    expr_ret_371 = SUCC;
    expr_ret_369 = expr_ret_371;
  }

  // ModExprList end
  if (!expr_ret_369) rew(mod_369);
  expr_ret_368 = expr_ret_369;
  if (!rule) rule = expr_ret_368;
  if (!expr_ret_368) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "logandexpr");
  else if (rule) intr_accept(ctx, "logandexpr");
  else intr_reject(ctx, "logandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_375
  daisho_astnode_t* expr_ret_375 = NULL;
  daisho_astnode_t* expr_ret_376 = NULL;
  intr_enter(ctx, "binorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_377 = NULL;
  rec(mod_377);
  // ModExprList 0
  daisho_astnode_t* expr_ret_378 = NULL;
  expr_ret_378 = daisho_parse_binxorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_377 = expr_ret_378;
  rule = expr_ret_378;
  // ModExprList 1
  if (expr_ret_377) {
    daisho_astnode_t* expr_ret_379 = NULL;
    daisho_astnode_t* expr_ret_380 = SUCC;
    while (expr_ret_380)
    {
      rec(kleene_rew_379);
      daisho_astnode_t* expr_ret_381 = NULL;
      rec(mod_381);
      // ModExprList 0
      intr_enter(ctx, "OR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Not capturing OR.
        expr_ret_381 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_381 = NULL;
      }

      if (expr_ret_381) intr_accept(ctx, "OR"); else intr_reject(ctx, "OR");
      // ModExprList 1
      if (expr_ret_381) {
        daisho_astnode_t* expr_ret_382 = NULL;
        expr_ret_382 = daisho_parse_binxorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_381 = expr_ret_382;
        n = expr_ret_382;
      }

      // ModExprList 2
      if (expr_ret_381) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_381
        ret = SUCC;
        #line 398 "daisho.peg"
        rule=node(OR,     rule, n);
        #line 8625 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_381) rew(mod_381);
      expr_ret_380 = expr_ret_381;
    }

    expr_ret_379 = SUCC;
    expr_ret_377 = expr_ret_379;
  }

  // ModExprList end
  if (!expr_ret_377) rew(mod_377);
  expr_ret_376 = expr_ret_377;
  if (!rule) rule = expr_ret_376;
  if (!expr_ret_376) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "binorexpr");
  else if (rule) intr_accept(ctx, "binorexpr");
  else intr_reject(ctx, "binorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_383
  daisho_astnode_t* expr_ret_383 = NULL;
  daisho_astnode_t* expr_ret_384 = NULL;
  intr_enter(ctx, "binxorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_385 = NULL;
  rec(mod_385);
  // ModExprList 0
  daisho_astnode_t* expr_ret_386 = NULL;
  expr_ret_386 = daisho_parse_binandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_385 = expr_ret_386;
  rule = expr_ret_386;
  // ModExprList 1
  if (expr_ret_385) {
    daisho_astnode_t* expr_ret_387 = NULL;
    daisho_astnode_t* expr_ret_388 = SUCC;
    while (expr_ret_388)
    {
      rec(kleene_rew_387);
      daisho_astnode_t* expr_ret_389 = NULL;
      rec(mod_389);
      // ModExprList 0
      intr_enter(ctx, "XOR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Not capturing XOR.
        expr_ret_389 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_389 = NULL;
      }

      if (expr_ret_389) intr_accept(ctx, "XOR"); else intr_reject(ctx, "XOR");
      // ModExprList 1
      if (expr_ret_389) {
        daisho_astnode_t* expr_ret_390 = NULL;
        expr_ret_390 = daisho_parse_binandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_389 = expr_ret_390;
        n = expr_ret_390;
      }

      // ModExprList 2
      if (expr_ret_389) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_389
        ret = SUCC;
        #line 399 "daisho.peg"
        rule=node(XOR,    rule, n);
        #line 8704 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_389) rew(mod_389);
      expr_ret_388 = expr_ret_389;
    }

    expr_ret_387 = SUCC;
    expr_ret_385 = expr_ret_387;
  }

  // ModExprList end
  if (!expr_ret_385) rew(mod_385);
  expr_ret_384 = expr_ret_385;
  if (!rule) rule = expr_ret_384;
  if (!expr_ret_384) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "binxorexpr");
  else if (rule) intr_accept(ctx, "binxorexpr");
  else intr_reject(ctx, "binxorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_391
  daisho_astnode_t* expr_ret_391 = NULL;
  daisho_astnode_t* expr_ret_392 = NULL;
  intr_enter(ctx, "binandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_393 = NULL;
  rec(mod_393);
  // ModExprList 0
  daisho_astnode_t* expr_ret_394 = NULL;
  expr_ret_394 = daisho_parse_deneqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_393 = expr_ret_394;
  rule = expr_ret_394;
  // ModExprList 1
  if (expr_ret_393) {
    daisho_astnode_t* expr_ret_395 = NULL;
    daisho_astnode_t* expr_ret_396 = SUCC;
    while (expr_ret_396)
    {
      rec(kleene_rew_395);
      daisho_astnode_t* expr_ret_397 = NULL;
      rec(mod_397);
      // ModExprList 0
      intr_enter(ctx, "AND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Not capturing AND.
        expr_ret_397 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_397 = NULL;
      }

      if (expr_ret_397) intr_accept(ctx, "AND"); else intr_reject(ctx, "AND");
      // ModExprList 1
      if (expr_ret_397) {
        daisho_astnode_t* expr_ret_398 = NULL;
        expr_ret_398 = daisho_parse_deneqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_397 = expr_ret_398;
        n = expr_ret_398;
      }

      // ModExprList 2
      if (expr_ret_397) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_397
        ret = SUCC;
        #line 400 "daisho.peg"
        rule=node(AND,    rule, n);
        #line 8783 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_397) rew(mod_397);
      expr_ret_396 = expr_ret_397;
    }

    expr_ret_395 = SUCC;
    expr_ret_393 = expr_ret_395;
  }

  // ModExprList end
  if (!expr_ret_393) rew(mod_393);
  expr_ret_392 = expr_ret_393;
  if (!rule) rule = expr_ret_392;
  if (!expr_ret_392) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "binandexpr");
  else if (rule) intr_accept(ctx, "binandexpr");
  else intr_reject(ctx, "binandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_399
  daisho_astnode_t* expr_ret_399 = NULL;
  daisho_astnode_t* expr_ret_400 = NULL;
  intr_enter(ctx, "deneqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_401 = NULL;
  rec(mod_401);
  // ModExprList 0
  daisho_astnode_t* expr_ret_402 = NULL;
  expr_ret_402 = daisho_parse_cmpexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_401 = expr_ret_402;
  rule = expr_ret_402;
  // ModExprList 1
  if (expr_ret_401) {
    daisho_astnode_t* expr_ret_403 = NULL;
    daisho_astnode_t* expr_ret_404 = SUCC;
    while (expr_ret_404)
    {
      rec(kleene_rew_403);
      daisho_astnode_t* expr_ret_405 = NULL;

      // SlashExpr 0
      if (!expr_ret_405) {
        daisho_astnode_t* expr_ret_406 = NULL;
        rec(mod_406);
        // ModExprList 0
        intr_enter(ctx, "DEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Not capturing DEQ.
          expr_ret_406 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_406 = NULL;
        }

        if (expr_ret_406) intr_accept(ctx, "DEQ"); else intr_reject(ctx, "DEQ");
        // ModExprList 1
        if (expr_ret_406) {
          daisho_astnode_t* expr_ret_407 = NULL;
          expr_ret_407 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_406 = expr_ret_407;
          n = expr_ret_407;
        }

        // ModExprList 2
        if (expr_ret_406) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_406
          ret = SUCC;
          #line 403 "daisho.peg"
          rule=node(DEQ, rule, n);
          #line 8866 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_406) rew(mod_406);
        expr_ret_405 = expr_ret_406;
      }

      // SlashExpr 1
      if (!expr_ret_405) {
        daisho_astnode_t* expr_ret_408 = NULL;
        rec(mod_408);
        // ModExprList 0
        intr_enter(ctx, "NEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Not capturing NEQ.
          expr_ret_408 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_408 = NULL;
        }

        if (expr_ret_408) intr_accept(ctx, "NEQ"); else intr_reject(ctx, "NEQ");
        // ModExprList 1
        if (expr_ret_408) {
          daisho_astnode_t* expr_ret_409 = NULL;
          expr_ret_409 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_408 = expr_ret_409;
          n = expr_ret_409;
        }

        // ModExprList 2
        if (expr_ret_408) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_408
          ret = SUCC;
          #line 404 "daisho.peg"
          rule=node(NEQ, rule, n);
          #line 8909 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_408) rew(mod_408);
        expr_ret_405 = expr_ret_408;
      }

      // SlashExpr end
      expr_ret_404 = expr_ret_405;

    }

    expr_ret_403 = SUCC;
    expr_ret_401 = expr_ret_403;
  }

  // ModExprList end
  if (!expr_ret_401) rew(mod_401);
  expr_ret_400 = expr_ret_401;
  if (!rule) rule = expr_ret_400;
  if (!expr_ret_400) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "deneqexpr");
  else if (rule) intr_accept(ctx, "deneqexpr");
  else intr_reject(ctx, "deneqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_410
  daisho_astnode_t* expr_ret_410 = NULL;
  daisho_astnode_t* expr_ret_411 = NULL;
  intr_enter(ctx, "cmpexpr", ctx->pos);
  daisho_astnode_t* expr_ret_412 = NULL;
  rec(mod_412);
  // ModExprList 0
  daisho_astnode_t* expr_ret_413 = NULL;
  expr_ret_413 = daisho_parse_shfexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_412 = expr_ret_413;
  rule = expr_ret_413;
  // ModExprList 1
  if (expr_ret_412) {
    daisho_astnode_t* expr_ret_414 = NULL;
    daisho_astnode_t* expr_ret_415 = SUCC;
    while (expr_ret_415)
    {
      rec(kleene_rew_414);
      daisho_astnode_t* expr_ret_416 = NULL;

      // SlashExpr 0
      if (!expr_ret_416) {
        daisho_astnode_t* expr_ret_417 = NULL;
        rec(mod_417);
        // ModExprList 0
        intr_enter(ctx, "LT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Not capturing LT.
          expr_ret_417 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_417 = NULL;
        }

        if (expr_ret_417) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
        // ModExprList 1
        if (expr_ret_417) {
          daisho_astnode_t* expr_ret_418 = NULL;
          expr_ret_418 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_417 = expr_ret_418;
          n = expr_ret_418;
        }

        // ModExprList 2
        if (expr_ret_417) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_417
          ret = SUCC;
          #line 407 "daisho.peg"
          rule=node(LT,  rule, n);
          #line 8997 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_417) rew(mod_417);
        expr_ret_416 = expr_ret_417;
      }

      // SlashExpr 1
      if (!expr_ret_416) {
        daisho_astnode_t* expr_ret_419 = NULL;
        rec(mod_419);
        // ModExprList 0
        intr_enter(ctx, "GT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Not capturing GT.
          expr_ret_419 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_419 = NULL;
        }

        if (expr_ret_419) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
        // ModExprList 1
        if (expr_ret_419) {
          daisho_astnode_t* expr_ret_420 = NULL;
          expr_ret_420 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_419 = expr_ret_420;
          n = expr_ret_420;
        }

        // ModExprList 2
        if (expr_ret_419) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_419
          ret = SUCC;
          #line 408 "daisho.peg"
          rule=node(GT,  rule, n);
          #line 9040 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_419) rew(mod_419);
        expr_ret_416 = expr_ret_419;
      }

      // SlashExpr 2
      if (!expr_ret_416) {
        daisho_astnode_t* expr_ret_421 = NULL;
        rec(mod_421);
        // ModExprList 0
        intr_enter(ctx, "LEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Not capturing LEQ.
          expr_ret_421 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_421 = NULL;
        }

        if (expr_ret_421) intr_accept(ctx, "LEQ"); else intr_reject(ctx, "LEQ");
        // ModExprList 1
        if (expr_ret_421) {
          daisho_astnode_t* expr_ret_422 = NULL;
          expr_ret_422 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_421 = expr_ret_422;
          n = expr_ret_422;
        }

        // ModExprList 2
        if (expr_ret_421) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_421
          ret = SUCC;
          #line 409 "daisho.peg"
          rule=node(LEQ, rule, n);
          #line 9083 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_421) rew(mod_421);
        expr_ret_416 = expr_ret_421;
      }

      // SlashExpr 3
      if (!expr_ret_416) {
        daisho_astnode_t* expr_ret_423 = NULL;
        rec(mod_423);
        // ModExprList 0
        intr_enter(ctx, "GEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Not capturing GEQ.
          expr_ret_423 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_423 = NULL;
        }

        if (expr_ret_423) intr_accept(ctx, "GEQ"); else intr_reject(ctx, "GEQ");
        // ModExprList 1
        if (expr_ret_423) {
          daisho_astnode_t* expr_ret_424 = NULL;
          expr_ret_424 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_423 = expr_ret_424;
          n = expr_ret_424;
        }

        // ModExprList 2
        if (expr_ret_423) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_423
          ret = SUCC;
          #line 410 "daisho.peg"
          rule=node(GEQ, rule, n);
          #line 9126 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_423) rew(mod_423);
        expr_ret_416 = expr_ret_423;
      }

      // SlashExpr end
      expr_ret_415 = expr_ret_416;

    }

    expr_ret_414 = SUCC;
    expr_ret_412 = expr_ret_414;
  }

  // ModExprList end
  if (!expr_ret_412) rew(mod_412);
  expr_ret_411 = expr_ret_412;
  if (!rule) rule = expr_ret_411;
  if (!expr_ret_411) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "cmpexpr");
  else if (rule) intr_accept(ctx, "cmpexpr");
  else intr_reject(ctx, "cmpexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  #define rule expr_ret_425
  daisho_astnode_t* expr_ret_425 = NULL;
  daisho_astnode_t* expr_ret_426 = NULL;
  intr_enter(ctx, "shfexpr", ctx->pos);
  daisho_astnode_t* expr_ret_427 = NULL;
  rec(mod_427);
  // ModExprList 0
  daisho_astnode_t* expr_ret_428 = NULL;
  expr_ret_428 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_427 = expr_ret_428;
  rule = expr_ret_428;
  // ModExprList 1
  if (expr_ret_427) {
    daisho_astnode_t* expr_ret_429 = NULL;
    daisho_astnode_t* expr_ret_430 = SUCC;
    while (expr_ret_430)
    {
      rec(kleene_rew_429);
      daisho_astnode_t* expr_ret_431 = NULL;

      // SlashExpr 0
      if (!expr_ret_431) {
        daisho_astnode_t* expr_ret_432 = NULL;
        rec(mod_432);
        // ModExprList 0
        daisho_astnode_t* expr_ret_433 = NULL;
        intr_enter(ctx, "LT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_433 = leaf(LT);
          expr_ret_433->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_433->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_433 = NULL;
        }

        if (expr_ret_433) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
        expr_ret_432 = expr_ret_433;
        l = expr_ret_433;
        // ModExprList 1
        if (expr_ret_432) {
          daisho_astnode_t* expr_ret_434 = NULL;
          intr_enter(ctx, "LT", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_434 = leaf(LT);
            expr_ret_434->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_434->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_434 = NULL;
          }

          if (expr_ret_434) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
          expr_ret_432 = expr_ret_434;
          lt = expr_ret_434;
        }

        // ModExprList 2
        if (expr_ret_432) {
          daisho_astnode_t* expr_ret_435 = NULL;
          expr_ret_435 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_432 = expr_ret_435;
          n = expr_ret_435;
        }

        // ModExprList 3
        if (expr_ret_432) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_432
          ret = SUCC;
          #line 413 "daisho.peg"
          rule=node(BSL, l, lt, rule, n);
          #line 9242 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_432) rew(mod_432);
        expr_ret_431 = expr_ret_432;
      }

      // SlashExpr 1
      if (!expr_ret_431) {
        daisho_astnode_t* expr_ret_436 = NULL;
        rec(mod_436);
        // ModExprList 0
        daisho_astnode_t* expr_ret_437 = NULL;
        intr_enter(ctx, "GT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_437 = leaf(GT);
          expr_ret_437->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_437->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_437 = NULL;
        }

        if (expr_ret_437) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
        expr_ret_436 = expr_ret_437;
        g = expr_ret_437;
        // ModExprList 1
        if (expr_ret_436) {
          daisho_astnode_t* expr_ret_438 = NULL;
          intr_enter(ctx, "GT", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_438 = leaf(GT);
            expr_ret_438->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_438->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_438 = NULL;
          }

          if (expr_ret_438) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
          expr_ret_436 = expr_ret_438;
          gt = expr_ret_438;
        }

        // ModExprList 2
        if (expr_ret_436) {
          daisho_astnode_t* expr_ret_439 = NULL;
          expr_ret_439 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_436 = expr_ret_439;
          n = expr_ret_439;
        }

        // ModExprList 3
        if (expr_ret_436) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_436
          ret = SUCC;
          #line 414 "daisho.peg"
          rule=node(BSR, g, gt, rule, n);
          #line 9309 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_436) rew(mod_436);
        expr_ret_431 = expr_ret_436;
      }

      // SlashExpr end
      expr_ret_430 = expr_ret_431;

    }

    expr_ret_429 = SUCC;
    expr_ret_427 = expr_ret_429;
  }

  // ModExprList end
  if (!expr_ret_427) rew(mod_427);
  expr_ret_426 = expr_ret_427;
  if (!rule) rule = expr_ret_426;
  if (!expr_ret_426) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "shfexpr");
  else if (rule) intr_accept(ctx, "shfexpr");
  else intr_reject(ctx, "shfexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_440
  daisho_astnode_t* expr_ret_440 = NULL;
  daisho_astnode_t* expr_ret_441 = NULL;
  intr_enter(ctx, "sumexpr", ctx->pos);
  daisho_astnode_t* expr_ret_442 = NULL;
  rec(mod_442);
  // ModExprList 0
  daisho_astnode_t* expr_ret_443 = NULL;
  expr_ret_443 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_442 = expr_ret_443;
  rule = expr_ret_443;
  // ModExprList 1
  if (expr_ret_442) {
    daisho_astnode_t* expr_ret_444 = NULL;
    daisho_astnode_t* expr_ret_445 = SUCC;
    while (expr_ret_445)
    {
      rec(kleene_rew_444);
      daisho_astnode_t* expr_ret_446 = NULL;

      // SlashExpr 0
      if (!expr_ret_446) {
        daisho_astnode_t* expr_ret_447 = NULL;
        rec(mod_447);
        // ModExprList 0
        daisho_astnode_t* expr_ret_448 = NULL;
        intr_enter(ctx, "PLUS", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_448 = leaf(PLUS);
          expr_ret_448->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_448->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_448 = NULL;
        }

        if (expr_ret_448) intr_accept(ctx, "PLUS"); else intr_reject(ctx, "PLUS");
        expr_ret_447 = expr_ret_448;
        p = expr_ret_448;
        // ModExprList 1
        if (expr_ret_447) {
          daisho_astnode_t* expr_ret_449 = NULL;
          expr_ret_449 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_447 = expr_ret_449;
          n = expr_ret_449;
        }

        // ModExprList 2
        if (expr_ret_447) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_447
          ret = SUCC;
          #line 417 "daisho.peg"
          rule=node(PLUS, rule, n);
          #line 9404 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_447) rew(mod_447);
        expr_ret_446 = expr_ret_447;
      }

      // SlashExpr 1
      if (!expr_ret_446) {
        daisho_astnode_t* expr_ret_450 = NULL;
        rec(mod_450);
        // ModExprList 0
        daisho_astnode_t* expr_ret_451 = NULL;
        intr_enter(ctx, "MINUS", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_451 = leaf(MINUS);
          expr_ret_451->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_451->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_451 = NULL;
        }

        if (expr_ret_451) intr_accept(ctx, "MINUS"); else intr_reject(ctx, "MINUS");
        expr_ret_450 = expr_ret_451;
        m = expr_ret_451;
        // ModExprList 1
        if (expr_ret_450) {
          daisho_astnode_t* expr_ret_452 = NULL;
          expr_ret_452 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_450 = expr_ret_452;
          n = expr_ret_452;
        }

        // ModExprList 2
        if (expr_ret_450) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_450
          ret = SUCC;
          #line 418 "daisho.peg"
          rule=node(MINUS, rule, n);
          #line 9452 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_450) rew(mod_450);
        expr_ret_446 = expr_ret_450;
      }

      // SlashExpr end
      expr_ret_445 = expr_ret_446;

    }

    expr_ret_444 = SUCC;
    expr_ret_442 = expr_ret_444;
  }

  // ModExprList end
  if (!expr_ret_442) rew(mod_442);
  expr_ret_441 = expr_ret_442;
  if (!rule) rule = expr_ret_441;
  if (!expr_ret_441) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sumexpr");
  else if (rule) intr_accept(ctx, "sumexpr");
  else intr_reject(ctx, "sumexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_453
  daisho_astnode_t* expr_ret_453 = NULL;
  daisho_astnode_t* expr_ret_454 = NULL;
  intr_enter(ctx, "multexpr", ctx->pos);
  daisho_astnode_t* expr_ret_455 = NULL;
  rec(mod_455);
  // ModExprList 0
  daisho_astnode_t* expr_ret_456 = NULL;
  expr_ret_456 = daisho_parse_accexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_455 = expr_ret_456;
  rule = expr_ret_456;
  // ModExprList 1
  if (expr_ret_455) {
    daisho_astnode_t* expr_ret_457 = NULL;
    daisho_astnode_t* expr_ret_458 = SUCC;
    while (expr_ret_458)
    {
      rec(kleene_rew_457);
      daisho_astnode_t* expr_ret_459 = NULL;

      // SlashExpr 0
      if (!expr_ret_459) {
        daisho_astnode_t* expr_ret_460 = NULL;
        rec(mod_460);
        // ModExprList 0
        intr_enter(ctx, "STAR", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_460 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_460 = NULL;
        }

        if (expr_ret_460) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
        // ModExprList 1
        if (expr_ret_460) {
          daisho_astnode_t* expr_ret_461 = NULL;
          expr_ret_461 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_460 = expr_ret_461;
          n = expr_ret_461;
        }

        // ModExprList 2
        if (expr_ret_460) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_460
          ret = SUCC;
          #line 421 "daisho.peg"
          rule=node(STAR, rule, n);
          #line 9540 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_460) rew(mod_460);
        expr_ret_459 = expr_ret_460;
      }

      // SlashExpr 1
      if (!expr_ret_459) {
        daisho_astnode_t* expr_ret_462 = NULL;
        rec(mod_462);
        // ModExprList 0
        intr_enter(ctx, "DIV", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Not capturing DIV.
          expr_ret_462 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_462 = NULL;
        }

        if (expr_ret_462) intr_accept(ctx, "DIV"); else intr_reject(ctx, "DIV");
        // ModExprList 1
        if (expr_ret_462) {
          daisho_astnode_t* expr_ret_463 = NULL;
          expr_ret_463 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_462 = expr_ret_463;
          n = expr_ret_463;
        }

        // ModExprList 2
        if (expr_ret_462) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_462
          ret = SUCC;
          #line 422 "daisho.peg"
          rule=node(DIV,  rule, n);
          #line 9583 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_462) rew(mod_462);
        expr_ret_459 = expr_ret_462;
      }

      // SlashExpr 2
      if (!expr_ret_459) {
        daisho_astnode_t* expr_ret_464 = NULL;
        rec(mod_464);
        // ModExprList 0
        intr_enter(ctx, "MOD", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Not capturing MOD.
          expr_ret_464 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_464 = NULL;
        }

        if (expr_ret_464) intr_accept(ctx, "MOD"); else intr_reject(ctx, "MOD");
        // ModExprList 1
        if (expr_ret_464) {
          daisho_astnode_t* expr_ret_465 = NULL;
          expr_ret_465 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_464 = expr_ret_465;
          n = expr_ret_465;
        }

        // ModExprList 2
        if (expr_ret_464) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_464
          ret = SUCC;
          #line 423 "daisho.peg"
          rule=node(MOD,  rule, n);
          #line 9626 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_464) rew(mod_464);
        expr_ret_459 = expr_ret_464;
      }

      // SlashExpr 3
      if (!expr_ret_459) {
        daisho_astnode_t* expr_ret_466 = NULL;
        rec(mod_466);
        // ModExprList 0
        intr_enter(ctx, "POW", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_466 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_466 = NULL;
        }

        if (expr_ret_466) intr_accept(ctx, "POW"); else intr_reject(ctx, "POW");
        // ModExprList 1
        if (expr_ret_466) {
          daisho_astnode_t* expr_ret_467 = NULL;
          expr_ret_467 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_466 = expr_ret_467;
          n = expr_ret_467;
        }

        // ModExprList 2
        if (expr_ret_466) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_466
          ret = SUCC;
          #line 424 "daisho.peg"
          rule=node(POW,  rule, n);
          #line 9669 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_466) rew(mod_466);
        expr_ret_459 = expr_ret_466;
      }

      // SlashExpr end
      expr_ret_458 = expr_ret_459;

    }

    expr_ret_457 = SUCC;
    expr_ret_455 = expr_ret_457;
  }

  // ModExprList end
  if (!expr_ret_455) rew(mod_455);
  expr_ret_454 = expr_ret_455;
  if (!rule) rule = expr_ret_454;
  if (!expr_ret_454) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "multexpr");
  else if (rule) intr_accept(ctx, "multexpr");
  else intr_reject(ctx, "multexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_468
  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_469 = NULL;
  intr_enter(ctx, "accexpr", ctx->pos);
  daisho_astnode_t* expr_ret_470 = NULL;
  rec(mod_470);
  // ModExprList 0
  daisho_astnode_t* expr_ret_471 = NULL;
  expr_ret_471 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_470 = expr_ret_471;
  rule = expr_ret_471;
  // ModExprList 1
  if (expr_ret_470) {
    daisho_astnode_t* expr_ret_472 = NULL;
    daisho_astnode_t* expr_ret_473 = SUCC;
    while (expr_ret_473)
    {
      rec(kleene_rew_472);
      daisho_astnode_t* expr_ret_474 = NULL;
      rec(mod_474);
      // ModExprList 0
      intr_enter(ctx, "LSBRACK", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_474 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_474 = NULL;
      }

      if (expr_ret_474) intr_accept(ctx, "LSBRACK"); else intr_reject(ctx, "LSBRACK");
      // ModExprList 1
      if (expr_ret_474) {
        daisho_astnode_t* expr_ret_475 = NULL;
        expr_ret_475 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_474 = expr_ret_475;
        e = expr_ret_475;
      }

      // ModExprList 2
      if (expr_ret_474) {
        intr_enter(ctx, "RSBRACK", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_474 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_474 = NULL;
        }

        if (expr_ret_474) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
      }

      // ModExprList 3
      if (expr_ret_474) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_474
        ret = SUCC;
        #line 426 "daisho.peg"
        rule=node(ACCESS, rule, e);
        #line 9767 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_474) rew(mod_474);
      expr_ret_473 = expr_ret_474;
    }

    expr_ret_472 = SUCC;
    expr_ret_470 = expr_ret_472;
  }

  // ModExprList end
  if (!expr_ret_470) rew(mod_470);
  expr_ret_469 = expr_ret_470;
  if (!rule) rule = expr_ret_469;
  if (!expr_ret_469) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "accexpr");
  else if (rule) intr_accept(ctx, "accexpr");
  else intr_reject(ctx, "accexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_476
  daisho_astnode_t* expr_ret_476 = NULL;
  daisho_astnode_t* expr_ret_477 = NULL;
  intr_enter(ctx, "dotexpr", ctx->pos);
  daisho_astnode_t* expr_ret_478 = NULL;
  rec(mod_478);
  // ModExprList 0
  daisho_astnode_t* expr_ret_479 = NULL;
  expr_ret_479 = daisho_parse_refexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_478 = expr_ret_479;
  rule = expr_ret_479;
  // ModExprList 1
  if (expr_ret_478) {
    daisho_astnode_t* expr_ret_480 = NULL;
    daisho_astnode_t* expr_ret_481 = SUCC;
    while (expr_ret_481)
    {
      rec(kleene_rew_480);
      daisho_astnode_t* expr_ret_482 = NULL;
      rec(mod_482);
      // ModExprList 0
      intr_enter(ctx, "DOT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_482 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_482 = NULL;
      }

      if (expr_ret_482) intr_accept(ctx, "DOT"); else intr_reject(ctx, "DOT");
      // ModExprList 1
      if (expr_ret_482) {
        daisho_astnode_t* expr_ret_483 = NULL;
        intr_enter(ctx, "VARIDENT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_483 = leaf(VARIDENT);
          expr_ret_483->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_483->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_483 = NULL;
        }

        if (expr_ret_483) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
        expr_ret_482 = expr_ret_483;
        i = expr_ret_483;
      }

      // ModExprList 2
      if (expr_ret_482) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_482
        ret = SUCC;
        #line 428 "daisho.peg"
        rule=node(DOT, rule, i);
        #line 9856 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_482) rew(mod_482);
      expr_ret_481 = expr_ret_482;
    }

    expr_ret_480 = SUCC;
    expr_ret_478 = expr_ret_480;
  }

  // ModExprList end
  if (!expr_ret_478) rew(mod_478);
  expr_ret_477 = expr_ret_478;
  if (!rule) rule = expr_ret_477;
  if (!expr_ret_477) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "dotexpr");
  else if (rule) intr_accept(ctx, "dotexpr");
  else intr_reject(ctx, "dotexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_484
  daisho_astnode_t* expr_ret_484 = NULL;
  daisho_astnode_t* expr_ret_485 = NULL;
  intr_enter(ctx, "refexpr", ctx->pos);
  daisho_astnode_t* expr_ret_486 = NULL;
  rec(mod_486);
  // ModExprList 0
  daisho_astnode_t* expr_ret_487 = NULL;
  expr_ret_487 = daisho_parse_castexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_486 = expr_ret_487;
  rule = expr_ret_487;
  // ModExprList 1
  if (expr_ret_486) {
    daisho_astnode_t* expr_ret_488 = NULL;
    daisho_astnode_t* expr_ret_489 = SUCC;
    while (expr_ret_489)
    {
      rec(kleene_rew_488);
      daisho_astnode_t* expr_ret_490 = NULL;

      // SlashExpr 0
      if (!expr_ret_490) {
        daisho_astnode_t* expr_ret_491 = NULL;
        rec(mod_491);
        // ModExprList 0
        intr_enter(ctx, "REF", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_491 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_491 = NULL;
        }

        if (expr_ret_491) intr_accept(ctx, "REF"); else intr_reject(ctx, "REF");
        // ModExprList 1
        if (expr_ret_491) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_491
          ret = SUCC;
          #line 431 "daisho.peg"
          rd++;
          #line 9931 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_491) rew(mod_491);
        expr_ret_490 = expr_ret_491;
      }

      // SlashExpr 1
      if (!expr_ret_490) {
        daisho_astnode_t* expr_ret_492 = NULL;
        rec(mod_492);
        // ModExprList 0
        intr_enter(ctx, "DEREF", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_492 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_492 = NULL;
        }

        if (expr_ret_492) intr_accept(ctx, "DEREF"); else intr_reject(ctx, "DEREF");
        // ModExprList 1
        if (expr_ret_492) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_492
          ret = SUCC;
          #line 431 "daisho.peg"
          rd--;
          #line 9965 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_492) rew(mod_492);
        expr_ret_490 = expr_ret_492;
      }

      // SlashExpr end
      expr_ret_489 = expr_ret_490;

    }

    expr_ret_488 = SUCC;
    expr_ret_486 = expr_ret_488;
  }

  // ModExprList 2
  if (expr_ret_486) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_486
    ret = SUCC;
    #line 432 "daisho.peg"
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                rule = rd > 0 ? node(REF, rule) : node(DEREF, rule);
              };
    #line 9995 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_486) rew(mod_486);
  expr_ret_485 = expr_ret_486;
  if (!rule) rule = expr_ret_485;
  if (!expr_ret_485) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "refexpr");
  else if (rule) intr_accept(ctx, "refexpr");
  else intr_reject(ctx, "refexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_493
  daisho_astnode_t* expr_ret_493 = NULL;
  daisho_astnode_t* expr_ret_494 = NULL;
  intr_enter(ctx, "castexpr", ctx->pos);
  daisho_astnode_t* expr_ret_495 = NULL;
  rec(mod_495);
  // ModExprList 0
  daisho_astnode_t* expr_ret_496 = NULL;
  expr_ret_496 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_495 = expr_ret_496;
  rule = expr_ret_496;
  // ModExprList 1
  if (expr_ret_495) {
    daisho_astnode_t* expr_ret_497 = NULL;
    daisho_astnode_t* expr_ret_498 = SUCC;
    while (expr_ret_498)
    {
      rec(kleene_rew_497);
      daisho_astnode_t* expr_ret_499 = NULL;
      rec(mod_499);
      // ModExprList 0
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_499 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_499 = NULL;
      }

      if (expr_ret_499) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // ModExprList 1
      if (expr_ret_499) {
        daisho_astnode_t* expr_ret_500 = NULL;
        expr_ret_500 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_499 = expr_ret_500;
        t = expr_ret_500;
      }

      // ModExprList 2
      if (expr_ret_499) {
        intr_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_499 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_499 = NULL;
        }

        if (expr_ret_499) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      }

      // ModExprList 3
      if (expr_ret_499) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_499
        ret = SUCC;
        #line 436 "daisho.peg"
        rule=node(CAST, rule, t);
        #line 10079 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_499) rew(mod_499);
      expr_ret_498 = expr_ret_499;
    }

    expr_ret_497 = SUCC;
    expr_ret_495 = expr_ret_497;
  }

  // ModExprList end
  if (!expr_ret_495) rew(mod_495);
  expr_ret_494 = expr_ret_495;
  if (!rule) rule = expr_ret_494;
  if (!expr_ret_494) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "castexpr");
  else if (rule) intr_accept(ctx, "castexpr");
  else intr_reject(ctx, "castexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* te = NULL;
  daisho_astnode_t* el = NULL;
  #define rule expr_ret_501
  daisho_astnode_t* expr_ret_501 = NULL;
  daisho_astnode_t* expr_ret_502 = NULL;
  intr_enter(ctx, "callexpr", ctx->pos);
  daisho_astnode_t* expr_ret_503 = NULL;
  rec(mod_503);
  // ModExprList 0
  daisho_astnode_t* expr_ret_504 = NULL;
  expr_ret_504 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_503 = expr_ret_504;
  rule = expr_ret_504;
  // ModExprList 1
  if (expr_ret_503) {
    daisho_astnode_t* expr_ret_505 = NULL;
    daisho_astnode_t* expr_ret_506 = NULL;
    rec(mod_506);
    // ModExprList 0
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_506
    ret = SUCC;
    #line 439 "daisho.peg"
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #line 10134 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList 1
    if (expr_ret_506) {
      daisho_astnode_t* expr_ret_507 = NULL;
      expr_ret_507 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_506 = expr_ret_507;
      te = expr_ret_507;
    }

    // ModExprList end
    if (!expr_ret_506) rew(mod_506);
    expr_ret_505 = expr_ret_506;
    // optional
    if (!expr_ret_505)
      expr_ret_505 = SUCC;
    expr_ret_503 = expr_ret_505;
  }

  // ModExprList 2
  if (expr_ret_503) {
    daisho_astnode_t* expr_ret_508 = NULL;
    daisho_astnode_t* expr_ret_509 = SUCC;
    while (expr_ret_509)
    {
      rec(kleene_rew_508);
      daisho_astnode_t* expr_ret_510 = NULL;
      rec(mod_510);
      // ModExprList 0
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_510 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_510 = NULL;
      }

      if (expr_ret_510) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // ModExprList 1
      if (expr_ret_510) {
        daisho_astnode_t* expr_ret_511 = NULL;
        expr_ret_511 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_510 = expr_ret_511;
        el = expr_ret_511;
      }

      // ModExprList 2
      if (expr_ret_510) {
        intr_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_510 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_510 = NULL;
        }

        if (expr_ret_510) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      }

      // ModExprList 3
      if (expr_ret_510) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_510
        ret = SUCC;
        #line 441 "daisho.peg"
        rule = node(CALL, rule, te, el); te=NULL;
        #line 10207 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_510) rew(mod_510);
      expr_ret_509 = expr_ret_510;
    }

    expr_ret_508 = SUCC;
    expr_ret_503 = expr_ret_508;
  }

  // ModExprList end
  if (!expr_ret_503) rew(mod_503);
  expr_ret_502 = expr_ret_503;
  if (!rule) rule = expr_ret_502;
  if (!expr_ret_502) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "callexpr");
  else if (rule) intr_accept(ctx, "callexpr");
  else intr_reject(ctx, "callexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_512
  daisho_astnode_t* expr_ret_512 = NULL;
  daisho_astnode_t* expr_ret_513 = NULL;
  intr_enter(ctx, "increxpr", ctx->pos);
  daisho_astnode_t* expr_ret_514 = NULL;
  rec(mod_514);
  // ModExprList 0
  daisho_astnode_t* expr_ret_515 = NULL;
  expr_ret_515 = daisho_parse_notexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_514 = expr_ret_515;
  rule = expr_ret_515;
  // ModExprList 1
  if (expr_ret_514) {
    daisho_astnode_t* expr_ret_516 = NULL;
    daisho_astnode_t* expr_ret_517 = NULL;

    // SlashExpr 0
    if (!expr_ret_517) {
      daisho_astnode_t* expr_ret_518 = NULL;
      rec(mod_518);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_519 = NULL;
      rec(mod_519);
      // ModExprList 0
      intr_enter(ctx, "INCR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Not capturing INCR.
        expr_ret_519 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_519 = NULL;
      }

      if (expr_ret_519) intr_accept(ctx, "INCR"); else intr_reject(ctx, "INCR");
      // ModExprList 1
      if (expr_ret_519) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_519
        ret = SUCC;
        #line 443 "daisho.peg"
        rule=node(INCR, rule);
        #line 10279 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_519) rew(mod_519);
      expr_ret_518 = expr_ret_519;
      // ModExprList end
      if (!expr_ret_518) rew(mod_518);
      expr_ret_517 = expr_ret_518;
    }

    // SlashExpr 1
    if (!expr_ret_517) {
      daisho_astnode_t* expr_ret_520 = NULL;
      rec(mod_520);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_521 = NULL;
      rec(mod_521);
      // ModExprList 0
      intr_enter(ctx, "DECR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Not capturing DECR.
        expr_ret_521 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_521 = NULL;
      }

      if (expr_ret_521) intr_accept(ctx, "DECR"); else intr_reject(ctx, "DECR");
      // ModExprList 1
      if (expr_ret_521) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_521
        ret = SUCC;
        #line 444 "daisho.peg"
        rule=node(DECR, rule);
        #line 10319 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_521) rew(mod_521);
      expr_ret_520 = expr_ret_521;
      // ModExprList end
      if (!expr_ret_520) rew(mod_520);
      expr_ret_517 = expr_ret_520;
    }

    // SlashExpr end
    expr_ret_516 = expr_ret_517;

    // optional
    if (!expr_ret_516)
      expr_ret_516 = SUCC;
    expr_ret_514 = expr_ret_516;
  }

  // ModExprList end
  if (!expr_ret_514) rew(mod_514);
  expr_ret_513 = expr_ret_514;
  if (!rule) rule = expr_ret_513;
  if (!expr_ret_513) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "increxpr");
  else if (rule) intr_accept(ctx, "increxpr");
  else intr_reject(ctx, "increxpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_notexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_522
  daisho_astnode_t* expr_ret_522 = NULL;
  daisho_astnode_t* expr_ret_523 = NULL;
  intr_enter(ctx, "notexpr", ctx->pos);
  daisho_astnode_t* expr_ret_524 = NULL;
  rec(mod_524);
  // ModExprList 0
  daisho_astnode_t* expr_ret_525 = NULL;
  expr_ret_525 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_524 = expr_ret_525;
  rule = expr_ret_525;
  // ModExprList 1
  if (expr_ret_524) {
    daisho_astnode_t* expr_ret_526 = NULL;
    daisho_astnode_t* expr_ret_527 = SUCC;
    while (expr_ret_527)
    {
      rec(kleene_rew_526);
      daisho_astnode_t* expr_ret_528 = NULL;
      rec(mod_528);
      // ModExprList 0
      intr_enter(ctx, "EXCL", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Not capturing EXCL.
        expr_ret_528 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_528 = NULL;
      }

      if (expr_ret_528) intr_accept(ctx, "EXCL"); else intr_reject(ctx, "EXCL");
      // ModExprList 1
      if (expr_ret_528) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_528
        ret = SUCC;
        #line 446 "daisho.peg"
        rule=node(EXCL, rule);
        #line 10396 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_528) rew(mod_528);
      expr_ret_527 = expr_ret_528;
    }

    expr_ret_526 = SUCC;
    expr_ret_524 = expr_ret_526;
  }

  // ModExprList end
  if (!expr_ret_524) rew(mod_524);
  expr_ret_523 = expr_ret_524;
  if (!rule) rule = expr_ret_523;
  if (!expr_ret_523) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "notexpr");
  else if (rule) intr_accept(ctx, "notexpr");
  else intr_reject(ctx, "notexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_529
  daisho_astnode_t* expr_ret_529 = NULL;
  daisho_astnode_t* expr_ret_530 = NULL;
  intr_enter(ctx, "atomexpr", ctx->pos);
  daisho_astnode_t* expr_ret_531 = NULL;

  // SlashExpr 0
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_532 = NULL;
    rec(mod_532);
    // ModExprList Forwarding
    expr_ret_532 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_532) rew(mod_532);
    expr_ret_531 = expr_ret_532;
  }

  // SlashExpr 1
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_533 = NULL;
    rec(mod_533);
    // ModExprList Forwarding
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_533 = leaf(VARIDENT);
      expr_ret_533->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_533->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_533 = NULL;
    }

    if (expr_ret_533) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    // ModExprList end
    if (!expr_ret_533) rew(mod_533);
    expr_ret_531 = expr_ret_533;
  }

  // SlashExpr 2
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_534 = NULL;
    rec(mod_534);
    // ModExprList Forwarding
    expr_ret_534 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_534) rew(mod_534);
    expr_ret_531 = expr_ret_534;
  }

  // SlashExpr 3
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_535 = NULL;
    rec(mod_535);
    // ModExprList Forwarding
    expr_ret_535 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_535) rew(mod_535);
    expr_ret_531 = expr_ret_535;
  }

  // SlashExpr 4
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_536 = NULL;
    rec(mod_536);
    // ModExprList Forwarding
    expr_ret_536 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_536) rew(mod_536);
    expr_ret_531 = expr_ret_536;
  }

  // SlashExpr 5
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_537 = NULL;
    rec(mod_537);
    // ModExprList Forwarding
    expr_ret_537 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_537) rew(mod_537);
    expr_ret_531 = expr_ret_537;
  }

  // SlashExpr 6
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_538 = NULL;
    rec(mod_538);
    // ModExprList Forwarding
    expr_ret_538 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_538) rew(mod_538);
    expr_ret_531 = expr_ret_538;
  }

  // SlashExpr 7
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_539 = NULL;
    rec(mod_539);
    // ModExprList Forwarding
    expr_ret_539 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_539) rew(mod_539);
    expr_ret_531 = expr_ret_539;
  }

  // SlashExpr 8
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_540 = NULL;
    rec(mod_540);
    // ModExprList Forwarding
    intr_enter(ctx, "NUMLIT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_540 = leaf(NUMLIT);
      expr_ret_540->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_540->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_540 = NULL;
    }

    if (expr_ret_540) intr_accept(ctx, "NUMLIT"); else intr_reject(ctx, "NUMLIT");
    // ModExprList end
    if (!expr_ret_540) rew(mod_540);
    expr_ret_531 = expr_ret_540;
  }

  // SlashExpr 9
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_541 = NULL;
    rec(mod_541);
    // ModExprList Forwarding
    intr_enter(ctx, "SELFVAR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_541 = leaf(SELFVAR);
      expr_ret_541->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_541->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_541 = NULL;
    }

    if (expr_ret_541) intr_accept(ctx, "SELFVAR"); else intr_reject(ctx, "SELFVAR");
    // ModExprList end
    if (!expr_ret_541) rew(mod_541);
    expr_ret_531 = expr_ret_541;
  }

  // SlashExpr 10
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_542 = NULL;
    rec(mod_542);
    // ModExprList Forwarding
    intr_enter(ctx, "CHARLIT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CHARLIT) {
      // Capturing CHARLIT.
      expr_ret_542 = leaf(CHARLIT);
      expr_ret_542->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_542->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_542 = NULL;
    }

    if (expr_ret_542) intr_accept(ctx, "CHARLIT"); else intr_reject(ctx, "CHARLIT");
    // ModExprList end
    if (!expr_ret_542) rew(mod_542);
    expr_ret_531 = expr_ret_542;
  }

  // SlashExpr 11
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_543 = NULL;
    rec(mod_543);
    // ModExprList Forwarding
    expr_ret_543 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_543) rew(mod_543);
    expr_ret_531 = expr_ret_543;
  }

  // SlashExpr 12
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_544 = NULL;
    rec(mod_544);
    // ModExprList Forwarding
    expr_ret_544 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_544) rew(mod_544);
    expr_ret_531 = expr_ret_544;
  }

  // SlashExpr 13
  if (!expr_ret_531) {
    daisho_astnode_t* expr_ret_545 = NULL;
    rec(mod_545);
    // ModExprList Forwarding
    expr_ret_545 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_545) rew(mod_545);
    expr_ret_531 = expr_ret_545;
  }

  // SlashExpr end
  expr_ret_530 = expr_ret_531;

  if (!rule) rule = expr_ret_530;
  if (!expr_ret_530) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "atomexpr");
  else if (rule) intr_accept(ctx, "atomexpr");
  else intr_reject(ctx, "atomexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  int skip=0;

  daisho_astnode_t* e = NULL;
  #define rule expr_ret_546
  daisho_astnode_t* expr_ret_546 = NULL;
  daisho_astnode_t* expr_ret_547 = NULL;
  intr_enter(ctx, "blockexpr", ctx->pos);
  daisho_astnode_t* expr_ret_548 = NULL;
  rec(mod_548);
  // ModExprList 0
  intr_enter(ctx, "LCBRACK", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_548 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_548 = NULL;
  }

  if (expr_ret_548) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  // ModExprList 1
  if (expr_ret_548) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_548
    ret = SUCC;
    #line 568 "daisho.peg"
    rule=list(BLOCK);
    #line 10679 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_548) {
    daisho_astnode_t* expr_ret_549 = NULL;
    daisho_astnode_t* expr_ret_550 = SUCC;
    while (expr_ret_550)
    {
      rec(kleene_rew_549);
      daisho_astnode_t* expr_ret_551 = NULL;
      rec(mod_551);
      // ModExprList 0
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_551
      ret = SUCC;
      #line 569 "daisho.peg"
      if (skip) ret=NULL;
      #line 10701 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList 1
      if (expr_ret_551) {
        rec(mexpr_state_552)
        daisho_astnode_t* expr_ret_552 = NULL;
        intr_enter(ctx, "RCBRACK", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
          // Not capturing RCBRACK.
          expr_ret_552 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_552 = NULL;
        }

        if (expr_ret_552) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
        // invert
        expr_ret_552 = expr_ret_552 ? NULL : SUCC;
        // rewind
        rew(mexpr_state_552);
        expr_ret_551 = expr_ret_552;
      }

      // ModExprList 2
      if (expr_ret_551) {
        daisho_astnode_t* expr_ret_553 = NULL;
        expr_ret_553 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        // optional
        if (!expr_ret_553)
          expr_ret_553 = SUCC;
        expr_ret_551 = expr_ret_553;
        e = expr_ret_553;
      }

      // ModExprList 3
      if (expr_ret_551) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_551
        ret = SUCC;
        #line 570 "daisho.peg"
        if(has(e)) add(rule, e);
        #line 10746 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 4
      if (expr_ret_551) {
        daisho_astnode_t* expr_ret_554 = NULL;

        // SlashExpr 0
        if (!expr_ret_554) {
          daisho_astnode_t* expr_ret_555 = NULL;
          rec(mod_555);
          // ModExprList Forwarding
          expr_ret_555 = daisho_parse_semiornl(ctx);
          if (ctx->exit) return NULL;
          // ModExprList end
          if (!expr_ret_555) rew(mod_555);
          expr_ret_554 = expr_ret_555;
        }

        // SlashExpr 1
        if (!expr_ret_554) {
          daisho_astnode_t* expr_ret_556 = NULL;
          rec(mod_556);
          // ModExprList Forwarding
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_556
          ret = SUCC;
          #line 571 "daisho.peg"
          skip=1;
          #line 10779 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
          // ModExprList end
          if (!expr_ret_556) rew(mod_556);
          expr_ret_554 = expr_ret_556;
        }

        // SlashExpr end
        expr_ret_551 = expr_ret_554;

      }

      // ModExprList end
      if (!expr_ret_551) rew(mod_551);
      expr_ret_550 = expr_ret_551;
    }

    expr_ret_549 = SUCC;
    expr_ret_548 = expr_ret_549;
  }

  // ModExprList 3
  if (expr_ret_548) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_548 = leaf(RCBRACK);
      expr_ret_548->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_548->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_548 = NULL;
    }

    if (expr_ret_548) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList end
  if (!expr_ret_548) rew(mod_548);
  expr_ret_547 = expr_ret_548;
  if (!rule) rule = expr_ret_547;
  if (!expr_ret_547) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "blockexpr");
  else if (rule) intr_accept(ctx, "blockexpr");
  else intr_reject(ctx, "blockexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_557
  daisho_astnode_t* expr_ret_557 = NULL;
  daisho_astnode_t* expr_ret_558 = NULL;
  intr_enter(ctx, "nsexpr", ctx->pos);
  daisho_astnode_t* expr_ret_559 = NULL;
  rec(mod_559);
  // ModExprList 0
  daisho_astnode_t* expr_ret_560 = NULL;
  intr_enter(ctx, "TYPEIDENT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
    // Capturing TYPEIDENT.
    expr_ret_560 = leaf(TYPEIDENT);
    expr_ret_560->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_560->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_560 = NULL;
  }

  if (expr_ret_560) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
  expr_ret_559 = expr_ret_560;
  ns = expr_ret_560;
  // ModExprList 1
  if (expr_ret_559) {
    intr_enter(ctx, "DOT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
      // Not capturing DOT.
      expr_ret_559 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_559 = NULL;
    }

    if (expr_ret_559) intr_accept(ctx, "DOT"); else intr_reject(ctx, "DOT");
  }

  // ModExprList 2
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_561 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_561 = leaf(VARIDENT);
      expr_ret_561->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_561->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_561 = NULL;
    }

    if (expr_ret_561) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_559 = expr_ret_561;
    v = expr_ret_561;
  }

  // ModExprList 3
  if (expr_ret_559) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_559
    ret = SUCC;
    #line 575 "daisho.peg"
    rule=node(NSACCESS, ns, v);
    #line 10896 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_559) rew(mod_559);
  expr_ret_558 = expr_ret_559;
  if (!rule) rule = expr_ret_558;
  if (!expr_ret_558) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nsexpr");
  else if (rule) intr_accept(ctx, "nsexpr");
  else intr_reject(ctx, "nsexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_562
  daisho_astnode_t* expr_ret_562 = NULL;
  daisho_astnode_t* expr_ret_563 = NULL;
  intr_enter(ctx, "lambdaexpr", ctx->pos);
  daisho_astnode_t* expr_ret_564 = NULL;
  rec(mod_564);
  // ModExprList 0
  daisho_astnode_t* expr_ret_565 = NULL;
  rec(mod_565);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_565 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_565 = NULL;
  }

  if (expr_ret_565) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_565) {
    daisho_astnode_t* expr_ret_566 = NULL;
    daisho_astnode_t* expr_ret_567 = NULL;

    // SlashExpr 0
    if (!expr_ret_567) {
      daisho_astnode_t* expr_ret_568 = NULL;
      rec(mod_568);
      // ModExprList 0
      rec(mexpr_state_569)
      daisho_astnode_t* expr_ret_569 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_569 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_569 = NULL;
      }

      if (expr_ret_569) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // invert
      expr_ret_569 = expr_ret_569 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_569);
      expr_ret_568 = expr_ret_569;
      // ModExprList 1
      if (expr_ret_568) {
        daisho_astnode_t* expr_ret_570 = NULL;
        expr_ret_570 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_568 = expr_ret_570;
        al = expr_ret_570;
      }

      // ModExprList end
      if (!expr_ret_568) rew(mod_568);
      expr_ret_567 = expr_ret_568;
    }

    // SlashExpr 1
    if (!expr_ret_567) {
      daisho_astnode_t* expr_ret_571 = NULL;
      rec(mod_571);
      // ModExprList Forwarding
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_571
      ret = SUCC;
      #line 577 "daisho.peg"
      al=leaf(ARGLIST);
      #line 10989 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList end
      if (!expr_ret_571) rew(mod_571);
      expr_ret_567 = expr_ret_571;
    }

    // SlashExpr end
    expr_ret_566 = expr_ret_567;

    // optional
    if (!expr_ret_566)
      expr_ret_566 = SUCC;
    expr_ret_565 = expr_ret_566;
  }

  // ModExprList 2
  if (expr_ret_565) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_565 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_565 = NULL;
    }

    if (expr_ret_565) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_565) rew(mod_565);
  expr_ret_564 = expr_ret_565;
  // ModExprList 1
  if (expr_ret_564) {
    intr_enter(ctx, "ARROW", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_564 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_564 = NULL;
    }

    if (expr_ret_564) intr_accept(ctx, "ARROW"); else intr_reject(ctx, "ARROW");
  }

  // ModExprList 2
  if (expr_ret_564) {
    daisho_astnode_t* expr_ret_572 = NULL;
    expr_ret_572 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_564 = expr_ret_572;
    e = expr_ret_572;
  }

  // ModExprList 3
  if (expr_ret_564) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_564
    ret = SUCC;
    #line 579 "daisho.peg"
    rule=node(LAMBDA, al, e);
    #line 11055 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_564) rew(mod_564);
  expr_ret_563 = expr_ret_564;
  if (!rule) rule = expr_ret_563;
  if (!expr_ret_563) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "lambdaexpr");
  else if (rule) intr_accept(ctx, "lambdaexpr");
  else intr_reject(ctx, "lambdaexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* en = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* in = NULL;
  daisho_astnode_t* cond = NULL;
  #define rule expr_ret_573
  daisho_astnode_t* expr_ret_573 = NULL;
  daisho_astnode_t* expr_ret_574 = NULL;
  intr_enter(ctx, "listcomp", ctx->pos);
  daisho_astnode_t* expr_ret_575 = NULL;
  rec(mod_575);
  // ModExprList 0
  intr_enter(ctx, "LSBRACK", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_575 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_575 = NULL;
  }

  if (expr_ret_575) intr_accept(ctx, "LSBRACK"); else intr_reject(ctx, "LSBRACK");
  // ModExprList 1
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_576 = NULL;
    daisho_astnode_t* expr_ret_577 = NULL;
    rec(mod_577);
    // ModExprList 0
    daisho_astnode_t* expr_ret_578 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_578 = leaf(VARIDENT);
      expr_ret_578->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_578->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_578 = NULL;
    }

    if (expr_ret_578) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_577 = expr_ret_578;
    en = expr_ret_578;
    // ModExprList 1
    if (expr_ret_577) {
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_577 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_577 = NULL;
      }

      if (expr_ret_577) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    }

    // ModExprList end
    if (!expr_ret_577) rew(mod_577);
    expr_ret_576 = expr_ret_577;
    // optional
    if (!expr_ret_576)
      expr_ret_576 = SUCC;
    expr_ret_575 = expr_ret_576;
  }

  // ModExprList 2
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_579 = NULL;
    expr_ret_579 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_575 = expr_ret_579;
    e = expr_ret_579;
  }

  // ModExprList 3
  if (expr_ret_575) {
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_575 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_575 = NULL;
    }

    if (expr_ret_575) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_580 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_580 = leaf(VARIDENT);
      expr_ret_580->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_580->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_580 = NULL;
    }

    if (expr_ret_580) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_575 = expr_ret_580;
    item = expr_ret_580;
  }

  // ModExprList 5
  if (expr_ret_575) {
    intr_enter(ctx, "IN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_575 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_575 = NULL;
    }

    if (expr_ret_575) intr_accept(ctx, "IN"); else intr_reject(ctx, "IN");
  }

  // ModExprList 6
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_581 = NULL;
    expr_ret_581 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_575 = expr_ret_581;
    in = expr_ret_581;
  }

  // ModExprList 7
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_582 = NULL;
    daisho_astnode_t* expr_ret_583 = NULL;
    rec(mod_583);
    // ModExprList 0
    intr_enter(ctx, "WHERE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_583 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_583 = NULL;
    }

    if (expr_ret_583) intr_accept(ctx, "WHERE"); else intr_reject(ctx, "WHERE");
    // ModExprList 1
    if (expr_ret_583) {
      daisho_astnode_t* expr_ret_584 = NULL;
      expr_ret_584 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_583 = expr_ret_584;
      cond = expr_ret_584;
    }

    // ModExprList end
    if (!expr_ret_583) rew(mod_583);
    expr_ret_582 = expr_ret_583;
    // optional
    if (!expr_ret_582)
      expr_ret_582 = SUCC;
    expr_ret_575 = expr_ret_582;
  }

  // ModExprList 8
  if (expr_ret_575) {
    intr_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_575 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_575 = NULL;
    }

    if (expr_ret_575) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
  }

  // ModExprList 9
  if (expr_ret_575) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_575
    ret = SUCC;
    #line 588 "daisho.peg"
    rule = list(LISTCOMP);
              if (en) add(rule, node(COMPENUMERATE, en));
              add(rule, e);add(rule, item);add(rule, in);
              if (cond) add(rule, node(COMPCOND, cond));;
    #line 11264 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_575) rew(mod_575);
  expr_ret_574 = expr_ret_575;
  if (!rule) rule = expr_ret_574;
  if (!expr_ret_574) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "listcomp");
  else if (rule) intr_accept(ctx, "listcomp");
  else intr_reject(ctx, "listcomp");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_585
  daisho_astnode_t* expr_ret_585 = NULL;
  daisho_astnode_t* expr_ret_586 = NULL;
  intr_enter(ctx, "parenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_587 = NULL;
  rec(mod_587);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_587 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_587 = NULL;
  }

  if (expr_ret_587) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_587) {
    daisho_astnode_t* expr_ret_588 = NULL;
    expr_ret_588 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_587 = expr_ret_588;
    rule = expr_ret_588;
  }

  // ModExprList 2
  if (expr_ret_587) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_587 = leaf(CLOSE);
      expr_ret_587->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_587->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_587 = NULL;
    }

    if (expr_ret_587) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_587) rew(mod_587);
  expr_ret_586 = expr_ret_587;
  if (!rule) rule = expr_ret_586;
  if (!expr_ret_586) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "parenexpr");
  else if (rule) intr_accept(ctx, "parenexpr");
  else intr_reject(ctx, "parenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_589
  daisho_astnode_t* expr_ret_589 = NULL;
  daisho_astnode_t* expr_ret_590 = NULL;
  intr_enter(ctx, "listlit", ctx->pos);
  daisho_astnode_t* expr_ret_591 = NULL;
  rec(mod_591);
  // ModExprList 0
  intr_enter(ctx, "LSBRACK", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_591 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_591 = NULL;
  }

  if (expr_ret_591) intr_accept(ctx, "LSBRACK"); else intr_reject(ctx, "LSBRACK");
  // ModExprList 1
  if (expr_ret_591) {
    daisho_astnode_t* expr_ret_592 = NULL;
    expr_ret_592 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_591 = expr_ret_592;
    rule = expr_ret_592;
  }

  // ModExprList 2
  if (expr_ret_591) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_591
    ret = SUCC;
    #line 596 "daisho.peg"
    rule->kind = kind(LISTLIT);
    #line 11374 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_591) {
    intr_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_591 = leaf(RSBRACK);
      expr_ret_591->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_591->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_591 = NULL;
    }

    if (expr_ret_591) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
  }

  // ModExprList end
  if (!expr_ret_591) rew(mod_591);
  expr_ret_590 = expr_ret_591;
  if (!rule) rule = expr_ret_590;
  if (!expr_ret_590) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "listlit");
  else if (rule) intr_accept(ctx, "listlit");
  else intr_reject(ctx, "listlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_593
  daisho_astnode_t* expr_ret_593 = NULL;
  daisho_astnode_t* expr_ret_594 = NULL;
  intr_enter(ctx, "tuplelit", ctx->pos);
  daisho_astnode_t* expr_ret_595 = NULL;
  rec(mod_595);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_595 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_595 = NULL;
  }

  if (expr_ret_595) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_595) {
    daisho_astnode_t* expr_ret_596 = NULL;
    expr_ret_596 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_595 = expr_ret_596;
    rule = expr_ret_596;
  }

  // ModExprList 2
  if (expr_ret_595) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_595
    ret = SUCC;
    #line 600 "daisho.peg"
    rule->kind = kind(TUPLELIT);
    #line 11444 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_595) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_595 = leaf(CLOSE);
      expr_ret_595->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_595->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_595 = NULL;
    }

    if (expr_ret_595) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_595) rew(mod_595);
  expr_ret_594 = expr_ret_595;
  if (!rule) rule = expr_ret_594;
  if (!expr_ret_594) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tuplelit");
  else if (rule) intr_accept(ctx, "tuplelit");
  else intr_reject(ctx, "tuplelit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_597
  daisho_astnode_t* expr_ret_597 = NULL;
  daisho_astnode_t* expr_ret_598 = NULL;
  intr_enter(ctx, "vardeclexpr", ctx->pos);
  daisho_astnode_t* expr_ret_599 = NULL;
  rec(mod_599);
  // ModExprList 0
  daisho_astnode_t* expr_ret_600 = NULL;
  expr_ret_600 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_599 = expr_ret_600;
  t = expr_ret_600;
  // ModExprList 1
  if (expr_ret_599) {
    daisho_astnode_t* expr_ret_601 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_601 = leaf(VARIDENT);
      expr_ret_601->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_601->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_601 = NULL;
    }

    if (expr_ret_601) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_599 = expr_ret_601;
    i = expr_ret_601;
  }

  // ModExprList 2
  if (expr_ret_599) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_599
    ret = SUCC;
    #line 608 "daisho.peg"
    rule=node(VARDECL, t, i);
    #line 11520 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_599) rew(mod_599);
  expr_ret_598 = expr_ret_599;
  if (!rule) rule = expr_ret_598;
  if (!expr_ret_598) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "vardeclexpr");
  else if (rule) intr_accept(ctx, "vardeclexpr");
  else intr_reject(ctx, "vardeclexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_602
  daisho_astnode_t* expr_ret_602 = NULL;
  daisho_astnode_t* expr_ret_603 = NULL;
  intr_enter(ctx, "strlit", ctx->pos);
  daisho_astnode_t* expr_ret_604 = NULL;

  // SlashExpr 0
  if (!expr_ret_604) {
    daisho_astnode_t* expr_ret_605 = NULL;
    rec(mod_605);
    // ModExprList Forwarding
    expr_ret_605 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_605) rew(mod_605);
    expr_ret_604 = expr_ret_605;
  }

  // SlashExpr 1
  if (!expr_ret_604) {
    daisho_astnode_t* expr_ret_606 = NULL;
    rec(mod_606);
    // ModExprList Forwarding
    expr_ret_606 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_606) rew(mod_606);
    expr_ret_604 = expr_ret_606;
  }

  // SlashExpr end
  expr_ret_603 = expr_ret_604;

  if (!rule) rule = expr_ret_603;
  if (!expr_ret_603) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "strlit");
  else if (rule) intr_accept(ctx, "strlit");
  else intr_reject(ctx, "strlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_607
  daisho_astnode_t* expr_ret_607 = NULL;
  daisho_astnode_t* expr_ret_608 = NULL;
  intr_enter(ctx, "sstrlit", ctx->pos);
  daisho_astnode_t* expr_ret_609 = NULL;
  rec(mod_609);
  // ModExprList 0
  daisho_astnode_t* expr_ret_610 = NULL;
  intr_enter(ctx, "STRLIT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_610 = leaf(STRLIT);
    expr_ret_610->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_610->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_610 = NULL;
  }

  if (expr_ret_610) intr_accept(ctx, "STRLIT"); else intr_reject(ctx, "STRLIT");
  expr_ret_609 = expr_ret_610;
  s = expr_ret_610;
  // ModExprList 1
  if (expr_ret_609) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_609
    ret = SUCC;
    #line 613 "daisho.peg"
    rule=list(SSTR); add(rule, s);
    #line 11613 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_609) {
    daisho_astnode_t* expr_ret_611 = NULL;
    daisho_astnode_t* expr_ret_612 = SUCC;
    while (expr_ret_612)
    {
      rec(kleene_rew_611);
      daisho_astnode_t* expr_ret_613 = NULL;
      rec(mod_613);
      // ModExprList 0
      daisho_astnode_t* expr_ret_614 = NULL;
      intr_enter(ctx, "STRLIT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_614 = leaf(STRLIT);
        expr_ret_614->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_614->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_614 = NULL;
      }

      if (expr_ret_614) intr_accept(ctx, "STRLIT"); else intr_reject(ctx, "STRLIT");
      expr_ret_613 = expr_ret_614;
      s = expr_ret_614;
      // ModExprList 1
      if (expr_ret_613) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_613
        ret = SUCC;
        #line 614 "daisho.peg"
        add(rule, s);
        #line 11652 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_613) rew(mod_613);
      expr_ret_612 = expr_ret_613;
    }

    expr_ret_611 = SUCC;
    expr_ret_609 = expr_ret_611;
  }

  // ModExprList end
  if (!expr_ret_609) rew(mod_609);
  expr_ret_608 = expr_ret_609;
  if (!rule) rule = expr_ret_608;
  if (!expr_ret_608) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sstrlit");
  else if (rule) intr_accept(ctx, "sstrlit");
  else intr_reject(ctx, "sstrlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_615
  daisho_astnode_t* expr_ret_615 = NULL;
  daisho_astnode_t* expr_ret_616 = NULL;
  intr_enter(ctx, "fstrlit", ctx->pos);
  daisho_astnode_t* expr_ret_617 = NULL;
  rec(mod_617);
  // ModExprList 0
  daisho_astnode_t* expr_ret_618 = NULL;
  expr_ret_618 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_617 = expr_ret_618;
  f = expr_ret_618;
  // ModExprList 1
  if (expr_ret_617) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_617
    ret = SUCC;
    #line 616 "daisho.peg"
    rule=list(FSTR); add(rule, f);
    #line 11701 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_617) {
    daisho_astnode_t* expr_ret_619 = NULL;
    daisho_astnode_t* expr_ret_620 = SUCC;
    while (expr_ret_620)
    {
      rec(kleene_rew_619);
      daisho_astnode_t* expr_ret_621 = NULL;
      rec(mod_621);
      // ModExprList 0
      daisho_astnode_t* expr_ret_622 = NULL;
      expr_ret_622 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_621 = expr_ret_622;
      f = expr_ret_622;
      // ModExprList 1
      if (expr_ret_621) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_621
        ret = SUCC;
        #line 617 "daisho.peg"
        add(rule, f);
        #line 11730 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_621) rew(mod_621);
      expr_ret_620 = expr_ret_621;
    }

    expr_ret_619 = SUCC;
    expr_ret_617 = expr_ret_619;
  }

  // ModExprList end
  if (!expr_ret_617) rew(mod_617);
  expr_ret_616 = expr_ret_617;
  if (!rule) rule = expr_ret_616;
  if (!expr_ret_616) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fstrlit");
  else if (rule) intr_accept(ctx, "fstrlit");
  else intr_reject(ctx, "fstrlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_623
  daisho_astnode_t* expr_ret_623 = NULL;
  daisho_astnode_t* expr_ret_624 = NULL;
  intr_enter(ctx, "fstrfrag", ctx->pos);
  daisho_astnode_t* expr_ret_625 = NULL;

  // SlashExpr 0
  if (!expr_ret_625) {
    daisho_astnode_t* expr_ret_626 = NULL;
    rec(mod_626);
    // ModExprList Forwarding
    intr_enter(ctx, "STRLIT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_626 = leaf(STRLIT);
      expr_ret_626->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_626->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_626 = NULL;
    }

    if (expr_ret_626) intr_accept(ctx, "STRLIT"); else intr_reject(ctx, "STRLIT");
    // ModExprList end
    if (!expr_ret_626) rew(mod_626);
    expr_ret_625 = expr_ret_626;
  }

  // SlashExpr 1
  if (!expr_ret_625) {
    daisho_astnode_t* expr_ret_627 = NULL;
    rec(mod_627);
    // ModExprList 0
    daisho_astnode_t* expr_ret_628 = NULL;
    intr_enter(ctx, "FSTRLITSTART", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_628 = leaf(FSTRLITSTART);
      expr_ret_628->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_628->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_628 = NULL;
    }

    if (expr_ret_628) intr_accept(ctx, "FSTRLITSTART"); else intr_reject(ctx, "FSTRLITSTART");
    expr_ret_627 = expr_ret_628;
    s = expr_ret_628;
    // ModExprList 1
    if (expr_ret_627) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_627
      ret = SUCC;
      #line 620 "daisho.peg"
      rule=list(FSTRFRAG); add(rule, s);
      #line 11818 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 2
    if (expr_ret_627) {
      daisho_astnode_t* expr_ret_629 = NULL;
      expr_ret_629 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_627 = expr_ret_629;
      x = expr_ret_629;
    }

    // ModExprList 3
    if (expr_ret_627) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_627
      ret = SUCC;
      #line 621 "daisho.peg"
      add(rule, x);
      #line 11841 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 4
    if (expr_ret_627) {
      daisho_astnode_t* expr_ret_630 = NULL;
      daisho_astnode_t* expr_ret_631 = SUCC;
      while (expr_ret_631)
      {
        rec(kleene_rew_630);
        daisho_astnode_t* expr_ret_632 = NULL;
        rec(mod_632);
        // ModExprList 0
        daisho_astnode_t* expr_ret_633 = NULL;
        intr_enter(ctx, "FSTRLITMID", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_633 = leaf(FSTRLITMID);
          expr_ret_633->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_633->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_633 = NULL;
        }

        if (expr_ret_633) intr_accept(ctx, "FSTRLITMID"); else intr_reject(ctx, "FSTRLITMID");
        expr_ret_632 = expr_ret_633;
        m = expr_ret_633;
        // ModExprList 1
        if (expr_ret_632) {
          daisho_astnode_t* expr_ret_634 = NULL;
          expr_ret_634 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_632 = expr_ret_634;
          x = expr_ret_634;
        }

        // ModExprList 2
        if (expr_ret_632) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_632
          ret = SUCC;
          #line 622 "daisho.peg"
          add(rule, m); add(rule, x);
          #line 11889 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_632) rew(mod_632);
        expr_ret_631 = expr_ret_632;
      }

      expr_ret_630 = SUCC;
      expr_ret_627 = expr_ret_630;
    }

    // ModExprList 5
    if (expr_ret_627) {
      daisho_astnode_t* expr_ret_635 = NULL;
      intr_enter(ctx, "FSTRLITEND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_635 = leaf(FSTRLITEND);
        expr_ret_635->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_635->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_635 = NULL;
      }

      if (expr_ret_635) intr_accept(ctx, "FSTRLITEND"); else intr_reject(ctx, "FSTRLITEND");
      expr_ret_627 = expr_ret_635;
      e = expr_ret_635;
    }

    // ModExprList 6
    if (expr_ret_627) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_627
      ret = SUCC;
      #line 623 "daisho.peg"
      add(rule, e);
      #line 11931 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_627) rew(mod_627);
    expr_ret_625 = expr_ret_627;
  }

  // SlashExpr end
  expr_ret_624 = expr_ret_625;

  if (!rule) rule = expr_ret_624;
  if (!expr_ret_624) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fstrfrag");
  else if (rule) intr_accept(ctx, "fstrfrag");
  else intr_reject(ctx, "fstrfrag");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_636
  daisho_astnode_t* expr_ret_636 = NULL;
  daisho_astnode_t* expr_ret_637 = NULL;
  intr_enter(ctx, "sizeofexpr", ctx->pos);
  daisho_astnode_t* expr_ret_638 = NULL;
  rec(mod_638);
  // ModExprList 0
  intr_enter(ctx, "SIZEOF", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_638 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_638 = NULL;
  }

  if (expr_ret_638) intr_accept(ctx, "SIZEOF"); else intr_reject(ctx, "SIZEOF");
  // ModExprList 1
  if (expr_ret_638) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_638 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_638 = NULL;
    }

    if (expr_ret_638) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 2
  if (expr_ret_638) {
    daisho_astnode_t* expr_ret_639 = NULL;
    daisho_astnode_t* expr_ret_640 = NULL;

    // SlashExpr 0
    if (!expr_ret_640) {
      daisho_astnode_t* expr_ret_641 = NULL;
      rec(mod_641);
      // ModExprList Forwarding
      expr_ret_641 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_641) rew(mod_641);
      expr_ret_640 = expr_ret_641;
    }

    // SlashExpr 1
    if (!expr_ret_640) {
      daisho_astnode_t* expr_ret_642 = NULL;
      rec(mod_642);
      // ModExprList Forwarding
      expr_ret_642 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_642) rew(mod_642);
      expr_ret_640 = expr_ret_642;
    }

    // SlashExpr end
    expr_ret_639 = expr_ret_640;

    expr_ret_638 = expr_ret_639;
    te = expr_ret_639;
  }

  // ModExprList 3
  if (expr_ret_638) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_638 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_638 = NULL;
    }

    if (expr_ret_638) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 4
  if (expr_ret_638) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_638
    ret = SUCC;
    #line 625 "daisho.peg"
    rule=node(SIZEOF, te);
    #line 12045 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_638) rew(mod_638);
  expr_ret_637 = expr_ret_638;
  if (!rule) rule = expr_ret_637;
  if (!expr_ret_637) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sizeofexpr");
  else if (rule) intr_accept(ctx, "sizeofexpr");
  else intr_reject(ctx, "sizeofexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_643
  daisho_astnode_t* expr_ret_643 = NULL;
  daisho_astnode_t* expr_ret_644 = NULL;
  intr_enter(ctx, "nativeexpr", ctx->pos);
  daisho_astnode_t* expr_ret_645 = NULL;
  rec(mod_645);
  // ModExprList 0
  intr_enter(ctx, "NATIVE", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVE) {
    // Not capturing NATIVE.
    expr_ret_645 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_645 = NULL;
  }

  if (expr_ret_645) intr_accept(ctx, "NATIVE"); else intr_reject(ctx, "NATIVE");
  // ModExprList 1
  if (expr_ret_645) {
    daisho_astnode_t* expr_ret_646 = NULL;
    intr_enter(ctx, "NATIVE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVE) {
      // Capturing NATIVE.
      expr_ret_646 = leaf(NATIVE);
      expr_ret_646->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_646->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_646 = NULL;
    }

    if (expr_ret_646) intr_accept(ctx, "NATIVE"); else intr_reject(ctx, "NATIVE");
    expr_ret_645 = expr_ret_646;
    rule = expr_ret_646;
  }

  // ModExprList end
  if (!expr_ret_645) rew(mod_645);
  expr_ret_644 = expr_ret_645;
  if (!rule) rule = expr_ret_644;
  if (!expr_ret_644) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nativeexpr");
  else if (rule) intr_accept(ctx, "nativeexpr");
  else intr_reject(ctx, "nativeexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_647
  daisho_astnode_t* expr_ret_647 = NULL;
  daisho_astnode_t* expr_ret_648 = NULL;
  intr_enter(ctx, "cident", ctx->pos);
  daisho_astnode_t* expr_ret_649 = NULL;
  rec(mod_649);
  // ModExprList 0
  daisho_astnode_t* expr_ret_650 = NULL;
  intr_enter(ctx, "VARIDENT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
    // Capturing VARIDENT.
    expr_ret_650 = leaf(VARIDENT);
    expr_ret_650->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_650->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_650 = NULL;
  }

  if (expr_ret_650) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
  expr_ret_649 = expr_ret_650;
  rule = expr_ret_650;
  // ModExprList 1
  if (expr_ret_649) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_649
    ret = SUCC;
    #line 667 "daisho.peg"
    
  for (size_t i = 0; i < rule->repr_len; i++) {
    codepoint_t c = rule->tok_repr[i];
    int acc = ((c >= 'A') & (c <= 'Z')) |
              ((c >= 'a') & (c <= 'z')) |
               (c == '_');
    if (i) acc |= ((c >= '0') & (c <= '9'));
    if (!acc) {
      ctx->pos--;
      WARNING("Not a valid C identifier.");
      ctx->pos++;
    }
  };
    #line 12157 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_649) rew(mod_649);
  expr_ret_648 = expr_ret_649;
  if (!rule) rule = expr_ret_648;
  if (!expr_ret_648) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "cident");
  else if (rule) intr_accept(ctx, "cident");
  else intr_reject(ctx, "cident");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_651
  daisho_astnode_t* expr_ret_651 = NULL;
  daisho_astnode_t* expr_ret_652 = NULL;
  intr_enter(ctx, "semiornl", ctx->pos);
  daisho_astnode_t* expr_ret_653 = NULL;

  // SlashExpr 0
  if (!expr_ret_653) {
    daisho_astnode_t* expr_ret_654 = NULL;
    rec(mod_654);
    // ModExprList Forwarding
    intr_enter(ctx, "SEMI", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_654 = leaf(SEMI);
      expr_ret_654->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_654->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_654 = NULL;
    }

    if (expr_ret_654) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
    // ModExprList end
    if (!expr_ret_654) rew(mod_654);
    expr_ret_653 = expr_ret_654;
  }

  // SlashExpr 1
  if (!expr_ret_653) {
    daisho_astnode_t* expr_ret_655 = NULL;
    rec(mod_655);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_655
    ret = SUCC;
    #line 682 "daisho.peg"
    ret = (ctx->pos >= ctx->len ||
                      ctx->tokens[ctx->pos - 1].line < ctx->tokens[ctx->pos].line)
                      ? leaf(SEMI)
                      : NULL;
    #line 12218 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_655) rew(mod_655);
    expr_ret_653 = expr_ret_655;
  }

  // SlashExpr end
  expr_ret_652 = expr_ret_653;

  if (!rule) rule = expr_ret_652;
  if (!expr_ret_652) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "semiornl");
  else if (rule) intr_accept(ctx, "semiornl");
  else intr_reject(ctx, "semiornl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx) {
  #define rule expr_ret_656
  daisho_astnode_t* expr_ret_656 = NULL;
  daisho_astnode_t* expr_ret_657 = NULL;
  intr_enter(ctx, "overloadable", ctx->pos);
  daisho_astnode_t* expr_ret_658 = NULL;

  // SlashExpr 0
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_659 = NULL;
    rec(mod_659);
    // ModExprList Forwarding
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_659 = leaf(VARIDENT);
      expr_ret_659->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_659->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_659 = NULL;
    }

    if (expr_ret_659) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    // ModExprList end
    if (!expr_ret_659) rew(mod_659);
    expr_ret_658 = expr_ret_659;
  }

  // SlashExpr 1
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_660 = NULL;
    rec(mod_660);
    // ModExprList Forwarding
    intr_enter(ctx, "PLUS", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
      // Capturing PLUS.
      expr_ret_660 = leaf(PLUS);
      expr_ret_660->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_660->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_660 = NULL;
    }

    if (expr_ret_660) intr_accept(ctx, "PLUS"); else intr_reject(ctx, "PLUS");
    // ModExprList end
    if (!expr_ret_660) rew(mod_660);
    expr_ret_658 = expr_ret_660;
  }

  // SlashExpr 2
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_661 = NULL;
    rec(mod_661);
    // ModExprList Forwarding
    intr_enter(ctx, "MINUS", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
      // Capturing MINUS.
      expr_ret_661 = leaf(MINUS);
      expr_ret_661->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_661->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_661 = NULL;
    }

    if (expr_ret_661) intr_accept(ctx, "MINUS"); else intr_reject(ctx, "MINUS");
    // ModExprList end
    if (!expr_ret_661) rew(mod_661);
    expr_ret_658 = expr_ret_661;
  }

  // SlashExpr 3
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_662 = NULL;
    rec(mod_662);
    // ModExprList Forwarding
    intr_enter(ctx, "STAR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
      // Capturing STAR.
      expr_ret_662 = leaf(STAR);
      expr_ret_662->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_662->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_662 = NULL;
    }

    if (expr_ret_662) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
    // ModExprList end
    if (!expr_ret_662) rew(mod_662);
    expr_ret_658 = expr_ret_662;
  }

  // SlashExpr 4
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_663 = NULL;
    rec(mod_663);
    // ModExprList Forwarding
    intr_enter(ctx, "POW", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
      // Capturing POW.
      expr_ret_663 = leaf(POW);
      expr_ret_663->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_663->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_663 = NULL;
    }

    if (expr_ret_663) intr_accept(ctx, "POW"); else intr_reject(ctx, "POW");
    // ModExprList end
    if (!expr_ret_663) rew(mod_663);
    expr_ret_658 = expr_ret_663;
  }

  // SlashExpr 5
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_664 = NULL;
    rec(mod_664);
    // ModExprList Forwarding
    intr_enter(ctx, "DIV", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
      // Capturing DIV.
      expr_ret_664 = leaf(DIV);
      expr_ret_664->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_664->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_664 = NULL;
    }

    if (expr_ret_664) intr_accept(ctx, "DIV"); else intr_reject(ctx, "DIV");
    // ModExprList end
    if (!expr_ret_664) rew(mod_664);
    expr_ret_658 = expr_ret_664;
  }

  // SlashExpr 6
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_665 = NULL;
    rec(mod_665);
    // ModExprList Forwarding
    intr_enter(ctx, "MOD", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
      // Capturing MOD.
      expr_ret_665 = leaf(MOD);
      expr_ret_665->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_665->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_665 = NULL;
    }

    if (expr_ret_665) intr_accept(ctx, "MOD"); else intr_reject(ctx, "MOD");
    // ModExprList end
    if (!expr_ret_665) rew(mod_665);
    expr_ret_658 = expr_ret_665;
  }

  // SlashExpr 7
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_666 = NULL;
    rec(mod_666);
    // ModExprList Forwarding
    intr_enter(ctx, "AND", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
      // Capturing AND.
      expr_ret_666 = leaf(AND);
      expr_ret_666->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_666->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_666 = NULL;
    }

    if (expr_ret_666) intr_accept(ctx, "AND"); else intr_reject(ctx, "AND");
    // ModExprList end
    if (!expr_ret_666) rew(mod_666);
    expr_ret_658 = expr_ret_666;
  }

  // SlashExpr 8
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_667 = NULL;
    rec(mod_667);
    // ModExprList Forwarding
    intr_enter(ctx, "OR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
      // Capturing OR.
      expr_ret_667 = leaf(OR);
      expr_ret_667->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_667->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_667 = NULL;
    }

    if (expr_ret_667) intr_accept(ctx, "OR"); else intr_reject(ctx, "OR");
    // ModExprList end
    if (!expr_ret_667) rew(mod_667);
    expr_ret_658 = expr_ret_667;
  }

  // SlashExpr 9
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_668 = NULL;
    rec(mod_668);
    // ModExprList Forwarding
    intr_enter(ctx, "XOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
      // Capturing XOR.
      expr_ret_668 = leaf(XOR);
      expr_ret_668->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_668->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_668 = NULL;
    }

    if (expr_ret_668) intr_accept(ctx, "XOR"); else intr_reject(ctx, "XOR");
    // ModExprList end
    if (!expr_ret_668) rew(mod_668);
    expr_ret_658 = expr_ret_668;
  }

  // SlashExpr 10
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_669 = NULL;
    rec(mod_669);
    // ModExprList Forwarding
    intr_enter(ctx, "EXCL", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
      // Capturing EXCL.
      expr_ret_669 = leaf(EXCL);
      expr_ret_669->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_669->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_669 = NULL;
    }

    if (expr_ret_669) intr_accept(ctx, "EXCL"); else intr_reject(ctx, "EXCL");
    // ModExprList end
    if (!expr_ret_669) rew(mod_669);
    expr_ret_658 = expr_ret_669;
  }

  // SlashExpr 11
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_670 = NULL;
    rec(mod_670);
    // ModExprList Forwarding
    intr_enter(ctx, "BITNOT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BITNOT) {
      // Capturing BITNOT.
      expr_ret_670 = leaf(BITNOT);
      expr_ret_670->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_670->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_670 = NULL;
    }

    if (expr_ret_670) intr_accept(ctx, "BITNOT"); else intr_reject(ctx, "BITNOT");
    // ModExprList end
    if (!expr_ret_670) rew(mod_670);
    expr_ret_658 = expr_ret_670;
  }

  // SlashExpr 12
  if (!expr_ret_658) {
    daisho_astnode_t* expr_ret_671 = NULL;
    rec(mod_671);
    // ModExprList end
    if (!expr_ret_671) rew(mod_671);
    expr_ret_658 = expr_ret_671;
  }

  // SlashExpr end
  expr_ret_657 = expr_ret_658;

  if (!rule) rule = expr_ret_657;
  if (!expr_ret_657) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "overloadable");
  else if (rule) intr_accept(ctx, "overloadable");
  else intr_reject(ctx, "overloadable");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_672
  daisho_astnode_t* expr_ret_672 = NULL;
  daisho_astnode_t* expr_ret_673 = NULL;
  intr_enter(ctx, "wexpr", ctx->pos);
  daisho_astnode_t* expr_ret_674 = NULL;
  rec(mod_674);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_675 = NULL;

  // SlashExpr 0
  if (!expr_ret_675) {
    daisho_astnode_t* expr_ret_676 = NULL;
    rec(mod_676);
    // ModExprList Forwarding
    expr_ret_676 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_676) rew(mod_676);
    expr_ret_675 = expr_ret_676;
  }

  // SlashExpr 1
  if (!expr_ret_675) {
    daisho_astnode_t* expr_ret_677 = NULL;
    rec(mod_677);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_677
    ret = SUCC;
    #line 745 "daisho.peg"
    WARNING("Missing expression."); ret=leaf(RECOVERY);
    #line 12564 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_677) rew(mod_677);
    expr_ret_675 = expr_ret_677;
  }

  // SlashExpr end
  expr_ret_674 = expr_ret_675;

  // ModExprList end
  if (!expr_ret_674) rew(mod_674);
  expr_ret_673 = expr_ret_674;
  if (!rule) rule = expr_ret_673;
  if (!expr_ret_673) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wexpr");
  else if (rule) intr_accept(ctx, "wexpr");
  else intr_reject(ctx, "wexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_678
  daisho_astnode_t* expr_ret_678 = NULL;
  daisho_astnode_t* expr_ret_679 = NULL;
  intr_enter(ctx, "noexpr", ctx->pos);
  daisho_astnode_t* expr_ret_680 = NULL;
  rec(mod_680);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_681 = NULL;
  rec(mod_681);
  // ModExprList 0
  daisho_astnode_t* expr_ret_682 = NULL;
  expr_ret_682 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_681 = expr_ret_682;
  e = expr_ret_682;
  // ModExprList 1
  if (expr_ret_681) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_681
    ret = SUCC;
    #line 746 "daisho.peg"
    WARNING("Extra expression."); ret=e;
    #line 12613 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_681) rew(mod_681);
  expr_ret_680 = expr_ret_681;
  // ModExprList end
  if (!expr_ret_680) rew(mod_680);
  expr_ret_679 = expr_ret_680;
  if (!rule) rule = expr_ret_679;
  if (!expr_ret_679) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "noexpr");
  else if (rule) intr_accept(ctx, "noexpr");
  else intr_reject(ctx, "noexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_683
  daisho_astnode_t* expr_ret_683 = NULL;
  daisho_astnode_t* expr_ret_684 = NULL;
  intr_enter(ctx, "wcomma", ctx->pos);
  daisho_astnode_t* expr_ret_685 = NULL;
  rec(mod_685);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_686 = NULL;

  // SlashExpr 0
  if (!expr_ret_686) {
    daisho_astnode_t* expr_ret_687 = NULL;
    rec(mod_687);
    // ModExprList Forwarding
    intr_enter(ctx, "COMMA", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_687 = leaf(COMMA);
      expr_ret_687->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_687->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_687 = NULL;
    }

    if (expr_ret_687) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    // ModExprList end
    if (!expr_ret_687) rew(mod_687);
    expr_ret_686 = expr_ret_687;
  }

  // SlashExpr 1
  if (!expr_ret_686) {
    daisho_astnode_t* expr_ret_688 = NULL;
    rec(mod_688);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_688
    ret = SUCC;
    #line 747 "daisho.peg"
    WARNING("Missing comma."); ret=leaf(COMMA);
    #line 12677 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_688) rew(mod_688);
    expr_ret_686 = expr_ret_688;
  }

  // SlashExpr end
  expr_ret_685 = expr_ret_686;

  // ModExprList end
  if (!expr_ret_685) rew(mod_685);
  expr_ret_684 = expr_ret_685;
  if (!rule) rule = expr_ret_684;
  if (!expr_ret_684) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wcomma");
  else if (rule) intr_accept(ctx, "wcomma");
  else intr_reject(ctx, "wcomma");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_689
  daisho_astnode_t* expr_ret_689 = NULL;
  daisho_astnode_t* expr_ret_690 = NULL;
  intr_enter(ctx, "nocomma", ctx->pos);
  daisho_astnode_t* expr_ret_691 = NULL;
  rec(mod_691);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_692 = NULL;
  rec(mod_692);
  // ModExprList 0
  daisho_astnode_t* expr_ret_693 = NULL;
  intr_enter(ctx, "COMMA", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_693 = leaf(COMMA);
    expr_ret_693->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_693->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_693 = NULL;
  }

  if (expr_ret_693) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
  expr_ret_692 = expr_ret_693;
  c = expr_ret_693;
  // ModExprList 1
  if (expr_ret_692) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_692
    ret = SUCC;
    #line 748 "daisho.peg"
    WARNING("Extra comma."); ret=c;
    #line 12736 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_692) rew(mod_692);
  expr_ret_691 = expr_ret_692;
  // ModExprList end
  if (!expr_ret_691) rew(mod_691);
  expr_ret_690 = expr_ret_691;
  if (!rule) rule = expr_ret_690;
  if (!expr_ret_690) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nocomma");
  else if (rule) intr_accept(ctx, "nocomma");
  else intr_reject(ctx, "nocomma");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_694
  daisho_astnode_t* expr_ret_694 = NULL;
  daisho_astnode_t* expr_ret_695 = NULL;
  intr_enter(ctx, "wsemi", ctx->pos);
  daisho_astnode_t* expr_ret_696 = NULL;
  rec(mod_696);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_697 = NULL;

  // SlashExpr 0
  if (!expr_ret_697) {
    daisho_astnode_t* expr_ret_698 = NULL;
    rec(mod_698);
    // ModExprList Forwarding
    intr_enter(ctx, "SEMI", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_698 = leaf(SEMI);
      expr_ret_698->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_698->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_698 = NULL;
    }

    if (expr_ret_698) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
    // ModExprList end
    if (!expr_ret_698) rew(mod_698);
    expr_ret_697 = expr_ret_698;
  }

  // SlashExpr 1
  if (!expr_ret_697) {
    daisho_astnode_t* expr_ret_699 = NULL;
    rec(mod_699);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_699
    ret = SUCC;
    #line 749 "daisho.peg"
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #line 12800 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_699) rew(mod_699);
    expr_ret_697 = expr_ret_699;
  }

  // SlashExpr end
  expr_ret_696 = expr_ret_697;

  // ModExprList end
  if (!expr_ret_696) rew(mod_696);
  expr_ret_695 = expr_ret_696;
  if (!rule) rule = expr_ret_695;
  if (!expr_ret_695) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wsemi");
  else if (rule) intr_accept(ctx, "wsemi");
  else intr_reject(ctx, "wsemi");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_700
  daisho_astnode_t* expr_ret_700 = NULL;
  daisho_astnode_t* expr_ret_701 = NULL;
  intr_enter(ctx, "nosemi", ctx->pos);
  daisho_astnode_t* expr_ret_702 = NULL;
  rec(mod_702);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_703 = NULL;
  rec(mod_703);
  // ModExprList 0
  daisho_astnode_t* expr_ret_704 = NULL;
  intr_enter(ctx, "SEMI", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_704 = leaf(SEMI);
    expr_ret_704->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_704->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_704 = NULL;
  }

  if (expr_ret_704) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
  expr_ret_703 = expr_ret_704;
  s = expr_ret_704;
  // ModExprList 1
  if (expr_ret_703) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_703
    ret = SUCC;
    #line 750 "daisho.peg"
    WARNING("Extra semicolon."); ret=s;
    #line 12859 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_703) rew(mod_703);
  expr_ret_702 = expr_ret_703;
  // ModExprList end
  if (!expr_ret_702) rew(mod_702);
  expr_ret_701 = expr_ret_702;
  if (!rule) rule = expr_ret_701;
  if (!expr_ret_701) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nosemi");
  else if (rule) intr_accept(ctx, "nosemi");
  else intr_reject(ctx, "nosemi");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_705
  daisho_astnode_t* expr_ret_705 = NULL;
  daisho_astnode_t* expr_ret_706 = NULL;
  intr_enter(ctx, "wsemiornl", ctx->pos);
  daisho_astnode_t* expr_ret_707 = NULL;
  rec(mod_707);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_708 = NULL;

  // SlashExpr 0
  if (!expr_ret_708) {
    daisho_astnode_t* expr_ret_709 = NULL;
    rec(mod_709);
    // ModExprList Forwarding
    expr_ret_709 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_709) rew(mod_709);
    expr_ret_708 = expr_ret_709;
  }

  // SlashExpr 1
  if (!expr_ret_708) {
    daisho_astnode_t* expr_ret_710 = NULL;
    rec(mod_710);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_710
    ret = SUCC;
    #line 751 "daisho.peg"
    WARNING("Missing semicolon or newline."); ret=leaf(SEMI);
    #line 12913 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_710) rew(mod_710);
    expr_ret_708 = expr_ret_710;
  }

  // SlashExpr end
  expr_ret_707 = expr_ret_708;

  // ModExprList end
  if (!expr_ret_707) rew(mod_707);
  expr_ret_706 = expr_ret_707;
  if (!rule) rule = expr_ret_706;
  if (!expr_ret_706) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wsemiornl");
  else if (rule) intr_accept(ctx, "wsemiornl");
  else intr_reject(ctx, "wsemiornl");
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
#undef expect
#undef repr
#undef srepr
#undef cprepr
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

#undef LB
#undef RB

#undef INFO
#undef INFO_F
#undef WARNING
#undef WARNING_F
#undef ERROR
#undef ERROR_F
#undef FATAL
#undef FATAL_F
#endif /* PGEN_DAISHO_ASTNODE_INCLUDE */

