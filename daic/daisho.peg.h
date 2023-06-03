#ifndef PGEN_DAISHO_PARSER_H
#define PGEN_DAISHO_PARSER_H


/* START OF UTF8 LIBRARY */

#ifndef UTF8_INCLUDED
#define UTF8_INCLUDED
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>

#define UTF8_END -1 /* 1111 1111 */
#define UTF8_ERR -2 /* 1111 1110 */

#ifndef UTF8_MALLOC
#define UTF8_MALLOC malloc
#endif

#ifndef UTF8_FREE
#define UTF8_FREE free
#endif

typedef int32_t codepoint_t;
#define PRI_CODEPOINT PRIu32

typedef struct {
  char *start;
  size_t pos;
  size_t len;
} UTF8Decoder;

static inline void UTF8_decoder_init(UTF8Decoder *state, char *str,
                                     size_t len) {
  state->start = str;
  state->pos = 0;
  state->len = len;
}

static inline char UTF8_nextByte(UTF8Decoder *state) {
  char c;
  if (state->pos >= state->len)
    return UTF8_END;
  c = state->start[state->pos++];
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

  if (state->pos >= state->len)
    return state->pos == state->len ? UTF8_END : UTF8_ERR;

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
 * This will UTF8_MALLOC() a buffer large enough, and store it to retstr and its
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
  if (!(out_buf = (char *)UTF8_MALLOC(len * sizeof(codepoint_t) + 1)))
    return 0;

  characters_used = 0;
  for (i = 0; i < len; i++) {
    if (!(used = UTF8_encodeNext(codepoints[i], buf4)))
      return UTF8_FREE(out_buf), 0;
    for (j = 0; j < used; j++)
      out_buf[characters_used++] = buf4[j];
  }

  out_buf[characters_used] = '\0';
  *retstr = out_buf;
  *retlen = characters_used;
  return 1;
}

/*
 * Convert a UTF8 string to UTF32 codepoints.
 * This will UTF8_MALLOC() a buffer large enough, and store it to retstr and its
 * length to retcps. The result is not null terminated.
 * Returns 1 on success, 0 on failure. Cleans up the buffer and does not store
 * to retcps or retlen on failure.
 * Also, if map is not null, UTF8_MALLOC()s and a pointer to a list of the
 * position of the beginning of each utf8 codepoint in str to map. There are
 * retlen many of them. Cleans up and does not store the list to map on failure.
 */
static inline int UTF8_decode_map(char *str, size_t len, codepoint_t **retcps,
                                  size_t *retlen, size_t **map) {

  UTF8Decoder state;
  codepoint_t *cpbuf, cp;
  size_t cps_read = 0;

  if ((!str) | (!len))
    return 0;
  if (!(cpbuf = (codepoint_t *)UTF8_MALLOC(sizeof(codepoint_t) * len)))
    return 0;

  size_t *mapbuf = NULL;
  if (map) {
    mapbuf = (size_t *)UTF8_MALLOC(sizeof(size_t) * len);
    if (!mapbuf) {
      free(cpbuf);
      return 0;
    }
  }

  UTF8_decoder_init(&state, str, len);
  for (;;) {
    size_t prepos = state.pos;
    cp = UTF8_decodeNext(&state);
    if ((cp == UTF8_ERR) | (cp == UTF8_END))
      break;
    if (mapbuf)
      mapbuf[cps_read] = prepos;
    cpbuf[cps_read] = cp;
    cps_read++;
  }

  if (cp == UTF8_ERR) {
    UTF8_FREE(cpbuf);
    if (mapbuf)
      UTF8_FREE(mapbuf);
    return 0;
  }

  if (mapbuf)
    *map = mapbuf;
  *retcps = cpbuf;
  *retlen = cps_read;
  return 1;
}

/*
 * Convert a UTF8 string to UTF32 codepoints.
 * This will UTF8_MALLOC() a buffer large enough, and store it to retstr and its
 * length to retcps. The result is not null terminated.
 * Returns 1 on success, 0 on failure. Cleans up the buffer and does not store
 * to retcps or retlen on failure.
 */
static inline int UTF8_decode(char *str, size_t len, codepoint_t **retcps,
                              size_t *retlen) {
  return UTF8_decode_map(str, len, retcps, retlen, NULL);
}

#endif /* UTF8_INCLUDED */

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
#define PGEN_NUM_ARENAS 256
#define PGEN_NUM_FREELIST 256

#ifndef PGEN_PAGESIZE
#define PGEN_PAGESIZE 4096
#endif

#ifndef PGEN_MALLOC
#define PGEN_MALLOC malloc
#endif

#ifndef PGEN_FREE
#define PGEN_FREE free
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

  alloc.freelist.entries = (pgen_freelist_entry_t *)PGEN_MALLOC(
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
        char *nb = (char *)PGEN_MALLOC(PGEN_BUFFER_SIZE);
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
#include "types.h"
#endif
struct PreMonoSymtab;
typedef struct PreMonoSymtab PreMonoSymtab;
struct PreExprType;
typedef struct PreExprType PreExprType;
struct InputFile;
typedef struct InputFile InputFile;

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
  DAISHO_TOK_NATIVEBODY,
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
  DAISHO_TOK_INCLUDE,
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
  DAISHO_TOK_INCLUDEPATH,
  DAISHO_TOK_WS,
  DAISHO_TOK_MLCOM,
  DAISHO_TOK_SLCOM,
  DAISHO_TOK_SHEBANG,
} daisho_token_kind;

// The 0th token is beginning of stream.
// The 1st token isend of stream.
// Tokens 1 through 93 are the ones you defined.
// This totals 95 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 95
static const char* daisho_tokenkind_name[DAISHO_NUM_TOKENKINDS] = {
  "STREAMBEGIN",
  "STREAMEND",
  "NATIVEBODY",
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
  "INCLUDE",
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
  "INCLUDEPATH",
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
  // Extra fields from %tokenextra directives:
  InputFile* from_file;
  size_t from_pos;
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
  int smaut_state_18 = 0;
  int smaut_state_19 = 0;
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
  size_t smaut_munch_size_18 = 0;
  size_t smaut_munch_size_19 = 0;
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
         (c == 'c')) {
          smaut_state_0 = 1;
      }
      else if ((smaut_state_0 == 1) &
         (c == 'l')) {
          smaut_state_0 = 2;
      }
      else if ((smaut_state_0 == 2) &
         (c == 'a')) {
          smaut_state_0 = 3;
      }
      else if ((smaut_state_0 == 3) &
         (c == 's')) {
          smaut_state_0 = 4;
      }
      else if ((smaut_state_0 == 4) &
         (c == 's')) {
          smaut_state_0 = 5;
      }
      else if ((smaut_state_0 == 0) &
         (c == 's')) {
          smaut_state_0 = 6;
      }
      else if ((smaut_state_0 == 6) &
         (c == 't')) {
          smaut_state_0 = 7;
      }
      else if ((smaut_state_0 == 7) &
         (c == 'r')) {
          smaut_state_0 = 8;
      }
      else if ((smaut_state_0 == 8) &
         (c == 'u')) {
          smaut_state_0 = 9;
      }
      else if ((smaut_state_0 == 9) &
         (c == 'c')) {
          smaut_state_0 = 10;
      }
      else if ((smaut_state_0 == 10) &
         (c == 't')) {
          smaut_state_0 = 11;
      }
      else if ((smaut_state_0 == 0) &
         (c == 't')) {
          smaut_state_0 = 13;
      }
      else if ((smaut_state_0 == 13) &
         (c == 'y')) {
          smaut_state_0 = 14;
      }
      else if ((smaut_state_0 == 14) &
         (c == 'p')) {
          smaut_state_0 = 15;
      }
      else if ((smaut_state_0 == 15) &
         (c == 'e')) {
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
         (c == 'i')) {
          smaut_state_1 = 1;
      }
      else if ((smaut_state_1 == 1) &
         (c == 'm')) {
          smaut_state_1 = 2;
      }
      else if ((smaut_state_1 == 2) &
         (c == 'p')) {
          smaut_state_1 = 3;
      }
      else if ((smaut_state_1 == 3) &
         (c == 'l')) {
          smaut_state_1 = 4;
      }
      else if ((smaut_state_1 == 4) &
         (c == 'e')) {
          smaut_state_1 = 5;
      }
      else if ((smaut_state_1 == 4) &
         (c == 'i')) {
          smaut_state_1 = 5;
      }
      else if ((smaut_state_1 == 5) &
         (c == 'm')) {
          smaut_state_1 = 6;
      }
      else if ((smaut_state_1 == 6) &
         (c == 'e')) {
          smaut_state_1 = 7;
      }
      else if ((smaut_state_1 == 7) &
         (c == 'n')) {
          smaut_state_1 = 8;
      }
      else if ((smaut_state_1 == 8) &
         (c == 't')) {
          smaut_state_1 = 9;
      }
      else if ((smaut_state_1 == 9) &
         (c == 's')) {
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
         (c == 'n')) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 'a')) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 't')) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 'i')) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 'v')) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 'e')) {
          smaut_state_2 = 6;
      }
      else if ((smaut_state_2 == 0) &
         (c == 'c')) {
          smaut_state_2 = 7;
      }
      else if ((smaut_state_2 == 7) &
         (c == 'c')) {
          smaut_state_2 = 8;
      }
      else if ((smaut_state_2 == 8) &
         (c == 'o')) {
          smaut_state_2 = 9;
      }
      else if ((smaut_state_2 == 9) &
         (c == 'd')) {
          smaut_state_2 = 10;
      }
      else if ((smaut_state_2 == 10) &
         (c == 'e')) {
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

    // Transition INCLUDE State Machine
    if (smaut_state_3 != -1) {
      all_dead = 0;

      if ((smaut_state_3 == 0) &
         (c == '#')) {
          smaut_state_3 = 0;
      }
      else if ((smaut_state_3 == 0) &
         (c == 'i')) {
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 1) &
         (c == 'n')) {
          smaut_state_3 = 2;
      }
      else if ((smaut_state_3 == 2) &
         (c == 'c')) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 'l')) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 'u')) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 5) &
         (c == 'd')) {
          smaut_state_3 = 6;
      }
      else if ((smaut_state_3 == 6) &
         (c == 'e')) {
          smaut_state_3 = 7;
      }
      else if ((smaut_state_3 == 1) &
         (c == 'm')) {
          smaut_state_3 = 8;
      }
      else if ((smaut_state_3 == 8) &
         (c == 'p')) {
          smaut_state_3 = 9;
      }
      else if ((smaut_state_3 == 9) &
         (c == 'o')) {
          smaut_state_3 = 10;
      }
      else if ((smaut_state_3 == 10) &
         (c == 'r')) {
          smaut_state_3 = 11;
      }
      else if ((smaut_state_3 == 11) &
         (c == 't')) {
          smaut_state_3 = 12;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 7) | (smaut_state_3 == 12)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition RET State Machine
    if (smaut_state_4 != -1) {
      all_dead = 0;

      if ((smaut_state_4 == 0) &
         (c == 'r')) {
          smaut_state_4 = 1;
      }
      else if ((smaut_state_4 == 1) &
         (c == 'e')) {
          smaut_state_4 = 2;
      }
      else if ((smaut_state_4 == 2) &
         (c == 't')) {
          smaut_state_4 = 3;
      }
      else if ((smaut_state_4 == 3) &
         (c == 'u')) {
          smaut_state_4 = 4;
      }
      else if ((smaut_state_4 == 4) &
         (c == 'r')) {
          smaut_state_4 = 5;
      }
      else if ((smaut_state_4 == 5) &
         (c == 'n')) {
          smaut_state_4 = 6;
      }
      else {
        smaut_state_4 = -1;
      }

      // Check accept
      if ((smaut_state_4 == 3) | (smaut_state_4 == 6)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition OP State Machine
    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         (c == 'o')) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 1) &
         (c == 'p')) {
          smaut_state_5 = 2;
      }
      else if ((smaut_state_5 == 2) &
         (c == 'e')) {
          smaut_state_5 = 3;
      }
      else if ((smaut_state_5 == 3) &
         (c == 'r')) {
          smaut_state_5 = 4;
      }
      else if ((smaut_state_5 == 4) &
         (c == 'a')) {
          smaut_state_5 = 5;
      }
      else if ((smaut_state_5 == 5) &
         (c == 't')) {
          smaut_state_5 = 6;
      }
      else if ((smaut_state_5 == 6) &
         (c == 'o')) {
          smaut_state_5 = 7;
      }
      else if ((smaut_state_5 == 7) &
         (c == 'r')) {
          smaut_state_5 = 8;
      }
      else {
        smaut_state_5 = -1;
      }

      // Check accept
      if ((smaut_state_5 == 2) | (smaut_state_5 == 8)) {
        smaut_munch_size_5 = iidx + 1;
      }
    }

    // Transition REDEF State Machine
    if (smaut_state_6 != -1) {
      all_dead = 0;

      if ((smaut_state_6 == 0) &
         (c == 'r')) {
          smaut_state_6 = 1;
      }
      else if ((smaut_state_6 == 1) &
         (c == 'e')) {
          smaut_state_6 = 2;
      }
      else if ((smaut_state_6 == 2) &
         (c == 'd')) {
          smaut_state_6 = 3;
      }
      else if ((smaut_state_6 == 3) &
         (c == 'e')) {
          smaut_state_6 = 4;
      }
      else if ((smaut_state_6 == 4) &
         (c == 'f')) {
          smaut_state_6 = 5;
      }
      else if ((smaut_state_6 == 5) &
         (c == 'i')) {
          smaut_state_6 = 6;
      }
      else if ((smaut_state_6 == 6) &
         (c == 'n')) {
          smaut_state_6 = 7;
      }
      else if ((smaut_state_6 == 7) &
         (c == 'e')) {
          smaut_state_6 = 8;
      }
      else {
        smaut_state_6 = -1;
      }

      // Check accept
      if ((smaut_state_6 == 5) | (smaut_state_6 == 8)) {
        smaut_munch_size_6 = iidx + 1;
      }
    }

    // Transition TYPEIDENT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         ((c >= 'A') & (c <= 'Z'))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         ((c == '_') | ((c >= 'a') & (c <= 'z')) | ((c >= 'A') & (c <= 'Z')) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= '0') & (c <= '9')))) {
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

    // Transition VARIDENT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         ((c == '_') | ((c >= 'a') & (c <= 'z')) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         ((c == '_') | ((c >= 'a') & (c <= 'z')) | ((c >= 'A') & (c <= 'Z')) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= '0') & (c <= '9')))) {
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
         ((c == '-') | (c == '+'))) {
          smaut_state_9 = 1;
      }
      else if (((smaut_state_9 >= 0) & (smaut_state_9 <= 2)) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 2) &
         (c == '.')) {
          smaut_state_9 = 3;
      }
      else if ((smaut_state_9 == 3) &
         ((c >= '0') & (c <= '9'))) {
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
         (c == '\"')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 1) &
         (c == '\"')) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 1) &
         (c == '{')) {
          smaut_state_10 = -1;
      }
      else if ((smaut_state_10 == 1) &
         (c == '\n')) {
          smaut_state_10 = -1;
      }
      else if ((smaut_state_10 == 1) &
         (c == '\\')) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 1) &
         (1)) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 'n')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 'f')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 'b')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 'r')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 't')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == 'e')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == '\\')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == '\'')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == '\"')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == '{')) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 3) &
         (c == '}')) {
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

    // Transition FSTRLITSTART State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == '\"')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == '{')) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 1) &
         (c == '\"')) {
          smaut_state_11 = -1;
      }
      else if ((smaut_state_11 == 1) &
         (c == '\n')) {
          smaut_state_11 = -1;
      }
      else if ((smaut_state_11 == 1) &
         (c == '\\')) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 1) &
         (1)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 'n')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 'f')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 'b')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 'r')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 't')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == 'e')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == '\\')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == '\'')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == '\"')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == '{')) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 3) &
         (c == '}')) {
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

    // Transition FSTRLITMID State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == '}')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == '{')) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 1) &
         (c == '\"')) {
          smaut_state_12 = -1;
      }
      else if ((smaut_state_12 == 1) &
         (c == '\n')) {
          smaut_state_12 = -1;
      }
      else if ((smaut_state_12 == 1) &
         (c == '\\')) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 1) &
         (1)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'n')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'f')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'b')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'r')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 't')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'e')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == '\\')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == '\'')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == '\"')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == '{')) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 3) &
         (c == '}')) {
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

    // Transition FSTRLITEND State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == '}')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == '\"')) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 1) &
         (c == '{')) {
          smaut_state_13 = -1;
      }
      else if ((smaut_state_13 == 1) &
         (c == '\n')) {
          smaut_state_13 = -1;
      }
      else if ((smaut_state_13 == 1) &
         (c == '\\')) {
          smaut_state_13 = 3;
      }
      else if ((smaut_state_13 == 1) &
         (1)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 'n')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 'f')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 'b')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 'r')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 't')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 'e')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == '\\')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == '\'')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == '\"')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == '{')) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == '}')) {
          smaut_state_13 = 1;
      }
      else {
        smaut_state_13 = -1;
      }

      // Check accept
      if (smaut_state_13 == 2) {
        smaut_munch_size_13 = iidx + 1;
      }
    }

    // Transition CHARLIT State Machine
    if (smaut_state_14 != -1) {
      all_dead = 0;

      if ((smaut_state_14 == 0) &
         (c == '\'')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 1) &
         (c == '\n')) {
          smaut_state_14 = -1;
      }
      else if ((smaut_state_14 == 1) &
         (c == '\\')) {
          smaut_state_14 = 4;
      }
      else if ((smaut_state_14 == 1) &
         (1)) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 'n')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 'f')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 'b')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 'r')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 't')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == 'e')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == '\\')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 4) &
         (c == '\'')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 2) &
         (c == '\'')) {
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

    // Transition INCLUDEPATH State Machine
    if (smaut_state_15 != -1) {
      all_dead = 0;

      if ((smaut_state_15 == 0) &
         (c == '<')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 1) &
         (c == '>')) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 1) &
         (c == '{')) {
          smaut_state_15 = -1;
      }
      else if ((smaut_state_15 == 1) &
         (c == '\n')) {
          smaut_state_15 = -1;
      }
      else if ((smaut_state_15 == 1) &
         (c == '\\')) {
          smaut_state_15 = 3;
      }
      else if ((smaut_state_15 == 1) &
         (1)) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 'n')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 'f')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 'b')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 'r')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 't')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == 'e')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == '\\')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == '\'')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == '\"')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == '{')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 3) &
         (c == '}')) {
          smaut_state_15 = 1;
      }
      else {
        smaut_state_15 = -1;
      }

      // Check accept
      if (smaut_state_15 == 2) {
        smaut_munch_size_15 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_16 != -1) {
      all_dead = 0;

      if (((smaut_state_16 == 0) | (smaut_state_16 == 1)) &
         ((c == 32) | (c == '\n') | (c == 13) | (c == 9))) {
          smaut_state_16 = 1;
      }
      else {
        smaut_state_16 = -1;
      }

      // Check accept
      if (smaut_state_16 == 1) {
        smaut_munch_size_16 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_17 != -1) {
      all_dead = 0;

      if ((smaut_state_17 == 0) &
         (c == '/')) {
          smaut_state_17 = 1;
      }
      else if ((smaut_state_17 == 1) &
         (c == '*')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 2) &
         (c == '*')) {
          smaut_state_17 = 3;
      }
      else if ((smaut_state_17 == 2) &
         (1)) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 3) &
         (c == '*')) {
          smaut_state_17 = 3;
      }
      else if ((smaut_state_17 == 3) &
         (c == '/')) {
          smaut_state_17 = 4;
      }
      else if ((smaut_state_17 == 3) &
         (1)) {
          smaut_state_17 = 2;
      }
      else {
        smaut_state_17 = -1;
      }

      // Check accept
      if (smaut_state_17 == 4) {
        smaut_munch_size_17 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_18 != -1) {
      all_dead = 0;

      if ((smaut_state_18 == 0) &
         (c == '/')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 1) &
         (c == '/')) {
          smaut_state_18 = 2;
      }
      else if ((smaut_state_18 == 2) &
         (!(c == '\n'))) {
          smaut_state_18 = 2;
      }
      else if ((smaut_state_18 == 2) &
         (c == '\n')) {
          smaut_state_18 = 3;
      }
      else {
        smaut_state_18 = -1;
      }

      // Check accept
      if ((smaut_state_18 == 2) | (smaut_state_18 == 3)) {
        smaut_munch_size_18 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_19 != -1) {
      all_dead = 0;

      if ((smaut_state_19 == 0) &
         (c == '#')) {
          smaut_state_19 = 1;
      }
      else if ((smaut_state_19 == 1) &
         (c == '!')) {
          smaut_state_19 = 2;
      }
      else if ((smaut_state_19 == 2) &
         (!(c == '\n'))) {
          smaut_state_19 = 2;
      }
      else if ((smaut_state_19 == 2) &
         (c == '\n')) {
          smaut_state_19 = 3;
      }
      else {
        smaut_state_19 = -1;
      }

      // Check accept
      if (smaut_state_19 == 3) {
        smaut_munch_size_19 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_19 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_19;
  }
  if (smaut_munch_size_18 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_18;
  }
  if (smaut_munch_size_17 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_17;
  }
  if (smaut_munch_size_16 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_16;
  }
  if (smaut_munch_size_15 >= max_munch) {
    kind = DAISHO_TOK_INCLUDEPATH;
    max_munch = smaut_munch_size_15;
  }
  if (smaut_munch_size_14 >= max_munch) {
    kind = DAISHO_TOK_CHARLIT;
    max_munch = smaut_munch_size_14;
  }
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITEND;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITMID;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITSTART;
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
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_TYPEIDENT;
    max_munch = smaut_munch_size_7;
  }
  if (smaut_munch_size_6 >= max_munch) {
    kind = DAISHO_TOK_REDEF;
    max_munch = smaut_munch_size_6;
  }
  if (smaut_munch_size_5 >= max_munch) {
    kind = DAISHO_TOK_OP;
    max_munch = smaut_munch_size_5;
  }
  if (smaut_munch_size_4 >= max_munch) {
    kind = DAISHO_TOK_RET;
    max_munch = smaut_munch_size_4;
  }
  if (smaut_munch_size_3 >= max_munch) {
    kind = DAISHO_TOK_INCLUDE;
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

  daisho_token tok;
  tok.kind = kind;
  tok.content = tokenizer->start + tokenizer->pos;
  tok.len = max_munch;

  tok.line = tokenizer->pos_line;
  tok.col = tokenizer->pos_col;

  for (size_t i = 0; i < tok.len; i++) {
    if (current[i] == '\n') {
      tokenizer->pos_line++;
      tokenizer->pos_col = 0;
    } else {
      tokenizer->pos_col++;
    }
  }

  tokenizer->pos += max_munch;
  return tok;
}

#endif /* DAISHO_TOKENIZER_INCLUDE */

#ifndef PGEN_DAISHO_ASTNODE_INCLUDE
#define PGEN_DAISHO_ASTNODE_INCLUDE

struct daisho_parse_err;
typedef struct daisho_parse_err daisho_parse_err;
struct daisho_parse_err {
  const char* msg;
  InputFile* from_file;
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
  PGEN_FREE((void*)msg);
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
  size_t toknum = ctx->pos + (ctx->pos != ctx->len - 1);
  daisho_token tok = ctx->tokens[toknum];
  err->line = tok.line;
  err->col = tok.col;

  err->from_file = tok.from_file;
  if (severity == 3)
    ctx->exit = 1;
  return err;
}

typedef enum {
  DAISHO_NODE_NATIVEBODY,
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
  DAISHO_NODE_INCLUDE,
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
  DAISHO_NODE_INCLUDEPATH,
  DAISHO_NODE_WS,
  DAISHO_NODE_MLCOM,
  DAISHO_NODE_SLCOM,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_BASETYPE,
  DAISHO_NODE_CURRENT_NS,
  DAISHO_NODE_NSACCESS,
  DAISHO_NODE_BOOL,
  DAISHO_NODE_ITER,
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
  DAISHO_NODE_ARRAYACCESS,
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

#define DAISHO_NUM_NODEKINDS 141
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "NATIVEBODY",
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
  "INCLUDE",
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
  "INCLUDEPATH",
  "WS",
  "MLCOM",
  "SLCOM",
  "SHEBANG",
  "BASETYPE",
  "CURRENT_NS",
  "NSACCESS",
  "BOOL",
  "ITER",
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
  "ARRAYACCESS",
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
    children = (daisho_astnode_t**)PGEN_MALLOC(sizeof(daisho_astnode_t*) * initial_size);
    if (!children) PGEN_OOM();
    pgen_defer(alloc, PGEN_FREE, children, alloc->rew);
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
        else if (utf8[i] == '"') fputc('\\', stdout), fputc(utf8[i], stdout);
        else fputc(utf8[i], stdout);
      return PGEN_FREE(utf8), 1;
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
  if (node)    daisho_astnode_print_h(tokens, node, 0, 1);
  else    puts("The AST is null.");}

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
#include "../stdlib/Daisho.h"
static inline int cpstr_equals(codepoint_t* s1, size_t l1, codepoint_t* s2, size_t l2) {
if (l1 != l2) return 0;
if (s1 == s2) return 1;
for (size_t i = 0; i < l1; i++)
if (s1[i] != s2[i]) return 0;
return 1;
}
#define boolconv(expr)                                                                               daisho_astnode_fixed_3(ctx->alloc, DAISHO_NODE_CALL, repr(leaf(BOOL), expr), leaf(NOEXPAND),                            daisho_astnode_fixed_1(ctx->alloc, DAISHO_NODE_EXPRLIST, (expr)))
#define iterconv(expr)                                                                               daisho_astnode_fixed_3(ctx->alloc, DAISHO_NODE_CALL, repr(leaf(ITER), expr), leaf(NOEXPAND),                            daisho_astnode_fixed_1(ctx->alloc, DAISHO_NODE_EXPRLIST, (expr)))
#define unop(op, on)                                                                                 daisho_astnode_fixed_3(ctx->alloc, DAISHO_NODE_CALL, (op),                   leaf(NOEXPAND),                            daisho_astnode_fixed_1(ctx->alloc, DAISHO_NODE_EXPRLIST, (on)))
#define binop(op, left, right)                                  daisho_astnode_fixed_3(                                         ctx->alloc, DAISHO_NODE_CALL, (op), leaf(NOEXPAND),         daisho_astnode_fixed_2(ctx->alloc, DAISHO_NODE_EXPRLIST, (left), (right)))

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
  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList 0
  daisho_astnode_t* expr_ret_3 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
    // Not capturing SHEBANG.
    expr_ret_3 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_3 = NULL;
  }

  // optional
  if (!expr_ret_3)
    expr_ret_3 = SUCC;
  expr_ret_2 = expr_ret_3;
  sh = expr_ret_3;
  // ModExprList 1
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_4 = NULL;
    // CodeExpr
    #define ret expr_ret_4
    ret = SUCC;
    #line 24 "daisho.peg"
    ret=list(NSLIST);
    #line 3596 "daisho.peg.h"

    #undef ret
    expr_ret_2 = expr_ret_4;
    nses = expr_ret_4;
  }

  // ModExprList 2
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_5 = NULL;
    // CodeExpr
    #define ret expr_ret_5
    ret = SUCC;
    #line 24 "daisho.peg"
    ;
    #line 3611 "daisho.peg.h"

    #undef ret
    expr_ret_2 = expr_ret_5;
    nsn = expr_ret_5;
  }

  // ModExprList 3
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_6 = NULL;
    // CodeExpr
    #define ret expr_ret_6
    ret = SUCC;
    #line 24 "daisho.peg"
    ;
    #line 3626 "daisho.peg.h"

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
      #define ret expr_ret_9
      ret = SUCC;
      #line 25 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 3648 "daisho.peg.h"

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
        #define ret expr_ret_11
        ret = SUCC;
        #line 25 "daisho.peg"
        
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
        #line 3685 "daisho.peg.h"

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
    #define ret expr_ret_2
    ret = SUCC;
    #line 43 "daisho.peg"
    rule=(!has(sh)) ? node(PROGRAM, nses)
                              : node(PROGRAM, nses, sh);
    #line 3709 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2;
  if (!rule) rule = expr_ret_1;
  if (!expr_ret_1) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule program returned SUCC.\n"), exit(1);
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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

    // ModExprList 1
    if (expr_ret_17) {
      daisho_astnode_t* expr_ret_18 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_18 = leaf(TYPEIDENT);
        expr_ret_18->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_18->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_18 = NULL;
      }

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
    #define ret expr_ret_20
    ret = SUCC;
    #line 47 "daisho.peg"
    ret=srepr(leaf(TYPEIDENT), "GLOBAL");
    #line 3794 "daisho.peg.h"

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
    #define ret expr_ret_22
    ret = SUCC;
    #line 48 "daisho.peg"
    ret = list(NSDECLS);
    #line 3824 "daisho.peg.h"

    #undef ret
    expr_ret_14 = expr_ret_22;
    l = expr_ret_22;
  }

  // ModExprList 3
  if (expr_ret_14) {
    // CodeExpr
    #define ret expr_ret_14
    ret = SUCC;
    #line 48 "daisho.peg"
    add(l, t);
    #line 3838 "daisho.peg.h"

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
      #define ret expr_ret_25
      ret = SUCC;
      #line 49 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 3858 "daisho.peg.h"

      #undef ret
      // ModExprList 1
      if (expr_ret_25) {
        daisho_astnode_t* expr_ret_26 = NULL;

        // SlashExpr 0
        if (!expr_ret_26) {
          daisho_astnode_t* expr_ret_27 = NULL;
          rec(mod_27);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_27 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_27 = NULL;
          }

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
          #define ret expr_ret_28
          ret = SUCC;
          #line 50 "daisho.peg"
          t=NULL;
          #line 3893 "daisho.peg.h"

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
            #define ret expr_ret_28
            ret = SUCC;
            #line 50 "daisho.peg"
            add(l, t);
            #line 3912 "daisho.peg.h"

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
    #define ret expr_ret_14
    ret = SUCC;
    #line 51 "daisho.peg"
    rule = node(NAMESPACE, name, l);
    #line 3943 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_14) rew(mod_14);
  expr_ret_13 = expr_ret_14;
  if (!rule) rule = expr_ret_13;
  if (!expr_ret_13) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule namespace returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_30
  daisho_astnode_t* expr_ret_30 = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule topdecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_43 = NULL;
  rec(mod_43);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
    // Not capturing STRUCT.
    expr_ret_43 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_43 = NULL;
  }

  // ModExprList 1
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_44 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_44 = leaf(TYPEIDENT);
      expr_ret_44->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_44->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_44 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_43) {
    daisho_astnode_t* expr_ret_47 = NULL;
    // CodeExpr
    #define ret expr_ret_47
    ret = SUCC;
    #line 109 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4157 "daisho.peg.h"

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
        #define ret expr_ret_50
        ret = SUCC;
        #line 110 "daisho.peg"
        add(members, m);
        #line 4186 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_43) {
    // CodeExpr
    #define ret expr_ret_43
    ret = SUCC;
    #line 112 "daisho.peg"
    rule = node(STRUCT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4219 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_43) rew(mod_43);
  expr_ret_42 = expr_ret_43;
  if (!rule) rule = expr_ret_42;
  if (!expr_ret_42) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule structdecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_54 = NULL;
  rec(mod_54);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_54 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_54 = NULL;
  }

  // ModExprList 1
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_55 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_55 = leaf(TYPEIDENT);
      expr_ret_55->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_55->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_55 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_54 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_54 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_57 = NULL;
    // CodeExpr
    #define ret expr_ret_57
    ret = SUCC;
    #line 115 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4299 "daisho.peg.h"

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
        #define ret expr_ret_60
        ret = SUCC;
        #line 116 "daisho.peg"
        add(members, m);
        #line 4328 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_54 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_54 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_54) {
    // CodeExpr
    #define ret expr_ret_54
    ret = SUCC;
    #line 118 "daisho.peg"
    rule = node(UNION, id, tmpl, members);
    #line 4361 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_54) rew(mod_54);
  expr_ret_53 = expr_ret_54;
  if (!rule) rule = expr_ret_53;
  if (!expr_ret_53) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule uniondecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_64 = NULL;
  rec(mod_64);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
    expr_ret_64 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_64 = NULL;
  }

  // ModExprList 1
  if (expr_ret_64) {
    daisho_astnode_t* expr_ret_65 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_65 = leaf(TYPEIDENT);
      expr_ret_65->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_65->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_65 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_68 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_68 = NULL;
    }

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
    #define ret expr_ret_70
    ret = SUCC;
    #line 121 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4462 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_72 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_72 = NULL;
    }

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
          #define ret expr_ret_75
          ret = SUCC;
          #line 122 "daisho.peg"
          add(members, m);
          #line 4505 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
        // Not capturing RCBRACK.
        expr_ret_72 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_72 = NULL;
      }

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
    #define ret expr_ret_64
    ret = SUCC;
    #line 123 "daisho.peg"
    rule = node(TRAIT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4547 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_64) rew(mod_64);
  expr_ret_63 = expr_ret_64;
  if (!rule) rule = expr_ret_63;
  if (!expr_ret_63) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule traitdecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_79 = NULL;
  rec(mod_79);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_79 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_79 = NULL;
  }

  // ModExprList 1
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_80 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_80 = leaf(TYPEIDENT);
      expr_ret_80->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_80->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_80 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_83 = NULL;
    // CodeExpr
    #define ret expr_ret_83
    ret = SUCC;
    #line 126 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4649 "daisho.peg.h"

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
        #define ret expr_ret_86
        ret = SUCC;
        #line 127 "daisho.peg"
        add(members, m);
        #line 4678 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_79) {
    // CodeExpr
    #define ret expr_ret_79
    ret = SUCC;
    #line 129 "daisho.peg"
    rule = node(IMPL, id, tmpl, ft, members);
    #line 4711 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_79) rew(mod_79);
  expr_ret_78 = expr_ret_79;
  if (!rule) rule = expr_ret_78;
  if (!expr_ret_78) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule impldecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_88
  daisho_astnode_t* expr_ret_88 = NULL;
  daisho_astnode_t* expr_ret_89 = NULL;
  daisho_astnode_t* expr_ret_90 = NULL;
  rec(mod_90);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_90 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_90 = NULL;
  }

  // ModExprList 1
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_91 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_91 = leaf(TYPEIDENT);
      expr_ret_91->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_91->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

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
    #define ret expr_ret_90
    ret = SUCC;
    #line 132 "daisho.peg"
    rule = node(CTYPE, id, c);
    #line 4776 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_90) rew(mod_90);
  expr_ret_89 = expr_ret_90;
  if (!rule) rule = expr_ret_89;
  if (!expr_ret_89) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ctypedecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_95 = NULL;
  rec(mod_95);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_95 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_95 = NULL;
  }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_95 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_95 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_95) {
    expr_ret_95 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 7
  if (expr_ret_95) {
    // CodeExpr
    #define ret expr_ret_95
    ret = SUCC;
    #line 138 "daisho.peg"
    rule = node(CFN, rett, ci, al);
    #line 4873 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_95) rew(mod_95);
  expr_ret_94 = expr_ret_95;
  if (!rule) rule = expr_ret_94;
  if (!expr_ret_94) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cfndecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_101 = NULL;
  rec(mod_101);
  // ModExprList 0
  daisho_astnode_t* expr_ret_102 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_102 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_102 = NULL;
  }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_104 = leaf(VARIDENT);
      expr_ret_104->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_104->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_101 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_101 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_101 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_101 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_107 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_107 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_107 = NULL;
    }

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
    #define ret expr_ret_101
    ret = SUCC;
    #line 144 "daisho.peg"
    rule=node(FNDECL, rett, name, tmpl, al, e);
    #line 5025 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_101) rew(mod_101);
  expr_ret_100 = expr_ret_101;
  if (!rule) rule = expr_ret_100;
  if (!expr_ret_100) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fndecl returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_112 = NULL;
  rec(mod_112);
  // ModExprList 0
  daisho_astnode_t* expr_ret_113 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_113 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_113 = NULL;
  }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_115 = leaf(VARIDENT);
      expr_ret_115->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_115->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_115 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_112 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_112 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_112 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_112 = NULL;
    }

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
    #define ret expr_ret_112
    ret = SUCC;
    #line 150 "daisho.peg"
    rule=node(FNPROTO, rett, name, tmpl, al);
    #line 5150 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_112) rew(mod_112);
  expr_ret_111 = expr_ret_112;
  if (!rule) rule = expr_ret_111;
  if (!expr_ret_111) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnproto returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_119
  daisho_astnode_t* expr_ret_119 = NULL;
  daisho_astnode_t* expr_ret_120 = NULL;
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnmember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_126
  daisho_astnode_t* expr_ret_126 = NULL;
  daisho_astnode_t* expr_ret_127 = NULL;
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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_130 = leaf(VARIDENT);
      expr_ret_130->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_130->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_130 = NULL;
    }

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
    #define ret expr_ret_128
    ret = SUCC;
    #line 156 "daisho.peg"
    rule=node(TYPEMEMBER, t, v);
    #line 5256 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_128) rew(mod_128);
  expr_ret_127 = expr_ret_128;
  if (!rule) rule = expr_ret_127;
  if (!expr_ret_127) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typemember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_131
  daisho_astnode_t* expr_ret_131 = NULL;
  daisho_astnode_t* expr_ret_132 = NULL;
  daisho_astnode_t* expr_ret_133 = NULL;

  // SlashExpr 0
  if (!expr_ret_133) {
    daisho_astnode_t* expr_ret_134 = NULL;
    rec(mod_134);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_134 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_134 = NULL;
    }

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
      #define ret expr_ret_134
      ret = SUCC;
      #line 158 "daisho.peg"
      rule->kind = kind(TMPLEXPAND);
      #line 5307 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 3
    if (expr_ret_134) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Capturing GT.
        expr_ret_134 = leaf(GT);
        expr_ret_134->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_134->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_134 = NULL;
      }

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
    #define ret expr_ret_136
    ret = SUCC;
    #line 159 "daisho.peg"
    rule=leaf(NOEXPAND);
    #line 5341 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_136) rew(mod_136);
    expr_ret_133 = expr_ret_136;
  }

  // SlashExpr end
  expr_ret_132 = expr_ret_133;

  if (!rule) rule = expr_ret_132;
  if (!expr_ret_132) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tmplexpand returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx) {
  #define rule expr_ret_137
  daisho_astnode_t* expr_ret_137 = NULL;
  daisho_astnode_t* expr_ret_138 = NULL;
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
    #define ret expr_ret_142
    ret = SUCC;
    #line 161 "daisho.peg"
    ret=leaf(VOIDTYPE);
    #line 5390 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule returntype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_143
  daisho_astnode_t* expr_ret_143 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_148 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_148 = NULL;
    }

    // ModExprList end
    if (!expr_ret_148) rew(mod_148);
    expr_ret_147 = expr_ret_148;
  }

  // SlashExpr 1
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_149 = NULL;
    rec(mod_149);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Not capturing SELFTYPE.
      expr_ret_149 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_149 = NULL;
    }

    // ModExprList end
    if (!expr_ret_149) rew(mod_149);
    expr_ret_147 = expr_ret_149;
  }

  // SlashExpr 2
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_150 = NULL;
    rec(mod_150);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Not capturing VOIDTYPE.
      expr_ret_150 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_150 = NULL;
    }

    // ModExprList end
    if (!expr_ret_150) rew(mod_150);
    expr_ret_147 = expr_ret_150;
  }

  // SlashExpr 3
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_151 = NULL;
    rec(mod_151);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Not capturing VOIDPTR.
      expr_ret_151 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_151 = NULL;
    }

    // ModExprList end
    if (!expr_ret_151) rew(mod_151);
    expr_ret_147 = expr_ret_151;
  }

  // SlashExpr 4
  if (!expr_ret_147) {
    daisho_astnode_t* expr_ret_152 = NULL;
    rec(mod_152);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_152 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_152 = NULL;
    }

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule type returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_156 = NULL;
  rec(mod_156);
  // ModExprList 0
  daisho_astnode_t* expr_ret_157 = NULL;
  // CodeExpr
  #define ret expr_ret_157
  ret = SUCC;
  #line 191 "daisho.peg"
  ;
  #line 5554 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_161 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_161 = NULL;
      }

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
        #define ret expr_ret_161
        ret = SUCC;
        #line 193 "daisho.peg"
        if (!has(from)) from = list(TYPELIST);
        #line 5602 "daisho.peg.h"

        #undef ret
      }

      // ModExprList 3
      if (expr_ret_161) {
        // CodeExpr
        #define ret expr_ret_161
        ret = SUCC;
        #line 194 "daisho.peg"
        add(from, to); to = n;
        #line 5614 "daisho.peg.h"

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
    #define ret expr_ret_156
    ret = SUCC;
    #line 195 "daisho.peg"
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #line 5635 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_156) rew(mod_156);
  expr_ret_155 = expr_ret_156;
  if (!rule) rule = expr_ret_155;
  if (!expr_ret_155) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fntype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_163
  daisho_astnode_t* expr_ret_163 = NULL;
  daisho_astnode_t* expr_ret_164 = NULL;
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_169 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_169 = NULL;
      }

      // ModExprList 1
      if (expr_ret_169) {
        // CodeExpr
        #define ret expr_ret_169
        ret = SUCC;
        #line 197 "daisho.peg"
        rule=node(PTRTYPE, rule);
        #line 5688 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ptrtype returned SUCC.\n"), exit(1);
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
  daisho_astnode_t* expr_ret_172 = NULL;

  // SlashExpr 0
  if (!expr_ret_172) {
    daisho_astnode_t* expr_ret_173 = NULL;
    rec(mod_173);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_173 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_173 = NULL;
    }

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_173 = leaf(CLOSE);
        expr_ret_173->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_173->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_173 = NULL;
      }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Capturing SELFTYPE.
      expr_ret_176 = leaf(SELFTYPE);
      expr_ret_176->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_176->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_176 = NULL;
    }

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_178 = leaf(VOIDTYPE);
      expr_ret_178->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_178->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_178 = NULL;
    }

    expr_ret_177 = expr_ret_178;
    v = expr_ret_178;
    // ModExprList 1
    if (expr_ret_177) {
      rec(mexpr_state_179)
      daisho_astnode_t* expr_ret_179 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_179 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_179 = NULL;
      }

      // invert
      expr_ret_179 = expr_ret_179 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_179);
      expr_ret_177 = expr_ret_179;
    }

    // ModExprList 2
    if (expr_ret_177) {
      // CodeExpr
      #define ret expr_ret_177
      ret = SUCC;
      #line 204 "daisho.peg"
      rule=v;
      #line 5841 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_185 = leaf(TYPEIDENT);
      expr_ret_185->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_185->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_185 = NULL;
    }

    expr_ret_184 = expr_ret_185;
    nns = expr_ret_185;
    // ModExprList 1
    if (expr_ret_184) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_184 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_184 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_184) {
      daisho_astnode_t* expr_ret_186 = NULL;
      // CodeExpr
      #define ret expr_ret_186
      ret = SUCC;
      #line 206 "daisho.peg"
      ret=nns;
      #line 5908 "daisho.peg.h"

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
      #define ret expr_ret_182
      ret = SUCC;
      #line 207 "daisho.peg"
      if (!has(ns)) ns = leaf(CURRENT_NS);
      #line 5930 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_182) {
      daisho_astnode_t* expr_ret_187 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_187 = leaf(TYPEIDENT);
        expr_ret_187->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_187->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_187 = NULL;
      }

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
      #define ret expr_ret_182
      ret = SUCC;
      #line 209 "daisho.peg"
      rule=node(BASETYPE, ns, s, t);
      #line 5968 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule basetype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_189
  daisho_astnode_t* expr_ret_189 = NULL;
  daisho_astnode_t* expr_ret_190 = NULL;
  daisho_astnode_t* expr_ret_191 = NULL;

  // SlashExpr 0
  if (!expr_ret_191) {
    daisho_astnode_t* expr_ret_192 = NULL;
    rec(mod_192);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_192 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_192 = NULL;
    }

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_192 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_192 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_192) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_192 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_192 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_192) {
      // CodeExpr
      #define ret expr_ret_192
      ret = SUCC;
      #line 211 "daisho.peg"
      rule=node(TUPLETYPE, t);
      #line 6051 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_194 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_194 = NULL;
    }

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_194 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_194 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_194) {
      // CodeExpr
      #define ret expr_ret_194
      ret = SUCC;
      #line 212 "daisho.peg"
      rule->kind = kind(TUPLETYPE);
      #line 6102 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tupletype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_196
  daisho_astnode_t* expr_ret_196 = NULL;
  daisho_astnode_t* expr_ret_197 = NULL;
  daisho_astnode_t* expr_ret_198 = NULL;

  // SlashExpr 0
  if (!expr_ret_198) {
    daisho_astnode_t* expr_ret_199 = NULL;
    rec(mod_199);
    // ModExprList 0
    daisho_astnode_t* expr_ret_200 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_200 = leaf(VOIDPTR);
      expr_ret_200->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_200->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_200 = NULL;
    }

    expr_ret_199 = expr_ret_200;
    v = expr_ret_200;
    // ModExprList 1
    if (expr_ret_199) {
      // CodeExpr
      #define ret expr_ret_199
      ret = SUCC;
      #line 214 "daisho.peg"
      rule=v;
      #line 6155 "daisho.peg.h"

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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_202 = leaf(VOIDTYPE);
      expr_ret_202->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_202->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_202 = NULL;
    }

    expr_ret_201 = expr_ret_202;
    v = expr_ret_202;
    // ModExprList 1
    if (expr_ret_201) {
      daisho_astnode_t* expr_ret_203 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_203 = leaf(STAR);
        expr_ret_203->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_203->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_203 = NULL;
      }

      expr_ret_201 = expr_ret_203;
      s = expr_ret_203;
    }

    // ModExprList 2
    if (expr_ret_201) {
      // CodeExpr
      #define ret expr_ret_201
      ret = SUCC;
      #line 215 "daisho.peg"
      rule=leaf(VOIDPTR);
      #line 6207 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule voidptr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_204
  daisho_astnode_t* expr_ret_204 = NULL;
  daisho_astnode_t* expr_ret_205 = NULL;
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
    #define ret expr_ret_206
    ret = SUCC;
    #line 285 "daisho.peg"
    rule=list(TYPELIST);
    #line 6249 "daisho.peg.h"

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
    #define ret expr_ret_206
    ret = SUCC;
    #line 286 "daisho.peg"
    if has(t) add(rule, t);
    #line 6273 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_211 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_211 = NULL;
      }

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
        #define ret expr_ret_211
        ret = SUCC;
        #line 287 "daisho.peg"
        add(rule, t);
        #line 6312 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typelist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_214
  daisho_astnode_t* expr_ret_214 = NULL;
  daisho_astnode_t* expr_ret_215 = NULL;
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
    #define ret expr_ret_216
    ret = SUCC;
    #line 289 "daisho.peg"
    rule=list(EXPRLIST);
    #line 6369 "daisho.peg.h"

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
    #define ret expr_ret_216
    ret = SUCC;
    #line 290 "daisho.peg"
    if has(e) add(rule, e);
    #line 6393 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_221 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_221 = NULL;
      }

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
        #define ret expr_ret_221
        ret = SUCC;
        #line 291 "daisho.peg"
        add(rule, e);
        #line 6432 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule exprlist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_224
  daisho_astnode_t* expr_ret_224 = NULL;
  daisho_astnode_t* expr_ret_225 = NULL;
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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_228 = leaf(VARIDENT);
      expr_ret_228->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_228->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_228 = NULL;
    }

    expr_ret_226 = expr_ret_228;
    i = expr_ret_228;
  }

  // ModExprList 2
  if (expr_ret_226) {
    // CodeExpr
    #define ret expr_ret_226
    ret = SUCC;
    #line 294 "daisho.peg"
    rule=node(FNARG, t, i);
    #line 6505 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_226) rew(mod_226);
  expr_ret_225 = expr_ret_226;
  if (!rule) rule = expr_ret_225;
  if (!expr_ret_225) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_229
  daisho_astnode_t* expr_ret_229 = NULL;
  daisho_astnode_t* expr_ret_230 = NULL;
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
    #define ret expr_ret_231
    ret = SUCC;
    #line 295 "daisho.peg"
    rule=list(ARGLIST);
    #line 6542 "daisho.peg.h"

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
    #define ret expr_ret_231
    ret = SUCC;
    #line 296 "daisho.peg"
    if has(a) add(rule, a);
    #line 6566 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_236 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_236 = NULL;
      }

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
        #define ret expr_ret_236
        ret = SUCC;
        #line 297 "daisho.peg"
        add(rule, a);
        #line 6605 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule arglist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_239
  daisho_astnode_t* expr_ret_239 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
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
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Not capturing VARIDENT.
      expr_ret_243 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_243 = NULL;
    }

    // optional
    if (!expr_ret_243)
      expr_ret_243 = SUCC;
    expr_ret_241 = expr_ret_243;
    i = expr_ret_243;
  }

  // ModExprList 2
  if (expr_ret_241) {
    // CodeExpr
    #define ret expr_ret_241
    ret = SUCC;
    #line 300 "daisho.peg"
    rule=node(PROTOARG, t);
    #line 6679 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_241) rew(mod_241);
  expr_ret_240 = expr_ret_241;
  if (!rule) rule = expr_ret_240;
  if (!expr_ret_240) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protoarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_244
  daisho_astnode_t* expr_ret_244 = NULL;
  daisho_astnode_t* expr_ret_245 = NULL;
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
    #define ret expr_ret_246
    ret = SUCC;
    #line 302 "daisho.peg"
    rule=list(PROTOLIST);
    #line 6716 "daisho.peg.h"

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
    #define ret expr_ret_246
    ret = SUCC;
    #line 303 "daisho.peg"
    if has(p) add(rule, p);
    #line 6740 "daisho.peg.h"

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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_251 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_251 = NULL;
      }

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
        #define ret expr_ret_251
        ret = SUCC;
        #line 304 "daisho.peg"
        add(rule, p);
        #line 6779 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protoarglist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_254
  daisho_astnode_t* expr_ret_254 = NULL;
  daisho_astnode_t* expr_ret_255 = NULL;
  daisho_astnode_t* expr_ret_256 = NULL;
  rec(mod_256);
  // ModExprList 0
  rec(mexpr_state_257)
  daisho_astnode_t* expr_ret_257 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Not capturing SEMI.
    expr_ret_257 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_257 = NULL;
  }

  // invert
  expr_ret_257 = expr_ret_257 ? NULL : SUCC;
  // rewind
  rew(mexpr_state_257);
  expr_ret_256 = expr_ret_257;
  // ModExprList 1
  if (expr_ret_256) {
    rec(mexpr_state_258)
    daisho_astnode_t* expr_ret_258 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_258 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_258 = NULL;
    }

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule expr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_260
  daisho_astnode_t* expr_ret_260 = NULL;
  daisho_astnode_t* expr_ret_261 = NULL;
  daisho_astnode_t* expr_ret_262 = NULL;

  // SlashExpr 0
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_263 = NULL;
    rec(mod_263);
    // ModExprList 0
    daisho_astnode_t* expr_ret_264 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_264 = leaf(RET);
      expr_ret_264->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_264->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_264 = NULL;
    }

    expr_ret_263 = expr_ret_264;
    r = expr_ret_264;
    // ModExprList 1
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_265 = NULL;
      expr_ret_265 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_263 = expr_ret_265;
      n = expr_ret_265;
    }

    // ModExprList 2
    if (expr_ret_263) {
      // CodeExpr
      #define ret expr_ret_263
      ret = SUCC;
      #line 352 "daisho.peg"
      rule=node(RET, r, n);
      #line 6917 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_263) rew(mod_263);
    expr_ret_262 = expr_ret_263;
  }

  // SlashExpr 1
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_266 = NULL;
    rec(mod_266);
    // ModExprList 0
    daisho_astnode_t* expr_ret_267 = NULL;
    expr_ret_267 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_266 = expr_ret_267;
    rule = expr_ret_267;
    // ModExprList 1
    if (expr_ret_266) {
      daisho_astnode_t* expr_ret_268 = NULL;
      daisho_astnode_t* expr_ret_269 = NULL;
      rec(mod_269);
      // ModExprList 0
      daisho_astnode_t* expr_ret_270 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Capturing GRAVE.
        expr_ret_270 = leaf(GRAVE);
        expr_ret_270->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_270->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_270 = NULL;
      }

      expr_ret_269 = expr_ret_270;
      r = expr_ret_270;
      // ModExprList 1
      if (expr_ret_269) {
        // CodeExpr
        #define ret expr_ret_269
        ret = SUCC;
        #line 353 "daisho.peg"
        rule = node(RET, r, rule);
        #line 6963 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_269) rew(mod_269);
      expr_ret_268 = expr_ret_269;
      // optional
      if (!expr_ret_268)
        expr_ret_268 = SUCC;
      expr_ret_266 = expr_ret_268;
    }

    // ModExprList end
    if (!expr_ret_266) rew(mod_266);
    expr_ret_262 = expr_ret_266;
  }

  // SlashExpr end
  expr_ret_261 = expr_ret_262;

  if (!rule) rule = expr_ret_261;
  if (!expr_ret_261) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule preretexpr returned SUCC.\n"), exit(1);
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
  #define rule expr_ret_271
  daisho_astnode_t* expr_ret_271 = NULL;
  daisho_astnode_t* expr_ret_272 = NULL;
  daisho_astnode_t* expr_ret_273 = NULL;

  // SlashExpr 0
  if (!expr_ret_273) {
    daisho_astnode_t* expr_ret_274 = NULL;
    rec(mod_274);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_274 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_274 = NULL;
    }

    // ModExprList 1
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_275 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_275 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_275 = NULL;
      }

      // optional
      if (!expr_ret_275)
        expr_ret_275 = SUCC;
      expr_ret_274 = expr_ret_275;
      o = expr_ret_275;
    }

    // ModExprList 2
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_276 = NULL;
      expr_ret_276 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_274 = expr_ret_276;
      f = expr_ret_276;
    }

    // ModExprList 3
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_277 = NULL;

      // SlashExpr 0
      if (!expr_ret_277) {
        daisho_astnode_t* expr_ret_278 = NULL;
        rec(mod_278);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_279 = NULL;

        // SlashExpr 0
        if (!expr_ret_279) {
          daisho_astnode_t* expr_ret_280 = NULL;
          rec(mod_280);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_280 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_280 = NULL;
          }

          // ModExprList end
          if (!expr_ret_280) rew(mod_280);
          expr_ret_279 = expr_ret_280;
        }

        // SlashExpr 1
        if (!expr_ret_279) {
          daisho_astnode_t* expr_ret_281 = NULL;
          rec(mod_281);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_281 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_281 = NULL;
          }

          // ModExprList end
          if (!expr_ret_281) rew(mod_281);
          expr_ret_279 = expr_ret_281;
        }

        // SlashExpr end
        expr_ret_278 = expr_ret_279;

        // ModExprList end
        if (!expr_ret_278) rew(mod_278);
        expr_ret_277 = expr_ret_278;
      }

      // SlashExpr 1
      if (!expr_ret_277) {
        daisho_astnode_t* expr_ret_282 = NULL;
        rec(mod_282);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_283 = NULL;
        rec(mod_283);
        // ModExprList 0
        expr_ret_283 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_283) {
          daisho_astnode_t* expr_ret_284 = NULL;
          expr_ret_284 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_283 = expr_ret_284;
          s = expr_ret_284;
        }

        // ModExprList 2
        if (expr_ret_283) {
          expr_ret_283 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_283) rew(mod_283);
        expr_ret_282 = expr_ret_283;
        // ModExprList end
        if (!expr_ret_282) rew(mod_282);
        expr_ret_277 = expr_ret_282;
      }

      // SlashExpr end
      expr_ret_274 = expr_ret_277;

    }

    // ModExprList 4
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_285 = NULL;
      expr_ret_285 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_274 = expr_ret_285;
      t = expr_ret_285;
    }

    // ModExprList 5
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_286 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_286 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_286 = NULL;
      }

      // optional
      if (!expr_ret_286)
        expr_ret_286 = SUCC;
      expr_ret_274 = expr_ret_286;
      c = expr_ret_286;
    }

    // ModExprList 6
    if (expr_ret_274) {
      // CodeExpr
      #define ret expr_ret_274
      ret = SUCC;
      #line 357 "daisho.peg"
      if (has(o) != has(c)) WARNING("For expression parens mismatch.");
      #line 7171 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 7
    if (expr_ret_274) {
      daisho_astnode_t* expr_ret_287 = NULL;
      expr_ret_287 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_274 = expr_ret_287;
      e = expr_ret_287;
    }

    // ModExprList 8
    if (expr_ret_274) {
      // CodeExpr
      #define ret expr_ret_274
      ret = SUCC;
      #line 359 "daisho.peg"
      rule = has(s) ? node(FOR, f, boolconv(s), t, e)
                    :          node(FOREACH, f, t, e);
      #line 7193 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_274) rew(mod_274);
    expr_ret_273 = expr_ret_274;
  }

  // SlashExpr 1
  if (!expr_ret_273) {
    daisho_astnode_t* expr_ret_288 = NULL;
    rec(mod_288);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_289 = NULL;
    expr_ret_289 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_288 = expr_ret_289;
    rule = expr_ret_289;
    // ModExprList end
    if (!expr_ret_288) rew(mod_288);
    expr_ret_273 = expr_ret_288;
  }

  // SlashExpr end
  expr_ret_272 = expr_ret_273;

  if (!rule) rule = expr_ret_272;
  if (!expr_ret_272) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule forexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_290
  daisho_astnode_t* expr_ret_290 = NULL;
  daisho_astnode_t* expr_ret_291 = NULL;
  daisho_astnode_t* expr_ret_292 = NULL;

  // SlashExpr 0
  if (!expr_ret_292) {
    daisho_astnode_t* expr_ret_293 = NULL;
    rec(mod_293);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_293 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_293 = NULL;
    }

    // ModExprList 1
    if (expr_ret_293) {
      daisho_astnode_t* expr_ret_294 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_294 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_294 = NULL;
      }

      // optional
      if (!expr_ret_294)
        expr_ret_294 = SUCC;
      expr_ret_293 = expr_ret_294;
      o = expr_ret_294;
    }

    // ModExprList 2
    if (expr_ret_293) {
      daisho_astnode_t* expr_ret_295 = NULL;
      expr_ret_295 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_293 = expr_ret_295;
      n = expr_ret_295;
    }

    // ModExprList 3
    if (expr_ret_293) {
      daisho_astnode_t* expr_ret_296 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_296 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_296 = NULL;
      }

      // optional
      if (!expr_ret_296)
        expr_ret_296 = SUCC;
      expr_ret_293 = expr_ret_296;
      c = expr_ret_296;
    }

    // ModExprList 4
    if (expr_ret_293) {
      // CodeExpr
      #define ret expr_ret_293
      ret = SUCC;
      #line 364 "daisho.peg"
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #line 7303 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_293) {
      daisho_astnode_t* expr_ret_297 = NULL;
      expr_ret_297 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_293 = expr_ret_297;
      e = expr_ret_297;
    }

    // ModExprList 6
    if (expr_ret_293) {
      // CodeExpr
      #define ret expr_ret_293
      ret = SUCC;
      #line 365 "daisho.peg"
      rule=node(WHILE, n, e);
      #line 7324 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_293) rew(mod_293);
    expr_ret_292 = expr_ret_293;
  }

  // SlashExpr 1
  if (!expr_ret_292) {
    daisho_astnode_t* expr_ret_298 = NULL;
    rec(mod_298);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_299 = NULL;
    expr_ret_299 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_298 = expr_ret_299;
    rule = expr_ret_299;
    // ModExprList end
    if (!expr_ret_298) rew(mod_298);
    expr_ret_292 = expr_ret_298;
  }

  // SlashExpr end
  expr_ret_291 = expr_ret_292;

  if (!rule) rule = expr_ret_291;
  if (!expr_ret_291) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule whileexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preifexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* ee = NULL;
  #define rule expr_ret_300
  daisho_astnode_t* expr_ret_300 = NULL;
  daisho_astnode_t* expr_ret_301 = NULL;
  daisho_astnode_t* expr_ret_302 = NULL;

  // SlashExpr 0
  if (!expr_ret_302) {
    daisho_astnode_t* expr_ret_303 = NULL;
    rec(mod_303);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_303 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_303 = NULL;
    }

    // ModExprList 1
    if (expr_ret_303) {
      daisho_astnode_t* expr_ret_304 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_304 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_304 = NULL;
      }

      // optional
      if (!expr_ret_304)
        expr_ret_304 = SUCC;
      expr_ret_303 = expr_ret_304;
      o = expr_ret_304;
    }

    // ModExprList 2
    if (expr_ret_303) {
      daisho_astnode_t* expr_ret_305 = NULL;
      expr_ret_305 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_303 = expr_ret_305;
      n = expr_ret_305;
    }

    // ModExprList 3
    if (expr_ret_303) {
      daisho_astnode_t* expr_ret_306 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_306 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_306 = NULL;
      }

      // optional
      if (!expr_ret_306)
        expr_ret_306 = SUCC;
      expr_ret_303 = expr_ret_306;
      c = expr_ret_306;
    }

    // ModExprList 4
    if (expr_ret_303) {
      // CodeExpr
      #define ret expr_ret_303
      ret = SUCC;
      #line 369 "daisho.peg"
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #line 7435 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_303) {
      daisho_astnode_t* expr_ret_307 = NULL;
      expr_ret_307 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_303 = expr_ret_307;
      e = expr_ret_307;
    }

    // ModExprList 6
    if (expr_ret_303) {
      daisho_astnode_t* expr_ret_308 = NULL;
      daisho_astnode_t* expr_ret_309 = NULL;
      rec(mod_309);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_309 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_309 = NULL;
      }

      // ModExprList 1
      if (expr_ret_309) {
        daisho_astnode_t* expr_ret_310 = NULL;
        expr_ret_310 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_309 = expr_ret_310;
        ee = expr_ret_310;
      }

      // ModExprList end
      if (!expr_ret_309) rew(mod_309);
      expr_ret_308 = expr_ret_309;
      // optional
      if (!expr_ret_308)
        expr_ret_308 = SUCC;
      expr_ret_303 = expr_ret_308;
    }

    // ModExprList 7
    if (expr_ret_303) {
      // CodeExpr
      #define ret expr_ret_303
      ret = SUCC;
      #line 372 "daisho.peg"
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #line 7489 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_303) rew(mod_303);
    expr_ret_302 = expr_ret_303;
  }

  // SlashExpr 1
  if (!expr_ret_302) {
    daisho_astnode_t* expr_ret_311 = NULL;
    rec(mod_311);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_312 = NULL;
    expr_ret_312 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_311 = expr_ret_312;
    rule = expr_ret_312;
    // ModExprList end
    if (!expr_ret_311) rew(mod_311);
    expr_ret_302 = expr_ret_311;
  }

  // SlashExpr end
  expr_ret_301 = expr_ret_302;

  if (!rule) rule = expr_ret_301;
  if (!expr_ret_301) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule preifexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_313
  daisho_astnode_t* expr_ret_313 = NULL;
  daisho_astnode_t* expr_ret_314 = NULL;
  daisho_astnode_t* expr_ret_315 = NULL;
  rec(mod_315);
  // ModExprList 0
  daisho_astnode_t* expr_ret_316 = NULL;
  expr_ret_316 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_315 = expr_ret_316;
  n = expr_ret_316;
  // ModExprList 1
  if (expr_ret_315) {
    daisho_astnode_t* expr_ret_317 = NULL;
    daisho_astnode_t* expr_ret_318 = NULL;
    rec(mod_318);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_318 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_318 = NULL;
    }

    // ModExprList 1
    if (expr_ret_318) {
      daisho_astnode_t* expr_ret_319 = NULL;
      expr_ret_319 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_318 = expr_ret_319;
      qe = expr_ret_319;
    }

    // ModExprList 2
    if (expr_ret_318) {
      daisho_astnode_t* expr_ret_320 = NULL;
      daisho_astnode_t* expr_ret_321 = NULL;
      rec(mod_321);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_321 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_321 = NULL;
      }

      // ModExprList 1
      if (expr_ret_321) {
        daisho_astnode_t* expr_ret_322 = NULL;
        expr_ret_322 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_321 = expr_ret_322;
        ce = expr_ret_322;
      }

      // ModExprList end
      if (!expr_ret_321) rew(mod_321);
      expr_ret_320 = expr_ret_321;
      // optional
      if (!expr_ret_320)
        expr_ret_320 = SUCC;
      expr_ret_318 = expr_ret_320;
    }

    // ModExprList end
    if (!expr_ret_318) rew(mod_318);
    expr_ret_317 = expr_ret_318;
    // optional
    if (!expr_ret_317)
      expr_ret_317 = SUCC;
    expr_ret_315 = expr_ret_317;
  }

  // ModExprList 2
  if (expr_ret_315) {
    // CodeExpr
    #define ret expr_ret_315
    ret = SUCC;
    #line 377 "daisho.peg"
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #line 7612 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_315) rew(mod_315);
  expr_ret_314 = expr_ret_315;
  if (!rule) rule = expr_ret_314;
  if (!expr_ret_314) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ternexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_323
  daisho_astnode_t* expr_ret_323 = NULL;
  daisho_astnode_t* expr_ret_324 = NULL;
  daisho_astnode_t* expr_ret_325 = NULL;
  rec(mod_325);
  // ModExprList 0
  daisho_astnode_t* expr_ret_326 = NULL;
  expr_ret_326 = daisho_parse_alsoexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_325 = expr_ret_326;
  rule = expr_ret_326;
  // ModExprList 1
  if (expr_ret_325) {
    daisho_astnode_t* expr_ret_327 = NULL;
    daisho_astnode_t* expr_ret_328 = SUCC;
    while (expr_ret_328)
    {
      rec(kleene_rew_327);
      daisho_astnode_t* expr_ret_329 = NULL;
      rec(mod_329);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_329 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_329 = NULL;
      }

      // ModExprList 1
      if (expr_ret_329) {
        daisho_astnode_t* expr_ret_330 = NULL;
        expr_ret_330 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_329 = expr_ret_330;
        nn = expr_ret_330;
      }

      // ModExprList 2
      if (expr_ret_329) {
        // CodeExpr
        #define ret expr_ret_329
        ret = SUCC;
        #line 381 "daisho.peg"
        rule=node(THEN, rule, nn);
        #line 7675 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule thenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_331
  daisho_astnode_t* expr_ret_331 = NULL;
  daisho_astnode_t* expr_ret_332 = NULL;
  daisho_astnode_t* expr_ret_333 = NULL;
  rec(mod_333);
  // ModExprList 0
  daisho_astnode_t* expr_ret_334 = NULL;
  expr_ret_334 = daisho_parse_ceqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_333 = expr_ret_334;
  rule = expr_ret_334;
  // ModExprList 1
  if (expr_ret_333) {
    daisho_astnode_t* expr_ret_335 = NULL;
    daisho_astnode_t* expr_ret_336 = SUCC;
    while (expr_ret_336)
    {
      rec(kleene_rew_335);
      daisho_astnode_t* expr_ret_337 = NULL;
      rec(mod_337);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_337 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_337 = NULL;
      }

      // ModExprList 1
      if (expr_ret_337) {
        daisho_astnode_t* expr_ret_338 = NULL;
        expr_ret_338 = daisho_parse_ceqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_337 = expr_ret_338;
        nn = expr_ret_338;
      }

      // ModExprList 2
      if (expr_ret_337) {
        // CodeExpr
        #define ret expr_ret_337
        ret = SUCC;
        #line 383 "daisho.peg"
        rule=node(ALSO, rule, nn);
        #line 7747 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_337) rew(mod_337);
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule alsoexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_339
  daisho_astnode_t* expr_ret_339 = NULL;
  daisho_astnode_t* expr_ret_340 = NULL;
  daisho_astnode_t* expr_ret_341 = NULL;
  rec(mod_341);
  // ModExprList 0
  daisho_astnode_t* expr_ret_342 = NULL;
  expr_ret_342 = daisho_parse_logorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_341 = expr_ret_342;
  rule = expr_ret_342;
  // ModExprList 1
  if (expr_ret_341) {
    daisho_astnode_t* expr_ret_343 = NULL;
    daisho_astnode_t* expr_ret_344 = SUCC;
    while (expr_ret_344)
    {
      rec(kleene_rew_343);
      daisho_astnode_t* expr_ret_345 = NULL;
      rec(mod_345);
      // ModExprList 0
      daisho_astnode_t* expr_ret_346 = NULL;
      daisho_astnode_t* expr_ret_347 = NULL;

      // SlashExpr 0
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_348 = NULL;
        rec(mod_348);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_348 = leaf(EQ);
          expr_ret_348->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_348->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_348 = NULL;
        }

        // ModExprList end
        if (!expr_ret_348) rew(mod_348);
        expr_ret_347 = expr_ret_348;
      }

      // SlashExpr 1
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_349 = NULL;
        rec(mod_349);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_349 = leaf(PLEQ);
          expr_ret_349->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_349->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_349 = NULL;
        }

        // ModExprList end
        if (!expr_ret_349) rew(mod_349);
        expr_ret_347 = expr_ret_349;
      }

      // SlashExpr 2
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_350 = NULL;
        rec(mod_350);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_350 = leaf(MINEQ);
          expr_ret_350->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_350->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_350 = NULL;
        }

        // ModExprList end
        if (!expr_ret_350) rew(mod_350);
        expr_ret_347 = expr_ret_350;
      }

      // SlashExpr 3
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_351 = NULL;
        rec(mod_351);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_351 = leaf(MULEQ);
          expr_ret_351->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_351->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_351 = NULL;
        }

        // ModExprList end
        if (!expr_ret_351) rew(mod_351);
        expr_ret_347 = expr_ret_351;
      }

      // SlashExpr 4
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_352 = NULL;
        rec(mod_352);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_352 = leaf(DIVEQ);
          expr_ret_352->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_352->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_352 = NULL;
        }

        // ModExprList end
        if (!expr_ret_352) rew(mod_352);
        expr_ret_347 = expr_ret_352;
      }

      // SlashExpr 5
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_353 = NULL;
        rec(mod_353);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_353 = leaf(MODEQ);
          expr_ret_353->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_353->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_353 = NULL;
        }

        // ModExprList end
        if (!expr_ret_353) rew(mod_353);
        expr_ret_347 = expr_ret_353;
      }

      // SlashExpr 6
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_354 = NULL;
        rec(mod_354);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_354 = leaf(ANDEQ);
          expr_ret_354->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_354->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_354 = NULL;
        }

        // ModExprList end
        if (!expr_ret_354) rew(mod_354);
        expr_ret_347 = expr_ret_354;
      }

      // SlashExpr 7
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_355 = NULL;
        rec(mod_355);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_355 = leaf(OREQ);
          expr_ret_355->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_355->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_355 = NULL;
        }

        // ModExprList end
        if (!expr_ret_355) rew(mod_355);
        expr_ret_347 = expr_ret_355;
      }

      // SlashExpr 8
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_356 = NULL;
        rec(mod_356);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_356 = leaf(XOREQ);
          expr_ret_356->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_356->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_356 = NULL;
        }

        // ModExprList end
        if (!expr_ret_356) rew(mod_356);
        expr_ret_347 = expr_ret_356;
      }

      // SlashExpr 9
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_357 = NULL;
        rec(mod_357);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_357 = leaf(BNEQ);
          expr_ret_357->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_357->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_357 = NULL;
        }

        // ModExprList end
        if (!expr_ret_357) rew(mod_357);
        expr_ret_347 = expr_ret_357;
      }

      // SlashExpr 10
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_358 = NULL;
        rec(mod_358);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_358 = leaf(BSREQ);
          expr_ret_358->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_358->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_358 = NULL;
        }

        // ModExprList end
        if (!expr_ret_358) rew(mod_358);
        expr_ret_347 = expr_ret_358;
      }

      // SlashExpr 11
      if (!expr_ret_347) {
        daisho_astnode_t* expr_ret_359 = NULL;
        rec(mod_359);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_359 = leaf(BSLEQ);
          expr_ret_359->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_359->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_359 = NULL;
        }

        // ModExprList end
        if (!expr_ret_359) rew(mod_359);
        expr_ret_347 = expr_ret_359;
      }

      // SlashExpr end
      expr_ret_346 = expr_ret_347;

      expr_ret_345 = expr_ret_346;
      op = expr_ret_346;
      // ModExprList 1
      if (expr_ret_345) {
        daisho_astnode_t* expr_ret_360 = NULL;
        expr_ret_360 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_345 = expr_ret_360;
        t = expr_ret_360;
      }

      // ModExprList 2
      if (expr_ret_345) {
        // CodeExpr
        #define ret expr_ret_345
        ret = SUCC;
        #line 387 "daisho.peg"
        
                if      (op->kind == kind(EQ))    rule=repr(node(EQ, rule, t), op);
                else if (op->kind == kind(PLEQ))  rule=repr(node(EQ, rule, binop(repr(leaf(PLUS), op),  rule, t)), op);
                else if (op->kind == kind(MINEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(MINUS), op), rule, t)), op);
                else if (op->kind == kind(MULEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(MUL), op),   rule, t)), op);
                else if (op->kind == kind(DIVEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(DIV), op),   rule, t)), op);
                else if (op->kind == kind(MODEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(MOD), op),   rule, t)), op);
                else if (op->kind == kind(ANDEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(AND), op),   rule, t)), op);
                else if (op->kind == kind(OREQ))  rule=repr(node(EQ, rule, binop(repr(leaf(OR), op),    rule, t)), op);
                else if (op->kind == kind(XOREQ)) rule=repr(node(EQ, rule, binop(repr(leaf(BNEQ), op),  rule, t)), op);
                else if (op->kind == kind(BSREQ)) rule=repr(node(EQ, rule, binop(repr(leaf(BSR), op),   rule, t)), op);
                else if (op->kind == kind(BSLEQ)) rule=repr(node(EQ, rule, binop(repr(leaf(BSL), op),   rule, t)), op);
                else _DAI_UNREACHABLE()
              ;
        #line 8073 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_345) rew(mod_345);
      expr_ret_344 = expr_ret_345;
    }

    expr_ret_343 = SUCC;
    expr_ret_341 = expr_ret_343;
  }

  // ModExprList end
  if (!expr_ret_341) rew(mod_341);
  expr_ret_340 = expr_ret_341;
  if (!rule) rule = expr_ret_340;
  if (!expr_ret_340) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ceqexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* lo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_361
  daisho_astnode_t* expr_ret_361 = NULL;
  daisho_astnode_t* expr_ret_362 = NULL;
  daisho_astnode_t* expr_ret_363 = NULL;
  rec(mod_363);
  // ModExprList 0
  daisho_astnode_t* expr_ret_364 = NULL;
  expr_ret_364 = daisho_parse_logandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_363 = expr_ret_364;
  rule = expr_ret_364;
  // ModExprList 1
  if (expr_ret_363) {
    daisho_astnode_t* expr_ret_365 = NULL;
    daisho_astnode_t* expr_ret_366 = SUCC;
    while (expr_ret_366)
    {
      rec(kleene_rew_365);
      daisho_astnode_t* expr_ret_367 = NULL;
      rec(mod_367);
      // ModExprList 0
      daisho_astnode_t* expr_ret_368 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Capturing LOGOR.
        expr_ret_368 = leaf(LOGOR);
        expr_ret_368->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_368->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_368 = NULL;
      }

      expr_ret_367 = expr_ret_368;
      lo = expr_ret_368;
      // ModExprList 1
      if (expr_ret_367) {
        daisho_astnode_t* expr_ret_369 = NULL;
        expr_ret_369 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_367 = expr_ret_369;
        n = expr_ret_369;
      }

      // ModExprList 2
      if (expr_ret_367) {
        // CodeExpr
        #define ret expr_ret_367
        ret = SUCC;
        #line 402 "daisho.peg"
        rule=binop(lo, rule, n);
        #line 8151 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_367) rew(mod_367);
      expr_ret_366 = expr_ret_367;
    }

    expr_ret_365 = SUCC;
    expr_ret_363 = expr_ret_365;
  }

  // ModExprList end
  if (!expr_ret_363) rew(mod_363);
  expr_ret_362 = expr_ret_363;
  if (!rule) rule = expr_ret_362;
  if (!expr_ret_362) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* la = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_370
  daisho_astnode_t* expr_ret_370 = NULL;
  daisho_astnode_t* expr_ret_371 = NULL;
  daisho_astnode_t* expr_ret_372 = NULL;
  rec(mod_372);
  // ModExprList 0
  daisho_astnode_t* expr_ret_373 = NULL;
  expr_ret_373 = daisho_parse_binorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_372 = expr_ret_373;
  rule = expr_ret_373;
  // ModExprList 1
  if (expr_ret_372) {
    daisho_astnode_t* expr_ret_374 = NULL;
    daisho_astnode_t* expr_ret_375 = SUCC;
    while (expr_ret_375)
    {
      rec(kleene_rew_374);
      daisho_astnode_t* expr_ret_376 = NULL;
      rec(mod_376);
      // ModExprList 0
      daisho_astnode_t* expr_ret_377 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Capturing LOGAND.
        expr_ret_377 = leaf(LOGAND);
        expr_ret_377->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_377->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_377 = NULL;
      }

      expr_ret_376 = expr_ret_377;
      la = expr_ret_377;
      // ModExprList 1
      if (expr_ret_376) {
        daisho_astnode_t* expr_ret_378 = NULL;
        expr_ret_378 = daisho_parse_binorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_376 = expr_ret_378;
        n = expr_ret_378;
      }

      // ModExprList 2
      if (expr_ret_376) {
        // CodeExpr
        #define ret expr_ret_376
        ret = SUCC;
        #line 403 "daisho.peg"
        rule=binop(la, rule, n);
        #line 8229 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_376) rew(mod_376);
      expr_ret_375 = expr_ret_376;
    }

    expr_ret_374 = SUCC;
    expr_ret_372 = expr_ret_374;
  }

  // ModExprList end
  if (!expr_ret_372) rew(mod_372);
  expr_ret_371 = expr_ret_372;
  if (!rule) rule = expr_ret_371;
  if (!expr_ret_371) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* ro = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_379
  daisho_astnode_t* expr_ret_379 = NULL;
  daisho_astnode_t* expr_ret_380 = NULL;
  daisho_astnode_t* expr_ret_381 = NULL;
  rec(mod_381);
  // ModExprList 0
  daisho_astnode_t* expr_ret_382 = NULL;
  expr_ret_382 = daisho_parse_binxorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_381 = expr_ret_382;
  rule = expr_ret_382;
  // ModExprList 1
  if (expr_ret_381) {
    daisho_astnode_t* expr_ret_383 = NULL;
    daisho_astnode_t* expr_ret_384 = SUCC;
    while (expr_ret_384)
    {
      rec(kleene_rew_383);
      daisho_astnode_t* expr_ret_385 = NULL;
      rec(mod_385);
      // ModExprList 0
      daisho_astnode_t* expr_ret_386 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Capturing OR.
        expr_ret_386 = leaf(OR);
        expr_ret_386->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_386->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_386 = NULL;
      }

      expr_ret_385 = expr_ret_386;
      ro = expr_ret_386;
      // ModExprList 1
      if (expr_ret_385) {
        daisho_astnode_t* expr_ret_387 = NULL;
        expr_ret_387 = daisho_parse_binxorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_385 = expr_ret_387;
        n = expr_ret_387;
      }

      // ModExprList 2
      if (expr_ret_385) {
        // CodeExpr
        #define ret expr_ret_385
        ret = SUCC;
        #line 404 "daisho.peg"
        rule=binop(ro, rule, n);
        #line 8307 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_385) rew(mod_385);
      expr_ret_384 = expr_ret_385;
    }

    expr_ret_383 = SUCC;
    expr_ret_381 = expr_ret_383;
  }

  // ModExprList end
  if (!expr_ret_381) rew(mod_381);
  expr_ret_380 = expr_ret_381;
  if (!rule) rule = expr_ret_380;
  if (!expr_ret_380) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* xo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_388
  daisho_astnode_t* expr_ret_388 = NULL;
  daisho_astnode_t* expr_ret_389 = NULL;
  daisho_astnode_t* expr_ret_390 = NULL;
  rec(mod_390);
  // ModExprList 0
  daisho_astnode_t* expr_ret_391 = NULL;
  expr_ret_391 = daisho_parse_binandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_390 = expr_ret_391;
  rule = expr_ret_391;
  // ModExprList 1
  if (expr_ret_390) {
    daisho_astnode_t* expr_ret_392 = NULL;
    daisho_astnode_t* expr_ret_393 = SUCC;
    while (expr_ret_393)
    {
      rec(kleene_rew_392);
      daisho_astnode_t* expr_ret_394 = NULL;
      rec(mod_394);
      // ModExprList 0
      daisho_astnode_t* expr_ret_395 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Capturing XOR.
        expr_ret_395 = leaf(XOR);
        expr_ret_395->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_395->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_395 = NULL;
      }

      expr_ret_394 = expr_ret_395;
      xo = expr_ret_395;
      // ModExprList 1
      if (expr_ret_394) {
        daisho_astnode_t* expr_ret_396 = NULL;
        expr_ret_396 = daisho_parse_binandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_394 = expr_ret_396;
        n = expr_ret_396;
      }

      // ModExprList 2
      if (expr_ret_394) {
        // CodeExpr
        #define ret expr_ret_394
        ret = SUCC;
        #line 405 "daisho.peg"
        rule=binop(xo, rule, n);
        #line 8385 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_394) rew(mod_394);
      expr_ret_393 = expr_ret_394;
    }

    expr_ret_392 = SUCC;
    expr_ret_390 = expr_ret_392;
  }

  // ModExprList end
  if (!expr_ret_390) rew(mod_390);
  expr_ret_389 = expr_ret_390;
  if (!rule) rule = expr_ret_389;
  if (!expr_ret_389) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binxorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* an = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_397
  daisho_astnode_t* expr_ret_397 = NULL;
  daisho_astnode_t* expr_ret_398 = NULL;
  daisho_astnode_t* expr_ret_399 = NULL;
  rec(mod_399);
  // ModExprList 0
  daisho_astnode_t* expr_ret_400 = NULL;
  expr_ret_400 = daisho_parse_deneqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_399 = expr_ret_400;
  rule = expr_ret_400;
  // ModExprList 1
  if (expr_ret_399) {
    daisho_astnode_t* expr_ret_401 = NULL;
    daisho_astnode_t* expr_ret_402 = SUCC;
    while (expr_ret_402)
    {
      rec(kleene_rew_401);
      daisho_astnode_t* expr_ret_403 = NULL;
      rec(mod_403);
      // ModExprList 0
      daisho_astnode_t* expr_ret_404 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Capturing AND.
        expr_ret_404 = leaf(AND);
        expr_ret_404->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_404->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_404 = NULL;
      }

      expr_ret_403 = expr_ret_404;
      an = expr_ret_404;
      // ModExprList 1
      if (expr_ret_403) {
        daisho_astnode_t* expr_ret_405 = NULL;
        expr_ret_405 = daisho_parse_deneqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_403 = expr_ret_405;
        n = expr_ret_405;
      }

      // ModExprList 2
      if (expr_ret_403) {
        // CodeExpr
        #define ret expr_ret_403
        ret = SUCC;
        #line 406 "daisho.peg"
        rule=binop(an, rule, n);
        #line 8463 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_403) rew(mod_403);
      expr_ret_402 = expr_ret_403;
    }

    expr_ret_401 = SUCC;
    expr_ret_399 = expr_ret_401;
  }

  // ModExprList end
  if (!expr_ret_399) rew(mod_399);
  expr_ret_398 = expr_ret_399;
  if (!rule) rule = expr_ret_398;
  if (!expr_ret_398) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* x = NULL;
  #define rule expr_ret_406
  daisho_astnode_t* expr_ret_406 = NULL;
  daisho_astnode_t* expr_ret_407 = NULL;
  daisho_astnode_t* expr_ret_408 = NULL;
  rec(mod_408);
  // ModExprList 0
  daisho_astnode_t* expr_ret_409 = NULL;
  expr_ret_409 = daisho_parse_cmpexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_408 = expr_ret_409;
  rule = expr_ret_409;
  // ModExprList 1
  if (expr_ret_408) {
    daisho_astnode_t* expr_ret_410 = NULL;
    daisho_astnode_t* expr_ret_411 = SUCC;
    while (expr_ret_411)
    {
      rec(kleene_rew_410);
      daisho_astnode_t* expr_ret_412 = NULL;

      // SlashExpr 0
      if (!expr_ret_412) {
        daisho_astnode_t* expr_ret_413 = NULL;
        rec(mod_413);
        // ModExprList 0
        daisho_astnode_t* expr_ret_414 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Capturing DEQ.
          expr_ret_414 = leaf(DEQ);
          expr_ret_414->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_414->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_414 = NULL;
        }

        expr_ret_413 = expr_ret_414;
        e = expr_ret_414;
        // ModExprList 1
        if (expr_ret_413) {
          daisho_astnode_t* expr_ret_415 = NULL;
          expr_ret_415 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_413 = expr_ret_415;
          n = expr_ret_415;
        }

        // ModExprList 2
        if (expr_ret_413) {
          // CodeExpr
          #define ret expr_ret_413
          ret = SUCC;
          #line 409 "daisho.peg"
          rule=binop(e, rule, n);
          #line 8546 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_413) rew(mod_413);
        expr_ret_412 = expr_ret_413;
      }

      // SlashExpr 1
      if (!expr_ret_412) {
        daisho_astnode_t* expr_ret_416 = NULL;
        rec(mod_416);
        // ModExprList 0
        daisho_astnode_t* expr_ret_417 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Capturing NEQ.
          expr_ret_417 = leaf(NEQ);
          expr_ret_417->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_417->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_417 = NULL;
        }

        expr_ret_416 = expr_ret_417;
        x = expr_ret_417;
        // ModExprList 1
        if (expr_ret_416) {
          daisho_astnode_t* expr_ret_418 = NULL;
          expr_ret_418 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_416 = expr_ret_418;
          n = expr_ret_418;
        }

        // ModExprList 2
        if (expr_ret_416) {
          // CodeExpr
          #define ret expr_ret_416
          ret = SUCC;
          #line 410 "daisho.peg"
          rule=binop(x, rule, n);
          #line 8590 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_416) rew(mod_416);
        expr_ret_412 = expr_ret_416;
      }

      // SlashExpr end
      expr_ret_411 = expr_ret_412;

    }

    expr_ret_410 = SUCC;
    expr_ret_408 = expr_ret_410;
  }

  // ModExprList end
  if (!expr_ret_408) rew(mod_408);
  expr_ret_407 = expr_ret_408;
  if (!rule) rule = expr_ret_407;
  if (!expr_ret_407) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule deneqexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* le = NULL;
  daisho_astnode_t* ge = NULL;
  #define rule expr_ret_419
  daisho_astnode_t* expr_ret_419 = NULL;
  daisho_astnode_t* expr_ret_420 = NULL;
  daisho_astnode_t* expr_ret_421 = NULL;
  rec(mod_421);
  // ModExprList 0
  daisho_astnode_t* expr_ret_422 = NULL;
  expr_ret_422 = daisho_parse_shfexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_421 = expr_ret_422;
  rule = expr_ret_422;
  // ModExprList 1
  if (expr_ret_421) {
    daisho_astnode_t* expr_ret_423 = NULL;
    daisho_astnode_t* expr_ret_424 = SUCC;
    while (expr_ret_424)
    {
      rec(kleene_rew_423);
      daisho_astnode_t* expr_ret_425 = NULL;

      // SlashExpr 0
      if (!expr_ret_425) {
        daisho_astnode_t* expr_ret_426 = NULL;
        rec(mod_426);
        // ModExprList 0
        daisho_astnode_t* expr_ret_427 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_427 = leaf(LT);
          expr_ret_427->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_427->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_427 = NULL;
        }

        expr_ret_426 = expr_ret_427;
        l = expr_ret_427;
        // ModExprList 1
        if (expr_ret_426) {
          daisho_astnode_t* expr_ret_428 = NULL;
          expr_ret_428 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_426 = expr_ret_428;
          n = expr_ret_428;
        }

        // ModExprList 2
        if (expr_ret_426) {
          // CodeExpr
          #define ret expr_ret_426
          ret = SUCC;
          #line 413 "daisho.peg"
          rule=binop(l,  rule, n);
          #line 8680 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_426) rew(mod_426);
        expr_ret_425 = expr_ret_426;
      }

      // SlashExpr 1
      if (!expr_ret_425) {
        daisho_astnode_t* expr_ret_429 = NULL;
        rec(mod_429);
        // ModExprList 0
        daisho_astnode_t* expr_ret_430 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_430 = leaf(GT);
          expr_ret_430->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_430->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_430 = NULL;
        }

        expr_ret_429 = expr_ret_430;
        g = expr_ret_430;
        // ModExprList 1
        if (expr_ret_429) {
          daisho_astnode_t* expr_ret_431 = NULL;
          expr_ret_431 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_429 = expr_ret_431;
          n = expr_ret_431;
        }

        // ModExprList 2
        if (expr_ret_429) {
          // CodeExpr
          #define ret expr_ret_429
          ret = SUCC;
          #line 414 "daisho.peg"
          rule=binop(g,  rule, n);
          #line 8724 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_429) rew(mod_429);
        expr_ret_425 = expr_ret_429;
      }

      // SlashExpr 2
      if (!expr_ret_425) {
        daisho_astnode_t* expr_ret_432 = NULL;
        rec(mod_432);
        // ModExprList 0
        daisho_astnode_t* expr_ret_433 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Capturing LEQ.
          expr_ret_433 = leaf(LEQ);
          expr_ret_433->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_433->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_433 = NULL;
        }

        expr_ret_432 = expr_ret_433;
        le = expr_ret_433;
        // ModExprList 1
        if (expr_ret_432) {
          daisho_astnode_t* expr_ret_434 = NULL;
          expr_ret_434 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_432 = expr_ret_434;
          n = expr_ret_434;
        }

        // ModExprList 2
        if (expr_ret_432) {
          // CodeExpr
          #define ret expr_ret_432
          ret = SUCC;
          #line 415 "daisho.peg"
          rule=binop(le, rule, n);
          #line 8768 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_432) rew(mod_432);
        expr_ret_425 = expr_ret_432;
      }

      // SlashExpr 3
      if (!expr_ret_425) {
        daisho_astnode_t* expr_ret_435 = NULL;
        rec(mod_435);
        // ModExprList 0
        daisho_astnode_t* expr_ret_436 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Capturing GEQ.
          expr_ret_436 = leaf(GEQ);
          expr_ret_436->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_436->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_436 = NULL;
        }

        expr_ret_435 = expr_ret_436;
        ge = expr_ret_436;
        // ModExprList 1
        if (expr_ret_435) {
          daisho_astnode_t* expr_ret_437 = NULL;
          expr_ret_437 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_435 = expr_ret_437;
          n = expr_ret_437;
        }

        // ModExprList 2
        if (expr_ret_435) {
          // CodeExpr
          #define ret expr_ret_435
          ret = SUCC;
          #line 416 "daisho.peg"
          rule=binop(ge, rule, n);
          #line 8812 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_435) rew(mod_435);
        expr_ret_425 = expr_ret_435;
      }

      // SlashExpr end
      expr_ret_424 = expr_ret_425;

    }

    expr_ret_423 = SUCC;
    expr_ret_421 = expr_ret_423;
  }

  // ModExprList end
  if (!expr_ret_421) rew(mod_421);
  expr_ret_420 = expr_ret_421;
  if (!rule) rule = expr_ret_420;
  if (!expr_ret_420) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cmpexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* ll = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  daisho_astnode_t* gg = NULL;
  #define rule expr_ret_438
  daisho_astnode_t* expr_ret_438 = NULL;
  daisho_astnode_t* expr_ret_439 = NULL;
  daisho_astnode_t* expr_ret_440 = NULL;
  rec(mod_440);
  // ModExprList 0
  daisho_astnode_t* expr_ret_441 = NULL;
  expr_ret_441 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_440 = expr_ret_441;
  rule = expr_ret_441;
  // ModExprList 1
  if (expr_ret_440) {
    daisho_astnode_t* expr_ret_442 = NULL;
    daisho_astnode_t* expr_ret_443 = SUCC;
    while (expr_ret_443)
    {
      rec(kleene_rew_442);
      daisho_astnode_t* expr_ret_444 = NULL;

      // SlashExpr 0
      if (!expr_ret_444) {
        daisho_astnode_t* expr_ret_445 = NULL;
        rec(mod_445);
        // ModExprList 0
        daisho_astnode_t* expr_ret_446 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_446 = leaf(LT);
          expr_ret_446->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_446->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_446 = NULL;
        }

        expr_ret_445 = expr_ret_446;
        l = expr_ret_446;
        // ModExprList 1
        if (expr_ret_445) {
          daisho_astnode_t* expr_ret_447 = NULL;
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_447 = leaf(LT);
            expr_ret_447->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_447->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_447 = NULL;
          }

          expr_ret_445 = expr_ret_447;
          lt = expr_ret_447;
        }

        // ModExprList 2
        if (expr_ret_445) {
          daisho_astnode_t* expr_ret_448 = NULL;
          expr_ret_448 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_445 = expr_ret_448;
          n = expr_ret_448;
        }

        // ModExprList 3
        if (expr_ret_445) {
          daisho_astnode_t* expr_ret_449 = NULL;
          // CodeExpr
          #define ret expr_ret_449
          ret = SUCC;
          #line 419 "daisho.peg"
          ret=node(BSL, l, lt);
          #line 8922 "daisho.peg.h"

          #undef ret
          expr_ret_445 = expr_ret_449;
          ll = expr_ret_449;
        }

        // ModExprList 4
        if (expr_ret_445) {
          // CodeExpr
          #define ret expr_ret_445
          ret = SUCC;
          #line 420 "daisho.peg"
          rule=binop(ll, rule, n);
          #line 8936 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_445) rew(mod_445);
        expr_ret_444 = expr_ret_445;
      }

      // SlashExpr 1
      if (!expr_ret_444) {
        daisho_astnode_t* expr_ret_450 = NULL;
        rec(mod_450);
        // ModExprList 0
        daisho_astnode_t* expr_ret_451 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_451 = leaf(GT);
          expr_ret_451->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_451->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_451 = NULL;
        }

        expr_ret_450 = expr_ret_451;
        g = expr_ret_451;
        // ModExprList 1
        if (expr_ret_450) {
          daisho_astnode_t* expr_ret_452 = NULL;
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_452 = leaf(GT);
            expr_ret_452->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_452->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_452 = NULL;
          }

          expr_ret_450 = expr_ret_452;
          gt = expr_ret_452;
        }

        // ModExprList 2
        if (expr_ret_450) {
          daisho_astnode_t* expr_ret_453 = NULL;
          expr_ret_453 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_450 = expr_ret_453;
          n = expr_ret_453;
        }

        // ModExprList 3
        if (expr_ret_450) {
          daisho_astnode_t* expr_ret_454 = NULL;
          // CodeExpr
          #define ret expr_ret_454
          ret = SUCC;
          #line 421 "daisho.peg"
          ret=node(BSR, g, gt);
          #line 8998 "daisho.peg.h"

          #undef ret
          expr_ret_450 = expr_ret_454;
          gg = expr_ret_454;
        }

        // ModExprList 4
        if (expr_ret_450) {
          // CodeExpr
          #define ret expr_ret_450
          ret = SUCC;
          #line 422 "daisho.peg"
          rule=binop(gg, rule, n);
          #line 9012 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_450) rew(mod_450);
        expr_ret_444 = expr_ret_450;
      }

      // SlashExpr end
      expr_ret_443 = expr_ret_444;

    }

    expr_ret_442 = SUCC;
    expr_ret_440 = expr_ret_442;
  }

  // ModExprList end
  if (!expr_ret_440) rew(mod_440);
  expr_ret_439 = expr_ret_440;
  if (!rule) rule = expr_ret_439;
  if (!expr_ret_439) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule shfexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_455
  daisho_astnode_t* expr_ret_455 = NULL;
  daisho_astnode_t* expr_ret_456 = NULL;
  daisho_astnode_t* expr_ret_457 = NULL;
  rec(mod_457);
  // ModExprList 0
  daisho_astnode_t* expr_ret_458 = NULL;
  expr_ret_458 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_457 = expr_ret_458;
  rule = expr_ret_458;
  // ModExprList 1
  if (expr_ret_457) {
    daisho_astnode_t* expr_ret_459 = NULL;
    daisho_astnode_t* expr_ret_460 = SUCC;
    while (expr_ret_460)
    {
      rec(kleene_rew_459);
      daisho_astnode_t* expr_ret_461 = NULL;

      // SlashExpr 0
      if (!expr_ret_461) {
        daisho_astnode_t* expr_ret_462 = NULL;
        rec(mod_462);
        // ModExprList 0
        daisho_astnode_t* expr_ret_463 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_463 = leaf(PLUS);
          expr_ret_463->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_463->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_463 = NULL;
        }

        expr_ret_462 = expr_ret_463;
        p = expr_ret_463;
        // ModExprList 1
        if (expr_ret_462) {
          daisho_astnode_t* expr_ret_464 = NULL;
          expr_ret_464 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_462 = expr_ret_464;
          n = expr_ret_464;
        }

        // ModExprList 2
        if (expr_ret_462) {
          // CodeExpr
          #define ret expr_ret_462
          ret = SUCC;
          #line 425 "daisho.peg"
          rule=binop(p, rule, n);
          #line 9100 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_462) rew(mod_462);
        expr_ret_461 = expr_ret_462;
      }

      // SlashExpr 1
      if (!expr_ret_461) {
        daisho_astnode_t* expr_ret_465 = NULL;
        rec(mod_465);
        // ModExprList 0
        daisho_astnode_t* expr_ret_466 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_466 = leaf(MINUS);
          expr_ret_466->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_466->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_466 = NULL;
        }

        expr_ret_465 = expr_ret_466;
        m = expr_ret_466;
        // ModExprList 1
        if (expr_ret_465) {
          daisho_astnode_t* expr_ret_467 = NULL;
          expr_ret_467 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_465 = expr_ret_467;
          n = expr_ret_467;
        }

        // ModExprList 2
        if (expr_ret_465) {
          // CodeExpr
          #define ret expr_ret_465
          ret = SUCC;
          #line 426 "daisho.peg"
          rule=binop(m, rule, n);
          #line 9144 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_465) rew(mod_465);
        expr_ret_461 = expr_ret_465;
      }

      // SlashExpr end
      expr_ret_460 = expr_ret_461;

    }

    expr_ret_459 = SUCC;
    expr_ret_457 = expr_ret_459;
  }

  // ModExprList end
  if (!expr_ret_457) rew(mod_457);
  expr_ret_456 = expr_ret_457;
  if (!rule) rule = expr_ret_456;
  if (!expr_ret_456) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sumexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_468
  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_469 = NULL;
  daisho_astnode_t* expr_ret_470 = NULL;
  rec(mod_470);
  // ModExprList 0
  daisho_astnode_t* expr_ret_471 = NULL;
  expr_ret_471 = daisho_parse_accexpr(ctx);
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

      // SlashExpr 0
      if (!expr_ret_474) {
        daisho_astnode_t* expr_ret_475 = NULL;
        rec(mod_475);
        // ModExprList 0
        daisho_astnode_t* expr_ret_476 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Capturing STAR.
          expr_ret_476 = leaf(STAR);
          expr_ret_476->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_476->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_476 = NULL;
        }

        expr_ret_475 = expr_ret_476;
        s = expr_ret_476;
        // ModExprList 1
        if (expr_ret_475) {
          daisho_astnode_t* expr_ret_477 = NULL;
          expr_ret_477 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_475 = expr_ret_477;
          n = expr_ret_477;
        }

        // ModExprList 2
        if (expr_ret_475) {
          // CodeExpr
          #define ret expr_ret_475
          ret = SUCC;
          #line 429 "daisho.peg"
          rule=binop(s, rule, n);
          #line 9234 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_475) rew(mod_475);
        expr_ret_474 = expr_ret_475;
      }

      // SlashExpr 1
      if (!expr_ret_474) {
        daisho_astnode_t* expr_ret_478 = NULL;
        rec(mod_478);
        // ModExprList 0
        daisho_astnode_t* expr_ret_479 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Capturing DIV.
          expr_ret_479 = leaf(DIV);
          expr_ret_479->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_479->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_479 = NULL;
        }

        expr_ret_478 = expr_ret_479;
        d = expr_ret_479;
        // ModExprList 1
        if (expr_ret_478) {
          daisho_astnode_t* expr_ret_480 = NULL;
          expr_ret_480 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_478 = expr_ret_480;
          n = expr_ret_480;
        }

        // ModExprList 2
        if (expr_ret_478) {
          // CodeExpr
          #define ret expr_ret_478
          ret = SUCC;
          #line 430 "daisho.peg"
          rule=binop(d, rule, n);
          #line 9278 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_478) rew(mod_478);
        expr_ret_474 = expr_ret_478;
      }

      // SlashExpr 2
      if (!expr_ret_474) {
        daisho_astnode_t* expr_ret_481 = NULL;
        rec(mod_481);
        // ModExprList 0
        daisho_astnode_t* expr_ret_482 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Capturing MOD.
          expr_ret_482 = leaf(MOD);
          expr_ret_482->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_482->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_482 = NULL;
        }

        expr_ret_481 = expr_ret_482;
        m = expr_ret_482;
        // ModExprList 1
        if (expr_ret_481) {
          daisho_astnode_t* expr_ret_483 = NULL;
          expr_ret_483 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_481 = expr_ret_483;
          n = expr_ret_483;
        }

        // ModExprList 2
        if (expr_ret_481) {
          // CodeExpr
          #define ret expr_ret_481
          ret = SUCC;
          #line 431 "daisho.peg"
          rule=binop(m, rule, n);
          #line 9322 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_481) rew(mod_481);
        expr_ret_474 = expr_ret_481;
      }

      // SlashExpr 3
      if (!expr_ret_474) {
        daisho_astnode_t* expr_ret_484 = NULL;
        rec(mod_484);
        // ModExprList 0
        daisho_astnode_t* expr_ret_485 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Capturing POW.
          expr_ret_485 = leaf(POW);
          expr_ret_485->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_485->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_485 = NULL;
        }

        expr_ret_484 = expr_ret_485;
        p = expr_ret_485;
        // ModExprList 1
        if (expr_ret_484) {
          daisho_astnode_t* expr_ret_486 = NULL;
          expr_ret_486 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_484 = expr_ret_486;
          n = expr_ret_486;
        }

        // ModExprList 2
        if (expr_ret_484) {
          // CodeExpr
          #define ret expr_ret_484
          ret = SUCC;
          #line 432 "daisho.peg"
          rule=binop(p, rule, n);
          #line 9366 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_484) rew(mod_484);
        expr_ret_474 = expr_ret_484;
      }

      // SlashExpr end
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule multexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_487
  daisho_astnode_t* expr_ret_487 = NULL;
  daisho_astnode_t* expr_ret_488 = NULL;
  daisho_astnode_t* expr_ret_489 = NULL;
  rec(mod_489);
  // ModExprList 0
  daisho_astnode_t* expr_ret_490 = NULL;
  expr_ret_490 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_489 = expr_ret_490;
  rule = expr_ret_490;
  // ModExprList 1
  if (expr_ret_489) {
    daisho_astnode_t* expr_ret_491 = NULL;
    daisho_astnode_t* expr_ret_492 = SUCC;
    while (expr_ret_492)
    {
      rec(kleene_rew_491);
      daisho_astnode_t* expr_ret_493 = NULL;
      rec(mod_493);
      // ModExprList 0
      daisho_astnode_t* expr_ret_494 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Capturing LSBRACK.
        expr_ret_494 = leaf(LSBRACK);
        expr_ret_494->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_494->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_494 = NULL;
      }

      expr_ret_493 = expr_ret_494;
      l = expr_ret_494;
      // ModExprList 1
      if (expr_ret_493) {
        daisho_astnode_t* expr_ret_495 = NULL;
        expr_ret_495 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_493 = expr_ret_495;
        e = expr_ret_495;
      }

      // ModExprList 2
      if (expr_ret_493) {
        daisho_astnode_t* expr_ret_496 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Capturing RSBRACK.
          expr_ret_496 = leaf(RSBRACK);
          expr_ret_496->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_496->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_496 = NULL;
        }

        expr_ret_493 = expr_ret_496;
        r = expr_ret_496;
      }

      // ModExprList 3
      if (expr_ret_493) {
        daisho_astnode_t* expr_ret_497 = NULL;
        // CodeExpr
        #define ret expr_ret_497
        ret = SUCC;
        #line 435 "daisho.peg"
        ret=node(ARRAYACCESS, l, r);
        #line 9469 "daisho.peg.h"

        #undef ret
        expr_ret_493 = expr_ret_497;
        a = expr_ret_497;
      }

      // ModExprList 4
      if (expr_ret_493) {
        // CodeExpr
        #define ret expr_ret_493
        ret = SUCC;
        #line 436 "daisho.peg"
        rule=binop(a, rule, e);
        #line 9483 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_493) rew(mod_493);
      expr_ret_492 = expr_ret_493;
    }

    expr_ret_491 = SUCC;
    expr_ret_489 = expr_ret_491;
  }

  // ModExprList end
  if (!expr_ret_489) rew(mod_489);
  expr_ret_488 = expr_ret_489;
  if (!rule) rule = expr_ret_488;
  if (!expr_ret_488) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule accexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_498
  daisho_astnode_t* expr_ret_498 = NULL;
  daisho_astnode_t* expr_ret_499 = NULL;
  daisho_astnode_t* expr_ret_500 = NULL;
  rec(mod_500);
  // ModExprList 0
  daisho_astnode_t* expr_ret_501 = NULL;
  expr_ret_501 = daisho_parse_refexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_500 = expr_ret_501;
  rule = expr_ret_501;
  // ModExprList 1
  if (expr_ret_500) {
    daisho_astnode_t* expr_ret_502 = NULL;
    daisho_astnode_t* expr_ret_503 = SUCC;
    while (expr_ret_503)
    {
      rec(kleene_rew_502);
      daisho_astnode_t* expr_ret_504 = NULL;
      rec(mod_504);
      // ModExprList 0
      daisho_astnode_t* expr_ret_505 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Capturing DOT.
        expr_ret_505 = leaf(DOT);
        expr_ret_505->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_505->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_505 = NULL;
      }

      expr_ret_504 = expr_ret_505;
      d = expr_ret_505;
      // ModExprList 1
      if (expr_ret_504) {
        daisho_astnode_t* expr_ret_506 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_506 = leaf(VARIDENT);
          expr_ret_506->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_506->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_506 = NULL;
        }

        expr_ret_504 = expr_ret_506;
        i = expr_ret_506;
      }

      // ModExprList 2
      if (expr_ret_504) {
        // CodeExpr
        #define ret expr_ret_504
        ret = SUCC;
        #line 438 "daisho.peg"
        rule=binop(d, rule, i);
        #line 9569 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_504) rew(mod_504);
      expr_ret_503 = expr_ret_504;
    }

    expr_ret_502 = SUCC;
    expr_ret_500 = expr_ret_502;
  }

  // ModExprList end
  if (!expr_ret_500) rew(mod_500);
  expr_ret_499 = expr_ret_500;
  if (!rule) rule = expr_ret_499;
  if (!expr_ret_499) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule dotexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  #define rule expr_ret_507
  daisho_astnode_t* expr_ret_507 = NULL;
  daisho_astnode_t* expr_ret_508 = NULL;
  daisho_astnode_t* expr_ret_509 = NULL;
  rec(mod_509);
  // ModExprList 0
  daisho_astnode_t* expr_ret_510 = NULL;
  expr_ret_510 = daisho_parse_castexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_509 = expr_ret_510;
  rule = expr_ret_510;
  // ModExprList 1
  if (expr_ret_509) {
    daisho_astnode_t* expr_ret_511 = NULL;
    // CodeExpr
    #define ret expr_ret_511
    ret = SUCC;
    #line 443 "daisho.peg"
    ;
    #line 9617 "daisho.peg.h"

    #undef ret
    expr_ret_509 = expr_ret_511;
    op = expr_ret_511;
  }

  // ModExprList 2
  if (expr_ret_509) {
    daisho_astnode_t* expr_ret_512 = NULL;
    daisho_astnode_t* expr_ret_513 = SUCC;
    while (expr_ret_513)
    {
      rec(kleene_rew_512);
      daisho_astnode_t* expr_ret_514 = NULL;

      // SlashExpr 0
      if (!expr_ret_514) {
        daisho_astnode_t* expr_ret_515 = NULL;
        rec(mod_515);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_515 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_515 = NULL;
        }

        // ModExprList 1
        if (expr_ret_515) {
          // CodeExpr
          #define ret expr_ret_515
          ret = SUCC;
          #line 443 "daisho.peg"
          rd++;
          #line 9653 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_515) rew(mod_515);
        expr_ret_514 = expr_ret_515;
      }

      // SlashExpr 1
      if (!expr_ret_514) {
        daisho_astnode_t* expr_ret_516 = NULL;
        rec(mod_516);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_516 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_516 = NULL;
        }

        // ModExprList 1
        if (expr_ret_516) {
          // CodeExpr
          #define ret expr_ret_516
          ret = SUCC;
          #line 443 "daisho.peg"
          rd--;
          #line 9683 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_516) rew(mod_516);
        expr_ret_514 = expr_ret_516;
      }

      // SlashExpr end
      expr_ret_513 = expr_ret_514;

    }

    expr_ret_512 = SUCC;
    expr_ret_509 = expr_ret_512;
  }

  // ModExprList 3
  if (expr_ret_509) {
    // CodeExpr
    #define ret expr_ret_509
    ret = SUCC;
    #line 444 "daisho.peg"
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                op = rd > 0 ? leaf(REF) : leaf(DEREF);
                rule = unop(op, rule);
              };
    #line 9712 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_509) rew(mod_509);
  expr_ret_508 = expr_ret_509;
  if (!rule) rule = expr_ret_508;
  if (!expr_ret_508) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule refexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_517
  daisho_astnode_t* expr_ret_517 = NULL;
  daisho_astnode_t* expr_ret_518 = NULL;
  daisho_astnode_t* expr_ret_519 = NULL;
  rec(mod_519);
  // ModExprList 0
  daisho_astnode_t* expr_ret_520 = NULL;
  expr_ret_520 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_519 = expr_ret_520;
  rule = expr_ret_520;
  // ModExprList 1
  if (expr_ret_519) {
    daisho_astnode_t* expr_ret_521 = NULL;
    daisho_astnode_t* expr_ret_522 = SUCC;
    while (expr_ret_522)
    {
      rec(kleene_rew_521);
      daisho_astnode_t* expr_ret_523 = NULL;
      rec(mod_523);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_523 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_523 = NULL;
      }

      // ModExprList 1
      if (expr_ret_523) {
        daisho_astnode_t* expr_ret_524 = NULL;
        expr_ret_524 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_523 = expr_ret_524;
        t = expr_ret_524;
      }

      // ModExprList 2
      if (expr_ret_523) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_523 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_523 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_523) {
        // CodeExpr
        #define ret expr_ret_523
        ret = SUCC;
        #line 450 "daisho.peg"
        rule=node(CAST, rule, t);
        #line 9787 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_523) rew(mod_523);
      expr_ret_522 = expr_ret_523;
    }

    expr_ret_521 = SUCC;
    expr_ret_519 = expr_ret_521;
  }

  // ModExprList end
  if (!expr_ret_519) rew(mod_519);
  expr_ret_518 = expr_ret_519;
  if (!rule) rule = expr_ret_518;
  if (!expr_ret_518) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule castexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* te = NULL;
  daisho_astnode_t* el = NULL;
  #define rule expr_ret_525
  daisho_astnode_t* expr_ret_525 = NULL;
  daisho_astnode_t* expr_ret_526 = NULL;
  daisho_astnode_t* expr_ret_527 = NULL;
  rec(mod_527);
  // ModExprList 0
  daisho_astnode_t* expr_ret_528 = NULL;
  expr_ret_528 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_527 = expr_ret_528;
  rule = expr_ret_528;
  // ModExprList 1
  if (expr_ret_527) {
    daisho_astnode_t* expr_ret_529 = NULL;
    daisho_astnode_t* expr_ret_530 = NULL;
    rec(mod_530);
    // ModExprList 0
    // CodeExpr
    #define ret expr_ret_530
    ret = SUCC;
    #line 453 "daisho.peg"
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #line 9837 "daisho.peg.h"

    #undef ret
    // ModExprList 1
    if (expr_ret_530) {
      daisho_astnode_t* expr_ret_531 = NULL;
      expr_ret_531 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_530 = expr_ret_531;
      te = expr_ret_531;
    }

    // ModExprList end
    if (!expr_ret_530) rew(mod_530);
    expr_ret_529 = expr_ret_530;
    // optional
    if (!expr_ret_529)
      expr_ret_529 = SUCC;
    expr_ret_527 = expr_ret_529;
  }

  // ModExprList 2
  if (expr_ret_527) {
    daisho_astnode_t* expr_ret_532 = NULL;
    daisho_astnode_t* expr_ret_533 = SUCC;
    while (expr_ret_533)
    {
      rec(kleene_rew_532);
      daisho_astnode_t* expr_ret_534 = NULL;
      rec(mod_534);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_534 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_534 = NULL;
      }

      // ModExprList 1
      if (expr_ret_534) {
        daisho_astnode_t* expr_ret_535 = NULL;
        expr_ret_535 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_534 = expr_ret_535;
        el = expr_ret_535;
      }

      // ModExprList 2
      if (expr_ret_534) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_534 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_534 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_534) {
        // CodeExpr
        #define ret expr_ret_534
        ret = SUCC;
        #line 455 "daisho.peg"
        rule = node(CALL, rule, te, el); te=NULL;
        #line 9904 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_534) rew(mod_534);
      expr_ret_533 = expr_ret_534;
    }

    expr_ret_532 = SUCC;
    expr_ret_527 = expr_ret_532;
  }

  // ModExprList end
  if (!expr_ret_527) rew(mod_527);
  expr_ret_526 = expr_ret_527;
  if (!rule) rule = expr_ret_526;
  if (!expr_ret_526) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule callexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_536
  daisho_astnode_t* expr_ret_536 = NULL;
  daisho_astnode_t* expr_ret_537 = NULL;
  daisho_astnode_t* expr_ret_538 = NULL;
  rec(mod_538);
  // ModExprList 0
  daisho_astnode_t* expr_ret_539 = NULL;
  expr_ret_539 = daisho_parse_notexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_538 = expr_ret_539;
  rule = expr_ret_539;
  // ModExprList 1
  if (expr_ret_538) {
    daisho_astnode_t* expr_ret_540 = NULL;
    daisho_astnode_t* expr_ret_541 = NULL;

    // SlashExpr 0
    if (!expr_ret_541) {
      daisho_astnode_t* expr_ret_542 = NULL;
      rec(mod_542);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_543 = NULL;
      rec(mod_543);
      // ModExprList 0
      daisho_astnode_t* expr_ret_544 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Capturing INCR.
        expr_ret_544 = leaf(INCR);
        expr_ret_544->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_544->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_544 = NULL;
      }

      expr_ret_543 = expr_ret_544;
      i = expr_ret_544;
      // ModExprList 1
      if (expr_ret_543) {
        // CodeExpr
        #define ret expr_ret_543
        ret = SUCC;
        #line 457 "daisho.peg"
        rule=unop(i, rule);
        #line 9976 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_543) rew(mod_543);
      expr_ret_542 = expr_ret_543;
      // ModExprList end
      if (!expr_ret_542) rew(mod_542);
      expr_ret_541 = expr_ret_542;
    }

    // SlashExpr 1
    if (!expr_ret_541) {
      daisho_astnode_t* expr_ret_545 = NULL;
      rec(mod_545);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_546 = NULL;
      rec(mod_546);
      // ModExprList 0
      daisho_astnode_t* expr_ret_547 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Capturing DECR.
        expr_ret_547 = leaf(DECR);
        expr_ret_547->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_547->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_547 = NULL;
      }

      expr_ret_546 = expr_ret_547;
      d = expr_ret_547;
      // ModExprList 1
      if (expr_ret_546) {
        // CodeExpr
        #define ret expr_ret_546
        ret = SUCC;
        #line 458 "daisho.peg"
        rule=unop(d, rule);
        #line 10017 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_546) rew(mod_546);
      expr_ret_545 = expr_ret_546;
      // ModExprList end
      if (!expr_ret_545) rew(mod_545);
      expr_ret_541 = expr_ret_545;
    }

    // SlashExpr end
    expr_ret_540 = expr_ret_541;

    // optional
    if (!expr_ret_540)
      expr_ret_540 = SUCC;
    expr_ret_538 = expr_ret_540;
  }

  // ModExprList end
  if (!expr_ret_538) rew(mod_538);
  expr_ret_537 = expr_ret_538;
  if (!rule) rule = expr_ret_537;
  if (!expr_ret_537) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule increxpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_notexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_548
  daisho_astnode_t* expr_ret_548 = NULL;
  daisho_astnode_t* expr_ret_549 = NULL;
  daisho_astnode_t* expr_ret_550 = NULL;
  rec(mod_550);
  // ModExprList 0
  daisho_astnode_t* expr_ret_551 = NULL;
  expr_ret_551 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_550 = expr_ret_551;
  rule = expr_ret_551;
  // ModExprList 1
  if (expr_ret_550) {
    daisho_astnode_t* expr_ret_552 = NULL;
    daisho_astnode_t* expr_ret_553 = SUCC;
    while (expr_ret_553)
    {
      rec(kleene_rew_552);
      daisho_astnode_t* expr_ret_554 = NULL;
      rec(mod_554);
      // ModExprList 0
      daisho_astnode_t* expr_ret_555 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Capturing EXCL.
        expr_ret_555 = leaf(EXCL);
        expr_ret_555->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_555->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_555 = NULL;
      }

      expr_ret_554 = expr_ret_555;
      e = expr_ret_555;
      // ModExprList 1
      if (expr_ret_554) {
        // CodeExpr
        #define ret expr_ret_554
        ret = SUCC;
        #line 460 "daisho.peg"
        rule=unop(e, rule);
        #line 10093 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_554) rew(mod_554);
      expr_ret_553 = expr_ret_554;
    }

    expr_ret_552 = SUCC;
    expr_ret_550 = expr_ret_552;
  }

  // ModExprList end
  if (!expr_ret_550) rew(mod_550);
  expr_ret_549 = expr_ret_550;
  if (!rule) rule = expr_ret_549;
  if (!expr_ret_549) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule notexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_556
  daisho_astnode_t* expr_ret_556 = NULL;
  daisho_astnode_t* expr_ret_557 = NULL;
  daisho_astnode_t* expr_ret_558 = NULL;

  // SlashExpr 0
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_559 = NULL;
    rec(mod_559);
    // ModExprList Forwarding
    expr_ret_559 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_559) rew(mod_559);
    expr_ret_558 = expr_ret_559;
  }

  // SlashExpr 1
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_560 = NULL;
    rec(mod_560);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_560 = leaf(VARIDENT);
      expr_ret_560->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_560->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_560 = NULL;
    }

    // ModExprList end
    if (!expr_ret_560) rew(mod_560);
    expr_ret_558 = expr_ret_560;
  }

  // SlashExpr 2
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_561 = NULL;
    rec(mod_561);
    // ModExprList Forwarding
    expr_ret_561 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_561) rew(mod_561);
    expr_ret_558 = expr_ret_561;
  }

  // SlashExpr 3
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_562 = NULL;
    rec(mod_562);
    // ModExprList Forwarding
    expr_ret_562 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_562) rew(mod_562);
    expr_ret_558 = expr_ret_562;
  }

  // SlashExpr 4
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_563 = NULL;
    rec(mod_563);
    // ModExprList Forwarding
    expr_ret_563 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_563) rew(mod_563);
    expr_ret_558 = expr_ret_563;
  }

  // SlashExpr 5
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_564 = NULL;
    rec(mod_564);
    // ModExprList Forwarding
    expr_ret_564 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_564) rew(mod_564);
    expr_ret_558 = expr_ret_564;
  }

  // SlashExpr 6
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_565 = NULL;
    rec(mod_565);
    // ModExprList Forwarding
    expr_ret_565 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_565) rew(mod_565);
    expr_ret_558 = expr_ret_565;
  }

  // SlashExpr 7
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_566 = NULL;
    rec(mod_566);
    // ModExprList Forwarding
    expr_ret_566 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_566) rew(mod_566);
    expr_ret_558 = expr_ret_566;
  }

  // SlashExpr 8
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_567 = NULL;
    rec(mod_567);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_567 = leaf(NUMLIT);
      expr_ret_567->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_567->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_567 = NULL;
    }

    // ModExprList end
    if (!expr_ret_567) rew(mod_567);
    expr_ret_558 = expr_ret_567;
  }

  // SlashExpr 9
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_568 = NULL;
    rec(mod_568);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_568 = leaf(SELFVAR);
      expr_ret_568->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_568->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_568 = NULL;
    }

    // ModExprList end
    if (!expr_ret_568) rew(mod_568);
    expr_ret_558 = expr_ret_568;
  }

  // SlashExpr 10
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_569 = NULL;
    rec(mod_569);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CHARLIT) {
      // Capturing CHARLIT.
      expr_ret_569 = leaf(CHARLIT);
      expr_ret_569->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_569->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_569 = NULL;
    }

    // ModExprList end
    if (!expr_ret_569) rew(mod_569);
    expr_ret_558 = expr_ret_569;
  }

  // SlashExpr 11
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_570 = NULL;
    rec(mod_570);
    // ModExprList Forwarding
    expr_ret_570 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_570) rew(mod_570);
    expr_ret_558 = expr_ret_570;
  }

  // SlashExpr 12
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_571 = NULL;
    rec(mod_571);
    // ModExprList Forwarding
    expr_ret_571 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_571) rew(mod_571);
    expr_ret_558 = expr_ret_571;
  }

  // SlashExpr 13
  if (!expr_ret_558) {
    daisho_astnode_t* expr_ret_572 = NULL;
    rec(mod_572);
    // ModExprList Forwarding
    expr_ret_572 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_572) rew(mod_572);
    expr_ret_558 = expr_ret_572;
  }

  // SlashExpr end
  expr_ret_557 = expr_ret_558;

  if (!rule) rule = expr_ret_557;
  if (!expr_ret_557) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule atomexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  int skip=0;

  daisho_astnode_t* e = NULL;
  #define rule expr_ret_573
  daisho_astnode_t* expr_ret_573 = NULL;
  daisho_astnode_t* expr_ret_574 = NULL;
  daisho_astnode_t* expr_ret_575 = NULL;
  rec(mod_575);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_575 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_575 = NULL;
  }

  // ModExprList 1
  if (expr_ret_575) {
    // CodeExpr
    #define ret expr_ret_575
    ret = SUCC;
    #line 583 "daisho.peg"
    rule=list(BLOCK);
    #line 10358 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_575) {
    daisho_astnode_t* expr_ret_576 = NULL;
    daisho_astnode_t* expr_ret_577 = SUCC;
    while (expr_ret_577)
    {
      rec(kleene_rew_576);
      daisho_astnode_t* expr_ret_578 = NULL;
      rec(mod_578);
      // ModExprList 0
      // CodeExpr
      #define ret expr_ret_578
      ret = SUCC;
      #line 584 "daisho.peg"
      if (skip) ret=NULL;
      #line 10378 "daisho.peg.h"

      #undef ret
      // ModExprList 1
      if (expr_ret_578) {
        rec(mexpr_state_579)
        daisho_astnode_t* expr_ret_579 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
          // Not capturing RCBRACK.
          expr_ret_579 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_579 = NULL;
        }

        // invert
        expr_ret_579 = expr_ret_579 ? NULL : SUCC;
        // rewind
        rew(mexpr_state_579);
        expr_ret_578 = expr_ret_579;
      }

      // ModExprList 2
      if (expr_ret_578) {
        daisho_astnode_t* expr_ret_580 = NULL;
        expr_ret_580 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        // optional
        if (!expr_ret_580)
          expr_ret_580 = SUCC;
        expr_ret_578 = expr_ret_580;
        e = expr_ret_580;
      }

      // ModExprList 3
      if (expr_ret_578) {
        // CodeExpr
        #define ret expr_ret_578
        ret = SUCC;
        #line 585 "daisho.peg"
        if(has(e)) add(rule, e);
        #line 10419 "daisho.peg.h"

        #undef ret
      }

      // ModExprList 4
      if (expr_ret_578) {
        daisho_astnode_t* expr_ret_581 = NULL;

        // SlashExpr 0
        if (!expr_ret_581) {
          daisho_astnode_t* expr_ret_582 = NULL;
          rec(mod_582);
          // ModExprList Forwarding
          expr_ret_582 = daisho_parse_semiornl(ctx);
          if (ctx->exit) return NULL;
          // ModExprList end
          if (!expr_ret_582) rew(mod_582);
          expr_ret_581 = expr_ret_582;
        }

        // SlashExpr 1
        if (!expr_ret_581) {
          daisho_astnode_t* expr_ret_583 = NULL;
          rec(mod_583);
          // ModExprList Forwarding
          // CodeExpr
          #define ret expr_ret_583
          ret = SUCC;
          #line 586 "daisho.peg"
          skip=1;
          #line 10450 "daisho.peg.h"

          #undef ret
          // ModExprList end
          if (!expr_ret_583) rew(mod_583);
          expr_ret_581 = expr_ret_583;
        }

        // SlashExpr end
        expr_ret_578 = expr_ret_581;

      }

      // ModExprList end
      if (!expr_ret_578) rew(mod_578);
      expr_ret_577 = expr_ret_578;
    }

    expr_ret_576 = SUCC;
    expr_ret_575 = expr_ret_576;
  }

  // ModExprList 3
  if (expr_ret_575) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_575 = leaf(RCBRACK);
      expr_ret_575->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_575->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_575 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_575) rew(mod_575);
  expr_ret_574 = expr_ret_575;
  if (!rule) rule = expr_ret_574;
  if (!expr_ret_574) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule blockexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_584
  daisho_astnode_t* expr_ret_584 = NULL;
  daisho_astnode_t* expr_ret_585 = NULL;
  daisho_astnode_t* expr_ret_586 = NULL;
  rec(mod_586);
  // ModExprList 0
  daisho_astnode_t* expr_ret_587 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
    // Capturing TYPEIDENT.
    expr_ret_587 = leaf(TYPEIDENT);
    expr_ret_587->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_587->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_587 = NULL;
  }

  expr_ret_586 = expr_ret_587;
  ns = expr_ret_587;
  // ModExprList 1
  if (expr_ret_586) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
      // Not capturing DOT.
      expr_ret_586 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_586 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_586) {
    daisho_astnode_t* expr_ret_588 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_588 = leaf(VARIDENT);
      expr_ret_588->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_588->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_588 = NULL;
    }

    expr_ret_586 = expr_ret_588;
    v = expr_ret_588;
  }

  // ModExprList 3
  if (expr_ret_586) {
    // CodeExpr
    #define ret expr_ret_586
    ret = SUCC;
    #line 590 "daisho.peg"
    rule=node(NSACCESS, ns, v);
    #line 10554 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_586) rew(mod_586);
  expr_ret_585 = expr_ret_586;
  if (!rule) rule = expr_ret_585;
  if (!expr_ret_585) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nsexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_589
  daisho_astnode_t* expr_ret_589 = NULL;
  daisho_astnode_t* expr_ret_590 = NULL;
  daisho_astnode_t* expr_ret_591 = NULL;
  rec(mod_591);
  // ModExprList 0
  daisho_astnode_t* expr_ret_592 = NULL;
  rec(mod_592);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_592 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_592 = NULL;
  }

  // ModExprList 1
  if (expr_ret_592) {
    daisho_astnode_t* expr_ret_593 = NULL;
    daisho_astnode_t* expr_ret_594 = NULL;

    // SlashExpr 0
    if (!expr_ret_594) {
      daisho_astnode_t* expr_ret_595 = NULL;
      rec(mod_595);
      // ModExprList 0
      rec(mexpr_state_596)
      daisho_astnode_t* expr_ret_596 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_596 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_596 = NULL;
      }

      // invert
      expr_ret_596 = expr_ret_596 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_596);
      expr_ret_595 = expr_ret_596;
      // ModExprList 1
      if (expr_ret_595) {
        daisho_astnode_t* expr_ret_597 = NULL;
        expr_ret_597 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_595 = expr_ret_597;
        al = expr_ret_597;
      }

      // ModExprList end
      if (!expr_ret_595) rew(mod_595);
      expr_ret_594 = expr_ret_595;
    }

    // SlashExpr 1
    if (!expr_ret_594) {
      daisho_astnode_t* expr_ret_598 = NULL;
      rec(mod_598);
      // ModExprList Forwarding
      // CodeExpr
      #define ret expr_ret_598
      ret = SUCC;
      #line 592 "daisho.peg"
      al=leaf(ARGLIST);
      #line 10638 "daisho.peg.h"

      #undef ret
      // ModExprList end
      if (!expr_ret_598) rew(mod_598);
      expr_ret_594 = expr_ret_598;
    }

    // SlashExpr end
    expr_ret_593 = expr_ret_594;

    // optional
    if (!expr_ret_593)
      expr_ret_593 = SUCC;
    expr_ret_592 = expr_ret_593;
  }

  // ModExprList 2
  if (expr_ret_592) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_592 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_592 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_592) rew(mod_592);
  expr_ret_591 = expr_ret_592;
  // ModExprList 1
  if (expr_ret_591) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_591 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_591 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_591) {
    daisho_astnode_t* expr_ret_599 = NULL;
    expr_ret_599 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_591 = expr_ret_599;
    e = expr_ret_599;
  }

  // ModExprList 3
  if (expr_ret_591) {
    // CodeExpr
    #define ret expr_ret_591
    ret = SUCC;
    #line 594 "daisho.peg"
    rule=node(LAMBDA, al, e);
    #line 10698 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_591) rew(mod_591);
  expr_ret_590 = expr_ret_591;
  if (!rule) rule = expr_ret_590;
  if (!expr_ret_590) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule lambdaexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* en = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* in = NULL;
  daisho_astnode_t* cond = NULL;
  #define rule expr_ret_600
  daisho_astnode_t* expr_ret_600 = NULL;
  daisho_astnode_t* expr_ret_601 = NULL;
  daisho_astnode_t* expr_ret_602 = NULL;
  rec(mod_602);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_602 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_602 = NULL;
  }

  // ModExprList 1
  if (expr_ret_602) {
    daisho_astnode_t* expr_ret_603 = NULL;
    daisho_astnode_t* expr_ret_604 = NULL;
    rec(mod_604);
    // ModExprList 0
    daisho_astnode_t* expr_ret_605 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_605 = leaf(VARIDENT);
      expr_ret_605->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_605->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_605 = NULL;
    }

    expr_ret_604 = expr_ret_605;
    en = expr_ret_605;
    // ModExprList 1
    if (expr_ret_604) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_604 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_604 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_604) rew(mod_604);
    expr_ret_603 = expr_ret_604;
    // optional
    if (!expr_ret_603)
      expr_ret_603 = SUCC;
    expr_ret_602 = expr_ret_603;
  }

  // ModExprList 2
  if (expr_ret_602) {
    daisho_astnode_t* expr_ret_606 = NULL;
    expr_ret_606 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_602 = expr_ret_606;
    e = expr_ret_606;
  }

  // ModExprList 3
  if (expr_ret_602) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_602 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_602 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_602) {
    daisho_astnode_t* expr_ret_607 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_607 = leaf(VARIDENT);
      expr_ret_607->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_607->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_607 = NULL;
    }

    expr_ret_602 = expr_ret_607;
    item = expr_ret_607;
  }

  // ModExprList 5
  if (expr_ret_602) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_602 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_602 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_602) {
    daisho_astnode_t* expr_ret_608 = NULL;
    expr_ret_608 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_602 = expr_ret_608;
    in = expr_ret_608;
  }

  // ModExprList 7
  if (expr_ret_602) {
    daisho_astnode_t* expr_ret_609 = NULL;
    daisho_astnode_t* expr_ret_610 = NULL;
    rec(mod_610);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_610 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_610 = NULL;
    }

    // ModExprList 1
    if (expr_ret_610) {
      daisho_astnode_t* expr_ret_611 = NULL;
      expr_ret_611 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_610 = expr_ret_611;
      cond = expr_ret_611;
    }

    // ModExprList end
    if (!expr_ret_610) rew(mod_610);
    expr_ret_609 = expr_ret_610;
    // optional
    if (!expr_ret_609)
      expr_ret_609 = SUCC;
    expr_ret_602 = expr_ret_609;
  }

  // ModExprList 8
  if (expr_ret_602) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_602 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_602 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_602) {
    // CodeExpr
    #define ret expr_ret_602
    ret = SUCC;
    #line 603 "daisho.peg"
    rule = list(LISTCOMP);
              if (en) add(rule, node(COMPENUMERATE, en));
              add(rule, e);add(rule, item);add(rule, in);
              if (cond) add(rule, node(COMPCOND, cond));;
    #line 10886 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_602) rew(mod_602);
  expr_ret_601 = expr_ret_602;
  if (!rule) rule = expr_ret_601;
  if (!expr_ret_601) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listcomp returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_612
  daisho_astnode_t* expr_ret_612 = NULL;
  daisho_astnode_t* expr_ret_613 = NULL;
  daisho_astnode_t* expr_ret_614 = NULL;

  // SlashExpr 0
  if (!expr_ret_614) {
    daisho_astnode_t* expr_ret_615 = NULL;
    rec(mod_615);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_615 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_615 = NULL;
    }

    // ModExprList 1
    if (expr_ret_615) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Not capturing EXCL.
        expr_ret_615 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_615 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_615) {
      daisho_astnode_t* expr_ret_616 = NULL;
      expr_ret_616 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_615 = expr_ret_616;
      r = expr_ret_616;
    }

    // ModExprList 3
    if (expr_ret_615) {
      // CodeExpr
      #define ret expr_ret_615
      ret = SUCC;
      #line 608 "daisho.peg"
      rule=node(EXCL, r);
      #line 10949 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 4
    if (expr_ret_615) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_615 = leaf(CLOSE);
        expr_ret_615->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_615->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_615 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_615) rew(mod_615);
    expr_ret_614 = expr_ret_615;
  }

  // SlashExpr 1
  if (!expr_ret_614) {
    daisho_astnode_t* expr_ret_617 = NULL;
    rec(mod_617);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_617 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_617 = NULL;
    }

    // ModExprList 1
    if (expr_ret_617) {
      daisho_astnode_t* expr_ret_618 = NULL;
      expr_ret_618 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_617 = expr_ret_618;
      r = expr_ret_618;
    }

    // ModExprList 2
    if (expr_ret_617) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_617 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_617 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_617) {
      // CodeExpr
      #define ret expr_ret_617
      ret = SUCC;
      #line 609 "daisho.peg"
      rule=r;
      #line 11014 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_617) rew(mod_617);
    expr_ret_614 = expr_ret_617;
  }

  // SlashExpr end
  expr_ret_613 = expr_ret_614;

  if (!rule) rule = expr_ret_613;
  if (!expr_ret_613) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule parenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_619
  daisho_astnode_t* expr_ret_619 = NULL;
  daisho_astnode_t* expr_ret_620 = NULL;
  daisho_astnode_t* expr_ret_621 = NULL;
  rec(mod_621);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_621 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_621 = NULL;
  }

  // ModExprList 1
  if (expr_ret_621) {
    daisho_astnode_t* expr_ret_622 = NULL;
    expr_ret_622 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_621 = expr_ret_622;
    rule = expr_ret_622;
  }

  // ModExprList 2
  if (expr_ret_621) {
    // CodeExpr
    #define ret expr_ret_621
    ret = SUCC;
    #line 612 "daisho.peg"
    rule->kind = kind(LISTLIT);
    #line 11066 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_621) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_621 = leaf(RSBRACK);
      expr_ret_621->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_621->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_621 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_621) rew(mod_621);
  expr_ret_620 = expr_ret_621;
  if (!rule) rule = expr_ret_620;
  if (!expr_ret_620) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_623
  daisho_astnode_t* expr_ret_623 = NULL;
  daisho_astnode_t* expr_ret_624 = NULL;
  daisho_astnode_t* expr_ret_625 = NULL;
  rec(mod_625);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_625 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_625 = NULL;
  }

  // ModExprList 1
  if (expr_ret_625) {
    daisho_astnode_t* expr_ret_626 = NULL;
    expr_ret_626 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_625 = expr_ret_626;
    rule = expr_ret_626;
  }

  // ModExprList 2
  if (expr_ret_625) {
    // CodeExpr
    #define ret expr_ret_625
    ret = SUCC;
    #line 616 "daisho.peg"
    rule->kind = kind(TUPLELIT);
    #line 11127 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_625) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_625 = leaf(CLOSE);
      expr_ret_625->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_625->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_625 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_625) rew(mod_625);
  expr_ret_624 = expr_ret_625;
  if (!rule) rule = expr_ret_624;
  if (!expr_ret_624) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tuplelit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_627
  daisho_astnode_t* expr_ret_627 = NULL;
  daisho_astnode_t* expr_ret_628 = NULL;
  daisho_astnode_t* expr_ret_629 = NULL;
  rec(mod_629);
  // ModExprList 0
  daisho_astnode_t* expr_ret_630 = NULL;
  expr_ret_630 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_629 = expr_ret_630;
  t = expr_ret_630;
  // ModExprList 1
  if (expr_ret_629) {
    daisho_astnode_t* expr_ret_631 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_631 = leaf(VARIDENT);
      expr_ret_631->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_631->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_631 = NULL;
    }

    expr_ret_629 = expr_ret_631;
    i = expr_ret_631;
  }

  // ModExprList 2
  if (expr_ret_629) {
    // CodeExpr
    #define ret expr_ret_629
    ret = SUCC;
    #line 624 "daisho.peg"
    rule=node(VARDECL, t, i);
    #line 11194 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_629) rew(mod_629);
  expr_ret_628 = expr_ret_629;
  if (!rule) rule = expr_ret_628;
  if (!expr_ret_628) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule vardeclexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_632
  daisho_astnode_t* expr_ret_632 = NULL;
  daisho_astnode_t* expr_ret_633 = NULL;
  daisho_astnode_t* expr_ret_634 = NULL;

  // SlashExpr 0
  if (!expr_ret_634) {
    daisho_astnode_t* expr_ret_635 = NULL;
    rec(mod_635);
    // ModExprList Forwarding
    expr_ret_635 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_635) rew(mod_635);
    expr_ret_634 = expr_ret_635;
  }

  // SlashExpr 1
  if (!expr_ret_634) {
    daisho_astnode_t* expr_ret_636 = NULL;
    rec(mod_636);
    // ModExprList Forwarding
    expr_ret_636 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_636) rew(mod_636);
    expr_ret_634 = expr_ret_636;
  }

  // SlashExpr end
  expr_ret_633 = expr_ret_634;

  if (!rule) rule = expr_ret_633;
  if (!expr_ret_633) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule strlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_637
  daisho_astnode_t* expr_ret_637 = NULL;
  daisho_astnode_t* expr_ret_638 = NULL;
  daisho_astnode_t* expr_ret_639 = NULL;
  rec(mod_639);
  // ModExprList 0
  daisho_astnode_t* expr_ret_640 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_640 = leaf(STRLIT);
    expr_ret_640->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_640->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_640 = NULL;
  }

  expr_ret_639 = expr_ret_640;
  s = expr_ret_640;
  // ModExprList 1
  if (expr_ret_639) {
    // CodeExpr
    #define ret expr_ret_639
    ret = SUCC;
    #line 629 "daisho.peg"
    rule=list(SSTR); add(rule, s);
    #line 11277 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_639) {
    daisho_astnode_t* expr_ret_641 = NULL;
    daisho_astnode_t* expr_ret_642 = SUCC;
    while (expr_ret_642)
    {
      rec(kleene_rew_641);
      daisho_astnode_t* expr_ret_643 = NULL;
      rec(mod_643);
      // ModExprList 0
      daisho_astnode_t* expr_ret_644 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_644 = leaf(STRLIT);
        expr_ret_644->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_644->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_644 = NULL;
      }

      expr_ret_643 = expr_ret_644;
      s = expr_ret_644;
      // ModExprList 1
      if (expr_ret_643) {
        // CodeExpr
        #define ret expr_ret_643
        ret = SUCC;
        #line 630 "daisho.peg"
        add(rule, s);
        #line 11312 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_643) rew(mod_643);
      expr_ret_642 = expr_ret_643;
    }

    expr_ret_641 = SUCC;
    expr_ret_639 = expr_ret_641;
  }

  // ModExprList end
  if (!expr_ret_639) rew(mod_639);
  expr_ret_638 = expr_ret_639;
  if (!rule) rule = expr_ret_638;
  if (!expr_ret_638) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_645
  daisho_astnode_t* expr_ret_645 = NULL;
  daisho_astnode_t* expr_ret_646 = NULL;
  daisho_astnode_t* expr_ret_647 = NULL;
  rec(mod_647);
  // ModExprList 0
  daisho_astnode_t* expr_ret_648 = NULL;
  expr_ret_648 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_647 = expr_ret_648;
  f = expr_ret_648;
  // ModExprList 1
  if (expr_ret_647) {
    // CodeExpr
    #define ret expr_ret_647
    ret = SUCC;
    #line 632 "daisho.peg"
    rule=list(FSTR); add(rule, f);
    #line 11356 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_647) {
    daisho_astnode_t* expr_ret_649 = NULL;
    daisho_astnode_t* expr_ret_650 = SUCC;
    while (expr_ret_650)
    {
      rec(kleene_rew_649);
      daisho_astnode_t* expr_ret_651 = NULL;
      rec(mod_651);
      // ModExprList 0
      daisho_astnode_t* expr_ret_652 = NULL;
      expr_ret_652 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_651 = expr_ret_652;
      f = expr_ret_652;
      // ModExprList 1
      if (expr_ret_651) {
        // CodeExpr
        #define ret expr_ret_651
        ret = SUCC;
        #line 633 "daisho.peg"
        add(rule, f);
        #line 11383 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_651) rew(mod_651);
      expr_ret_650 = expr_ret_651;
    }

    expr_ret_649 = SUCC;
    expr_ret_647 = expr_ret_649;
  }

  // ModExprList end
  if (!expr_ret_647) rew(mod_647);
  expr_ret_646 = expr_ret_647;
  if (!rule) rule = expr_ret_646;
  if (!expr_ret_646) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_653
  daisho_astnode_t* expr_ret_653 = NULL;
  daisho_astnode_t* expr_ret_654 = NULL;
  daisho_astnode_t* expr_ret_655 = NULL;

  // SlashExpr 0
  if (!expr_ret_655) {
    daisho_astnode_t* expr_ret_656 = NULL;
    rec(mod_656);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_656 = leaf(STRLIT);
      expr_ret_656->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_656->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_656 = NULL;
    }

    // ModExprList end
    if (!expr_ret_656) rew(mod_656);
    expr_ret_655 = expr_ret_656;
  }

  // SlashExpr 1
  if (!expr_ret_655) {
    daisho_astnode_t* expr_ret_657 = NULL;
    rec(mod_657);
    // ModExprList 0
    daisho_astnode_t* expr_ret_658 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_658 = leaf(FSTRLITSTART);
      expr_ret_658->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_658->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_658 = NULL;
    }

    expr_ret_657 = expr_ret_658;
    s = expr_ret_658;
    // ModExprList 1
    if (expr_ret_657) {
      // CodeExpr
      #define ret expr_ret_657
      ret = SUCC;
      #line 636 "daisho.peg"
      rule=list(FSTRFRAG); add(rule, s);
      #line 11462 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_657) {
      daisho_astnode_t* expr_ret_659 = NULL;
      expr_ret_659 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_657 = expr_ret_659;
      x = expr_ret_659;
    }

    // ModExprList 3
    if (expr_ret_657) {
      // CodeExpr
      #define ret expr_ret_657
      ret = SUCC;
      #line 637 "daisho.peg"
      add(rule, x);
      #line 11483 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 4
    if (expr_ret_657) {
      daisho_astnode_t* expr_ret_660 = NULL;
      daisho_astnode_t* expr_ret_661 = SUCC;
      while (expr_ret_661)
      {
        rec(kleene_rew_660);
        daisho_astnode_t* expr_ret_662 = NULL;
        rec(mod_662);
        // ModExprList 0
        daisho_astnode_t* expr_ret_663 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_663 = leaf(FSTRLITMID);
          expr_ret_663->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_663->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_663 = NULL;
        }

        expr_ret_662 = expr_ret_663;
        m = expr_ret_663;
        // ModExprList 1
        if (expr_ret_662) {
          daisho_astnode_t* expr_ret_664 = NULL;
          expr_ret_664 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_662 = expr_ret_664;
          x = expr_ret_664;
        }

        // ModExprList 2
        if (expr_ret_662) {
          // CodeExpr
          #define ret expr_ret_662
          ret = SUCC;
          #line 638 "daisho.peg"
          add(rule, m); add(rule, x);
          #line 11527 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_662) rew(mod_662);
        expr_ret_661 = expr_ret_662;
      }

      expr_ret_660 = SUCC;
      expr_ret_657 = expr_ret_660;
    }

    // ModExprList 5
    if (expr_ret_657) {
      daisho_astnode_t* expr_ret_665 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_665 = leaf(FSTRLITEND);
        expr_ret_665->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_665->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_665 = NULL;
      }

      expr_ret_657 = expr_ret_665;
      e = expr_ret_665;
    }

    // ModExprList 6
    if (expr_ret_657) {
      // CodeExpr
      #define ret expr_ret_657
      ret = SUCC;
      #line 639 "daisho.peg"
      add(rule, e);
      #line 11565 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_657) rew(mod_657);
    expr_ret_655 = expr_ret_657;
  }

  // SlashExpr end
  expr_ret_654 = expr_ret_655;

  if (!rule) rule = expr_ret_654;
  if (!expr_ret_654) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrfrag returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_666
  daisho_astnode_t* expr_ret_666 = NULL;
  daisho_astnode_t* expr_ret_667 = NULL;
  daisho_astnode_t* expr_ret_668 = NULL;
  rec(mod_668);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_668 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_668 = NULL;
  }

  // ModExprList 1
  if (expr_ret_668) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_668 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_668 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_668) {
    daisho_astnode_t* expr_ret_669 = NULL;
    daisho_astnode_t* expr_ret_670 = NULL;

    // SlashExpr 0
    if (!expr_ret_670) {
      daisho_astnode_t* expr_ret_671 = NULL;
      rec(mod_671);
      // ModExprList Forwarding
      expr_ret_671 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_671) rew(mod_671);
      expr_ret_670 = expr_ret_671;
    }

    // SlashExpr 1
    if (!expr_ret_670) {
      daisho_astnode_t* expr_ret_672 = NULL;
      rec(mod_672);
      // ModExprList Forwarding
      expr_ret_672 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_672) rew(mod_672);
      expr_ret_670 = expr_ret_672;
    }

    // SlashExpr end
    expr_ret_669 = expr_ret_670;

    expr_ret_668 = expr_ret_669;
    te = expr_ret_669;
  }

  // ModExprList 3
  if (expr_ret_668) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_668 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_668 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_668) {
    // CodeExpr
    #define ret expr_ret_668
    ret = SUCC;
    #line 641 "daisho.peg"
    rule=node(SIZEOF, te);
    #line 11668 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_668) rew(mod_668);
  expr_ret_667 = expr_ret_668;
  if (!rule) rule = expr_ret_667;
  if (!expr_ret_667) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sizeofexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_673
  daisho_astnode_t* expr_ret_673 = NULL;
  daisho_astnode_t* expr_ret_674 = NULL;
  daisho_astnode_t* expr_ret_675 = NULL;
  rec(mod_675);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVE) {
    // Not capturing NATIVE.
    expr_ret_675 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_675 = NULL;
  }

  // ModExprList 1
  if (expr_ret_675) {
    daisho_astnode_t* expr_ret_676 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVEBODY) {
      // Capturing NATIVEBODY.
      expr_ret_676 = leaf(NATIVEBODY);
      expr_ret_676->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_676->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_676 = NULL;
    }

    expr_ret_675 = expr_ret_676;
    rule = expr_ret_676;
  }

  // ModExprList end
  if (!expr_ret_675) rew(mod_675);
  expr_ret_674 = expr_ret_675;
  if (!rule) rule = expr_ret_674;
  if (!expr_ret_674) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nativeexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_677
  daisho_astnode_t* expr_ret_677 = NULL;
  daisho_astnode_t* expr_ret_678 = NULL;
  daisho_astnode_t* expr_ret_679 = NULL;
  rec(mod_679);
  // ModExprList 0
  daisho_astnode_t* expr_ret_680 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
    // Capturing VARIDENT.
    expr_ret_680 = leaf(VARIDENT);
    expr_ret_680->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_680->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_680 = NULL;
  }

  expr_ret_679 = expr_ret_680;
  rule = expr_ret_680;
  // ModExprList 1
  if (expr_ret_679) {
    // CodeExpr
    #define ret expr_ret_679
    ret = SUCC;
    #line 693 "daisho.peg"
    
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
    #line 11766 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_679) rew(mod_679);
  expr_ret_678 = expr_ret_679;
  if (!rule) rule = expr_ret_678;
  if (!expr_ret_678) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cident returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_681
  daisho_astnode_t* expr_ret_681 = NULL;
  daisho_astnode_t* expr_ret_682 = NULL;
  daisho_astnode_t* expr_ret_683 = NULL;

  // SlashExpr 0
  if (!expr_ret_683) {
    daisho_astnode_t* expr_ret_684 = NULL;
    rec(mod_684);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_684 = leaf(SEMI);
      expr_ret_684->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_684->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_684 = NULL;
    }

    // ModExprList end
    if (!expr_ret_684) rew(mod_684);
    expr_ret_683 = expr_ret_684;
  }

  // SlashExpr 1
  if (!expr_ret_683) {
    daisho_astnode_t* expr_ret_685 = NULL;
    rec(mod_685);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_685
    ret = SUCC;
    #line 708 "daisho.peg"
    ret = (ctx->pos >= ctx->len ||
                      ctx->tokens[ctx->pos - 1].line < ctx->tokens[ctx->pos].line)
                      ? leaf(SEMI)
                      : NULL;
    #line 11820 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_685) rew(mod_685);
    expr_ret_683 = expr_ret_685;
  }

  // SlashExpr end
  expr_ret_682 = expr_ret_683;

  if (!rule) rule = expr_ret_682;
  if (!expr_ret_682) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule semiornl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx) {
  #define rule expr_ret_686
  daisho_astnode_t* expr_ret_686 = NULL;
  daisho_astnode_t* expr_ret_687 = NULL;
  daisho_astnode_t* expr_ret_688 = NULL;

  // SlashExpr 0
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_689 = NULL;
    rec(mod_689);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_689 = leaf(VARIDENT);
      expr_ret_689->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_689->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_689 = NULL;
    }

    // ModExprList end
    if (!expr_ret_689) rew(mod_689);
    expr_ret_688 = expr_ret_689;
  }

  // SlashExpr 1
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_690 = NULL;
    rec(mod_690);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
      // Capturing PLUS.
      expr_ret_690 = leaf(PLUS);
      expr_ret_690->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_690->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_690 = NULL;
    }

    // ModExprList end
    if (!expr_ret_690) rew(mod_690);
    expr_ret_688 = expr_ret_690;
  }

  // SlashExpr 2
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_691 = NULL;
    rec(mod_691);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
      // Capturing MINUS.
      expr_ret_691 = leaf(MINUS);
      expr_ret_691->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_691->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_691 = NULL;
    }

    // ModExprList end
    if (!expr_ret_691) rew(mod_691);
    expr_ret_688 = expr_ret_691;
  }

  // SlashExpr 3
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_692 = NULL;
    rec(mod_692);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
      // Capturing STAR.
      expr_ret_692 = leaf(STAR);
      expr_ret_692->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_692->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_692 = NULL;
    }

    // ModExprList end
    if (!expr_ret_692) rew(mod_692);
    expr_ret_688 = expr_ret_692;
  }

  // SlashExpr 4
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_693 = NULL;
    rec(mod_693);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
      // Capturing POW.
      expr_ret_693 = leaf(POW);
      expr_ret_693->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_693->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_693 = NULL;
    }

    // ModExprList end
    if (!expr_ret_693) rew(mod_693);
    expr_ret_688 = expr_ret_693;
  }

  // SlashExpr 5
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_694 = NULL;
    rec(mod_694);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
      // Capturing DIV.
      expr_ret_694 = leaf(DIV);
      expr_ret_694->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_694->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_694 = NULL;
    }

    // ModExprList end
    if (!expr_ret_694) rew(mod_694);
    expr_ret_688 = expr_ret_694;
  }

  // SlashExpr 6
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_695 = NULL;
    rec(mod_695);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
      // Capturing MOD.
      expr_ret_695 = leaf(MOD);
      expr_ret_695->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_695->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_695 = NULL;
    }

    // ModExprList end
    if (!expr_ret_695) rew(mod_695);
    expr_ret_688 = expr_ret_695;
  }

  // SlashExpr 7
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_696 = NULL;
    rec(mod_696);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
      // Capturing AND.
      expr_ret_696 = leaf(AND);
      expr_ret_696->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_696->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_696 = NULL;
    }

    // ModExprList end
    if (!expr_ret_696) rew(mod_696);
    expr_ret_688 = expr_ret_696;
  }

  // SlashExpr 8
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_697 = NULL;
    rec(mod_697);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
      // Capturing OR.
      expr_ret_697 = leaf(OR);
      expr_ret_697->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_697->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_697 = NULL;
    }

    // ModExprList end
    if (!expr_ret_697) rew(mod_697);
    expr_ret_688 = expr_ret_697;
  }

  // SlashExpr 9
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_698 = NULL;
    rec(mod_698);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
      // Capturing XOR.
      expr_ret_698 = leaf(XOR);
      expr_ret_698->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_698->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_698 = NULL;
    }

    // ModExprList end
    if (!expr_ret_698) rew(mod_698);
    expr_ret_688 = expr_ret_698;
  }

  // SlashExpr 10
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_699 = NULL;
    rec(mod_699);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
      // Capturing EXCL.
      expr_ret_699 = leaf(EXCL);
      expr_ret_699->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_699->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_699 = NULL;
    }

    // ModExprList end
    if (!expr_ret_699) rew(mod_699);
    expr_ret_688 = expr_ret_699;
  }

  // SlashExpr 11
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_700 = NULL;
    rec(mod_700);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BITNOT) {
      // Capturing BITNOT.
      expr_ret_700 = leaf(BITNOT);
      expr_ret_700->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_700->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_700 = NULL;
    }

    // ModExprList end
    if (!expr_ret_700) rew(mod_700);
    expr_ret_688 = expr_ret_700;
  }

  // SlashExpr 12
  if (!expr_ret_688) {
    daisho_astnode_t* expr_ret_701 = NULL;
    rec(mod_701);
    // ModExprList end
    if (!expr_ret_701) rew(mod_701);
    expr_ret_688 = expr_ret_701;
  }

  // SlashExpr end
  expr_ret_687 = expr_ret_688;

  if (!rule) rule = expr_ret_687;
  if (!expr_ret_687) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule overloadable returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_702
  daisho_astnode_t* expr_ret_702 = NULL;
  daisho_astnode_t* expr_ret_703 = NULL;
  daisho_astnode_t* expr_ret_704 = NULL;
  rec(mod_704);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_705 = NULL;

  // SlashExpr 0
  if (!expr_ret_705) {
    daisho_astnode_t* expr_ret_706 = NULL;
    rec(mod_706);
    // ModExprList Forwarding
    expr_ret_706 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_706) rew(mod_706);
    expr_ret_705 = expr_ret_706;
  }

  // SlashExpr 1
  if (!expr_ret_705) {
    daisho_astnode_t* expr_ret_707 = NULL;
    rec(mod_707);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_707
    ret = SUCC;
    #line 772 "daisho.peg"
    WARNING("Missing expression."); ret=leaf(RECOVERY);
    #line 12134 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_707) rew(mod_707);
    expr_ret_705 = expr_ret_707;
  }

  // SlashExpr end
  expr_ret_704 = expr_ret_705;

  // ModExprList end
  if (!expr_ret_704) rew(mod_704);
  expr_ret_703 = expr_ret_704;
  if (!rule) rule = expr_ret_703;
  if (!expr_ret_703) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_708
  daisho_astnode_t* expr_ret_708 = NULL;
  daisho_astnode_t* expr_ret_709 = NULL;
  daisho_astnode_t* expr_ret_710 = NULL;
  rec(mod_710);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_711 = NULL;
  rec(mod_711);
  // ModExprList 0
  daisho_astnode_t* expr_ret_712 = NULL;
  expr_ret_712 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_711 = expr_ret_712;
  e = expr_ret_712;
  // ModExprList 1
  if (expr_ret_711) {
    // CodeExpr
    #define ret expr_ret_711
    ret = SUCC;
    #line 773 "daisho.peg"
    WARNING("Extra expression."); ret=e;
    #line 12178 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_711) rew(mod_711);
  expr_ret_710 = expr_ret_711;
  // ModExprList end
  if (!expr_ret_710) rew(mod_710);
  expr_ret_709 = expr_ret_710;
  if (!rule) rule = expr_ret_709;
  if (!expr_ret_709) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule noexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_713
  daisho_astnode_t* expr_ret_713 = NULL;
  daisho_astnode_t* expr_ret_714 = NULL;
  daisho_astnode_t* expr_ret_715 = NULL;
  rec(mod_715);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_716 = NULL;

  // SlashExpr 0
  if (!expr_ret_716) {
    daisho_astnode_t* expr_ret_717 = NULL;
    rec(mod_717);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_717 = leaf(COMMA);
      expr_ret_717->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_717->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_717 = NULL;
    }

    // ModExprList end
    if (!expr_ret_717) rew(mod_717);
    expr_ret_716 = expr_ret_717;
  }

  // SlashExpr 1
  if (!expr_ret_716) {
    daisho_astnode_t* expr_ret_718 = NULL;
    rec(mod_718);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_718
    ret = SUCC;
    #line 774 "daisho.peg"
    WARNING("Missing comma."); ret=leaf(COMMA);
    #line 12235 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_718) rew(mod_718);
    expr_ret_716 = expr_ret_718;
  }

  // SlashExpr end
  expr_ret_715 = expr_ret_716;

  // ModExprList end
  if (!expr_ret_715) rew(mod_715);
  expr_ret_714 = expr_ret_715;
  if (!rule) rule = expr_ret_714;
  if (!expr_ret_714) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wcomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_719
  daisho_astnode_t* expr_ret_719 = NULL;
  daisho_astnode_t* expr_ret_720 = NULL;
  daisho_astnode_t* expr_ret_721 = NULL;
  rec(mod_721);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_722 = NULL;
  rec(mod_722);
  // ModExprList 0
  daisho_astnode_t* expr_ret_723 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_723 = leaf(COMMA);
    expr_ret_723->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_723->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_723 = NULL;
  }

  expr_ret_722 = expr_ret_723;
  c = expr_ret_723;
  // ModExprList 1
  if (expr_ret_722) {
    // CodeExpr
    #define ret expr_ret_722
    ret = SUCC;
    #line 775 "daisho.peg"
    WARNING("Extra comma."); ret=c;
    #line 12287 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_722) rew(mod_722);
  expr_ret_721 = expr_ret_722;
  // ModExprList end
  if (!expr_ret_721) rew(mod_721);
  expr_ret_720 = expr_ret_721;
  if (!rule) rule = expr_ret_720;
  if (!expr_ret_720) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nocomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_724
  daisho_astnode_t* expr_ret_724 = NULL;
  daisho_astnode_t* expr_ret_725 = NULL;
  daisho_astnode_t* expr_ret_726 = NULL;
  rec(mod_726);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_727 = NULL;

  // SlashExpr 0
  if (!expr_ret_727) {
    daisho_astnode_t* expr_ret_728 = NULL;
    rec(mod_728);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_728 = leaf(SEMI);
      expr_ret_728->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_728->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_728 = NULL;
    }

    // ModExprList end
    if (!expr_ret_728) rew(mod_728);
    expr_ret_727 = expr_ret_728;
  }

  // SlashExpr 1
  if (!expr_ret_727) {
    daisho_astnode_t* expr_ret_729 = NULL;
    rec(mod_729);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_729
    ret = SUCC;
    #line 776 "daisho.peg"
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #line 12344 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_729) rew(mod_729);
    expr_ret_727 = expr_ret_729;
  }

  // SlashExpr end
  expr_ret_726 = expr_ret_727;

  // ModExprList end
  if (!expr_ret_726) rew(mod_726);
  expr_ret_725 = expr_ret_726;
  if (!rule) rule = expr_ret_725;
  if (!expr_ret_725) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wsemi returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_730
  daisho_astnode_t* expr_ret_730 = NULL;
  daisho_astnode_t* expr_ret_731 = NULL;
  daisho_astnode_t* expr_ret_732 = NULL;
  rec(mod_732);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_733 = NULL;
  rec(mod_733);
  // ModExprList 0
  daisho_astnode_t* expr_ret_734 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_734 = leaf(SEMI);
    expr_ret_734->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_734->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_734 = NULL;
  }

  expr_ret_733 = expr_ret_734;
  s = expr_ret_734;
  // ModExprList 1
  if (expr_ret_733) {
    // CodeExpr
    #define ret expr_ret_733
    ret = SUCC;
    #line 777 "daisho.peg"
    WARNING("Extra semicolon."); ret=s;
    #line 12396 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_733) rew(mod_733);
  expr_ret_732 = expr_ret_733;
  // ModExprList end
  if (!expr_ret_732) rew(mod_732);
  expr_ret_731 = expr_ret_732;
  if (!rule) rule = expr_ret_731;
  if (!expr_ret_731) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nosemi returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_735
  daisho_astnode_t* expr_ret_735 = NULL;
  daisho_astnode_t* expr_ret_736 = NULL;
  daisho_astnode_t* expr_ret_737 = NULL;
  rec(mod_737);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_738 = NULL;

  // SlashExpr 0
  if (!expr_ret_738) {
    daisho_astnode_t* expr_ret_739 = NULL;
    rec(mod_739);
    // ModExprList Forwarding
    expr_ret_739 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_739) rew(mod_739);
    expr_ret_738 = expr_ret_739;
  }

  // SlashExpr 1
  if (!expr_ret_738) {
    daisho_astnode_t* expr_ret_740 = NULL;
    rec(mod_740);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_740
    ret = SUCC;
    #line 778 "daisho.peg"
    WARNING("Missing semicolon or newline."); ret=leaf(SEMI);
    #line 12445 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_740) rew(mod_740);
    expr_ret_738 = expr_ret_740;
  }

  // SlashExpr end
  expr_ret_737 = expr_ret_738;

  // ModExprList end
  if (!expr_ret_737) rew(mod_737);
  expr_ret_736 = expr_ret_737;
  if (!rule) rule = expr_ret_736;
  if (!expr_ret_736) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wsemiornl returned SUCC.\n"), exit(1);
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

#endif /* PGEN_DAISHO_PARSER_H */
