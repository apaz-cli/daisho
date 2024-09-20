#ifndef PGEN_DAISHO_PARSER_H
#define PGEN_DAISHO_PARSER_H


/* START OF UTF8 LIBRARY */

#ifndef UTF8_INCLUDED
#define UTF8_INCLUDED
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#define UTF8_END (char)(CHAR_MIN ? CHAR_MIN     : CHAR_MAX    ) /* 1111 1111 */
#define UTF8_ERR (char)(CHAR_MIN ? CHAR_MIN + 1 : CHAR_MAX - 1) /* 1111 1110 */

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

static inline int UTF8_validByte(char c) {
  return (c != UTF8_ERR) & (c != UTF8_END);
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
    if (UTF8_validByte(c1)) {
      c = ((c0 & 0x1F) << 6) | c1;
      if (c >= 128)
        return c;
    }
  } else if ((c0 & 0xF0) == 0xE0) {
    c1 = UTF8_contByte(state);
    c2 = UTF8_contByte(state);
    if (UTF8_validByte(c1) & UTF8_validByte(c2)) {
      c = ((c0 & 0x0F) << 12) | (c1 << 6) | c2;
      if ((c >= 2048) & ((c < 55296) | (c > 57343)))
        return c;
    }
  } else if ((c0 & 0xF8) == 0xF0) {
    c1 = UTF8_contByte(state);
    c2 = UTF8_contByte(state);
    c3 = UTF8_contByte(state);
    if (UTF8_validByte(c1) & UTF8_validByte(c2) & UTF8_validByte(c3)) {
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
#include <stdbool.h>
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
  DAISHO_TOK_CUDAKERNEL,
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
  DAISHO_TOK_INTLIT,
  DAISHO_TOK_TINTLIT,
  DAISHO_TOK_FLOATLIT,
  DAISHO_TOK_TFLOATLIT,
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
// Tokens 1 through 97 are the ones you defined.
// This totals 99 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 99
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
  "CUDAKERNEL",
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
  "INTLIT",
  "TINTLIT",
  "FLOATLIT",
  "TFLOATLIT",
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
  int smaut_state_20 = 0;
  int smaut_state_21 = 0;
  int smaut_state_22 = 0;
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
  size_t smaut_munch_size_20 = 0;
  size_t smaut_munch_size_21 = 0;
  size_t smaut_munch_size_22 = 0;
  daisho_token_kind trie_tokenkind = DAISHO_TOK_STREAMEND;

  for (size_t iidx = 0; iidx < remaining; iidx++) {
    codepoint_t c = current[iidx];
    int all_dead = 1;

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 10;
        else if (c == 35 /*'#'*/) trie_state = 132;
        else if (c == 36 /*'$'*/) trie_state = 134;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 39 /*'''*/) trie_state = 125;
        else if (c == 40 /*'('*/) trie_state = 126;
        else if (c == 41 /*')'*/) trie_state = 127;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 124;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 123;
        else if (c == 47 /*'/'*/) trie_state = 5;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 122;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 133;
        else if (c == 70 /*'F'*/) trie_state = 75;
        else if (c == 83 /*'S'*/) trie_state = 84;
        else if (c == 86 /*'V'*/) trie_state = 92;
        else if (c == 91 /*'['*/) trie_state = 130;
        else if (c == 93 /*']'*/) trie_state = 131;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 135;
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
        else if (c == 123 /*'{'*/) trie_state = 128;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 129;
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
        else if (c == 62 /*'>'*/) trie_state = 136;
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
        else if (c == 62 /*'>'*/) trie_state = 137;
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
        else if (c == 117 /*'u'*/) trie_state = 113;
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
      else if (trie_state == 113) {
        if (c == 100 /*'d'*/) trie_state = 114;
        else trie_state = -1;
      }
      else if (trie_state == 114) {
        if (c == 97 /*'a'*/) trie_state = 115;
        else trie_state = -1;
      }
      else if (trie_state == 115) {
        if (c == 107 /*'k'*/) trie_state = 116;
        else trie_state = -1;
      }
      else if (trie_state == 116) {
        if (c == 101 /*'e'*/) trie_state = 117;
        else trie_state = -1;
      }
      else if (trie_state == 117) {
        if (c == 114 /*'r'*/) trie_state = 118;
        else trie_state = -1;
      }
      else if (trie_state == 118) {
        if (c == 110 /*'n'*/) trie_state = 119;
        else trie_state = -1;
      }
      else if (trie_state == 119) {
        if (c == 101 /*'e'*/) trie_state = 120;
        else trie_state = -1;
      }
      else if (trie_state == 120) {
        if (c == 108 /*'l'*/) trie_state = 121;
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
      else if (trie_state == 121) {
        trie_tokenkind =  DAISHO_TOK_CUDAKERNEL;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 122) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 123) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 124) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 125) {
        trie_tokenkind =  DAISHO_TOK_APOSTROPHE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 126) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 127) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 128) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 129) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 130) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 131) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 132) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 133) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 134) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 135) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 136) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 137) {
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
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 0) &
         (c == '%')) {
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 1) &
         (c == 'i')) {
          smaut_state_3 = 2;
      }
      else if ((smaut_state_3 == 2) &
         (c == 'n')) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 'c')) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 'l')) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 5) &
         (c == 'u')) {
          smaut_state_3 = 6;
      }
      else if ((smaut_state_3 == 6) &
         (c == 'd')) {
          smaut_state_3 = 7;
      }
      else if ((smaut_state_3 == 7) &
         (c == 'e')) {
          smaut_state_3 = 8;
      }
      else if ((smaut_state_3 == 2) &
         (c == 'm')) {
          smaut_state_3 = 9;
      }
      else if ((smaut_state_3 == 10) &
         (c == 'p')) {
          smaut_state_3 = 11;
      }
      else if ((smaut_state_3 == 11) &
         (c == 'o')) {
          smaut_state_3 = 12;
      }
      else if ((smaut_state_3 == 12) &
         (c == 'r')) {
          smaut_state_3 = 13;
      }
      else if ((smaut_state_3 == 13) &
         (c == 't')) {
          smaut_state_3 = 14;
      }
      else {
        smaut_state_3 = -1;
      }

      // Check accept
      if ((smaut_state_3 == 5) | (smaut_state_3 == 8) | (smaut_state_3 == 14)) {
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

    // Transition INTLIT State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         (c == '0')) {
          smaut_state_9 = 100;
      }
      else if ((smaut_state_9 == 0) &
         ((c == '-') | (c == '+'))) {
          smaut_state_9 = 1;
      }
      else if (((smaut_state_9 >= 0) & (smaut_state_9 <= 2)) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 100) &
         ((c == 'b') | (c == 'B'))) {
          smaut_state_9 = 199;
      }
      else if (((smaut_state_9 == 199) | (smaut_state_9 == 200)) &
         ((c == '0') | (c == '1'))) {
          smaut_state_9 = 200;
      }
      else if ((smaut_state_9 == 100) &
         ((c == 'x') | (c == 'X'))) {
          smaut_state_9 = 299;
      }
      else if (((smaut_state_9 == 299) | (smaut_state_9 == 300)) &
         (((c >= '0') & (c <= '9')) | ((c >= 'a') & (c <= 'f')) | ((c >= 'A') & (c <= 'F')))) {
          smaut_state_9 = 300;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if ((smaut_state_9 == 2) | (smaut_state_9 == 100) | (smaut_state_9 == 200) | (smaut_state_9 == 300)) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition TINTLIT State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         ((c == '-') | (c == '+'))) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 0) &
         (c == '0')) {
          smaut_state_10 = 100;
      }
      else if (((smaut_state_10 >= 0) & (smaut_state_10 <= 2)) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 100) &
         ((c == 'b') | (c == 'B'))) {
          smaut_state_10 = 199;
      }
      else if (((smaut_state_10 == 199) | (smaut_state_10 == 200)) &
         ((c == '0') | (c == '1'))) {
          smaut_state_10 = 200;
      }
      else if ((smaut_state_10 == 100) &
         ((c == 'x') | (c == 'X'))) {
          smaut_state_10 = 299;
      }
      else if (((smaut_state_10 == 299) | (smaut_state_10 == 300)) &
         (((c >= '0') & (c <= '9')) | ((c >= 'a') & (c <= 'f')) | ((c >= 'A') & (c <= 'F')))) {
          smaut_state_10 = 300;
      }
      else if (((smaut_state_10 == 2) | (smaut_state_10 == 100) | (smaut_state_10 == 200) | (smaut_state_10 == 300)) &
         (c == 'i')) {
          smaut_state_10 = 101;
      }
      else if (((smaut_state_10 == 2) | (smaut_state_10 == 100) | (smaut_state_10 == 200) | (smaut_state_10 == 300)) &
         (c == 'u')) {
          smaut_state_10 = 102;
      }
      else if (((smaut_state_10 == 2) | (smaut_state_10 == 100) | (smaut_state_10 == 200) | (smaut_state_10 == 300)) &
         (c == 'l')) {
          smaut_state_10 = 103;
      }
      else if ((smaut_state_10 == 103) &
         (c == 'l')) {
          smaut_state_10 = 104;
      }
      else if (((smaut_state_10 == 2) | (smaut_state_10 == 100) | (smaut_state_10 == 200) | (smaut_state_10 == 300)) &
         (c == 's')) {
          smaut_state_10 = 105;
      }
      else if ((smaut_state_10 == 105) &
         (c == 's')) {
          smaut_state_10 = 106;
      }
      else if (((smaut_state_10 == 101) | (smaut_state_10 == 102)) &
         (c == '8')) {
          smaut_state_10 = 8;
      }
      else if (((smaut_state_10 == 101) | (smaut_state_10 == 102)) &
         (c == '1')) {
          smaut_state_10 = 15;
      }
      else if ((smaut_state_10 == 15) &
         (c == '6')) {
          smaut_state_10 = 16;
      }
      else if (((smaut_state_10 == 101) | (smaut_state_10 == 102)) &
         (c == '3')) {
          smaut_state_10 = 31;
      }
      else if ((smaut_state_10 == 31) &
         (c == '2')) {
          smaut_state_10 = 32;
      }
      else if (((smaut_state_10 == 101) | (smaut_state_10 == 102)) &
         (c == '6')) {
          smaut_state_10 = 63;
      }
      else if ((smaut_state_10 == 63) &
         (c == '4')) {
          smaut_state_10 = 64;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if ((smaut_state_10 == 8) | (smaut_state_10 == 16) | (smaut_state_10 == 32) | (smaut_state_10 == 64) | (smaut_state_10 == 101) | (smaut_state_10 == 102) | (smaut_state_10 == 103) | (smaut_state_10 == 104) | (smaut_state_10 == 105) | (smaut_state_10 == 106)) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition FLOATLIT State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         ((c == '-') | (c == '+'))) {
          smaut_state_11 = 1;
      }
      else if (((smaut_state_11 >= 0) & (smaut_state_11 <= 2)) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 2) &
         (c == '.')) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 3) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_11 = 3;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if (smaut_state_11 == 3) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition TFLOATLIT State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         ((c == '-') | (c == '+'))) {
          smaut_state_12 = 1;
      }
      else if (((smaut_state_12 >= 0) & (smaut_state_12 <= 2)) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (c == '.')) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 3) &
         ((c >= '0') & (c <= '9'))) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'd')) {
          smaut_state_12 = 4;
      }
      else if ((smaut_state_12 == 3) &
         (c == 'f')) {
          smaut_state_12 = 5;
      }
      else if ((smaut_state_12 == 5) &
         (c == '3')) {
          smaut_state_12 = 31;
      }
      else if ((smaut_state_12 == 31) &
         (c == '2')) {
          smaut_state_12 = 32;
      }
      else if ((smaut_state_12 == 5) &
         (c == '6')) {
          smaut_state_12 = 63;
      }
      else if ((smaut_state_12 == 63) &
         (c == '4')) {
          smaut_state_12 = 64;
      }
      else {
        smaut_state_12 = -1;
      }

      // Check accept
      if ((smaut_state_12 == 4) | (smaut_state_12 == 5) | (smaut_state_12 == 32) | (smaut_state_12 == 64)) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == '\"')) {
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

    // Transition FSTRLITSTART State Machine
    if (smaut_state_14 != -1) {
      all_dead = 0;

      if ((smaut_state_14 == 0) &
         (c == '\"')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 1) &
         (c == '{')) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 1) &
         (c == '\"')) {
          smaut_state_14 = -1;
      }
      else if ((smaut_state_14 == 1) &
         (c == '\n')) {
          smaut_state_14 = -1;
      }
      else if ((smaut_state_14 == 1) &
         (c == '\\')) {
          smaut_state_14 = 3;
      }
      else if ((smaut_state_14 == 1) &
         (1)) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 'n')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 'f')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 'b')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 'r')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 't')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == 'e')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == '\\')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == '\'')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == '\"')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == '{')) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 3) &
         (c == '}')) {
          smaut_state_14 = 1;
      }
      else {
        smaut_state_14 = -1;
      }

      // Check accept
      if (smaut_state_14 == 2) {
        smaut_munch_size_14 = iidx + 1;
      }
    }

    // Transition FSTRLITMID State Machine
    if (smaut_state_15 != -1) {
      all_dead = 0;

      if ((smaut_state_15 == 0) &
         (c == '}')) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 1) &
         (c == '{')) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 1) &
         (c == '\"')) {
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

    // Transition FSTRLITEND State Machine
    if (smaut_state_16 != -1) {
      all_dead = 0;

      if ((smaut_state_16 == 0) &
         (c == '}')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 1) &
         (c == '\"')) {
          smaut_state_16 = 2;
      }
      else if ((smaut_state_16 == 1) &
         (c == '{')) {
          smaut_state_16 = -1;
      }
      else if ((smaut_state_16 == 1) &
         (c == '\n')) {
          smaut_state_16 = -1;
      }
      else if ((smaut_state_16 == 1) &
         (c == '\\')) {
          smaut_state_16 = 3;
      }
      else if ((smaut_state_16 == 1) &
         (1)) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 'n')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 'f')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 'b')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 'r')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 't')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == 'e')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == '\\')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == '\'')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == '\"')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == '{')) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 3) &
         (c == '}')) {
          smaut_state_16 = 1;
      }
      else {
        smaut_state_16 = -1;
      }

      // Check accept
      if (smaut_state_16 == 2) {
        smaut_munch_size_16 = iidx + 1;
      }
    }

    // Transition CHARLIT State Machine
    if (smaut_state_17 != -1) {
      all_dead = 0;

      if ((smaut_state_17 == 0) &
         (c == '\'')) {
          smaut_state_17 = 1;
      }
      else if ((smaut_state_17 == 1) &
         (c == '\n')) {
          smaut_state_17 = -1;
      }
      else if ((smaut_state_17 == 1) &
         (c == '\\')) {
          smaut_state_17 = 4;
      }
      else if ((smaut_state_17 == 1) &
         (1)) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 'n')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 'f')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 'b')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 'r')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 't')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == 'e')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == '\\')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 4) &
         (c == '\'')) {
          smaut_state_17 = 2;
      }
      else if ((smaut_state_17 == 2) &
         (c == '\'')) {
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

    // Transition INCLUDEPATH State Machine
    if (smaut_state_18 != -1) {
      all_dead = 0;

      if ((smaut_state_18 == 0) &
         (c == '<')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 1) &
         (c == '>')) {
          smaut_state_18 = 2;
      }
      else if ((smaut_state_18 == 1) &
         (c == '{')) {
          smaut_state_18 = -1;
      }
      else if ((smaut_state_18 == 1) &
         (c == '\n')) {
          smaut_state_18 = -1;
      }
      else if ((smaut_state_18 == 1) &
         (c == '\\')) {
          smaut_state_18 = 3;
      }
      else if ((smaut_state_18 == 1) &
         (1)) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 'n')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 'f')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 'b')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 'r')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 't')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == 'e')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == '\\')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == '\'')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == '\"')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == '{')) {
          smaut_state_18 = 1;
      }
      else if ((smaut_state_18 == 3) &
         (c == '}')) {
          smaut_state_18 = 1;
      }
      else {
        smaut_state_18 = -1;
      }

      // Check accept
      if (smaut_state_18 == 2) {
        smaut_munch_size_18 = iidx + 1;
      }
    }

    // Transition WS State Machine
    if (smaut_state_19 != -1) {
      all_dead = 0;

      if (((smaut_state_19 == 0) | (smaut_state_19 == 1)) &
         ((c == 32) | (c == '\n') | (c == 13) | (c == 9))) {
          smaut_state_19 = 1;
      }
      else {
        smaut_state_19 = -1;
      }

      // Check accept
      if (smaut_state_19 == 1) {
        smaut_munch_size_19 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_20 != -1) {
      all_dead = 0;

      if ((smaut_state_20 == 0) &
         (c == '/')) {
          smaut_state_20 = 1;
      }
      else if ((smaut_state_20 == 1) &
         (c == '*')) {
          smaut_state_20 = 2;
      }
      else if ((smaut_state_20 == 2) &
         (c == '*')) {
          smaut_state_20 = 3;
      }
      else if ((smaut_state_20 == 2) &
         (1)) {
          smaut_state_20 = 2;
      }
      else if ((smaut_state_20 == 3) &
         (c == '*')) {
          smaut_state_20 = 3;
      }
      else if ((smaut_state_20 == 3) &
         (c == '/')) {
          smaut_state_20 = 4;
      }
      else if ((smaut_state_20 == 3) &
         (1)) {
          smaut_state_20 = 2;
      }
      else {
        smaut_state_20 = -1;
      }

      // Check accept
      if (smaut_state_20 == 4) {
        smaut_munch_size_20 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_21 != -1) {
      all_dead = 0;

      if ((smaut_state_21 == 0) &
         (c == '/')) {
          smaut_state_21 = 1;
      }
      else if ((smaut_state_21 == 1) &
         (c == '/')) {
          smaut_state_21 = 2;
      }
      else if ((smaut_state_21 == 2) &
         (!(c == '\n'))) {
          smaut_state_21 = 2;
      }
      else if ((smaut_state_21 == 2) &
         (c == '\n')) {
          smaut_state_21 = 3;
      }
      else {
        smaut_state_21 = -1;
      }

      // Check accept
      if ((smaut_state_21 == 2) | (smaut_state_21 == 3)) {
        smaut_munch_size_21 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_22 != -1) {
      all_dead = 0;

      if ((smaut_state_22 == 0) &
         (c == '#')) {
          smaut_state_22 = 1;
      }
      else if ((smaut_state_22 == 1) &
         (c == '!')) {
          smaut_state_22 = 2;
      }
      else if ((smaut_state_22 == 2) &
         (!(c == '\n'))) {
          smaut_state_22 = 2;
      }
      else if ((smaut_state_22 == 2) &
         (c == '\n')) {
          smaut_state_22 = 3;
      }
      else {
        smaut_state_22 = -1;
      }

      // Check accept
      if (smaut_state_22 == 3) {
        smaut_munch_size_22 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_22 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_22;
  }
  if (smaut_munch_size_21 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_21;
  }
  if (smaut_munch_size_20 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_20;
  }
  if (smaut_munch_size_19 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_19;
  }
  if (smaut_munch_size_18 >= max_munch) {
    kind = DAISHO_TOK_INCLUDEPATH;
    max_munch = smaut_munch_size_18;
  }
  if (smaut_munch_size_17 >= max_munch) {
    kind = DAISHO_TOK_CHARLIT;
    max_munch = smaut_munch_size_17;
  }
  if (smaut_munch_size_16 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITEND;
    max_munch = smaut_munch_size_16;
  }
  if (smaut_munch_size_15 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITMID;
    max_munch = smaut_munch_size_15;
  }
  if (smaut_munch_size_14 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITSTART;
    max_munch = smaut_munch_size_14;
  }
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_TFLOATLIT;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_FLOATLIT;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_TINTLIT;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_INTLIT;
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
static inline daisho_parse_err* daisho_report_parse_error(daisho_parser_ctx* ctx, const char* msg, int severity) {
  if (ctx->num_errors >= DAISHO_MAX_PARSER_ERRORS) {
    ctx->exit = 1;
    return NULL;
  }
  daisho_parse_err* err = &ctx->errlist[ctx->num_errors++];
  err->msg = (const char*)msg;
  err->severity = severity;
  size_t toknum = ctx->pos;
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
  DAISHO_NODE_CUDAKERNEL,
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
  DAISHO_NODE_INTLIT,
  DAISHO_NODE_TINTLIT,
  DAISHO_NODE_FLOATLIT,
  DAISHO_NODE_TFLOATLIT,
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
  DAISHO_NODE_KCALLARGS,
  DAISHO_NODE_INFER_TYPE,
  DAISHO_NODE_BASETYPE,
  DAISHO_NODE_CURRENT_NS,
  DAISHO_NODE_NOARG,
  DAISHO_NODE_NSACCESS,
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
  DAISHO_NODE_BOOL,
  DAISHO_NODE_ITER,
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
  DAISHO_NODE_PTRTYPE,
  DAISHO_NODE_TUPLETYPE,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_DTRAITIDENT,
  DAISHO_NODE_SSTR,
  DAISHO_NODE_FSTR,
  DAISHO_NODE_FSTRFRAG,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 146
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
  "CUDAKERNEL",
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
  "INTLIT",
  "TINTLIT",
  "FLOATLIT",
  "TFLOATLIT",
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
  "KCALLARGS",
  "INFER_TYPE",
  "BASETYPE",
  "CURRENT_NS",
  "NOARG",
  "NSACCESS",
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
  "BOOL",
  "ITER",
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
  PreExprType* pretype; // The pre-monomorphization type of this expression.
  // End of extra data.
  daisho_astnode_t** children;
};

#define PGEN_MIN1(a) a
#define PGEN_MIN2(a, b) PGEN_MIN(a, PGEN_MIN1(b))
#define PGEN_MIN3(a, b, c) PGEN_MIN(a, PGEN_MIN2(b, c))
#define PGEN_MIN4(a, b, c, d) PGEN_MIN(a, PGEN_MIN3(b, c, d))
#define PGEN_MIN5(a, b, c, d, e) PGEN_MIN(a, PGEN_MIN4(b, c, d, e))
#define PGEN_MIN6(a, b, c, d, e, f) PGEN_MIN(a, PGEN_MIN5(b, c, d, e, f))
#define PGEN_MIN7(a, b, c, d, e, f, g) PGEN_MIN(a, PGEN_MIN6(b, c, d, e, f, g))
#define PGEN_MIN8(a, b, c, d, e, f, g, h) PGEN_MIN(a, PGEN_MIN7(b, c, d, e, f, g, h))
#define PGEN_MIN9(a, b, c, d, e, f, g, h, i) PGEN_MIN(a, PGEN_MIN8(b, c, d, e, f, g, h, i))
#define PGEN_MIN10(a, b, c, d, e, f, g, h, i, j) PGEN_MIN(a, PGEN_MIN9(b, c, d, e, f, g, h, i, j))
#define PGEN_MAX1(a) a
#define PGEN_MAX2(a, b) PGEN_MAX(a, PGEN_MAX1(b))
#define PGEN_MAX3(a, b, c) PGEN_MAX(a, PGEN_MAX2(b, c))
#define PGEN_MAX4(a, b, c, d) PGEN_MAX(a, PGEN_MAX3(b, c, d))
#define PGEN_MAX5(a, b, c, d, e) PGEN_MAX(a, PGEN_MAX4(b, c, d, e))
#define PGEN_MAX6(a, b, c, d, e, f) PGEN_MAX(a, PGEN_MAX5(b, c, d, e, f))
#define PGEN_MAX7(a, b, c, d, e, f, g) PGEN_MAX(a, PGEN_MAX6(b, c, d, e, f, g))
#define PGEN_MAX8(a, b, c, d, e, f, g, h) PGEN_MAX(a, PGEN_MAX7(b, c, d, e, f, g, h))
#define PGEN_MAX9(a, b, c, d, e, f, g, h, i) PGEN_MAX(a, PGEN_MAX8(b, c, d, e, f, g, h, i))
#define PGEN_MAX10(a, b, c, d, e, f, g, h, i, j) PGEN_MAX(a, PGEN_MAX9(b, c, d, e, f, g, h, i, j))
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

static inline daisho_astnode_t* daisho_astnode_fixed_6(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4,
                             daisho_astnode_t* PGEN_RESTRICT n5) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 6,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 6;
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
  children[5] = n5;
  n5->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_7(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4,
                             daisho_astnode_t* PGEN_RESTRICT n5,
                             daisho_astnode_t* PGEN_RESTRICT n6) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 7,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 7;
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
  children[5] = n5;
  n5->parent = node;
  children[6] = n6;
  n6->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_8(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4,
                             daisho_astnode_t* PGEN_RESTRICT n5,
                             daisho_astnode_t* PGEN_RESTRICT n6,
                             daisho_astnode_t* PGEN_RESTRICT n7) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 8,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 8;
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
  children[5] = n5;
  n5->parent = node;
  children[6] = n6;
  n6->parent = node;
  children[7] = n7;
  n7->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_9(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4,
                             daisho_astnode_t* PGEN_RESTRICT n5,
                             daisho_astnode_t* PGEN_RESTRICT n6,
                             daisho_astnode_t* PGEN_RESTRICT n7,
                             daisho_astnode_t* PGEN_RESTRICT n8) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 9,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 9;
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
  children[5] = n5;
  n5->parent = node;
  children[6] = n6;
  n6->parent = node;
  children[7] = n7;
  n7->parent = node;
  children[8] = n8;
  n8->parent = node;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_10(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* PGEN_RESTRICT n0,
                             daisho_astnode_t* PGEN_RESTRICT n1,
                             daisho_astnode_t* PGEN_RESTRICT n2,
                             daisho_astnode_t* PGEN_RESTRICT n3,
                             daisho_astnode_t* PGEN_RESTRICT n4,
                             daisho_astnode_t* PGEN_RESTRICT n5,
                             daisho_astnode_t* PGEN_RESTRICT n6,
                             daisho_astnode_t* PGEN_RESTRICT n7,
                             daisho_astnode_t* PGEN_RESTRICT n8,
                             daisho_astnode_t* PGEN_RESTRICT n9) {
  char* ret = pgen_alloc(alloc,
                         sizeof(daisho_astnode_t) +
                         sizeof(daisho_astnode_t *) * 10,
                         _Alignof(daisho_astnode_t));
  daisho_astnode_t *node = (daisho_astnode_t *)ret;
  daisho_astnode_t **children = (daisho_astnode_t **)(node + 1);
  node->kind = kind;
  node->parent = NULL;
  node->max_children = 0;
  node->num_children = 10;
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
  children[5] = n5;
  n5->parent = node;
  children[6] = n6;
  n6->parent = node;
  children[7] = n7;
  n7->parent = node;
  children[8] = n8;
  n8->parent = node;
  children[9] = n9;
  n9->parent = node;
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

#define INFO(msg)                daisho_report_parse_error(ctx, (const char*)msg, 0)
#define WARNING(msg)             daisho_report_parse_error(ctx, (const char*)msg, 1)
#define ERROR(msg)               daisho_report_parse_error(ctx, (const char*)msg, 2)
#define FATAL(msg)               daisho_report_parse_error(ctx, (const char*)msg, 3)

/******************/
/* Mid Directives */
/******************/
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
static inline daisho_astnode_t* daisho_parse_fnkw(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_stunmembers(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_trimmembers(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_varmembers(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_kdim(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_kexpand(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_number(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_bsl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_bsr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* nses = NULL;
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
    ret=list(NSLIST);
    #undef ret
    expr_ret_2 = expr_ret_4;
    nses = expr_ret_4;
  }

  // ModExprList 2
  if (expr_ret_2) {
    daisho_astnode_t* expr_ret_5 = NULL;
    daisho_astnode_t* expr_ret_6 = SUCC;
    while (expr_ret_6)
    {
      rec(kleene_rew_5);
      daisho_astnode_t* expr_ret_7 = NULL;
      rec(mod_7);
      // ModExprList 0
      // CodeExpr
      #define ret expr_ret_7
      ret = SUCC;
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #undef ret
      // ModExprList 1
      if (expr_ret_7) {
        daisho_astnode_t* expr_ret_8 = NULL;
        expr_ret_8 = daisho_parse_namespace(ctx);
        if (ctx->exit) return NULL;
        expr_ret_7 = expr_ret_8;
        ns = expr_ret_8;
      }

      // ModExprList 2
      if (expr_ret_7) {
        daisho_astnode_t* expr_ret_9 = NULL;
        // CodeExpr
        #define ret expr_ret_9
        ret = SUCC;
        
                // You can switch namespaces by declaring them. So, we want to combine
                // namespaces with the same name, because they are the same namespace.
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
        #undef ret
        expr_ret_7 = expr_ret_9;
        current = expr_ret_9;
      }

      // ModExprList end
      if (!expr_ret_7) rew(mod_7);
      expr_ret_6 = expr_ret_7;
    }

    expr_ret_5 = SUCC;
    expr_ret_2 = expr_ret_5;
  }

  // ModExprList 3
  if (expr_ret_2) {
    // CodeExpr
    #define ret expr_ret_2
    ret = SUCC;
    rule=(!has(sh)) ? node(PROGRAM, nses)
                              : node(PROGRAM, nses, sh);
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
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* l = NULL;
  #define rule expr_ret_10
  daisho_astnode_t* expr_ret_10 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  daisho_astnode_t* expr_ret_12 = NULL;
  rec(mod_12);
  // ModExprList 0
  daisho_astnode_t* expr_ret_13 = NULL;

  // SlashExpr 0
  if (!expr_ret_13) {
    daisho_astnode_t* expr_ret_14 = NULL;
    rec(mod_14);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_15 = NULL;
    rec(mod_15);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_15 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_15 = NULL;
    }

    // ModExprList 1
    if (expr_ret_15) {
      daisho_astnode_t* expr_ret_16 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_16 = leaf(TYPEIDENT);
        expr_ret_16->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_16->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_16 = NULL;
      }

      expr_ret_15 = expr_ret_16;
      name = expr_ret_16;
    }

    // ModExprList 2
    if (expr_ret_15) {
      expr_ret_15 = daisho_parse_wsemi(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList end
    if (!expr_ret_15) rew(mod_15);
    expr_ret_14 = expr_ret_15;
    // ModExprList end
    if (!expr_ret_14) rew(mod_14);
    expr_ret_13 = expr_ret_14;
  }

  // SlashExpr 1
  if (!expr_ret_13) {
    daisho_astnode_t* expr_ret_17 = NULL;
    rec(mod_17);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_18 = NULL;
    // CodeExpr
    #define ret expr_ret_18
    ret = SUCC;
    ret=srepr(leaf(TYPEIDENT), "GLOBAL");
    #undef ret
    expr_ret_17 = expr_ret_18;
    name = expr_ret_18;
    // ModExprList end
    if (!expr_ret_17) rew(mod_17);
    expr_ret_13 = expr_ret_17;
  }

  // SlashExpr end
  expr_ret_12 = expr_ret_13;

  // ModExprList 1
  if (expr_ret_12) {
    daisho_astnode_t* expr_ret_19 = NULL;
    expr_ret_19 = daisho_parse_topdecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_12 = expr_ret_19;
    t = expr_ret_19;
  }

  // ModExprList 2
  if (expr_ret_12) {
    daisho_astnode_t* expr_ret_20 = NULL;
    // CodeExpr
    #define ret expr_ret_20
    ret = SUCC;
    ret = list(NSDECLS);
    #undef ret
    expr_ret_12 = expr_ret_20;
    l = expr_ret_20;
  }

  // ModExprList 3
  if (expr_ret_12) {
    // CodeExpr
    #define ret expr_ret_12
    ret = SUCC;
    add(l, t);
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_12) {
    daisho_astnode_t* expr_ret_21 = NULL;
    daisho_astnode_t* expr_ret_22 = SUCC;
    while (expr_ret_22)
    {
      rec(kleene_rew_21);
      daisho_astnode_t* expr_ret_23 = NULL;
      rec(mod_23);
      // ModExprList 0
      // CodeExpr
      #define ret expr_ret_23
      ret = SUCC;
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #undef ret
      // ModExprList 1
      if (expr_ret_23) {
        daisho_astnode_t* expr_ret_24 = NULL;

        // SlashExpr 0
        if (!expr_ret_24) {
          daisho_astnode_t* expr_ret_25 = NULL;
          rec(mod_25);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_25 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_25 = NULL;
          }

          // ModExprList end
          if (!expr_ret_25) rew(mod_25);
          expr_ret_24 = expr_ret_25;
        }

        // SlashExpr 1
        if (!expr_ret_24) {
          daisho_astnode_t* expr_ret_26 = NULL;
          rec(mod_26);
          // ModExprList 0
          // CodeExpr
          #define ret expr_ret_26
          ret = SUCC;
          t=NULL;
          #undef ret
          // ModExprList 1
          if (expr_ret_26) {
            daisho_astnode_t* expr_ret_27 = NULL;
            expr_ret_27 = daisho_parse_topdecl(ctx);
            if (ctx->exit) return NULL;
            expr_ret_26 = expr_ret_27;
            t = expr_ret_27;
          }

          // ModExprList 2
          if (expr_ret_26) {
            // CodeExpr
            #define ret expr_ret_26
            ret = SUCC;
            add(l, t);
            #undef ret
          }

          // ModExprList end
          if (!expr_ret_26) rew(mod_26);
          expr_ret_24 = expr_ret_26;
        }

        // SlashExpr end
        expr_ret_23 = expr_ret_24;

      }

      // ModExprList end
      if (!expr_ret_23) rew(mod_23);
      expr_ret_22 = expr_ret_23;
    }

    expr_ret_21 = SUCC;
    expr_ret_12 = expr_ret_21;
  }

  // ModExprList 5
  if (expr_ret_12) {
    // CodeExpr
    #define ret expr_ret_12
    ret = SUCC;
    rule = repr(node(NAMESPACE, name, l), name);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_12) rew(mod_12);
  expr_ret_11 = expr_ret_12;
  if (!rule) rule = expr_ret_11;
  if (!expr_ret_11) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_28
  daisho_astnode_t* expr_ret_28 = NULL;
  daisho_astnode_t* expr_ret_29 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;

  // SlashExpr 0
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_31 = NULL;
    rec(mod_31);
    // ModExprList Forwarding
    expr_ret_31 = daisho_parse_structdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_31) rew(mod_31);
    expr_ret_30 = expr_ret_31;
  }

  // SlashExpr 1
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_32 = NULL;
    rec(mod_32);
    // ModExprList Forwarding
    expr_ret_32 = daisho_parse_uniondecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_32) rew(mod_32);
    expr_ret_30 = expr_ret_32;
  }

  // SlashExpr 2
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_33 = NULL;
    rec(mod_33);
    // ModExprList Forwarding
    expr_ret_33 = daisho_parse_traitdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_33) rew(mod_33);
    expr_ret_30 = expr_ret_33;
  }

  // SlashExpr 3
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_34 = NULL;
    rec(mod_34);
    // ModExprList Forwarding
    expr_ret_34 = daisho_parse_impldecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_34) rew(mod_34);
    expr_ret_30 = expr_ret_34;
  }

  // SlashExpr 4
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_35 = NULL;
    rec(mod_35);
    // ModExprList Forwarding
    expr_ret_35 = daisho_parse_ctypedecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_35) rew(mod_35);
    expr_ret_30 = expr_ret_35;
  }

  // SlashExpr 5
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_36 = NULL;
    rec(mod_36);
    // ModExprList Forwarding
    expr_ret_36 = daisho_parse_cfndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_36) rew(mod_36);
    expr_ret_30 = expr_ret_36;
  }

  // SlashExpr 6
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_37 = NULL;
    rec(mod_37);
    // ModExprList Forwarding
    expr_ret_37 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_37) rew(mod_37);
    expr_ret_30 = expr_ret_37;
  }

  // SlashExpr 7
  if (!expr_ret_30) {
    daisho_astnode_t* expr_ret_38 = NULL;
    rec(mod_38);
    // ModExprList Forwarding
    expr_ret_38 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_38) rew(mod_38);
    expr_ret_30 = expr_ret_38;
  }

  // SlashExpr end
  expr_ret_29 = expr_ret_30;

  if (!rule) rule = expr_ret_29;
  if (!expr_ret_29) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* il = NULL;
  daisho_astnode_t* members = NULL;
  #define rule expr_ret_39
  daisho_astnode_t* expr_ret_39 = NULL;
  daisho_astnode_t* expr_ret_40 = NULL;
  daisho_astnode_t* expr_ret_41 = NULL;
  rec(mod_41);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
    // Not capturing STRUCT.
    expr_ret_41 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_41 = NULL;
  }

  // ModExprList 1
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_42 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_42 = leaf(TYPEIDENT);
      expr_ret_42->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_42->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_42 = NULL;
    }

    expr_ret_41 = expr_ret_42;
    id = expr_ret_42;
  }

  // ModExprList 2
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_43 = NULL;
    expr_ret_43 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_41 = expr_ret_43;
    tmpl = expr_ret_43;
  }

  // ModExprList 3
  if (expr_ret_41) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_44 = NULL;
    expr_ret_44 = daisho_parse_typelist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_41 = expr_ret_44;
    il = expr_ret_44;
  }

  // ModExprList 5
  if (expr_ret_41) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_45 = NULL;
    expr_ret_45 = daisho_parse_stunmembers(ctx);
    if (ctx->exit) return NULL;
    expr_ret_41 = expr_ret_45;
    members = expr_ret_45;
  }

  // ModExprList 7
  if (expr_ret_41) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_41) {
    // CodeExpr
    #define ret expr_ret_41
    ret = SUCC;
    rule = node(STRUCT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_41) rew(mod_41);
  expr_ret_40 = expr_ret_41;
  if (!rule) rule = expr_ret_40;
  if (!expr_ret_40) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* members = NULL;
  #define rule expr_ret_46
  daisho_astnode_t* expr_ret_46 = NULL;
  daisho_astnode_t* expr_ret_47 = NULL;
  daisho_astnode_t* expr_ret_48 = NULL;
  rec(mod_48);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_48 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_48 = NULL;
  }

  // ModExprList 1
  if (expr_ret_48) {
    daisho_astnode_t* expr_ret_49 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_49 = leaf(TYPEIDENT);
      expr_ret_49->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_49->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_49 = NULL;
    }

    expr_ret_48 = expr_ret_49;
    id = expr_ret_49;
  }

  // ModExprList 2
  if (expr_ret_48) {
    daisho_astnode_t* expr_ret_50 = NULL;
    expr_ret_50 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_48 = expr_ret_50;
    tmpl = expr_ret_50;
  }

  // ModExprList 3
  if (expr_ret_48) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_48 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_48 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_48) {
    daisho_astnode_t* expr_ret_51 = NULL;
    expr_ret_51 = daisho_parse_stunmembers(ctx);
    if (ctx->exit) return NULL;
    expr_ret_48 = expr_ret_51;
    members = expr_ret_51;
  }

  // ModExprList 5
  if (expr_ret_48) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_48 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_48 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_48) {
    // CodeExpr
    #define ret expr_ret_48
    ret = SUCC;
    rule = node(UNION, id, tmpl, members);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_48) rew(mod_48);
  expr_ret_47 = expr_ret_48;
  if (!rule) rule = expr_ret_47;
  if (!expr_ret_47) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* il = NULL;
  daisho_astnode_t* lc = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* rc = NULL;
  #define rule expr_ret_52
  daisho_astnode_t* expr_ret_52 = NULL;
  daisho_astnode_t* expr_ret_53 = NULL;
  daisho_astnode_t* expr_ret_54 = NULL;
  rec(mod_54);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
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
    daisho_astnode_t* expr_ret_57 = NULL;
    daisho_astnode_t* expr_ret_58 = NULL;
    rec(mod_58);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_58 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

    // ModExprList 1
    if (expr_ret_58) {
      daisho_astnode_t* expr_ret_59 = NULL;
      expr_ret_59 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_58 = expr_ret_59;
      il = expr_ret_59;
    }

    // ModExprList end
    if (!expr_ret_58) rew(mod_58);
    expr_ret_57 = expr_ret_58;
    // optional
    if (!expr_ret_57)
      expr_ret_57 = SUCC;
    expr_ret_54 = expr_ret_57;
  }

  // ModExprList 4
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_60 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_60 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_60 = NULL;
    }

    // optional
    if (!expr_ret_60)
      expr_ret_60 = SUCC;
    expr_ret_54 = expr_ret_60;
    lc = expr_ret_60;
  }

  // ModExprList 5
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_61 = NULL;
    // CodeExpr
    #define ret expr_ret_61
    ret = SUCC;
    ret=list(MEMBERLIST);
    #undef ret
    expr_ret_54 = expr_ret_61;
    members = expr_ret_61;
  }

  // ModExprList 6
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_62 = NULL;
    daisho_astnode_t* expr_ret_63 = SUCC;
    while (expr_ret_63)
    {
      rec(kleene_rew_62);
      daisho_astnode_t* expr_ret_64 = NULL;
      rec(mod_64);
      // ModExprList 0
      daisho_astnode_t* expr_ret_65 = NULL;
      expr_ret_65 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_64 = expr_ret_65;
      m = expr_ret_65;
      // ModExprList 1
      if (expr_ret_64) {
        // CodeExpr
        #define ret expr_ret_64
        ret = SUCC;
        add(members, m);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_64) rew(mod_64);
      expr_ret_63 = expr_ret_64;
    }

    expr_ret_62 = SUCC;
    expr_ret_54 = expr_ret_62;
  }

  // ModExprList 7
  if (expr_ret_54) {
    daisho_astnode_t* expr_ret_66 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

    // optional
    if (!expr_ret_66)
      expr_ret_66 = SUCC;
    expr_ret_54 = expr_ret_66;
    rc = expr_ret_66;
  }

  // ModExprList 8
  if (expr_ret_54) {
    // CodeExpr
    #define ret expr_ret_54
    ret = SUCC;
    if (has(lc) != has(rc)) FATAL("Trait declaration parens mismatch.");
    #undef ret
  }

  // ModExprList 9
  if (expr_ret_54) {
    // CodeExpr
    #define ret expr_ret_54
    ret = SUCC;
    rule = node(TRAIT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_54) rew(mod_54);
  expr_ret_53 = expr_ret_54;
  if (!rule) rule = expr_ret_53;
  if (!expr_ret_53) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_67
  daisho_astnode_t* expr_ret_67 = NULL;
  daisho_astnode_t* expr_ret_68 = NULL;
  daisho_astnode_t* expr_ret_69 = NULL;
  rec(mod_69);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_69 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_69 = NULL;
  }

  // ModExprList 1
  if (expr_ret_69) {
    daisho_astnode_t* expr_ret_70 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_70 = leaf(TYPEIDENT);
      expr_ret_70->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_70->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

    expr_ret_69 = expr_ret_70;
    id = expr_ret_70;
  }

  // ModExprList 2
  if (expr_ret_69) {
    daisho_astnode_t* expr_ret_71 = NULL;
    expr_ret_71 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_69 = expr_ret_71;
    tmpl = expr_ret_71;
  }

  // ModExprList 3
  if (expr_ret_69) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_69 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_69 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_69) {
    daisho_astnode_t* expr_ret_72 = NULL;
    expr_ret_72 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_69 = expr_ret_72;
    ft = expr_ret_72;
  }

  // ModExprList 5
  if (expr_ret_69) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_69 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_69 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_69) {
    daisho_astnode_t* expr_ret_73 = NULL;
    // CodeExpr
    #define ret expr_ret_73
    ret = SUCC;
    ret=list(MEMBERLIST);
    #undef ret
    expr_ret_69 = expr_ret_73;
    members = expr_ret_73;
  }

  // ModExprList 7
  if (expr_ret_69) {
    daisho_astnode_t* expr_ret_74 = NULL;
    daisho_astnode_t* expr_ret_75 = SUCC;
    while (expr_ret_75)
    {
      rec(kleene_rew_74);
      daisho_astnode_t* expr_ret_76 = NULL;
      rec(mod_76);
      // ModExprList 0
      daisho_astnode_t* expr_ret_77 = NULL;
      expr_ret_77 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_76 = expr_ret_77;
      m = expr_ret_77;
      // ModExprList 1
      if (expr_ret_76) {
        // CodeExpr
        #define ret expr_ret_76
        ret = SUCC;
        add(members, m);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_76) rew(mod_76);
      expr_ret_75 = expr_ret_76;
    }

    expr_ret_74 = SUCC;
    expr_ret_69 = expr_ret_74;
  }

  // ModExprList 8
  if (expr_ret_69) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_69 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_69 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_69) {
    // CodeExpr
    #define ret expr_ret_69
    ret = SUCC;
    rule = node(IMPL, id, tmpl, ft, members);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_69) rew(mod_69);
  expr_ret_68 = expr_ret_69;
  if (!rule) rule = expr_ret_68;
  if (!expr_ret_68) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_78
  daisho_astnode_t* expr_ret_78 = NULL;
  daisho_astnode_t* expr_ret_79 = NULL;
  daisho_astnode_t* expr_ret_80 = NULL;
  rec(mod_80);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_80 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_80 = NULL;
  }

  // ModExprList 1
  if (expr_ret_80) {
    daisho_astnode_t* expr_ret_81 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_81 = leaf(TYPEIDENT);
      expr_ret_81->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_81->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_81 = NULL;
    }

    expr_ret_80 = expr_ret_81;
    id = expr_ret_81;
  }

  // ModExprList 2
  if (expr_ret_80) {
    daisho_astnode_t* expr_ret_82 = NULL;
    expr_ret_82 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_80 = expr_ret_82;
    c = expr_ret_82;
  }

  // ModExprList 3
  if (expr_ret_80) {
    // CodeExpr
    #define ret expr_ret_80
    ret = SUCC;
    rule = node(CTYPE, id, c);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_80) rew(mod_80);
  expr_ret_79 = expr_ret_80;
  if (!rule) rule = expr_ret_79;
  if (!expr_ret_79) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* ci = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_83
  daisho_astnode_t* expr_ret_83 = NULL;
  daisho_astnode_t* expr_ret_84 = NULL;
  daisho_astnode_t* expr_ret_85 = NULL;
  rec(mod_85);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_85 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_85 = NULL;
  }

  // ModExprList 1
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_86 = NULL;
    expr_ret_86 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_85 = expr_ret_86;
    rett = expr_ret_86;
  }

  // ModExprList 2
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_87 = NULL;
    expr_ret_87 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_85 = expr_ret_87;
    ci = expr_ret_87;
  }

  // ModExprList 3
  if (expr_ret_85) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_88 = NULL;
    expr_ret_88 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_85 = expr_ret_88;
    al = expr_ret_88;
  }

  // ModExprList 5
  if (expr_ret_85) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_85) {
    expr_ret_85 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 7
  if (expr_ret_85) {
    // CodeExpr
    #define ret expr_ret_85
    ret = SUCC;
    rule = node(CFN, rett, ci, al);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_85) rew(mod_85);
  expr_ret_84 = expr_ret_85;
  if (!rule) rule = expr_ret_84;
  if (!expr_ret_84) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_89
  daisho_astnode_t* expr_ret_89 = NULL;
  daisho_astnode_t* expr_ret_90 = NULL;
  daisho_astnode_t* expr_ret_91 = NULL;
  rec(mod_91);
  // ModExprList 0
  daisho_astnode_t* expr_ret_92 = NULL;
  daisho_astnode_t* expr_ret_93 = NULL;
  rec(mod_93);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_94 = NULL;
  expr_ret_94 = daisho_parse_fnkw(ctx);
  if (ctx->exit) return NULL;
  expr_ret_93 = expr_ret_94;
  f = expr_ret_94;
  // ModExprList end
  if (!expr_ret_93) rew(mod_93);
  expr_ret_92 = expr_ret_93;
  // optional
  if (!expr_ret_92)
    expr_ret_92 = SUCC;
  expr_ret_91 = expr_ret_92;
  // ModExprList 1
  if (expr_ret_91) {
    // CodeExpr
    #define ret expr_ret_91
    ret = SUCC;
    f = has(f) ? f : leaf(FN);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_95 = NULL;
    expr_ret_95 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_91 = expr_ret_95;
    rett = expr_ret_95;
  }

  // ModExprList 3
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_96 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_96 = leaf(VARIDENT);
      expr_ret_96->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_96->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_96 = NULL;
    }

    expr_ret_91 = expr_ret_96;
    name = expr_ret_96;
  }

  // ModExprList 4
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_97 = NULL;
    expr_ret_97 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_91 = expr_ret_97;
    tmpl = expr_ret_97;
  }

  // ModExprList 5
  if (expr_ret_91) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_91 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_98 = NULL;
    expr_ret_98 = daisho_parse_arglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_91 = expr_ret_98;
    al = expr_ret_98;
  }

  // ModExprList 7
  if (expr_ret_91) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_91 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_99 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_99 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_99 = NULL;
    }

    // optional
    if (!expr_ret_99)
      expr_ret_99 = SUCC;
    expr_ret_91 = expr_ret_99;
  }

  // ModExprList 9
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_100 = NULL;
    expr_ret_100 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_91 = expr_ret_100;
    e = expr_ret_100;
  }

  // ModExprList 10
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_101 = NULL;
    expr_ret_101 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_101)
      expr_ret_101 = SUCC;
    expr_ret_91 = expr_ret_101;
  }

  // ModExprList 11
  if (expr_ret_91) {
    // CodeExpr
    #define ret expr_ret_91
    ret = SUCC;
    rule=node(FNDECL, f, rett, name, tmpl, al, e);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_91) rew(mod_91);
  expr_ret_90 = expr_ret_91;
  if (!rule) rule = expr_ret_90;
  if (!expr_ret_90) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_102
  daisho_astnode_t* expr_ret_102 = NULL;
  daisho_astnode_t* expr_ret_103 = NULL;
  daisho_astnode_t* expr_ret_104 = NULL;
  rec(mod_104);
  // ModExprList 0
  daisho_astnode_t* expr_ret_105 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_105 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_105 = NULL;
  }

  // optional
  if (!expr_ret_105)
    expr_ret_105 = SUCC;
  expr_ret_104 = expr_ret_105;
  // ModExprList 1
  if (expr_ret_104) {
    daisho_astnode_t* expr_ret_106 = NULL;
    expr_ret_106 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_104 = expr_ret_106;
    rett = expr_ret_106;
  }

  // ModExprList 2
  if (expr_ret_104) {
    daisho_astnode_t* expr_ret_107 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_107 = leaf(VARIDENT);
      expr_ret_107->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_107->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_107 = NULL;
    }

    expr_ret_104 = expr_ret_107;
    name = expr_ret_107;
  }

  // ModExprList 3
  if (expr_ret_104) {
    daisho_astnode_t* expr_ret_108 = NULL;
    expr_ret_108 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_104 = expr_ret_108;
    tmpl = expr_ret_108;
  }

  // ModExprList 4
  if (expr_ret_104) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_104) {
    daisho_astnode_t* expr_ret_109 = NULL;
    expr_ret_109 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_104 = expr_ret_109;
    al = expr_ret_109;
  }

  // ModExprList 6
  if (expr_ret_104) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_104) {
    daisho_astnode_t* expr_ret_110 = NULL;
    expr_ret_110 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_110)
      expr_ret_110 = SUCC;
    expr_ret_104 = expr_ret_110;
  }

  // ModExprList 8
  if (expr_ret_104) {
    // CodeExpr
    #define ret expr_ret_104
    ret = SUCC;
    rule=node(FNPROTO, rett, name, tmpl, al);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_104) rew(mod_104);
  expr_ret_103 = expr_ret_104;
  if (!rule) rule = expr_ret_103;
  if (!expr_ret_103) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnkw(daisho_parser_ctx* ctx) {
  #define rule expr_ret_111
  daisho_astnode_t* expr_ret_111 = NULL;
  daisho_astnode_t* expr_ret_112 = NULL;
  daisho_astnode_t* expr_ret_113 = NULL;

  // SlashExpr 0
  if (!expr_ret_113) {
    daisho_astnode_t* expr_ret_114 = NULL;
    rec(mod_114);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Capturing FN.
      expr_ret_114 = leaf(FN);
      expr_ret_114->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_114->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_114 = NULL;
    }

    // ModExprList end
    if (!expr_ret_114) rew(mod_114);
    expr_ret_113 = expr_ret_114;
  }

  // SlashExpr 1
  if (!expr_ret_113) {
    daisho_astnode_t* expr_ret_115 = NULL;
    rec(mod_115);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CUDAKERNEL) {
      // Capturing CUDAKERNEL.
      expr_ret_115 = leaf(CUDAKERNEL);
      expr_ret_115->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_115->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_115 = NULL;
    }

    // ModExprList end
    if (!expr_ret_115) rew(mod_115);
    expr_ret_113 = expr_ret_115;
  }

  // SlashExpr end
  expr_ret_112 = expr_ret_113;

  if (!rule) rule = expr_ret_112;
  if (!expr_ret_112) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_116
  daisho_astnode_t* expr_ret_116 = NULL;
  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_118 = NULL;

  // SlashExpr 0
  if (!expr_ret_118) {
    daisho_astnode_t* expr_ret_119 = NULL;
    rec(mod_119);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_120 = NULL;
    expr_ret_120 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_119 = expr_ret_120;
    rule = expr_ret_120;
    // ModExprList end
    if (!expr_ret_119) rew(mod_119);
    expr_ret_118 = expr_ret_119;
  }

  // SlashExpr 1
  if (!expr_ret_118) {
    daisho_astnode_t* expr_ret_121 = NULL;
    rec(mod_121);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_122 = NULL;
    expr_ret_122 = daisho_parse_fnproto(ctx);
    if (ctx->exit) return NULL;
    expr_ret_121 = expr_ret_122;
    rule = expr_ret_122;
    // ModExprList end
    if (!expr_ret_121) rew(mod_121);
    expr_ret_118 = expr_ret_121;
  }

  // SlashExpr end
  expr_ret_117 = expr_ret_118;

  if (!rule) rule = expr_ret_117;
  if (!expr_ret_117) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_stunmembers(daisho_parser_ctx* ctx) {
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* fd = NULL;
  daisho_astnode_t* vms = NULL;
  #define rule expr_ret_123
  daisho_astnode_t* expr_ret_123 = NULL;
  daisho_astnode_t* expr_ret_124 = NULL;
  daisho_astnode_t* expr_ret_125 = NULL;
  rec(mod_125);
  // ModExprList 0
  daisho_astnode_t* expr_ret_126 = NULL;
  // CodeExpr
  #define ret expr_ret_126
  ret = SUCC;
  ret=list(MEMBERLIST);
  #undef ret
  expr_ret_125 = expr_ret_126;
  members = expr_ret_126;
  // ModExprList 1
  if (expr_ret_125) {
    daisho_astnode_t* expr_ret_127 = NULL;
    daisho_astnode_t* expr_ret_128 = SUCC;
    while (expr_ret_128)
    {
      rec(kleene_rew_127);
      daisho_astnode_t* expr_ret_129 = NULL;

      // SlashExpr 0
      if (!expr_ret_129) {
        daisho_astnode_t* expr_ret_130 = NULL;
        rec(mod_130);
        // ModExprList 0
        daisho_astnode_t* expr_ret_131 = NULL;
        expr_ret_131 = daisho_parse_fndecl(ctx);
        if (ctx->exit) return NULL;
        expr_ret_130 = expr_ret_131;
        fd = expr_ret_131;
        // ModExprList 1
        if (expr_ret_130) {
          // CodeExpr
          #define ret expr_ret_130
          ret = SUCC;
          add(members, fd);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_130) rew(mod_130);
        expr_ret_129 = expr_ret_130;
      }

      // SlashExpr 1
      if (!expr_ret_129) {
        daisho_astnode_t* expr_ret_132 = NULL;
        rec(mod_132);
        // ModExprList 0
        daisho_astnode_t* expr_ret_133 = NULL;
        expr_ret_133 = daisho_parse_varmembers(ctx);
        if (ctx->exit) return NULL;
        expr_ret_132 = expr_ret_133;
        vms = expr_ret_133;
        // ModExprList 1
        if (expr_ret_132) {
          // CodeExpr
          #define ret expr_ret_132
          ret = SUCC;
          for (size_t i = 0; i < vms->num_children; i++) add(members, vms->children[i]);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_132) rew(mod_132);
        expr_ret_129 = expr_ret_132;
      }

      // SlashExpr end
      expr_ret_128 = expr_ret_129;

    }

    expr_ret_127 = SUCC;
    expr_ret_125 = expr_ret_127;
  }

  // ModExprList end
  if (!expr_ret_125) rew(mod_125);
  expr_ret_124 = expr_ret_125;
  if (!rule) rule = expr_ret_124;
  if (!expr_ret_124) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_trimmembers(daisho_parser_ctx* ctx) {
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_134
  daisho_astnode_t* expr_ret_134 = NULL;
  daisho_astnode_t* expr_ret_135 = NULL;
  daisho_astnode_t* expr_ret_136 = NULL;
  rec(mod_136);
  // ModExprList 0
  daisho_astnode_t* expr_ret_137 = NULL;
  // CodeExpr
  #define ret expr_ret_137
  ret = SUCC;
  ret=list(MEMBERLIST);
  #undef ret
  expr_ret_136 = expr_ret_137;
  members = expr_ret_137;
  // ModExprList 1
  if (expr_ret_136) {
    daisho_astnode_t* expr_ret_138 = NULL;
    daisho_astnode_t* expr_ret_139 = SUCC;
    while (expr_ret_139)
    {
      rec(kleene_rew_138);
      daisho_astnode_t* expr_ret_140 = NULL;
      rec(mod_140);
      // ModExprList 0
      daisho_astnode_t* expr_ret_141 = NULL;
      expr_ret_141 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_140 = expr_ret_141;
      m = expr_ret_141;
      // ModExprList 1
      if (expr_ret_140) {
        // CodeExpr
        #define ret expr_ret_140
        ret = SUCC;
        add(members, m);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_140) rew(mod_140);
      expr_ret_139 = expr_ret_140;
    }

    expr_ret_138 = SUCC;
    expr_ret_136 = expr_ret_138;
  }

  // ModExprList end
  if (!expr_ret_136) rew(mod_136);
  expr_ret_135 = expr_ret_136;
  if (!rule) rule = expr_ret_135;
  if (!expr_ret_135) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_varmembers(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* ret = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_142
  daisho_astnode_t* expr_ret_142 = NULL;
  daisho_astnode_t* expr_ret_143 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
  rec(mod_144);
  // ModExprList 0
  daisho_astnode_t* expr_ret_145 = NULL;
  expr_ret_145 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_144 = expr_ret_145;
  t = expr_ret_145;
  // ModExprList 1
  if (expr_ret_144) {
    daisho_astnode_t* expr_ret_146 = NULL;
    // CodeExpr
    #define ret expr_ret_146
    ret = SUCC;
    list(MEMBERLIST);
    #undef ret
    expr_ret_144 = expr_ret_146;
    ret = expr_ret_146;
  }

  // ModExprList 2
  if (expr_ret_144) {
    daisho_astnode_t* expr_ret_147 = NULL;
    daisho_astnode_t* expr_ret_148 = SUCC;
    while (expr_ret_148)
    {
      rec(kleene_rew_147);
      daisho_astnode_t* expr_ret_149 = NULL;
      rec(mod_149);
      // ModExprList 0
      daisho_astnode_t* expr_ret_150 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_150 = leaf(VARIDENT);
        expr_ret_150->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_150->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_150 = NULL;
      }

      expr_ret_149 = expr_ret_150;
      v = expr_ret_150;
      // ModExprList 1
      if (expr_ret_149) {
        // CodeExpr
        #define ret expr_ret_149
        ret = SUCC;
        add(ret, v);
        #undef ret
      }

      // ModExprList 2
      if (expr_ret_149) {
        daisho_astnode_t* expr_ret_151 = NULL;
        daisho_astnode_t* expr_ret_152 = SUCC;
        while (expr_ret_152)
        {
          rec(kleene_rew_151);
          daisho_astnode_t* expr_ret_153 = NULL;
          rec(mod_153);
          // ModExprList 0
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_153 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_153 = NULL;
          }

          // ModExprList 1
          if (expr_ret_153) {
            daisho_astnode_t* expr_ret_154 = NULL;
            if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
              // Capturing VARIDENT.
              expr_ret_154 = leaf(VARIDENT);
              expr_ret_154->tok_repr = ctx->tokens[ctx->pos].content;
              expr_ret_154->repr_len = ctx->tokens[ctx->pos].len;
              ctx->pos++;
            } else {
              expr_ret_154 = NULL;
            }

            expr_ret_153 = expr_ret_154;
            v = expr_ret_154;
          }

          // ModExprList end
          if (!expr_ret_153) rew(mod_153);
          expr_ret_152 = expr_ret_153;
        }

        expr_ret_151 = SUCC;
        expr_ret_149 = expr_ret_151;
      }

      // ModExprList 3
      if (expr_ret_149) {
        // CodeExpr
        #define ret expr_ret_149
        ret = SUCC;
        add(ret, v);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_149) rew(mod_149);
      expr_ret_148 = expr_ret_149;
    }

    expr_ret_147 = SUCC;
    expr_ret_144 = expr_ret_147;
  }

  // ModExprList 3
  if (expr_ret_144) {
    expr_ret_144 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 4
  if (expr_ret_144) {
    // CodeExpr
    #define ret expr_ret_144
    ret = SUCC;
    rule=node(TYPEMEMBER, t, v);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_144) rew(mod_144);
  expr_ret_143 = expr_ret_144;
  if (!rule) rule = expr_ret_143;
  if (!expr_ret_143) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_155
  daisho_astnode_t* expr_ret_155 = NULL;
  daisho_astnode_t* expr_ret_156 = NULL;
  daisho_astnode_t* expr_ret_157 = NULL;

  // SlashExpr 0
  if (!expr_ret_157) {
    daisho_astnode_t* expr_ret_158 = NULL;
    rec(mod_158);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_158 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_158 = NULL;
    }

    // ModExprList 1
    if (expr_ret_158) {
      daisho_astnode_t* expr_ret_159 = NULL;
      expr_ret_159 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_158 = expr_ret_159;
      rule = expr_ret_159;
    }

    // ModExprList 2
    if (expr_ret_158) {
      // CodeExpr
      #define ret expr_ret_158
      ret = SUCC;
      rule->kind = kind(TMPLEXPAND);
      #undef ret
    }

    // ModExprList 3
    if (expr_ret_158) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Capturing GT.
        expr_ret_158 = leaf(GT);
        expr_ret_158->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_158->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_158 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_158) rew(mod_158);
    expr_ret_157 = expr_ret_158;
  }

  // SlashExpr 1
  if (!expr_ret_157) {
    daisho_astnode_t* expr_ret_160 = NULL;
    rec(mod_160);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_160
    ret = SUCC;
    rule=leaf(NOEXPAND);
    #undef ret
    // ModExprList end
    if (!expr_ret_160) rew(mod_160);
    expr_ret_157 = expr_ret_160;
  }

  // SlashExpr end
  expr_ret_156 = expr_ret_157;

  if (!rule) rule = expr_ret_156;
  if (!expr_ret_156) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_kdim(daisho_parser_ctx* ctx) {
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* y = NULL;
  daisho_astnode_t* z = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_161
  daisho_astnode_t* expr_ret_161 = NULL;
  daisho_astnode_t* expr_ret_162 = NULL;
  daisho_astnode_t* expr_ret_163 = NULL;

  // SlashExpr 0
  if (!expr_ret_163) {
    daisho_astnode_t* expr_ret_164 = NULL;
    rec(mod_164);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_164 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_164 = NULL;
    }

    // ModExprList 1
    if (expr_ret_164) {
      daisho_astnode_t* expr_ret_165 = NULL;

      // SlashExpr 0
      if (!expr_ret_165) {
        daisho_astnode_t* expr_ret_166 = NULL;
        rec(mod_166);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_167 = NULL;
        expr_ret_167 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_166 = expr_ret_167;
        x = expr_ret_167;
        // ModExprList end
        if (!expr_ret_166) rew(mod_166);
        expr_ret_165 = expr_ret_166;
      }

      // SlashExpr 1
      if (!expr_ret_165) {
        daisho_astnode_t* expr_ret_168 = NULL;
        rec(mod_168);
        // ModExprList 0
        daisho_astnode_t* expr_ret_169 = NULL;
        expr_ret_169 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_168 = expr_ret_169;
        x = expr_ret_169;
        // ModExprList 1
        if (expr_ret_168) {
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_168 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_168 = NULL;
          }

        }

        // ModExprList 2
        if (expr_ret_168) {
          daisho_astnode_t* expr_ret_170 = NULL;
          expr_ret_170 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_168 = expr_ret_170;
          y = expr_ret_170;
        }

        // ModExprList end
        if (!expr_ret_168) rew(mod_168);
        expr_ret_165 = expr_ret_168;
      }

      // SlashExpr 2
      if (!expr_ret_165) {
        daisho_astnode_t* expr_ret_171 = NULL;
        rec(mod_171);
        // ModExprList 0
        daisho_astnode_t* expr_ret_172 = NULL;
        expr_ret_172 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_171 = expr_ret_172;
        x = expr_ret_172;
        // ModExprList 1
        if (expr_ret_171) {
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_171 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_171 = NULL;
          }

        }

        // ModExprList 2
        if (expr_ret_171) {
          daisho_astnode_t* expr_ret_173 = NULL;
          expr_ret_173 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_171 = expr_ret_173;
          y = expr_ret_173;
        }

        // ModExprList 3
        if (expr_ret_171) {
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_171 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_171 = NULL;
          }

        }

        // ModExprList 4
        if (expr_ret_171) {
          daisho_astnode_t* expr_ret_174 = NULL;
          expr_ret_174 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_171 = expr_ret_174;
          z = expr_ret_174;
        }

        // ModExprList end
        if (!expr_ret_171) rew(mod_171);
        expr_ret_165 = expr_ret_171;
      }

      // SlashExpr end
      expr_ret_164 = expr_ret_165;

    }

    // ModExprList 2
    if (expr_ret_164) {
      daisho_astnode_t* expr_ret_175 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_175 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_175 = NULL;
      }

      // optional
      if (!expr_ret_175)
        expr_ret_175 = SUCC;
      expr_ret_164 = expr_ret_175;
    }

    // ModExprList 3
    if (expr_ret_164) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
        // Capturing RCBRACK.
        expr_ret_164 = leaf(RCBRACK);
        expr_ret_164->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_164->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_164 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_164) rew(mod_164);
    expr_ret_163 = expr_ret_164;
  }

  // SlashExpr 1
  if (!expr_ret_163) {
    daisho_astnode_t* expr_ret_176 = NULL;
    rec(mod_176);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_177 = NULL;
    expr_ret_177 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_176 = expr_ret_177;
    e = expr_ret_177;
    // ModExprList end
    if (!expr_ret_176) rew(mod_176);
    expr_ret_163 = expr_ret_176;
  }

  // SlashExpr end
  expr_ret_162 = expr_ret_163;

  if (!rule) rule = expr_ret_162;
  if (!expr_ret_162) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_kexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* dg = NULL;
  daisho_astnode_t* db = NULL;
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_178
  daisho_astnode_t* expr_ret_178 = NULL;
  daisho_astnode_t* expr_ret_179 = NULL;
  daisho_astnode_t* expr_ret_180 = NULL;
  rec(mod_180);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
    // Not capturing LT.
    expr_ret_180 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_180 = NULL;
  }

  // ModExprList 1
  if (expr_ret_180) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_180 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_180 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_180) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_180 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_180 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_180) {
    daisho_astnode_t* expr_ret_181 = NULL;

    // SlashExpr 0
    if (!expr_ret_181) {
      daisho_astnode_t* expr_ret_182 = NULL;
      rec(mod_182);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_183 = NULL;
      expr_ret_183 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_182 = expr_ret_183;
      dg = expr_ret_183;
      // ModExprList end
      if (!expr_ret_182) rew(mod_182);
      expr_ret_181 = expr_ret_182;
    }

    // SlashExpr 1
    if (!expr_ret_181) {
      daisho_astnode_t* expr_ret_184 = NULL;
      rec(mod_184);
      // ModExprList 0
      daisho_astnode_t* expr_ret_185 = NULL;
      expr_ret_185 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_184 = expr_ret_185;
      dg = expr_ret_185;
      // ModExprList 1
      if (expr_ret_184) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_184 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_184 = NULL;
        }

      }

      // ModExprList 2
      if (expr_ret_184) {
        daisho_astnode_t* expr_ret_186 = NULL;
        expr_ret_186 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_184 = expr_ret_186;
        db = expr_ret_186;
      }

      // ModExprList end
      if (!expr_ret_184) rew(mod_184);
      expr_ret_181 = expr_ret_184;
    }

    // SlashExpr 2
    if (!expr_ret_181) {
      daisho_astnode_t* expr_ret_187 = NULL;
      rec(mod_187);
      // ModExprList 0
      daisho_astnode_t* expr_ret_188 = NULL;
      expr_ret_188 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_187 = expr_ret_188;
      dg = expr_ret_188;
      // ModExprList 1
      if (expr_ret_187) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_187 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_187 = NULL;
        }

      }

      // ModExprList 2
      if (expr_ret_187) {
        daisho_astnode_t* expr_ret_189 = NULL;
        expr_ret_189 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_187 = expr_ret_189;
        db = expr_ret_189;
      }

      // ModExprList 3
      if (expr_ret_187) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_187 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_187 = NULL;
        }

      }

      // ModExprList 4
      if (expr_ret_187) {
        daisho_astnode_t* expr_ret_190 = NULL;
        expr_ret_190 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_187 = expr_ret_190;
        ns = expr_ret_190;
      }

      // ModExprList end
      if (!expr_ret_187) rew(mod_187);
      expr_ret_181 = expr_ret_187;
    }

    // SlashExpr 3
    if (!expr_ret_181) {
      daisho_astnode_t* expr_ret_191 = NULL;
      rec(mod_191);
      // ModExprList 0
      daisho_astnode_t* expr_ret_192 = NULL;
      expr_ret_192 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_191 = expr_ret_192;
      dg = expr_ret_192;
      // ModExprList 1
      if (expr_ret_191) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_191 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_191 = NULL;
        }

      }

      // ModExprList 2
      if (expr_ret_191) {
        daisho_astnode_t* expr_ret_193 = NULL;
        expr_ret_193 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_191 = expr_ret_193;
        db = expr_ret_193;
      }

      // ModExprList 3
      if (expr_ret_191) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_191 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_191 = NULL;
        }

      }

      // ModExprList 4
      if (expr_ret_191) {
        daisho_astnode_t* expr_ret_194 = NULL;
        expr_ret_194 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_191 = expr_ret_194;
        ns = expr_ret_194;
      }

      // ModExprList 5
      if (expr_ret_191) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_191 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_191 = NULL;
        }

      }

      // ModExprList 6
      if (expr_ret_191) {
        daisho_astnode_t* expr_ret_195 = NULL;
        expr_ret_195 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_191 = expr_ret_195;
        s = expr_ret_195;
      }

      // ModExprList end
      if (!expr_ret_191) rew(mod_191);
      expr_ret_181 = expr_ret_191;
    }

    // SlashExpr end
    expr_ret_180 = expr_ret_181;

  }

  // ModExprList 4
  if (expr_ret_180) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_180 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_180 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_180) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_180 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_180 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_180) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_180 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_180 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_180) {
    // CodeExpr
    #define ret expr_ret_180
    ret = SUCC;
    rule=node(KCALLARGS, dg, db, ns, s);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_180) rew(mod_180);
  expr_ret_179 = expr_ret_180;
  if (!rule) rule = expr_ret_179;
  if (!expr_ret_179) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx) {
  #define rule expr_ret_196
  daisho_astnode_t* expr_ret_196 = NULL;
  daisho_astnode_t* expr_ret_197 = NULL;
  daisho_astnode_t* expr_ret_198 = NULL;
  rec(mod_198);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_199 = NULL;

  // SlashExpr 0
  if (!expr_ret_199) {
    daisho_astnode_t* expr_ret_200 = NULL;
    rec(mod_200);
    // ModExprList Forwarding
    expr_ret_200 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_200) rew(mod_200);
    expr_ret_199 = expr_ret_200;
  }

  // SlashExpr 1
  if (!expr_ret_199) {
    daisho_astnode_t* expr_ret_201 = NULL;
    rec(mod_201);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_201
    ret = SUCC;
    ret=leaf(INFER_TYPE);
    #undef ret
    // ModExprList end
    if (!expr_ret_201) rew(mod_201);
    expr_ret_199 = expr_ret_201;
  }

  // SlashExpr end
  expr_ret_198 = expr_ret_199;

  // ModExprList end
  if (!expr_ret_198) rew(mod_198);
  expr_ret_197 = expr_ret_198;
  if (!rule) rule = expr_ret_197;
  if (!expr_ret_197) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_202
  daisho_astnode_t* expr_ret_202 = NULL;
  daisho_astnode_t* expr_ret_203 = NULL;
  daisho_astnode_t* expr_ret_204 = NULL;
  rec(mod_204);
  // ModExprList 0
  rec(mexpr_state_205)
  daisho_astnode_t* expr_ret_205 = NULL;
  daisho_astnode_t* expr_ret_206 = NULL;

  // SlashExpr 0
  if (!expr_ret_206) {
    daisho_astnode_t* expr_ret_207 = NULL;
    rec(mod_207);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_207 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_207 = NULL;
    }

    // ModExprList end
    if (!expr_ret_207) rew(mod_207);
    expr_ret_206 = expr_ret_207;
  }

  // SlashExpr 1
  if (!expr_ret_206) {
    daisho_astnode_t* expr_ret_208 = NULL;
    rec(mod_208);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Not capturing SELFTYPE.
      expr_ret_208 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_208 = NULL;
    }

    // ModExprList end
    if (!expr_ret_208) rew(mod_208);
    expr_ret_206 = expr_ret_208;
  }

  // SlashExpr 2
  if (!expr_ret_206) {
    daisho_astnode_t* expr_ret_209 = NULL;
    rec(mod_209);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Not capturing VOIDTYPE.
      expr_ret_209 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_209 = NULL;
    }

    // ModExprList end
    if (!expr_ret_209) rew(mod_209);
    expr_ret_206 = expr_ret_209;
  }

  // SlashExpr 3
  if (!expr_ret_206) {
    daisho_astnode_t* expr_ret_210 = NULL;
    rec(mod_210);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Not capturing VOIDPTR.
      expr_ret_210 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_210 = NULL;
    }

    // ModExprList end
    if (!expr_ret_210) rew(mod_210);
    expr_ret_206 = expr_ret_210;
  }

  // SlashExpr 4
  if (!expr_ret_206) {
    daisho_astnode_t* expr_ret_211 = NULL;
    rec(mod_211);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_211 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_211 = NULL;
    }

    // ModExprList end
    if (!expr_ret_211) rew(mod_211);
    expr_ret_206 = expr_ret_211;
  }

  // SlashExpr end
  expr_ret_205 = expr_ret_206;

  // rewind
  rew(mexpr_state_205);
  expr_ret_204 = expr_ret_205;
  // ModExprList 1
  if (expr_ret_204) {
    daisho_astnode_t* expr_ret_212 = NULL;
    expr_ret_212 = daisho_parse_fntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_204 = expr_ret_212;
    rule = expr_ret_212;
  }

  // ModExprList end
  if (!expr_ret_204) rew(mod_204);
  expr_ret_203 = expr_ret_204;
  if (!rule) rule = expr_ret_203;
  if (!expr_ret_203) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* from = NULL;
  daisho_astnode_t* to = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_213
  daisho_astnode_t* expr_ret_213 = NULL;
  daisho_astnode_t* expr_ret_214 = NULL;
  daisho_astnode_t* expr_ret_215 = NULL;
  rec(mod_215);
  // ModExprList 0
  daisho_astnode_t* expr_ret_216 = NULL;
  // CodeExpr
  #define ret expr_ret_216
  ret = SUCC;
  ;
  #undef ret
  expr_ret_215 = expr_ret_216;
  from = expr_ret_216;
  // ModExprList 1
  if (expr_ret_215) {
    daisho_astnode_t* expr_ret_217 = NULL;
    expr_ret_217 = daisho_parse_ptrtype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_215 = expr_ret_217;
    to = expr_ret_217;
  }

  // ModExprList 2
  if (expr_ret_215) {
    daisho_astnode_t* expr_ret_218 = NULL;
    daisho_astnode_t* expr_ret_219 = SUCC;
    while (expr_ret_219)
    {
      rec(kleene_rew_218);
      daisho_astnode_t* expr_ret_220 = NULL;
      rec(mod_220);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_220 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_220 = NULL;
      }

      // ModExprList 1
      if (expr_ret_220) {
        daisho_astnode_t* expr_ret_221 = NULL;
        expr_ret_221 = daisho_parse_ptrtype(ctx);
        if (ctx->exit) return NULL;
        expr_ret_220 = expr_ret_221;
        n = expr_ret_221;
      }

      // ModExprList 2
      if (expr_ret_220) {
        // CodeExpr
        #define ret expr_ret_220
        ret = SUCC;
        if (!has(from)) from = list(TYPELIST);
        #undef ret
      }

      // ModExprList 3
      if (expr_ret_220) {
        // CodeExpr
        #define ret expr_ret_220
        ret = SUCC;
        add(from, to); to = n;
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_220) rew(mod_220);
      expr_ret_219 = expr_ret_220;
    }

    expr_ret_218 = SUCC;
    expr_ret_215 = expr_ret_218;
  }

  // ModExprList 3
  if (expr_ret_215) {
    // CodeExpr
    #define ret expr_ret_215
    ret = SUCC;
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_215) rew(mod_215);
  expr_ret_214 = expr_ret_215;
  if (!rule) rule = expr_ret_214;
  if (!expr_ret_214) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_222
  daisho_astnode_t* expr_ret_222 = NULL;
  daisho_astnode_t* expr_ret_223 = NULL;
  daisho_astnode_t* expr_ret_224 = NULL;
  rec(mod_224);
  // ModExprList 0
  daisho_astnode_t* expr_ret_225 = NULL;
  expr_ret_225 = daisho_parse_basetype(ctx);
  if (ctx->exit) return NULL;
  expr_ret_224 = expr_ret_225;
  rule = expr_ret_225;
  // ModExprList 1
  if (expr_ret_224) {
    daisho_astnode_t* expr_ret_226 = NULL;
    daisho_astnode_t* expr_ret_227 = SUCC;
    while (expr_ret_227)
    {
      rec(kleene_rew_226);
      daisho_astnode_t* expr_ret_228 = NULL;
      rec(mod_228);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_228 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_228 = NULL;
      }

      // ModExprList 1
      if (expr_ret_228) {
        // CodeExpr
        #define ret expr_ret_228
        ret = SUCC;
        rule=node(PTRTYPE, rule);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_228) rew(mod_228);
      expr_ret_227 = expr_ret_228;
    }

    expr_ret_226 = SUCC;
    expr_ret_224 = expr_ret_226;
  }

  // ModExprList end
  if (!expr_ret_224) rew(mod_224);
  expr_ret_223 = expr_ret_224;
  if (!rule) rule = expr_ret_223;
  if (!expr_ret_223) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_229
  daisho_astnode_t* expr_ret_229 = NULL;
  daisho_astnode_t* expr_ret_230 = NULL;
  daisho_astnode_t* expr_ret_231 = NULL;

  // SlashExpr 0
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_232 = NULL;
    rec(mod_232);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_232 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_232 = NULL;
    }

    // ModExprList 1
    if (expr_ret_232) {
      daisho_astnode_t* expr_ret_233 = NULL;
      expr_ret_233 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_232 = expr_ret_233;
      rule = expr_ret_233;
    }

    // ModExprList 2
    if (expr_ret_232) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_232 = leaf(CLOSE);
        expr_ret_232->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_232->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_232 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_232) rew(mod_232);
    expr_ret_231 = expr_ret_232;
  }

  // SlashExpr 1
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_234 = NULL;
    rec(mod_234);
    // ModExprList Forwarding
    expr_ret_234 = daisho_parse_tupletype(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_234) rew(mod_234);
    expr_ret_231 = expr_ret_234;
  }

  // SlashExpr 2
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_235 = NULL;
    rec(mod_235);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Capturing SELFTYPE.
      expr_ret_235 = leaf(SELFTYPE);
      expr_ret_235->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_235->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_235 = NULL;
    }

    // ModExprList end
    if (!expr_ret_235) rew(mod_235);
    expr_ret_231 = expr_ret_235;
  }

  // SlashExpr 3
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_236 = NULL;
    rec(mod_236);
    // ModExprList 0
    daisho_astnode_t* expr_ret_237 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_237 = leaf(VOIDTYPE);
      expr_ret_237->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_237->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_237 = NULL;
    }

    expr_ret_236 = expr_ret_237;
    v = expr_ret_237;
    // ModExprList 1
    if (expr_ret_236) {
      rec(mexpr_state_238)
      daisho_astnode_t* expr_ret_238 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_238 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_238 = NULL;
      }

      // invert
      expr_ret_238 = expr_ret_238 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_238);
      expr_ret_236 = expr_ret_238;
    }

    // ModExprList 2
    if (expr_ret_236) {
      // CodeExpr
      #define ret expr_ret_236
      ret = SUCC;
      rule=v;
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_236) rew(mod_236);
    expr_ret_231 = expr_ret_236;
  }

  // SlashExpr 4
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_239 = NULL;
    rec(mod_239);
    // ModExprList Forwarding
    expr_ret_239 = daisho_parse_voidptr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_239) rew(mod_239);
    expr_ret_231 = expr_ret_239;
  }

  // SlashExpr 5
  if (!expr_ret_231) {
    daisho_astnode_t* expr_ret_240 = NULL;
    rec(mod_240);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_241 = NULL;
    rec(mod_241);
    // ModExprList 0
    daisho_astnode_t* expr_ret_242 = NULL;
    daisho_astnode_t* expr_ret_243 = NULL;
    rec(mod_243);
    // ModExprList 0
    daisho_astnode_t* expr_ret_244 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_244 = leaf(TYPEIDENT);
      expr_ret_244->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_244->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_244 = NULL;
    }

    expr_ret_243 = expr_ret_244;
    ns = expr_ret_244;
    // ModExprList 1
    if (expr_ret_243) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_243 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_243 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_243) rew(mod_243);
    expr_ret_242 = expr_ret_243;
    // optional
    if (!expr_ret_242)
      expr_ret_242 = SUCC;
    expr_ret_241 = expr_ret_242;
    // ModExprList 1
    if (expr_ret_241) {
      daisho_astnode_t* expr_ret_245 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_245 = leaf(TYPEIDENT);
        expr_ret_245->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_245->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_245 = NULL;
      }

      expr_ret_241 = expr_ret_245;
      s = expr_ret_245;
    }

    // ModExprList 2
    if (expr_ret_241) {
      daisho_astnode_t* expr_ret_246 = NULL;
      expr_ret_246 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_241 = expr_ret_246;
      t = expr_ret_246;
    }

    // ModExprList 3
    if (expr_ret_241) {
      // CodeExpr
      #define ret expr_ret_241
      ret = SUCC;
      if (!has(ns)) ns = leaf(CURRENT_NS);
      #undef ret
    }

    // ModExprList 4
    if (expr_ret_241) {
      // CodeExpr
      #define ret expr_ret_241
      ret = SUCC;
      rule=node(BASETYPE, ns, s, t);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_241) rew(mod_241);
    expr_ret_240 = expr_ret_241;
    // ModExprList end
    if (!expr_ret_240) rew(mod_240);
    expr_ret_231 = expr_ret_240;
  }

  // SlashExpr end
  expr_ret_230 = expr_ret_231;

  if (!rule) rule = expr_ret_230;
  if (!expr_ret_230) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_247
  daisho_astnode_t* expr_ret_247 = NULL;
  daisho_astnode_t* expr_ret_248 = NULL;
  daisho_astnode_t* expr_ret_249 = NULL;

  // SlashExpr 0
  if (!expr_ret_249) {
    daisho_astnode_t* expr_ret_250 = NULL;
    rec(mod_250);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_250 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_250 = NULL;
    }

    // ModExprList 1
    if (expr_ret_250) {
      daisho_astnode_t* expr_ret_251 = NULL;
      expr_ret_251 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_250 = expr_ret_251;
      t = expr_ret_251;
    }

    // ModExprList 2
    if (expr_ret_250) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_250 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_250 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_250) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_250 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_250 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_250) {
      // CodeExpr
      #define ret expr_ret_250
      ret = SUCC;
      rule=node(TUPLETYPE, t);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_250) rew(mod_250);
    expr_ret_249 = expr_ret_250;
  }

  // SlashExpr 1
  if (!expr_ret_249) {
    daisho_astnode_t* expr_ret_252 = NULL;
    rec(mod_252);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_252 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_252 = NULL;
    }

    // ModExprList 1
    if (expr_ret_252) {
      daisho_astnode_t* expr_ret_253 = NULL;
      expr_ret_253 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_252 = expr_ret_253;
      rule = expr_ret_253;
    }

    // ModExprList 2
    if (expr_ret_252) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_252 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_252 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_252) {
      // CodeExpr
      #define ret expr_ret_252
      ret = SUCC;
      rule->kind = kind(TUPLETYPE);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_252) rew(mod_252);
    expr_ret_249 = expr_ret_252;
  }

  // SlashExpr end
  expr_ret_248 = expr_ret_249;

  if (!rule) rule = expr_ret_248;
  if (!expr_ret_248) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_254
  daisho_astnode_t* expr_ret_254 = NULL;
  daisho_astnode_t* expr_ret_255 = NULL;
  daisho_astnode_t* expr_ret_256 = NULL;

  // SlashExpr 0
  if (!expr_ret_256) {
    daisho_astnode_t* expr_ret_257 = NULL;
    rec(mod_257);
    // ModExprList 0
    daisho_astnode_t* expr_ret_258 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_258 = leaf(VOIDPTR);
      expr_ret_258->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_258->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_258 = NULL;
    }

    expr_ret_257 = expr_ret_258;
    v = expr_ret_258;
    // ModExprList 1
    if (expr_ret_257) {
      // CodeExpr
      #define ret expr_ret_257
      ret = SUCC;
      rule=v;
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_257) rew(mod_257);
    expr_ret_256 = expr_ret_257;
  }

  // SlashExpr 1
  if (!expr_ret_256) {
    daisho_astnode_t* expr_ret_259 = NULL;
    rec(mod_259);
    // ModExprList 0
    daisho_astnode_t* expr_ret_260 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_260 = leaf(VOIDTYPE);
      expr_ret_260->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_260->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_260 = NULL;
    }

    expr_ret_259 = expr_ret_260;
    v = expr_ret_260;
    // ModExprList 1
    if (expr_ret_259) {
      daisho_astnode_t* expr_ret_261 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_261 = leaf(STAR);
        expr_ret_261->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_261->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_261 = NULL;
      }

      expr_ret_259 = expr_ret_261;
      s = expr_ret_261;
    }

    // ModExprList 2
    if (expr_ret_259) {
      // CodeExpr
      #define ret expr_ret_259
      ret = SUCC;
      rule=leaf(VOIDPTR);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_259) rew(mod_259);
    expr_ret_256 = expr_ret_259;
  }

  // SlashExpr end
  expr_ret_255 = expr_ret_256;

  if (!rule) rule = expr_ret_255;
  if (!expr_ret_255) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_262
  daisho_astnode_t* expr_ret_262 = NULL;
  daisho_astnode_t* expr_ret_263 = NULL;
  daisho_astnode_t* expr_ret_264 = NULL;
  rec(mod_264);
  // ModExprList 0
  daisho_astnode_t* expr_ret_265 = NULL;
  expr_ret_265 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_265)
    expr_ret_265 = SUCC;
  expr_ret_264 = expr_ret_265;
  // ModExprList 1
  if (expr_ret_264) {
    // CodeExpr
    #define ret expr_ret_264
    ret = SUCC;
    rule=list(TYPELIST);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_264) {
    daisho_astnode_t* expr_ret_266 = NULL;
    expr_ret_266 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_266)
      expr_ret_266 = SUCC;
    expr_ret_264 = expr_ret_266;
    t = expr_ret_266;
  }

  // ModExprList 3
  if (expr_ret_264) {
    // CodeExpr
    #define ret expr_ret_264
    ret = SUCC;
    if has(t) add(rule, t);
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_264) {
    daisho_astnode_t* expr_ret_267 = NULL;
    daisho_astnode_t* expr_ret_268 = SUCC;
    while (expr_ret_268)
    {
      rec(kleene_rew_267);
      daisho_astnode_t* expr_ret_269 = NULL;
      rec(mod_269);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_269 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_269 = NULL;
      }

      // ModExprList 1
      if (expr_ret_269) {
        daisho_astnode_t* expr_ret_270 = NULL;
        expr_ret_270 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_269 = expr_ret_270;
        t = expr_ret_270;
      }

      // ModExprList 2
      if (expr_ret_269) {
        // CodeExpr
        #define ret expr_ret_269
        ret = SUCC;
        add(rule, t);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_269) rew(mod_269);
      expr_ret_268 = expr_ret_269;
    }

    expr_ret_267 = SUCC;
    expr_ret_264 = expr_ret_267;
  }

  // ModExprList 5
  if (expr_ret_264) {
    daisho_astnode_t* expr_ret_271 = NULL;
    expr_ret_271 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_271)
      expr_ret_271 = SUCC;
    expr_ret_264 = expr_ret_271;
  }

  // ModExprList end
  if (!expr_ret_264) rew(mod_264);
  expr_ret_263 = expr_ret_264;
  if (!rule) rule = expr_ret_263;
  if (!expr_ret_263) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_272
  daisho_astnode_t* expr_ret_272 = NULL;
  daisho_astnode_t* expr_ret_273 = NULL;
  daisho_astnode_t* expr_ret_274 = NULL;
  rec(mod_274);
  // ModExprList 0
  daisho_astnode_t* expr_ret_275 = NULL;
  expr_ret_275 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_275)
    expr_ret_275 = SUCC;
  expr_ret_274 = expr_ret_275;
  // ModExprList 1
  if (expr_ret_274) {
    // CodeExpr
    #define ret expr_ret_274
    ret = SUCC;
    rule=list(EXPRLIST);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_274) {
    daisho_astnode_t* expr_ret_276 = NULL;
    expr_ret_276 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_276)
      expr_ret_276 = SUCC;
    expr_ret_274 = expr_ret_276;
    e = expr_ret_276;
  }

  // ModExprList 3
  if (expr_ret_274) {
    // CodeExpr
    #define ret expr_ret_274
    ret = SUCC;
    if has(e) add(rule, e);
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_274) {
    daisho_astnode_t* expr_ret_277 = NULL;
    daisho_astnode_t* expr_ret_278 = SUCC;
    while (expr_ret_278)
    {
      rec(kleene_rew_277);
      daisho_astnode_t* expr_ret_279 = NULL;
      rec(mod_279);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_279 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_279 = NULL;
      }

      // ModExprList 1
      if (expr_ret_279) {
        daisho_astnode_t* expr_ret_280 = NULL;
        expr_ret_280 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_279 = expr_ret_280;
        e = expr_ret_280;
      }

      // ModExprList 2
      if (expr_ret_279) {
        // CodeExpr
        #define ret expr_ret_279
        ret = SUCC;
        add(rule, e);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_279) rew(mod_279);
      expr_ret_278 = expr_ret_279;
    }

    expr_ret_277 = SUCC;
    expr_ret_274 = expr_ret_277;
  }

  // ModExprList 5
  if (expr_ret_274) {
    daisho_astnode_t* expr_ret_281 = NULL;
    expr_ret_281 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_281)
      expr_ret_281 = SUCC;
    expr_ret_274 = expr_ret_281;
  }

  // ModExprList end
  if (!expr_ret_274) rew(mod_274);
  expr_ret_273 = expr_ret_274;
  if (!rule) rule = expr_ret_273;
  if (!expr_ret_273) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_282
  daisho_astnode_t* expr_ret_282 = NULL;
  daisho_astnode_t* expr_ret_283 = NULL;
  daisho_astnode_t* expr_ret_284 = NULL;
  rec(mod_284);
  // ModExprList 0
  daisho_astnode_t* expr_ret_285 = NULL;
  expr_ret_285 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_284 = expr_ret_285;
  t = expr_ret_285;
  // ModExprList 1
  if (expr_ret_284) {
    daisho_astnode_t* expr_ret_286 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_286 = leaf(VARIDENT);
      expr_ret_286->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_286->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_286 = NULL;
    }

    expr_ret_284 = expr_ret_286;
    i = expr_ret_286;
  }

  // ModExprList 2
  if (expr_ret_284) {
    // CodeExpr
    #define ret expr_ret_284
    ret = SUCC;
    rule=node(FNARG, t, i);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_284) rew(mod_284);
  expr_ret_283 = expr_ret_284;
  if (!rule) rule = expr_ret_283;
  if (!expr_ret_283) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_287
  daisho_astnode_t* expr_ret_287 = NULL;
  daisho_astnode_t* expr_ret_288 = NULL;
  daisho_astnode_t* expr_ret_289 = NULL;
  rec(mod_289);
  // ModExprList 0
  daisho_astnode_t* expr_ret_290 = NULL;
  expr_ret_290 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_290)
    expr_ret_290 = SUCC;
  expr_ret_289 = expr_ret_290;
  // ModExprList 1
  if (expr_ret_289) {
    // CodeExpr
    #define ret expr_ret_289
    ret = SUCC;
    rule=list(ARGLIST);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_289) {
    daisho_astnode_t* expr_ret_291 = NULL;
    expr_ret_291 = daisho_parse_fnarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_291)
      expr_ret_291 = SUCC;
    expr_ret_289 = expr_ret_291;
    a = expr_ret_291;
  }

  // ModExprList 3
  if (expr_ret_289) {
    // CodeExpr
    #define ret expr_ret_289
    ret = SUCC;
    if has(a) add(rule, a);
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_289) {
    daisho_astnode_t* expr_ret_292 = NULL;
    daisho_astnode_t* expr_ret_293 = SUCC;
    while (expr_ret_293)
    {
      rec(kleene_rew_292);
      daisho_astnode_t* expr_ret_294 = NULL;
      rec(mod_294);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_294 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_294 = NULL;
      }

      // ModExprList 1
      if (expr_ret_294) {
        daisho_astnode_t* expr_ret_295 = NULL;
        expr_ret_295 = daisho_parse_fnarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_294 = expr_ret_295;
        a = expr_ret_295;
      }

      // ModExprList 2
      if (expr_ret_294) {
        // CodeExpr
        #define ret expr_ret_294
        ret = SUCC;
        add(rule, a);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_294) rew(mod_294);
      expr_ret_293 = expr_ret_294;
    }

    expr_ret_292 = SUCC;
    expr_ret_289 = expr_ret_292;
  }

  // ModExprList 5
  if (expr_ret_289) {
    daisho_astnode_t* expr_ret_296 = NULL;
    expr_ret_296 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_296)
      expr_ret_296 = SUCC;
    expr_ret_289 = expr_ret_296;
  }

  // ModExprList end
  if (!expr_ret_289) rew(mod_289);
  expr_ret_288 = expr_ret_289;
  if (!rule) rule = expr_ret_288;
  if (!expr_ret_288) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_297
  daisho_astnode_t* expr_ret_297 = NULL;
  daisho_astnode_t* expr_ret_298 = NULL;
  daisho_astnode_t* expr_ret_299 = NULL;
  rec(mod_299);
  // ModExprList 0
  daisho_astnode_t* expr_ret_300 = NULL;
  expr_ret_300 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_299 = expr_ret_300;
  t = expr_ret_300;
  // ModExprList 1
  if (expr_ret_299) {
    daisho_astnode_t* expr_ret_301 = NULL;
    daisho_astnode_t* expr_ret_302 = NULL;

    // SlashExpr 0
    if (!expr_ret_302) {
      daisho_astnode_t* expr_ret_303 = NULL;
      rec(mod_303);
      // ModExprList Forwarding
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_303 = leaf(VARIDENT);
        expr_ret_303->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_303->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_303 = NULL;
      }

      // ModExprList end
      if (!expr_ret_303) rew(mod_303);
      expr_ret_302 = expr_ret_303;
    }

    // SlashExpr 1
    if (!expr_ret_302) {
      daisho_astnode_t* expr_ret_304 = NULL;
      rec(mod_304);
      // ModExprList Forwarding
      // CodeExpr
      #define ret expr_ret_304
      ret = SUCC;
      ret=leaf(NOARG);
      #undef ret
      // ModExprList end
      if (!expr_ret_304) rew(mod_304);
      expr_ret_302 = expr_ret_304;
    }

    // SlashExpr end
    expr_ret_301 = expr_ret_302;

    expr_ret_299 = expr_ret_301;
    i = expr_ret_301;
  }

  // ModExprList 2
  if (expr_ret_299) {
    // CodeExpr
    #define ret expr_ret_299
    ret = SUCC;
    rule=node(PROTOARG, t, i);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_299) rew(mod_299);
  expr_ret_298 = expr_ret_299;
  if (!rule) rule = expr_ret_298;
  if (!expr_ret_298) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_305
  daisho_astnode_t* expr_ret_305 = NULL;
  daisho_astnode_t* expr_ret_306 = NULL;
  daisho_astnode_t* expr_ret_307 = NULL;
  rec(mod_307);
  // ModExprList 0
  daisho_astnode_t* expr_ret_308 = NULL;
  expr_ret_308 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_308)
    expr_ret_308 = SUCC;
  expr_ret_307 = expr_ret_308;
  // ModExprList 1
  if (expr_ret_307) {
    // CodeExpr
    #define ret expr_ret_307
    ret = SUCC;
    rule=list(PROTOLIST);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_307) {
    daisho_astnode_t* expr_ret_309 = NULL;
    expr_ret_309 = daisho_parse_protoarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_309)
      expr_ret_309 = SUCC;
    expr_ret_307 = expr_ret_309;
    p = expr_ret_309;
  }

  // ModExprList 3
  if (expr_ret_307) {
    // CodeExpr
    #define ret expr_ret_307
    ret = SUCC;
    if has(p) add(rule, p);
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_307) {
    daisho_astnode_t* expr_ret_310 = NULL;
    daisho_astnode_t* expr_ret_311 = SUCC;
    while (expr_ret_311)
    {
      rec(kleene_rew_310);
      daisho_astnode_t* expr_ret_312 = NULL;
      rec(mod_312);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_312 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_312 = NULL;
      }

      // ModExprList 1
      if (expr_ret_312) {
        daisho_astnode_t* expr_ret_313 = NULL;
        expr_ret_313 = daisho_parse_protoarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_312 = expr_ret_313;
        p = expr_ret_313;
      }

      // ModExprList 2
      if (expr_ret_312) {
        // CodeExpr
        #define ret expr_ret_312
        ret = SUCC;
        add(rule, p);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_312) rew(mod_312);
      expr_ret_311 = expr_ret_312;
    }

    expr_ret_310 = SUCC;
    expr_ret_307 = expr_ret_310;
  }

  // ModExprList 5
  if (expr_ret_307) {
    daisho_astnode_t* expr_ret_314 = NULL;
    expr_ret_314 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_314)
      expr_ret_314 = SUCC;
    expr_ret_307 = expr_ret_314;
  }

  // ModExprList end
  if (!expr_ret_307) rew(mod_307);
  expr_ret_306 = expr_ret_307;
  if (!rule) rule = expr_ret_306;
  if (!expr_ret_306) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_315
  daisho_astnode_t* expr_ret_315 = NULL;
  daisho_astnode_t* expr_ret_316 = NULL;
  daisho_astnode_t* expr_ret_317 = NULL;
  rec(mod_317);
  // ModExprList 0
  rec(mexpr_state_318)
  daisho_astnode_t* expr_ret_318 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Not capturing SEMI.
    expr_ret_318 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_318 = NULL;
  }

  // invert
  expr_ret_318 = expr_ret_318 ? NULL : SUCC;
  // rewind
  rew(mexpr_state_318);
  expr_ret_317 = expr_ret_318;
  // ModExprList 1
  if (expr_ret_317) {
    rec(mexpr_state_319)
    daisho_astnode_t* expr_ret_319 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_319 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_319 = NULL;
    }

    // invert
    expr_ret_319 = expr_ret_319 ? NULL : SUCC;
    // rewind
    rew(mexpr_state_319);
    expr_ret_317 = expr_ret_319;
  }

  // ModExprList 2
  if (expr_ret_317) {
    daisho_astnode_t* expr_ret_320 = NULL;
    expr_ret_320 = daisho_parse_preretexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_317 = expr_ret_320;
    rule = expr_ret_320;
  }

  // ModExprList end
  if (!expr_ret_317) rew(mod_317);
  expr_ret_316 = expr_ret_317;
  if (!rule) rule = expr_ret_316;
  if (!expr_ret_316) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_321
  daisho_astnode_t* expr_ret_321 = NULL;
  daisho_astnode_t* expr_ret_322 = NULL;
  daisho_astnode_t* expr_ret_323 = NULL;

  // SlashExpr 0
  if (!expr_ret_323) {
    daisho_astnode_t* expr_ret_324 = NULL;
    rec(mod_324);
    // ModExprList 0
    daisho_astnode_t* expr_ret_325 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_325 = leaf(RET);
      expr_ret_325->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_325->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_325 = NULL;
    }

    expr_ret_324 = expr_ret_325;
    r = expr_ret_325;
    // ModExprList 1
    if (expr_ret_324) {
      daisho_astnode_t* expr_ret_326 = NULL;
      expr_ret_326 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_324 = expr_ret_326;
      n = expr_ret_326;
    }

    // ModExprList 2
    if (expr_ret_324) {
      // CodeExpr
      #define ret expr_ret_324
      ret = SUCC;
      rule=node(RET, r, n);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_324) rew(mod_324);
    expr_ret_323 = expr_ret_324;
  }

  // SlashExpr 1
  if (!expr_ret_323) {
    daisho_astnode_t* expr_ret_327 = NULL;
    rec(mod_327);
    // ModExprList 0
    daisho_astnode_t* expr_ret_328 = NULL;
    expr_ret_328 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_327 = expr_ret_328;
    rule = expr_ret_328;
    // ModExprList 1
    if (expr_ret_327) {
      daisho_astnode_t* expr_ret_329 = NULL;
      daisho_astnode_t* expr_ret_330 = NULL;
      rec(mod_330);
      // ModExprList 0
      daisho_astnode_t* expr_ret_331 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Capturing GRAVE.
        expr_ret_331 = leaf(GRAVE);
        expr_ret_331->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_331->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_331 = NULL;
      }

      expr_ret_330 = expr_ret_331;
      r = expr_ret_331;
      // ModExprList 1
      if (expr_ret_330) {
        // CodeExpr
        #define ret expr_ret_330
        ret = SUCC;
        rule = node(RET, r, rule);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_330) rew(mod_330);
      expr_ret_329 = expr_ret_330;
      // optional
      if (!expr_ret_329)
        expr_ret_329 = SUCC;
      expr_ret_327 = expr_ret_329;
    }

    // ModExprList end
    if (!expr_ret_327) rew(mod_327);
    expr_ret_323 = expr_ret_327;
  }

  // SlashExpr end
  expr_ret_322 = expr_ret_323;

  if (!rule) rule = expr_ret_322;
  if (!expr_ret_322) rule = NULL;
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
  #define rule expr_ret_332
  daisho_astnode_t* expr_ret_332 = NULL;
  daisho_astnode_t* expr_ret_333 = NULL;
  daisho_astnode_t* expr_ret_334 = NULL;

  // SlashExpr 0
  if (!expr_ret_334) {
    daisho_astnode_t* expr_ret_335 = NULL;
    rec(mod_335);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_335 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_335 = NULL;
    }

    // ModExprList 1
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_336 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_336 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_336 = NULL;
      }

      // optional
      if (!expr_ret_336)
        expr_ret_336 = SUCC;
      expr_ret_335 = expr_ret_336;
      o = expr_ret_336;
    }

    // ModExprList 2
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_337 = NULL;
      expr_ret_337 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_335 = expr_ret_337;
      f = expr_ret_337;
    }

    // ModExprList 3
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_338 = NULL;

      // SlashExpr 0
      if (!expr_ret_338) {
        daisho_astnode_t* expr_ret_339 = NULL;
        rec(mod_339);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_340 = NULL;

        // SlashExpr 0
        if (!expr_ret_340) {
          daisho_astnode_t* expr_ret_341 = NULL;
          rec(mod_341);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_341 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_341 = NULL;
          }

          // ModExprList end
          if (!expr_ret_341) rew(mod_341);
          expr_ret_340 = expr_ret_341;
        }

        // SlashExpr 1
        if (!expr_ret_340) {
          daisho_astnode_t* expr_ret_342 = NULL;
          rec(mod_342);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_342 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_342 = NULL;
          }

          // ModExprList end
          if (!expr_ret_342) rew(mod_342);
          expr_ret_340 = expr_ret_342;
        }

        // SlashExpr end
        expr_ret_339 = expr_ret_340;

        // ModExprList end
        if (!expr_ret_339) rew(mod_339);
        expr_ret_338 = expr_ret_339;
      }

      // SlashExpr 1
      if (!expr_ret_338) {
        daisho_astnode_t* expr_ret_343 = NULL;
        rec(mod_343);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_344 = NULL;
        rec(mod_344);
        // ModExprList 0
        expr_ret_344 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_344) {
          daisho_astnode_t* expr_ret_345 = NULL;
          expr_ret_345 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_344 = expr_ret_345;
          s = expr_ret_345;
        }

        // ModExprList 2
        if (expr_ret_344) {
          expr_ret_344 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_344) rew(mod_344);
        expr_ret_343 = expr_ret_344;
        // ModExprList end
        if (!expr_ret_343) rew(mod_343);
        expr_ret_338 = expr_ret_343;
      }

      // SlashExpr end
      expr_ret_335 = expr_ret_338;

    }

    // ModExprList 4
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_346 = NULL;
      expr_ret_346 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_335 = expr_ret_346;
      t = expr_ret_346;
    }

    // ModExprList 5
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_347 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_347 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_347 = NULL;
      }

      // optional
      if (!expr_ret_347)
        expr_ret_347 = SUCC;
      expr_ret_335 = expr_ret_347;
      c = expr_ret_347;
    }

    // ModExprList 6
    if (expr_ret_335) {
      // CodeExpr
      #define ret expr_ret_335
      ret = SUCC;
      if (has(o) != has(c)) FATAL("For expression parens mismatch.");
      #undef ret
    }

    // ModExprList 7
    if (expr_ret_335) {
      daisho_astnode_t* expr_ret_348 = NULL;
      expr_ret_348 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_335 = expr_ret_348;
      e = expr_ret_348;
    }

    // ModExprList 8
    if (expr_ret_335) {
      // CodeExpr
      #define ret expr_ret_335
      ret = SUCC;
      rule = has(s) ? node(FOR, f, boolconv(s), t, e)
                    :          node(FOREACH, f, t, e);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_335) rew(mod_335);
    expr_ret_334 = expr_ret_335;
  }

  // SlashExpr 1
  if (!expr_ret_334) {
    daisho_astnode_t* expr_ret_349 = NULL;
    rec(mod_349);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_350 = NULL;
    expr_ret_350 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_349 = expr_ret_350;
    rule = expr_ret_350;
    // ModExprList end
    if (!expr_ret_349) rew(mod_349);
    expr_ret_334 = expr_ret_349;
  }

  // SlashExpr end
  expr_ret_333 = expr_ret_334;

  if (!rule) rule = expr_ret_333;
  if (!expr_ret_333) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_351
  daisho_astnode_t* expr_ret_351 = NULL;
  daisho_astnode_t* expr_ret_352 = NULL;
  daisho_astnode_t* expr_ret_353 = NULL;

  // SlashExpr 0
  if (!expr_ret_353) {
    daisho_astnode_t* expr_ret_354 = NULL;
    rec(mod_354);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_354 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_354 = NULL;
    }

    // ModExprList 1
    if (expr_ret_354) {
      daisho_astnode_t* expr_ret_355 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_355 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_355 = NULL;
      }

      // optional
      if (!expr_ret_355)
        expr_ret_355 = SUCC;
      expr_ret_354 = expr_ret_355;
      o = expr_ret_355;
    }

    // ModExprList 2
    if (expr_ret_354) {
      daisho_astnode_t* expr_ret_356 = NULL;
      expr_ret_356 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_354 = expr_ret_356;
      n = expr_ret_356;
    }

    // ModExprList 3
    if (expr_ret_354) {
      daisho_astnode_t* expr_ret_357 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_357 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_357 = NULL;
      }

      // optional
      if (!expr_ret_357)
        expr_ret_357 = SUCC;
      expr_ret_354 = expr_ret_357;
      c = expr_ret_357;
    }

    // ModExprList 4
    if (expr_ret_354) {
      // CodeExpr
      #define ret expr_ret_354
      ret = SUCC;
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_354) {
      daisho_astnode_t* expr_ret_358 = NULL;
      expr_ret_358 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_354 = expr_ret_358;
      e = expr_ret_358;
    }

    // ModExprList 6
    if (expr_ret_354) {
      // CodeExpr
      #define ret expr_ret_354
      ret = SUCC;
      rule=node(WHILE, n, e);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_354) rew(mod_354);
    expr_ret_353 = expr_ret_354;
  }

  // SlashExpr 1
  if (!expr_ret_353) {
    daisho_astnode_t* expr_ret_359 = NULL;
    rec(mod_359);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_360 = NULL;
    expr_ret_360 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_359 = expr_ret_360;
    rule = expr_ret_360;
    // ModExprList end
    if (!expr_ret_359) rew(mod_359);
    expr_ret_353 = expr_ret_359;
  }

  // SlashExpr end
  expr_ret_352 = expr_ret_353;

  if (!rule) rule = expr_ret_352;
  if (!expr_ret_352) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preifexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* ee = NULL;
  #define rule expr_ret_361
  daisho_astnode_t* expr_ret_361 = NULL;
  daisho_astnode_t* expr_ret_362 = NULL;
  daisho_astnode_t* expr_ret_363 = NULL;

  // SlashExpr 0
  if (!expr_ret_363) {
    daisho_astnode_t* expr_ret_364 = NULL;
    rec(mod_364);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_364 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_364 = NULL;
    }

    // ModExprList 1
    if (expr_ret_364) {
      daisho_astnode_t* expr_ret_365 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_365 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_365 = NULL;
      }

      // optional
      if (!expr_ret_365)
        expr_ret_365 = SUCC;
      expr_ret_364 = expr_ret_365;
      o = expr_ret_365;
    }

    // ModExprList 2
    if (expr_ret_364) {
      daisho_astnode_t* expr_ret_366 = NULL;
      expr_ret_366 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_364 = expr_ret_366;
      n = expr_ret_366;
    }

    // ModExprList 3
    if (expr_ret_364) {
      daisho_astnode_t* expr_ret_367 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_367 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_367 = NULL;
      }

      // optional
      if (!expr_ret_367)
        expr_ret_367 = SUCC;
      expr_ret_364 = expr_ret_367;
      c = expr_ret_367;
    }

    // ModExprList 4
    if (expr_ret_364) {
      // CodeExpr
      #define ret expr_ret_364
      ret = SUCC;
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_364) {
      daisho_astnode_t* expr_ret_368 = NULL;
      expr_ret_368 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_364 = expr_ret_368;
      e = expr_ret_368;
    }

    // ModExprList 6
    if (expr_ret_364) {
      daisho_astnode_t* expr_ret_369 = NULL;
      daisho_astnode_t* expr_ret_370 = NULL;
      rec(mod_370);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_370 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_370 = NULL;
      }

      // ModExprList 1
      if (expr_ret_370) {
        daisho_astnode_t* expr_ret_371 = NULL;
        expr_ret_371 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_370 = expr_ret_371;
        ee = expr_ret_371;
      }

      // ModExprList end
      if (!expr_ret_370) rew(mod_370);
      expr_ret_369 = expr_ret_370;
      // optional
      if (!expr_ret_369)
        expr_ret_369 = SUCC;
      expr_ret_364 = expr_ret_369;
    }

    // ModExprList 7
    if (expr_ret_364) {
      // CodeExpr
      #define ret expr_ret_364
      ret = SUCC;
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_364) rew(mod_364);
    expr_ret_363 = expr_ret_364;
  }

  // SlashExpr 1
  if (!expr_ret_363) {
    daisho_astnode_t* expr_ret_372 = NULL;
    rec(mod_372);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_373 = NULL;
    expr_ret_373 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_372 = expr_ret_373;
    rule = expr_ret_373;
    // ModExprList end
    if (!expr_ret_372) rew(mod_372);
    expr_ret_363 = expr_ret_372;
  }

  // SlashExpr end
  expr_ret_362 = expr_ret_363;

  if (!rule) rule = expr_ret_362;
  if (!expr_ret_362) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_374
  daisho_astnode_t* expr_ret_374 = NULL;
  daisho_astnode_t* expr_ret_375 = NULL;
  daisho_astnode_t* expr_ret_376 = NULL;
  rec(mod_376);
  // ModExprList 0
  daisho_astnode_t* expr_ret_377 = NULL;
  expr_ret_377 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_376 = expr_ret_377;
  n = expr_ret_377;
  // ModExprList 1
  if (expr_ret_376) {
    daisho_astnode_t* expr_ret_378 = NULL;
    daisho_astnode_t* expr_ret_379 = NULL;
    rec(mod_379);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_379 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_379 = NULL;
    }

    // ModExprList 1
    if (expr_ret_379) {
      daisho_astnode_t* expr_ret_380 = NULL;
      expr_ret_380 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_379 = expr_ret_380;
      qe = expr_ret_380;
    }

    // ModExprList 2
    if (expr_ret_379) {
      daisho_astnode_t* expr_ret_381 = NULL;
      daisho_astnode_t* expr_ret_382 = NULL;
      rec(mod_382);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_382 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_382 = NULL;
      }

      // ModExprList 1
      if (expr_ret_382) {
        daisho_astnode_t* expr_ret_383 = NULL;
        expr_ret_383 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_382 = expr_ret_383;
        ce = expr_ret_383;
      }

      // ModExprList end
      if (!expr_ret_382) rew(mod_382);
      expr_ret_381 = expr_ret_382;
      // optional
      if (!expr_ret_381)
        expr_ret_381 = SUCC;
      expr_ret_379 = expr_ret_381;
    }

    // ModExprList end
    if (!expr_ret_379) rew(mod_379);
    expr_ret_378 = expr_ret_379;
    // optional
    if (!expr_ret_378)
      expr_ret_378 = SUCC;
    expr_ret_376 = expr_ret_378;
  }

  // ModExprList 2
  if (expr_ret_376) {
    // CodeExpr
    #define ret expr_ret_376
    ret = SUCC;
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_376) rew(mod_376);
  expr_ret_375 = expr_ret_376;
  if (!rule) rule = expr_ret_375;
  if (!expr_ret_375) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_384
  daisho_astnode_t* expr_ret_384 = NULL;
  daisho_astnode_t* expr_ret_385 = NULL;
  daisho_astnode_t* expr_ret_386 = NULL;
  rec(mod_386);
  // ModExprList 0
  daisho_astnode_t* expr_ret_387 = NULL;
  expr_ret_387 = daisho_parse_alsoexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_386 = expr_ret_387;
  rule = expr_ret_387;
  // ModExprList 1
  if (expr_ret_386) {
    daisho_astnode_t* expr_ret_388 = NULL;
    daisho_astnode_t* expr_ret_389 = SUCC;
    while (expr_ret_389)
    {
      rec(kleene_rew_388);
      daisho_astnode_t* expr_ret_390 = NULL;
      rec(mod_390);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_390 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_390 = NULL;
      }

      // ModExprList 1
      if (expr_ret_390) {
        daisho_astnode_t* expr_ret_391 = NULL;
        expr_ret_391 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_390 = expr_ret_391;
        nn = expr_ret_391;
      }

      // ModExprList 2
      if (expr_ret_390) {
        // CodeExpr
        #define ret expr_ret_390
        ret = SUCC;
        rule=node(THEN, rule, nn);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_390) rew(mod_390);
      expr_ret_389 = expr_ret_390;
    }

    expr_ret_388 = SUCC;
    expr_ret_386 = expr_ret_388;
  }

  // ModExprList end
  if (!expr_ret_386) rew(mod_386);
  expr_ret_385 = expr_ret_386;
  if (!rule) rule = expr_ret_385;
  if (!expr_ret_385) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_392
  daisho_astnode_t* expr_ret_392 = NULL;
  daisho_astnode_t* expr_ret_393 = NULL;
  daisho_astnode_t* expr_ret_394 = NULL;
  rec(mod_394);
  // ModExprList 0
  daisho_astnode_t* expr_ret_395 = NULL;
  expr_ret_395 = daisho_parse_ceqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_394 = expr_ret_395;
  rule = expr_ret_395;
  // ModExprList 1
  if (expr_ret_394) {
    daisho_astnode_t* expr_ret_396 = NULL;
    daisho_astnode_t* expr_ret_397 = SUCC;
    while (expr_ret_397)
    {
      rec(kleene_rew_396);
      daisho_astnode_t* expr_ret_398 = NULL;
      rec(mod_398);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_398 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_398 = NULL;
      }

      // ModExprList 1
      if (expr_ret_398) {
        daisho_astnode_t* expr_ret_399 = NULL;
        expr_ret_399 = daisho_parse_ceqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_398 = expr_ret_399;
        nn = expr_ret_399;
      }

      // ModExprList 2
      if (expr_ret_398) {
        // CodeExpr
        #define ret expr_ret_398
        ret = SUCC;
        rule=node(ALSO, rule, nn);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_398) rew(mod_398);
      expr_ret_397 = expr_ret_398;
    }

    expr_ret_396 = SUCC;
    expr_ret_394 = expr_ret_396;
  }

  // ModExprList end
  if (!expr_ret_394) rew(mod_394);
  expr_ret_393 = expr_ret_394;
  if (!rule) rule = expr_ret_393;
  if (!expr_ret_393) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_400
  daisho_astnode_t* expr_ret_400 = NULL;
  daisho_astnode_t* expr_ret_401 = NULL;
  daisho_astnode_t* expr_ret_402 = NULL;
  rec(mod_402);
  // ModExprList 0
  daisho_astnode_t* expr_ret_403 = NULL;
  expr_ret_403 = daisho_parse_logorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_402 = expr_ret_403;
  rule = expr_ret_403;
  // ModExprList 1
  if (expr_ret_402) {
    daisho_astnode_t* expr_ret_404 = NULL;
    daisho_astnode_t* expr_ret_405 = SUCC;
    while (expr_ret_405)
    {
      rec(kleene_rew_404);
      daisho_astnode_t* expr_ret_406 = NULL;
      rec(mod_406);
      // ModExprList 0
      daisho_astnode_t* expr_ret_407 = NULL;
      daisho_astnode_t* expr_ret_408 = NULL;

      // SlashExpr 0
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_409 = NULL;
        rec(mod_409);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_409 = leaf(EQ);
          expr_ret_409->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_409->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_409 = NULL;
        }

        // ModExprList end
        if (!expr_ret_409) rew(mod_409);
        expr_ret_408 = expr_ret_409;
      }

      // SlashExpr 1
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_410 = NULL;
        rec(mod_410);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_410 = leaf(PLEQ);
          expr_ret_410->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_410->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_410 = NULL;
        }

        // ModExprList end
        if (!expr_ret_410) rew(mod_410);
        expr_ret_408 = expr_ret_410;
      }

      // SlashExpr 2
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_411 = NULL;
        rec(mod_411);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_411 = leaf(MINEQ);
          expr_ret_411->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_411->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_411 = NULL;
        }

        // ModExprList end
        if (!expr_ret_411) rew(mod_411);
        expr_ret_408 = expr_ret_411;
      }

      // SlashExpr 3
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_412 = NULL;
        rec(mod_412);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_412 = leaf(MULEQ);
          expr_ret_412->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_412->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_412 = NULL;
        }

        // ModExprList end
        if (!expr_ret_412) rew(mod_412);
        expr_ret_408 = expr_ret_412;
      }

      // SlashExpr 4
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_413 = NULL;
        rec(mod_413);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_413 = leaf(DIVEQ);
          expr_ret_413->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_413->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_413 = NULL;
        }

        // ModExprList end
        if (!expr_ret_413) rew(mod_413);
        expr_ret_408 = expr_ret_413;
      }

      // SlashExpr 5
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_414 = NULL;
        rec(mod_414);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_414 = leaf(MODEQ);
          expr_ret_414->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_414->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_414 = NULL;
        }

        // ModExprList end
        if (!expr_ret_414) rew(mod_414);
        expr_ret_408 = expr_ret_414;
      }

      // SlashExpr 6
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_415 = NULL;
        rec(mod_415);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_415 = leaf(ANDEQ);
          expr_ret_415->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_415->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_415 = NULL;
        }

        // ModExprList end
        if (!expr_ret_415) rew(mod_415);
        expr_ret_408 = expr_ret_415;
      }

      // SlashExpr 7
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_416 = NULL;
        rec(mod_416);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_416 = leaf(OREQ);
          expr_ret_416->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_416->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_416 = NULL;
        }

        // ModExprList end
        if (!expr_ret_416) rew(mod_416);
        expr_ret_408 = expr_ret_416;
      }

      // SlashExpr 8
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_417 = NULL;
        rec(mod_417);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_417 = leaf(XOREQ);
          expr_ret_417->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_417->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_417 = NULL;
        }

        // ModExprList end
        if (!expr_ret_417) rew(mod_417);
        expr_ret_408 = expr_ret_417;
      }

      // SlashExpr 9
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_418 = NULL;
        rec(mod_418);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_418 = leaf(BNEQ);
          expr_ret_418->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_418->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_418 = NULL;
        }

        // ModExprList end
        if (!expr_ret_418) rew(mod_418);
        expr_ret_408 = expr_ret_418;
      }

      // SlashExpr 10
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_419 = NULL;
        rec(mod_419);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_419 = leaf(BSREQ);
          expr_ret_419->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_419->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_419 = NULL;
        }

        // ModExprList end
        if (!expr_ret_419) rew(mod_419);
        expr_ret_408 = expr_ret_419;
      }

      // SlashExpr 11
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_420 = NULL;
        rec(mod_420);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_420 = leaf(BSLEQ);
          expr_ret_420->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_420->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_420 = NULL;
        }

        // ModExprList end
        if (!expr_ret_420) rew(mod_420);
        expr_ret_408 = expr_ret_420;
      }

      // SlashExpr end
      expr_ret_407 = expr_ret_408;

      expr_ret_406 = expr_ret_407;
      op = expr_ret_407;
      // ModExprList 1
      if (expr_ret_406) {
        daisho_astnode_t* expr_ret_421 = NULL;
        expr_ret_421 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_406 = expr_ret_421;
        t = expr_ret_421;
      }

      // ModExprList 2
      if (expr_ret_406) {
        // CodeExpr
        #define ret expr_ret_406
        ret = SUCC;
        
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
                else Py_UNREACHABLE()
              ;
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_406) rew(mod_406);
      expr_ret_405 = expr_ret_406;
    }

    expr_ret_404 = SUCC;
    expr_ret_402 = expr_ret_404;
  }

  // ModExprList end
  if (!expr_ret_402) rew(mod_402);
  expr_ret_401 = expr_ret_402;
  if (!rule) rule = expr_ret_401;
  if (!expr_ret_401) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* lo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_422
  daisho_astnode_t* expr_ret_422 = NULL;
  daisho_astnode_t* expr_ret_423 = NULL;
  daisho_astnode_t* expr_ret_424 = NULL;
  rec(mod_424);
  // ModExprList 0
  daisho_astnode_t* expr_ret_425 = NULL;
  expr_ret_425 = daisho_parse_logandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_424 = expr_ret_425;
  rule = expr_ret_425;
  // ModExprList 1
  if (expr_ret_424) {
    daisho_astnode_t* expr_ret_426 = NULL;
    daisho_astnode_t* expr_ret_427 = SUCC;
    while (expr_ret_427)
    {
      rec(kleene_rew_426);
      daisho_astnode_t* expr_ret_428 = NULL;
      rec(mod_428);
      // ModExprList 0
      daisho_astnode_t* expr_ret_429 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Capturing LOGOR.
        expr_ret_429 = leaf(LOGOR);
        expr_ret_429->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_429->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_429 = NULL;
      }

      expr_ret_428 = expr_ret_429;
      lo = expr_ret_429;
      // ModExprList 1
      if (expr_ret_428) {
        daisho_astnode_t* expr_ret_430 = NULL;
        expr_ret_430 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_428 = expr_ret_430;
        n = expr_ret_430;
      }

      // ModExprList 2
      if (expr_ret_428) {
        // CodeExpr
        #define ret expr_ret_428
        ret = SUCC;
        rule=binop(lo, rule, n);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_428) rew(mod_428);
      expr_ret_427 = expr_ret_428;
    }

    expr_ret_426 = SUCC;
    expr_ret_424 = expr_ret_426;
  }

  // ModExprList end
  if (!expr_ret_424) rew(mod_424);
  expr_ret_423 = expr_ret_424;
  if (!rule) rule = expr_ret_423;
  if (!expr_ret_423) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* la = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_431
  daisho_astnode_t* expr_ret_431 = NULL;
  daisho_astnode_t* expr_ret_432 = NULL;
  daisho_astnode_t* expr_ret_433 = NULL;
  rec(mod_433);
  // ModExprList 0
  daisho_astnode_t* expr_ret_434 = NULL;
  expr_ret_434 = daisho_parse_binorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_433 = expr_ret_434;
  rule = expr_ret_434;
  // ModExprList 1
  if (expr_ret_433) {
    daisho_astnode_t* expr_ret_435 = NULL;
    daisho_astnode_t* expr_ret_436 = SUCC;
    while (expr_ret_436)
    {
      rec(kleene_rew_435);
      daisho_astnode_t* expr_ret_437 = NULL;
      rec(mod_437);
      // ModExprList 0
      daisho_astnode_t* expr_ret_438 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Capturing LOGAND.
        expr_ret_438 = leaf(LOGAND);
        expr_ret_438->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_438->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_438 = NULL;
      }

      expr_ret_437 = expr_ret_438;
      la = expr_ret_438;
      // ModExprList 1
      if (expr_ret_437) {
        daisho_astnode_t* expr_ret_439 = NULL;
        expr_ret_439 = daisho_parse_binorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_437 = expr_ret_439;
        n = expr_ret_439;
      }

      // ModExprList 2
      if (expr_ret_437) {
        // CodeExpr
        #define ret expr_ret_437
        ret = SUCC;
        rule=binop(la, rule, n);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_437) rew(mod_437);
      expr_ret_436 = expr_ret_437;
    }

    expr_ret_435 = SUCC;
    expr_ret_433 = expr_ret_435;
  }

  // ModExprList end
  if (!expr_ret_433) rew(mod_433);
  expr_ret_432 = expr_ret_433;
  if (!rule) rule = expr_ret_432;
  if (!expr_ret_432) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* ro = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_440
  daisho_astnode_t* expr_ret_440 = NULL;
  daisho_astnode_t* expr_ret_441 = NULL;
  daisho_astnode_t* expr_ret_442 = NULL;
  rec(mod_442);
  // ModExprList 0
  daisho_astnode_t* expr_ret_443 = NULL;
  expr_ret_443 = daisho_parse_binxorexpr(ctx);
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
      rec(mod_446);
      // ModExprList 0
      daisho_astnode_t* expr_ret_447 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Capturing OR.
        expr_ret_447 = leaf(OR);
        expr_ret_447->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_447->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_447 = NULL;
      }

      expr_ret_446 = expr_ret_447;
      ro = expr_ret_447;
      // ModExprList 1
      if (expr_ret_446) {
        daisho_astnode_t* expr_ret_448 = NULL;
        expr_ret_448 = daisho_parse_binxorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_446 = expr_ret_448;
        n = expr_ret_448;
      }

      // ModExprList 2
      if (expr_ret_446) {
        // CodeExpr
        #define ret expr_ret_446
        ret = SUCC;
        rule=binop(ro, rule, n);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_446) rew(mod_446);
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
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* xo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_449
  daisho_astnode_t* expr_ret_449 = NULL;
  daisho_astnode_t* expr_ret_450 = NULL;
  daisho_astnode_t* expr_ret_451 = NULL;
  rec(mod_451);
  // ModExprList 0
  daisho_astnode_t* expr_ret_452 = NULL;
  expr_ret_452 = daisho_parse_binandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_451 = expr_ret_452;
  rule = expr_ret_452;
  // ModExprList 1
  if (expr_ret_451) {
    daisho_astnode_t* expr_ret_453 = NULL;
    daisho_astnode_t* expr_ret_454 = SUCC;
    while (expr_ret_454)
    {
      rec(kleene_rew_453);
      daisho_astnode_t* expr_ret_455 = NULL;
      rec(mod_455);
      // ModExprList 0
      daisho_astnode_t* expr_ret_456 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Capturing XOR.
        expr_ret_456 = leaf(XOR);
        expr_ret_456->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_456->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_456 = NULL;
      }

      expr_ret_455 = expr_ret_456;
      xo = expr_ret_456;
      // ModExprList 1
      if (expr_ret_455) {
        daisho_astnode_t* expr_ret_457 = NULL;
        expr_ret_457 = daisho_parse_binandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_455 = expr_ret_457;
        n = expr_ret_457;
      }

      // ModExprList 2
      if (expr_ret_455) {
        // CodeExpr
        #define ret expr_ret_455
        ret = SUCC;
        rule=binop(xo, rule, n);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_455) rew(mod_455);
      expr_ret_454 = expr_ret_455;
    }

    expr_ret_453 = SUCC;
    expr_ret_451 = expr_ret_453;
  }

  // ModExprList end
  if (!expr_ret_451) rew(mod_451);
  expr_ret_450 = expr_ret_451;
  if (!rule) rule = expr_ret_450;
  if (!expr_ret_450) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* an = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_458
  daisho_astnode_t* expr_ret_458 = NULL;
  daisho_astnode_t* expr_ret_459 = NULL;
  daisho_astnode_t* expr_ret_460 = NULL;
  rec(mod_460);
  // ModExprList 0
  daisho_astnode_t* expr_ret_461 = NULL;
  expr_ret_461 = daisho_parse_deneqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_460 = expr_ret_461;
  rule = expr_ret_461;
  // ModExprList 1
  if (expr_ret_460) {
    daisho_astnode_t* expr_ret_462 = NULL;
    daisho_astnode_t* expr_ret_463 = SUCC;
    while (expr_ret_463)
    {
      rec(kleene_rew_462);
      daisho_astnode_t* expr_ret_464 = NULL;
      rec(mod_464);
      // ModExprList 0
      daisho_astnode_t* expr_ret_465 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Capturing AND.
        expr_ret_465 = leaf(AND);
        expr_ret_465->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_465->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_465 = NULL;
      }

      expr_ret_464 = expr_ret_465;
      an = expr_ret_465;
      // ModExprList 1
      if (expr_ret_464) {
        daisho_astnode_t* expr_ret_466 = NULL;
        expr_ret_466 = daisho_parse_deneqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_464 = expr_ret_466;
        n = expr_ret_466;
      }

      // ModExprList 2
      if (expr_ret_464) {
        // CodeExpr
        #define ret expr_ret_464
        ret = SUCC;
        rule=binop(an, rule, n);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_464) rew(mod_464);
      expr_ret_463 = expr_ret_464;
    }

    expr_ret_462 = SUCC;
    expr_ret_460 = expr_ret_462;
  }

  // ModExprList end
  if (!expr_ret_460) rew(mod_460);
  expr_ret_459 = expr_ret_460;
  if (!rule) rule = expr_ret_459;
  if (!expr_ret_459) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* x = NULL;
  #define rule expr_ret_467
  daisho_astnode_t* expr_ret_467 = NULL;
  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_469 = NULL;
  rec(mod_469);
  // ModExprList 0
  daisho_astnode_t* expr_ret_470 = NULL;
  expr_ret_470 = daisho_parse_cmpexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_469 = expr_ret_470;
  rule = expr_ret_470;
  // ModExprList 1
  if (expr_ret_469) {
    daisho_astnode_t* expr_ret_471 = NULL;
    daisho_astnode_t* expr_ret_472 = SUCC;
    while (expr_ret_472)
    {
      rec(kleene_rew_471);
      daisho_astnode_t* expr_ret_473 = NULL;

      // SlashExpr 0
      if (!expr_ret_473) {
        daisho_astnode_t* expr_ret_474 = NULL;
        rec(mod_474);
        // ModExprList 0
        daisho_astnode_t* expr_ret_475 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Capturing DEQ.
          expr_ret_475 = leaf(DEQ);
          expr_ret_475->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_475->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_475 = NULL;
        }

        expr_ret_474 = expr_ret_475;
        e = expr_ret_475;
        // ModExprList 1
        if (expr_ret_474) {
          daisho_astnode_t* expr_ret_476 = NULL;
          expr_ret_476 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_474 = expr_ret_476;
          n = expr_ret_476;
        }

        // ModExprList 2
        if (expr_ret_474) {
          // CodeExpr
          #define ret expr_ret_474
          ret = SUCC;
          rule=binop(e, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_474) rew(mod_474);
        expr_ret_473 = expr_ret_474;
      }

      // SlashExpr 1
      if (!expr_ret_473) {
        daisho_astnode_t* expr_ret_477 = NULL;
        rec(mod_477);
        // ModExprList 0
        daisho_astnode_t* expr_ret_478 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Capturing NEQ.
          expr_ret_478 = leaf(NEQ);
          expr_ret_478->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_478->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_478 = NULL;
        }

        expr_ret_477 = expr_ret_478;
        x = expr_ret_478;
        // ModExprList 1
        if (expr_ret_477) {
          daisho_astnode_t* expr_ret_479 = NULL;
          expr_ret_479 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_477 = expr_ret_479;
          n = expr_ret_479;
        }

        // ModExprList 2
        if (expr_ret_477) {
          // CodeExpr
          #define ret expr_ret_477
          ret = SUCC;
          rule=binop(x, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_477) rew(mod_477);
        expr_ret_473 = expr_ret_477;
      }

      // SlashExpr end
      expr_ret_472 = expr_ret_473;

    }

    expr_ret_471 = SUCC;
    expr_ret_469 = expr_ret_471;
  }

  // ModExprList end
  if (!expr_ret_469) rew(mod_469);
  expr_ret_468 = expr_ret_469;
  if (!rule) rule = expr_ret_468;
  if (!expr_ret_468) rule = NULL;
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
  #define rule expr_ret_480
  daisho_astnode_t* expr_ret_480 = NULL;
  daisho_astnode_t* expr_ret_481 = NULL;
  daisho_astnode_t* expr_ret_482 = NULL;
  rec(mod_482);
  // ModExprList 0
  daisho_astnode_t* expr_ret_483 = NULL;
  expr_ret_483 = daisho_parse_shfexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_482 = expr_ret_483;
  rule = expr_ret_483;
  // ModExprList 1
  if (expr_ret_482) {
    daisho_astnode_t* expr_ret_484 = NULL;
    daisho_astnode_t* expr_ret_485 = SUCC;
    while (expr_ret_485)
    {
      rec(kleene_rew_484);
      daisho_astnode_t* expr_ret_486 = NULL;

      // SlashExpr 0
      if (!expr_ret_486) {
        daisho_astnode_t* expr_ret_487 = NULL;
        rec(mod_487);
        // ModExprList 0
        daisho_astnode_t* expr_ret_488 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_488 = leaf(LT);
          expr_ret_488->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_488->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_488 = NULL;
        }

        expr_ret_487 = expr_ret_488;
        l = expr_ret_488;
        // ModExprList 1
        if (expr_ret_487) {
          daisho_astnode_t* expr_ret_489 = NULL;
          expr_ret_489 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_487 = expr_ret_489;
          n = expr_ret_489;
        }

        // ModExprList 2
        if (expr_ret_487) {
          // CodeExpr
          #define ret expr_ret_487
          ret = SUCC;
          rule=binop(l,  rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_487) rew(mod_487);
        expr_ret_486 = expr_ret_487;
      }

      // SlashExpr 1
      if (!expr_ret_486) {
        daisho_astnode_t* expr_ret_490 = NULL;
        rec(mod_490);
        // ModExprList 0
        daisho_astnode_t* expr_ret_491 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_491 = leaf(GT);
          expr_ret_491->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_491->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_491 = NULL;
        }

        expr_ret_490 = expr_ret_491;
        g = expr_ret_491;
        // ModExprList 1
        if (expr_ret_490) {
          daisho_astnode_t* expr_ret_492 = NULL;
          expr_ret_492 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_490 = expr_ret_492;
          n = expr_ret_492;
        }

        // ModExprList 2
        if (expr_ret_490) {
          // CodeExpr
          #define ret expr_ret_490
          ret = SUCC;
          rule=binop(g,  rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_490) rew(mod_490);
        expr_ret_486 = expr_ret_490;
      }

      // SlashExpr 2
      if (!expr_ret_486) {
        daisho_astnode_t* expr_ret_493 = NULL;
        rec(mod_493);
        // ModExprList 0
        daisho_astnode_t* expr_ret_494 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Capturing LEQ.
          expr_ret_494 = leaf(LEQ);
          expr_ret_494->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_494->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_494 = NULL;
        }

        expr_ret_493 = expr_ret_494;
        le = expr_ret_494;
        // ModExprList 1
        if (expr_ret_493) {
          daisho_astnode_t* expr_ret_495 = NULL;
          expr_ret_495 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_493 = expr_ret_495;
          n = expr_ret_495;
        }

        // ModExprList 2
        if (expr_ret_493) {
          // CodeExpr
          #define ret expr_ret_493
          ret = SUCC;
          rule=binop(le, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_493) rew(mod_493);
        expr_ret_486 = expr_ret_493;
      }

      // SlashExpr 3
      if (!expr_ret_486) {
        daisho_astnode_t* expr_ret_496 = NULL;
        rec(mod_496);
        // ModExprList 0
        daisho_astnode_t* expr_ret_497 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Capturing GEQ.
          expr_ret_497 = leaf(GEQ);
          expr_ret_497->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_497->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_497 = NULL;
        }

        expr_ret_496 = expr_ret_497;
        ge = expr_ret_497;
        // ModExprList 1
        if (expr_ret_496) {
          daisho_astnode_t* expr_ret_498 = NULL;
          expr_ret_498 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_496 = expr_ret_498;
          n = expr_ret_498;
        }

        // ModExprList 2
        if (expr_ret_496) {
          // CodeExpr
          #define ret expr_ret_496
          ret = SUCC;
          rule=binop(ge, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_496) rew(mod_496);
        expr_ret_486 = expr_ret_496;
      }

      // SlashExpr end
      expr_ret_485 = expr_ret_486;

    }

    expr_ret_484 = SUCC;
    expr_ret_482 = expr_ret_484;
  }

  // ModExprList end
  if (!expr_ret_482) rew(mod_482);
  expr_ret_481 = expr_ret_482;
  if (!rule) rule = expr_ret_481;
  if (!expr_ret_481) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_499
  daisho_astnode_t* expr_ret_499 = NULL;
  daisho_astnode_t* expr_ret_500 = NULL;
  daisho_astnode_t* expr_ret_501 = NULL;
  rec(mod_501);
  // ModExprList 0
  daisho_astnode_t* expr_ret_502 = NULL;
  expr_ret_502 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_501 = expr_ret_502;
  rule = expr_ret_502;
  // ModExprList 1
  if (expr_ret_501) {
    daisho_astnode_t* expr_ret_503 = NULL;
    daisho_astnode_t* expr_ret_504 = SUCC;
    while (expr_ret_504)
    {
      rec(kleene_rew_503);
      daisho_astnode_t* expr_ret_505 = NULL;

      // SlashExpr 0
      if (!expr_ret_505) {
        daisho_astnode_t* expr_ret_506 = NULL;
        rec(mod_506);
        // ModExprList 0
        daisho_astnode_t* expr_ret_507 = NULL;
        expr_ret_507 = daisho_parse_bsl(ctx);
        if (ctx->exit) return NULL;
        expr_ret_506 = expr_ret_507;
        l = expr_ret_507;
        // ModExprList 1
        if (expr_ret_506) {
          daisho_astnode_t* expr_ret_508 = NULL;
          expr_ret_508 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_506 = expr_ret_508;
          n = expr_ret_508;
        }

        // ModExprList 2
        if (expr_ret_506) {
          // CodeExpr
          #define ret expr_ret_506
          ret = SUCC;
          rule=binop(l, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_506) rew(mod_506);
        expr_ret_505 = expr_ret_506;
      }

      // SlashExpr 1
      if (!expr_ret_505) {
        daisho_astnode_t* expr_ret_509 = NULL;
        rec(mod_509);
        // ModExprList 0
        daisho_astnode_t* expr_ret_510 = NULL;
        expr_ret_510 = daisho_parse_bsr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_509 = expr_ret_510;
        r = expr_ret_510;
        // ModExprList 1
        if (expr_ret_509) {
          daisho_astnode_t* expr_ret_511 = NULL;
          expr_ret_511 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_509 = expr_ret_511;
          n = expr_ret_511;
        }

        // ModExprList 2
        if (expr_ret_509) {
          // CodeExpr
          #define ret expr_ret_509
          ret = SUCC;
          rule=binop(r, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_509) rew(mod_509);
        expr_ret_505 = expr_ret_509;
      }

      // SlashExpr end
      expr_ret_504 = expr_ret_505;

    }

    expr_ret_503 = SUCC;
    expr_ret_501 = expr_ret_503;
  }

  // ModExprList end
  if (!expr_ret_501) rew(mod_501);
  expr_ret_500 = expr_ret_501;
  if (!rule) rule = expr_ret_500;
  if (!expr_ret_500) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_512
  daisho_astnode_t* expr_ret_512 = NULL;
  daisho_astnode_t* expr_ret_513 = NULL;
  daisho_astnode_t* expr_ret_514 = NULL;
  rec(mod_514);
  // ModExprList 0
  daisho_astnode_t* expr_ret_515 = NULL;
  expr_ret_515 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_514 = expr_ret_515;
  rule = expr_ret_515;
  // ModExprList 1
  if (expr_ret_514) {
    daisho_astnode_t* expr_ret_516 = NULL;
    daisho_astnode_t* expr_ret_517 = SUCC;
    while (expr_ret_517)
    {
      rec(kleene_rew_516);
      daisho_astnode_t* expr_ret_518 = NULL;

      // SlashExpr 0
      if (!expr_ret_518) {
        daisho_astnode_t* expr_ret_519 = NULL;
        rec(mod_519);
        // ModExprList 0
        daisho_astnode_t* expr_ret_520 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_520 = leaf(PLUS);
          expr_ret_520->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_520->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_520 = NULL;
        }

        expr_ret_519 = expr_ret_520;
        p = expr_ret_520;
        // ModExprList 1
        if (expr_ret_519) {
          daisho_astnode_t* expr_ret_521 = NULL;
          expr_ret_521 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_519 = expr_ret_521;
          n = expr_ret_521;
        }

        // ModExprList 2
        if (expr_ret_519) {
          // CodeExpr
          #define ret expr_ret_519
          ret = SUCC;
          rule=binop(p, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_519) rew(mod_519);
        expr_ret_518 = expr_ret_519;
      }

      // SlashExpr 1
      if (!expr_ret_518) {
        daisho_astnode_t* expr_ret_522 = NULL;
        rec(mod_522);
        // ModExprList 0
        daisho_astnode_t* expr_ret_523 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_523 = leaf(MINUS);
          expr_ret_523->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_523->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_523 = NULL;
        }

        expr_ret_522 = expr_ret_523;
        m = expr_ret_523;
        // ModExprList 1
        if (expr_ret_522) {
          daisho_astnode_t* expr_ret_524 = NULL;
          expr_ret_524 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_522 = expr_ret_524;
          n = expr_ret_524;
        }

        // ModExprList 2
        if (expr_ret_522) {
          // CodeExpr
          #define ret expr_ret_522
          ret = SUCC;
          rule=binop(m, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_522) rew(mod_522);
        expr_ret_518 = expr_ret_522;
      }

      // SlashExpr end
      expr_ret_517 = expr_ret_518;

    }

    expr_ret_516 = SUCC;
    expr_ret_514 = expr_ret_516;
  }

  // ModExprList end
  if (!expr_ret_514) rew(mod_514);
  expr_ret_513 = expr_ret_514;
  if (!rule) rule = expr_ret_513;
  if (!expr_ret_513) rule = NULL;
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
  #define rule expr_ret_525
  daisho_astnode_t* expr_ret_525 = NULL;
  daisho_astnode_t* expr_ret_526 = NULL;
  daisho_astnode_t* expr_ret_527 = NULL;
  rec(mod_527);
  // ModExprList 0
  daisho_astnode_t* expr_ret_528 = NULL;
  expr_ret_528 = daisho_parse_accexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_527 = expr_ret_528;
  rule = expr_ret_528;
  // ModExprList 1
  if (expr_ret_527) {
    daisho_astnode_t* expr_ret_529 = NULL;
    daisho_astnode_t* expr_ret_530 = SUCC;
    while (expr_ret_530)
    {
      rec(kleene_rew_529);
      daisho_astnode_t* expr_ret_531 = NULL;

      // SlashExpr 0
      if (!expr_ret_531) {
        daisho_astnode_t* expr_ret_532 = NULL;
        rec(mod_532);
        // ModExprList 0
        daisho_astnode_t* expr_ret_533 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Capturing STAR.
          expr_ret_533 = leaf(STAR);
          expr_ret_533->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_533->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_533 = NULL;
        }

        expr_ret_532 = expr_ret_533;
        s = expr_ret_533;
        // ModExprList 1
        if (expr_ret_532) {
          daisho_astnode_t* expr_ret_534 = NULL;
          expr_ret_534 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_532 = expr_ret_534;
          n = expr_ret_534;
        }

        // ModExprList 2
        if (expr_ret_532) {
          // CodeExpr
          #define ret expr_ret_532
          ret = SUCC;
          rule=binop(s, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_532) rew(mod_532);
        expr_ret_531 = expr_ret_532;
      }

      // SlashExpr 1
      if (!expr_ret_531) {
        daisho_astnode_t* expr_ret_535 = NULL;
        rec(mod_535);
        // ModExprList 0
        daisho_astnode_t* expr_ret_536 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Capturing DIV.
          expr_ret_536 = leaf(DIV);
          expr_ret_536->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_536->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_536 = NULL;
        }

        expr_ret_535 = expr_ret_536;
        d = expr_ret_536;
        // ModExprList 1
        if (expr_ret_535) {
          daisho_astnode_t* expr_ret_537 = NULL;
          expr_ret_537 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_535 = expr_ret_537;
          n = expr_ret_537;
        }

        // ModExprList 2
        if (expr_ret_535) {
          // CodeExpr
          #define ret expr_ret_535
          ret = SUCC;
          rule=binop(d, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_535) rew(mod_535);
        expr_ret_531 = expr_ret_535;
      }

      // SlashExpr 2
      if (!expr_ret_531) {
        daisho_astnode_t* expr_ret_538 = NULL;
        rec(mod_538);
        // ModExprList 0
        daisho_astnode_t* expr_ret_539 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Capturing MOD.
          expr_ret_539 = leaf(MOD);
          expr_ret_539->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_539->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_539 = NULL;
        }

        expr_ret_538 = expr_ret_539;
        m = expr_ret_539;
        // ModExprList 1
        if (expr_ret_538) {
          daisho_astnode_t* expr_ret_540 = NULL;
          expr_ret_540 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_538 = expr_ret_540;
          n = expr_ret_540;
        }

        // ModExprList 2
        if (expr_ret_538) {
          // CodeExpr
          #define ret expr_ret_538
          ret = SUCC;
          rule=binop(m, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_538) rew(mod_538);
        expr_ret_531 = expr_ret_538;
      }

      // SlashExpr 3
      if (!expr_ret_531) {
        daisho_astnode_t* expr_ret_541 = NULL;
        rec(mod_541);
        // ModExprList 0
        daisho_astnode_t* expr_ret_542 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Capturing POW.
          expr_ret_542 = leaf(POW);
          expr_ret_542->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_542->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_542 = NULL;
        }

        expr_ret_541 = expr_ret_542;
        p = expr_ret_542;
        // ModExprList 1
        if (expr_ret_541) {
          daisho_astnode_t* expr_ret_543 = NULL;
          expr_ret_543 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_541 = expr_ret_543;
          n = expr_ret_543;
        }

        // ModExprList 2
        if (expr_ret_541) {
          // CodeExpr
          #define ret expr_ret_541
          ret = SUCC;
          rule=binop(p, rule, n);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_541) rew(mod_541);
        expr_ret_531 = expr_ret_541;
      }

      // SlashExpr end
      expr_ret_530 = expr_ret_531;

    }

    expr_ret_529 = SUCC;
    expr_ret_527 = expr_ret_529;
  }

  // ModExprList end
  if (!expr_ret_527) rew(mod_527);
  expr_ret_526 = expr_ret_527;
  if (!rule) rule = expr_ret_526;
  if (!expr_ret_526) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_544
  daisho_astnode_t* expr_ret_544 = NULL;
  daisho_astnode_t* expr_ret_545 = NULL;
  daisho_astnode_t* expr_ret_546 = NULL;
  rec(mod_546);
  // ModExprList 0
  daisho_astnode_t* expr_ret_547 = NULL;
  expr_ret_547 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_546 = expr_ret_547;
  rule = expr_ret_547;
  // ModExprList 1
  if (expr_ret_546) {
    daisho_astnode_t* expr_ret_548 = NULL;
    daisho_astnode_t* expr_ret_549 = SUCC;
    while (expr_ret_549)
    {
      rec(kleene_rew_548);
      daisho_astnode_t* expr_ret_550 = NULL;
      rec(mod_550);
      // ModExprList 0
      daisho_astnode_t* expr_ret_551 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Capturing LSBRACK.
        expr_ret_551 = leaf(LSBRACK);
        expr_ret_551->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_551->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_551 = NULL;
      }

      expr_ret_550 = expr_ret_551;
      l = expr_ret_551;
      // ModExprList 1
      if (expr_ret_550) {
        daisho_astnode_t* expr_ret_552 = NULL;
        expr_ret_552 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_550 = expr_ret_552;
        e = expr_ret_552;
      }

      // ModExprList 2
      if (expr_ret_550) {
        daisho_astnode_t* expr_ret_553 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Capturing RSBRACK.
          expr_ret_553 = leaf(RSBRACK);
          expr_ret_553->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_553->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_553 = NULL;
        }

        expr_ret_550 = expr_ret_553;
        r = expr_ret_553;
      }

      // ModExprList 3
      if (expr_ret_550) {
        daisho_astnode_t* expr_ret_554 = NULL;
        // CodeExpr
        #define ret expr_ret_554
        ret = SUCC;
        ret=node(ARRAYACCESS, l, r);
        #undef ret
        expr_ret_550 = expr_ret_554;
        a = expr_ret_554;
      }

      // ModExprList 4
      if (expr_ret_550) {
        // CodeExpr
        #define ret expr_ret_550
        ret = SUCC;
        rule=binop(a, rule, e);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_550) rew(mod_550);
      expr_ret_549 = expr_ret_550;
    }

    expr_ret_548 = SUCC;
    expr_ret_546 = expr_ret_548;
  }

  // ModExprList end
  if (!expr_ret_546) rew(mod_546);
  expr_ret_545 = expr_ret_546;
  if (!rule) rule = expr_ret_545;
  if (!expr_ret_545) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_555
  daisho_astnode_t* expr_ret_555 = NULL;
  daisho_astnode_t* expr_ret_556 = NULL;
  daisho_astnode_t* expr_ret_557 = NULL;
  rec(mod_557);
  // ModExprList 0
  daisho_astnode_t* expr_ret_558 = NULL;
  expr_ret_558 = daisho_parse_refexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_557 = expr_ret_558;
  rule = expr_ret_558;
  // ModExprList 1
  if (expr_ret_557) {
    daisho_astnode_t* expr_ret_559 = NULL;
    daisho_astnode_t* expr_ret_560 = SUCC;
    while (expr_ret_560)
    {
      rec(kleene_rew_559);
      daisho_astnode_t* expr_ret_561 = NULL;
      rec(mod_561);
      // ModExprList 0
      daisho_astnode_t* expr_ret_562 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Capturing DOT.
        expr_ret_562 = leaf(DOT);
        expr_ret_562->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_562->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_562 = NULL;
      }

      expr_ret_561 = expr_ret_562;
      d = expr_ret_562;
      // ModExprList 1
      if (expr_ret_561) {
        daisho_astnode_t* expr_ret_563 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_563 = leaf(VARIDENT);
          expr_ret_563->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_563->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_563 = NULL;
        }

        expr_ret_561 = expr_ret_563;
        i = expr_ret_563;
      }

      // ModExprList 2
      if (expr_ret_561) {
        // CodeExpr
        #define ret expr_ret_561
        ret = SUCC;
        rule=binop(d, rule, i);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_561) rew(mod_561);
      expr_ret_560 = expr_ret_561;
    }

    expr_ret_559 = SUCC;
    expr_ret_557 = expr_ret_559;
  }

  // ModExprList end
  if (!expr_ret_557) rew(mod_557);
  expr_ret_556 = expr_ret_557;
  if (!rule) rule = expr_ret_556;
  if (!expr_ret_556) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  #define rule expr_ret_564
  daisho_astnode_t* expr_ret_564 = NULL;
  daisho_astnode_t* expr_ret_565 = NULL;
  daisho_astnode_t* expr_ret_566 = NULL;
  rec(mod_566);
  // ModExprList 0
  daisho_astnode_t* expr_ret_567 = NULL;
  expr_ret_567 = daisho_parse_castexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_566 = expr_ret_567;
  rule = expr_ret_567;
  // ModExprList 1
  if (expr_ret_566) {
    daisho_astnode_t* expr_ret_568 = NULL;
    // CodeExpr
    #define ret expr_ret_568
    ret = SUCC;
    ;
    #undef ret
    expr_ret_566 = expr_ret_568;
    op = expr_ret_568;
  }

  // ModExprList 2
  if (expr_ret_566) {
    daisho_astnode_t* expr_ret_569 = NULL;
    daisho_astnode_t* expr_ret_570 = SUCC;
    while (expr_ret_570)
    {
      rec(kleene_rew_569);
      daisho_astnode_t* expr_ret_571 = NULL;

      // SlashExpr 0
      if (!expr_ret_571) {
        daisho_astnode_t* expr_ret_572 = NULL;
        rec(mod_572);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_572 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_572 = NULL;
        }

        // ModExprList 1
        if (expr_ret_572) {
          // CodeExpr
          #define ret expr_ret_572
          ret = SUCC;
          rd++;
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_572) rew(mod_572);
        expr_ret_571 = expr_ret_572;
      }

      // SlashExpr 1
      if (!expr_ret_571) {
        daisho_astnode_t* expr_ret_573 = NULL;
        rec(mod_573);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_573 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_573 = NULL;
        }

        // ModExprList 1
        if (expr_ret_573) {
          // CodeExpr
          #define ret expr_ret_573
          ret = SUCC;
          rd--;
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_573) rew(mod_573);
        expr_ret_571 = expr_ret_573;
      }

      // SlashExpr end
      expr_ret_570 = expr_ret_571;

    }

    expr_ret_569 = SUCC;
    expr_ret_566 = expr_ret_569;
  }

  // ModExprList 3
  if (expr_ret_566) {
    // CodeExpr
    #define ret expr_ret_566
    ret = SUCC;
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                op = rd > 0 ? leaf(REF) : leaf(DEREF);
                rule = unop(op, rule);
              };
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_566) rew(mod_566);
  expr_ret_565 = expr_ret_566;
  if (!rule) rule = expr_ret_565;
  if (!expr_ret_565) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_574
  daisho_astnode_t* expr_ret_574 = NULL;
  daisho_astnode_t* expr_ret_575 = NULL;
  daisho_astnode_t* expr_ret_576 = NULL;
  rec(mod_576);
  // ModExprList 0
  daisho_astnode_t* expr_ret_577 = NULL;
  expr_ret_577 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_576 = expr_ret_577;
  rule = expr_ret_577;
  // ModExprList 1
  if (expr_ret_576) {
    daisho_astnode_t* expr_ret_578 = NULL;
    daisho_astnode_t* expr_ret_579 = SUCC;
    while (expr_ret_579)
    {
      rec(kleene_rew_578);
      daisho_astnode_t* expr_ret_580 = NULL;
      rec(mod_580);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_580 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_580 = NULL;
      }

      // ModExprList 1
      if (expr_ret_580) {
        daisho_astnode_t* expr_ret_581 = NULL;
        expr_ret_581 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_580 = expr_ret_581;
        t = expr_ret_581;
      }

      // ModExprList 2
      if (expr_ret_580) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_580 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_580 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_580) {
        // CodeExpr
        #define ret expr_ret_580
        ret = SUCC;
        rule=node(CAST, rule, t);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_580) rew(mod_580);
      expr_ret_579 = expr_ret_580;
    }

    expr_ret_578 = SUCC;
    expr_ret_576 = expr_ret_578;
  }

  // ModExprList end
  if (!expr_ret_576) rew(mod_576);
  expr_ret_575 = expr_ret_576;
  if (!rule) rule = expr_ret_575;
  if (!expr_ret_575) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* ke = NULL;
  daisho_astnode_t* te = NULL;
  daisho_astnode_t* el = NULL;
  #define rule expr_ret_582
  daisho_astnode_t* expr_ret_582 = NULL;
  daisho_astnode_t* expr_ret_583 = NULL;
  daisho_astnode_t* expr_ret_584 = NULL;
  rec(mod_584);
  // ModExprList 0
  daisho_astnode_t* expr_ret_585 = NULL;
  expr_ret_585 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_584 = expr_ret_585;
  rule = expr_ret_585;
  // ModExprList 1
  if (expr_ret_584) {
    daisho_astnode_t* expr_ret_586 = NULL;
    daisho_astnode_t* expr_ret_587 = NULL;
    rec(mod_587);
    // ModExprList 0
    // CodeExpr
    #define ret expr_ret_587
    ret = SUCC;
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #undef ret
    // ModExprList 1
    if (expr_ret_587) {
      daisho_astnode_t* expr_ret_588 = NULL;

      // SlashExpr 0
      if (!expr_ret_588) {
        daisho_astnode_t* expr_ret_589 = NULL;
        rec(mod_589);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_590 = NULL;
        expr_ret_590 = daisho_parse_kexpand(ctx);
        if (ctx->exit) return NULL;
        expr_ret_589 = expr_ret_590;
        ke = expr_ret_590;
        // ModExprList end
        if (!expr_ret_589) rew(mod_589);
        expr_ret_588 = expr_ret_589;
      }

      // SlashExpr 1
      if (!expr_ret_588) {
        daisho_astnode_t* expr_ret_591 = NULL;
        rec(mod_591);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_592 = NULL;
        expr_ret_592 = daisho_parse_tmplexpand(ctx);
        if (ctx->exit) return NULL;
        expr_ret_591 = expr_ret_592;
        te = expr_ret_592;
        // ModExprList end
        if (!expr_ret_591) rew(mod_591);
        expr_ret_588 = expr_ret_591;
      }

      // SlashExpr end
      expr_ret_587 = expr_ret_588;

    }

    // ModExprList end
    if (!expr_ret_587) rew(mod_587);
    expr_ret_586 = expr_ret_587;
    // optional
    if (!expr_ret_586)
      expr_ret_586 = SUCC;
    expr_ret_584 = expr_ret_586;
  }

  // ModExprList 2
  if (expr_ret_584) {
    daisho_astnode_t* expr_ret_593 = NULL;
    daisho_astnode_t* expr_ret_594 = SUCC;
    while (expr_ret_594)
    {
      rec(kleene_rew_593);
      daisho_astnode_t* expr_ret_595 = NULL;
      rec(mod_595);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_595 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_595 = NULL;
      }

      // ModExprList 1
      if (expr_ret_595) {
        daisho_astnode_t* expr_ret_596 = NULL;
        expr_ret_596 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_595 = expr_ret_596;
        el = expr_ret_596;
      }

      // ModExprList 2
      if (expr_ret_595) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_595 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_595 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_595) {
        // CodeExpr
        #define ret expr_ret_595
        ret = SUCC;
        rule = node(CALL, rule, has(ke) ? ke : te, el); te=NULL;
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_595) rew(mod_595);
      expr_ret_594 = expr_ret_595;
    }

    expr_ret_593 = SUCC;
    expr_ret_584 = expr_ret_593;
  }

  // ModExprList end
  if (!expr_ret_584) rew(mod_584);
  expr_ret_583 = expr_ret_584;
  if (!rule) rule = expr_ret_583;
  if (!expr_ret_583) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_597
  daisho_astnode_t* expr_ret_597 = NULL;
  daisho_astnode_t* expr_ret_598 = NULL;
  daisho_astnode_t* expr_ret_599 = NULL;
  rec(mod_599);
  // ModExprList 0
  daisho_astnode_t* expr_ret_600 = NULL;
  expr_ret_600 = daisho_parse_notexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_599 = expr_ret_600;
  rule = expr_ret_600;
  // ModExprList 1
  if (expr_ret_599) {
    daisho_astnode_t* expr_ret_601 = NULL;
    daisho_astnode_t* expr_ret_602 = NULL;

    // SlashExpr 0
    if (!expr_ret_602) {
      daisho_astnode_t* expr_ret_603 = NULL;
      rec(mod_603);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_604 = NULL;
      rec(mod_604);
      // ModExprList 0
      daisho_astnode_t* expr_ret_605 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Capturing INCR.
        expr_ret_605 = leaf(INCR);
        expr_ret_605->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_605->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_605 = NULL;
      }

      expr_ret_604 = expr_ret_605;
      i = expr_ret_605;
      // ModExprList 1
      if (expr_ret_604) {
        // CodeExpr
        #define ret expr_ret_604
        ret = SUCC;
        rule=unop(i, rule);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_604) rew(mod_604);
      expr_ret_603 = expr_ret_604;
      // ModExprList end
      if (!expr_ret_603) rew(mod_603);
      expr_ret_602 = expr_ret_603;
    }

    // SlashExpr 1
    if (!expr_ret_602) {
      daisho_astnode_t* expr_ret_606 = NULL;
      rec(mod_606);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_607 = NULL;
      rec(mod_607);
      // ModExprList 0
      daisho_astnode_t* expr_ret_608 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Capturing DECR.
        expr_ret_608 = leaf(DECR);
        expr_ret_608->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_608->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_608 = NULL;
      }

      expr_ret_607 = expr_ret_608;
      d = expr_ret_608;
      // ModExprList 1
      if (expr_ret_607) {
        // CodeExpr
        #define ret expr_ret_607
        ret = SUCC;
        rule=unop(d, rule);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_607) rew(mod_607);
      expr_ret_606 = expr_ret_607;
      // ModExprList end
      if (!expr_ret_606) rew(mod_606);
      expr_ret_602 = expr_ret_606;
    }

    // SlashExpr end
    expr_ret_601 = expr_ret_602;

    // optional
    if (!expr_ret_601)
      expr_ret_601 = SUCC;
    expr_ret_599 = expr_ret_601;
  }

  // ModExprList end
  if (!expr_ret_599) rew(mod_599);
  expr_ret_598 = expr_ret_599;
  if (!rule) rule = expr_ret_598;
  if (!expr_ret_598) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_notexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_609
  daisho_astnode_t* expr_ret_609 = NULL;
  daisho_astnode_t* expr_ret_610 = NULL;
  daisho_astnode_t* expr_ret_611 = NULL;
  rec(mod_611);
  // ModExprList 0
  daisho_astnode_t* expr_ret_612 = NULL;
  expr_ret_612 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_611 = expr_ret_612;
  rule = expr_ret_612;
  // ModExprList 1
  if (expr_ret_611) {
    daisho_astnode_t* expr_ret_613 = NULL;
    daisho_astnode_t* expr_ret_614 = SUCC;
    while (expr_ret_614)
    {
      rec(kleene_rew_613);
      daisho_astnode_t* expr_ret_615 = NULL;
      rec(mod_615);
      // ModExprList 0
      daisho_astnode_t* expr_ret_616 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Capturing EXCL.
        expr_ret_616 = leaf(EXCL);
        expr_ret_616->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_616->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_616 = NULL;
      }

      expr_ret_615 = expr_ret_616;
      e = expr_ret_616;
      // ModExprList 1
      if (expr_ret_615) {
        // CodeExpr
        #define ret expr_ret_615
        ret = SUCC;
        rule=unop(e, rule);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_615) rew(mod_615);
      expr_ret_614 = expr_ret_615;
    }

    expr_ret_613 = SUCC;
    expr_ret_611 = expr_ret_613;
  }

  // ModExprList end
  if (!expr_ret_611) rew(mod_611);
  expr_ret_610 = expr_ret_611;
  if (!rule) rule = expr_ret_610;
  if (!expr_ret_610) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_617
  daisho_astnode_t* expr_ret_617 = NULL;
  daisho_astnode_t* expr_ret_618 = NULL;
  daisho_astnode_t* expr_ret_619 = NULL;

  // SlashExpr 0
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_620 = NULL;
    rec(mod_620);
    // ModExprList Forwarding
    expr_ret_620 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_620) rew(mod_620);
    expr_ret_619 = expr_ret_620;
  }

  // SlashExpr 1
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_621 = NULL;
    rec(mod_621);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_621 = leaf(VARIDENT);
      expr_ret_621->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_621->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_621 = NULL;
    }

    // ModExprList end
    if (!expr_ret_621) rew(mod_621);
    expr_ret_619 = expr_ret_621;
  }

  // SlashExpr 2
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_622 = NULL;
    rec(mod_622);
    // ModExprList Forwarding
    expr_ret_622 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_622) rew(mod_622);
    expr_ret_619 = expr_ret_622;
  }

  // SlashExpr 3
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_623 = NULL;
    rec(mod_623);
    // ModExprList Forwarding
    expr_ret_623 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_623) rew(mod_623);
    expr_ret_619 = expr_ret_623;
  }

  // SlashExpr 4
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_624 = NULL;
    rec(mod_624);
    // ModExprList Forwarding
    expr_ret_624 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_624) rew(mod_624);
    expr_ret_619 = expr_ret_624;
  }

  // SlashExpr 5
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_625 = NULL;
    rec(mod_625);
    // ModExprList Forwarding
    expr_ret_625 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_625) rew(mod_625);
    expr_ret_619 = expr_ret_625;
  }

  // SlashExpr 6
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_626 = NULL;
    rec(mod_626);
    // ModExprList Forwarding
    expr_ret_626 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_626) rew(mod_626);
    expr_ret_619 = expr_ret_626;
  }

  // SlashExpr 7
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_627 = NULL;
    rec(mod_627);
    // ModExprList Forwarding
    expr_ret_627 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_627) rew(mod_627);
    expr_ret_619 = expr_ret_627;
  }

  // SlashExpr 8
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_628 = NULL;
    rec(mod_628);
    // ModExprList Forwarding
    expr_ret_628 = daisho_parse_number(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_628) rew(mod_628);
    expr_ret_619 = expr_ret_628;
  }

  // SlashExpr 9
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_629 = NULL;
    rec(mod_629);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_629 = leaf(SELFVAR);
      expr_ret_629->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_629->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_629 = NULL;
    }

    // ModExprList end
    if (!expr_ret_629) rew(mod_629);
    expr_ret_619 = expr_ret_629;
  }

  // SlashExpr 10
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_630 = NULL;
    rec(mod_630);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CHARLIT) {
      // Capturing CHARLIT.
      expr_ret_630 = leaf(CHARLIT);
      expr_ret_630->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_630->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_630 = NULL;
    }

    // ModExprList end
    if (!expr_ret_630) rew(mod_630);
    expr_ret_619 = expr_ret_630;
  }

  // SlashExpr 11
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_631 = NULL;
    rec(mod_631);
    // ModExprList Forwarding
    expr_ret_631 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_631) rew(mod_631);
    expr_ret_619 = expr_ret_631;
  }

  // SlashExpr 12
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_632 = NULL;
    rec(mod_632);
    // ModExprList Forwarding
    expr_ret_632 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_632) rew(mod_632);
    expr_ret_619 = expr_ret_632;
  }

  // SlashExpr 13
  if (!expr_ret_619) {
    daisho_astnode_t* expr_ret_633 = NULL;
    rec(mod_633);
    // ModExprList Forwarding
    expr_ret_633 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_633) rew(mod_633);
    expr_ret_619 = expr_ret_633;
  }

  // SlashExpr end
  expr_ret_618 = expr_ret_619;

  if (!rule) rule = expr_ret_618;
  if (!expr_ret_618) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  int skip=0;

  daisho_astnode_t* e = NULL;
  #define rule expr_ret_634
  daisho_astnode_t* expr_ret_634 = NULL;
  daisho_astnode_t* expr_ret_635 = NULL;
  daisho_astnode_t* expr_ret_636 = NULL;
  rec(mod_636);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_636 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_636 = NULL;
  }

  // ModExprList 1
  if (expr_ret_636) {
    // CodeExpr
    #define ret expr_ret_636
    ret = SUCC;
    rule=list(BLOCK);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_636) {
    daisho_astnode_t* expr_ret_637 = NULL;
    daisho_astnode_t* expr_ret_638 = SUCC;
    while (expr_ret_638)
    {
      rec(kleene_rew_637);
      daisho_astnode_t* expr_ret_639 = NULL;
      rec(mod_639);
      // ModExprList 0
      // CodeExpr
      #define ret expr_ret_639
      ret = SUCC;
      if (skip) ret=NULL;
      #undef ret
      // ModExprList 1
      if (expr_ret_639) {
        rec(mexpr_state_640)
        daisho_astnode_t* expr_ret_640 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
          // Not capturing RCBRACK.
          expr_ret_640 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_640 = NULL;
        }

        // invert
        expr_ret_640 = expr_ret_640 ? NULL : SUCC;
        // rewind
        rew(mexpr_state_640);
        expr_ret_639 = expr_ret_640;
      }

      // ModExprList 2
      if (expr_ret_639) {
        daisho_astnode_t* expr_ret_641 = NULL;
        expr_ret_641 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        // optional
        if (!expr_ret_641)
          expr_ret_641 = SUCC;
        expr_ret_639 = expr_ret_641;
        e = expr_ret_641;
      }

      // ModExprList 3
      if (expr_ret_639) {
        // CodeExpr
        #define ret expr_ret_639
        ret = SUCC;
        if(has(e)) add(rule, e);
        #undef ret
      }

      // ModExprList 4
      if (expr_ret_639) {
        daisho_astnode_t* expr_ret_642 = NULL;

        // SlashExpr 0
        if (!expr_ret_642) {
          daisho_astnode_t* expr_ret_643 = NULL;
          rec(mod_643);
          // ModExprList Forwarding
          expr_ret_643 = daisho_parse_semiornl(ctx);
          if (ctx->exit) return NULL;
          // ModExprList end
          if (!expr_ret_643) rew(mod_643);
          expr_ret_642 = expr_ret_643;
        }

        // SlashExpr 1
        if (!expr_ret_642) {
          daisho_astnode_t* expr_ret_644 = NULL;
          rec(mod_644);
          // ModExprList Forwarding
          // CodeExpr
          #define ret expr_ret_644
          ret = SUCC;
          skip=1;
          #undef ret
          // ModExprList end
          if (!expr_ret_644) rew(mod_644);
          expr_ret_642 = expr_ret_644;
        }

        // SlashExpr end
        expr_ret_639 = expr_ret_642;

      }

      // ModExprList end
      if (!expr_ret_639) rew(mod_639);
      expr_ret_638 = expr_ret_639;
    }

    expr_ret_637 = SUCC;
    expr_ret_636 = expr_ret_637;
  }

  // ModExprList 3
  if (expr_ret_636) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_636 = leaf(RCBRACK);
      expr_ret_636->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_636->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_636 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_636) rew(mod_636);
  expr_ret_635 = expr_ret_636;
  if (!rule) rule = expr_ret_635;
  if (!expr_ret_635) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_645
  daisho_astnode_t* expr_ret_645 = NULL;
  daisho_astnode_t* expr_ret_646 = NULL;
  daisho_astnode_t* expr_ret_647 = NULL;
  rec(mod_647);
  // ModExprList 0
  daisho_astnode_t* expr_ret_648 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
    // Capturing TYPEIDENT.
    expr_ret_648 = leaf(TYPEIDENT);
    expr_ret_648->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_648->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_648 = NULL;
  }

  expr_ret_647 = expr_ret_648;
  ns = expr_ret_648;
  // ModExprList 1
  if (expr_ret_647) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
      // Not capturing DOT.
      expr_ret_647 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_647 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_647) {
    daisho_astnode_t* expr_ret_649 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_649 = leaf(VARIDENT);
      expr_ret_649->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_649->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_649 = NULL;
    }

    expr_ret_647 = expr_ret_649;
    v = expr_ret_649;
  }

  // ModExprList 3
  if (expr_ret_647) {
    // CodeExpr
    #define ret expr_ret_647
    ret = SUCC;
    rule=node(NSACCESS, ns, v);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_647) rew(mod_647);
  expr_ret_646 = expr_ret_647;
  if (!rule) rule = expr_ret_646;
  if (!expr_ret_646) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_650
  daisho_astnode_t* expr_ret_650 = NULL;
  daisho_astnode_t* expr_ret_651 = NULL;
  daisho_astnode_t* expr_ret_652 = NULL;
  rec(mod_652);
  // ModExprList 0
  daisho_astnode_t* expr_ret_653 = NULL;
  rec(mod_653);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_653 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_653 = NULL;
  }

  // ModExprList 1
  if (expr_ret_653) {
    daisho_astnode_t* expr_ret_654 = NULL;
    daisho_astnode_t* expr_ret_655 = NULL;

    // SlashExpr 0
    if (!expr_ret_655) {
      daisho_astnode_t* expr_ret_656 = NULL;
      rec(mod_656);
      // ModExprList 0
      rec(mexpr_state_657)
      daisho_astnode_t* expr_ret_657 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_657 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_657 = NULL;
      }

      // invert
      expr_ret_657 = expr_ret_657 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_657);
      expr_ret_656 = expr_ret_657;
      // ModExprList 1
      if (expr_ret_656) {
        daisho_astnode_t* expr_ret_658 = NULL;
        expr_ret_658 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_656 = expr_ret_658;
        al = expr_ret_658;
      }

      // ModExprList end
      if (!expr_ret_656) rew(mod_656);
      expr_ret_655 = expr_ret_656;
    }

    // SlashExpr 1
    if (!expr_ret_655) {
      daisho_astnode_t* expr_ret_659 = NULL;
      rec(mod_659);
      // ModExprList Forwarding
      // CodeExpr
      #define ret expr_ret_659
      ret = SUCC;
      al=leaf(ARGLIST);
      #undef ret
      // ModExprList end
      if (!expr_ret_659) rew(mod_659);
      expr_ret_655 = expr_ret_659;
    }

    // SlashExpr end
    expr_ret_654 = expr_ret_655;

    // optional
    if (!expr_ret_654)
      expr_ret_654 = SUCC;
    expr_ret_653 = expr_ret_654;
  }

  // ModExprList 2
  if (expr_ret_653) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_653 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_653 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_653) rew(mod_653);
  expr_ret_652 = expr_ret_653;
  // ModExprList 1
  if (expr_ret_652) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_652 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_652 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_652) {
    daisho_astnode_t* expr_ret_660 = NULL;
    expr_ret_660 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_652 = expr_ret_660;
    e = expr_ret_660;
  }

  // ModExprList 3
  if (expr_ret_652) {
    // CodeExpr
    #define ret expr_ret_652
    ret = SUCC;
    rule=node(LAMBDA, al, e);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_652) rew(mod_652);
  expr_ret_651 = expr_ret_652;
  if (!rule) rule = expr_ret_651;
  if (!expr_ret_651) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* en = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* in = NULL;
  daisho_astnode_t* cond = NULL;
  #define rule expr_ret_661
  daisho_astnode_t* expr_ret_661 = NULL;
  daisho_astnode_t* expr_ret_662 = NULL;
  daisho_astnode_t* expr_ret_663 = NULL;
  rec(mod_663);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_663 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_663 = NULL;
  }

  // ModExprList 1
  if (expr_ret_663) {
    daisho_astnode_t* expr_ret_664 = NULL;
    daisho_astnode_t* expr_ret_665 = NULL;
    rec(mod_665);
    // ModExprList 0
    daisho_astnode_t* expr_ret_666 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_666 = leaf(VARIDENT);
      expr_ret_666->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_666->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_666 = NULL;
    }

    expr_ret_665 = expr_ret_666;
    en = expr_ret_666;
    // ModExprList 1
    if (expr_ret_665) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_665 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_665 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_665) rew(mod_665);
    expr_ret_664 = expr_ret_665;
    // optional
    if (!expr_ret_664)
      expr_ret_664 = SUCC;
    expr_ret_663 = expr_ret_664;
  }

  // ModExprList 2
  if (expr_ret_663) {
    daisho_astnode_t* expr_ret_667 = NULL;
    expr_ret_667 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_663 = expr_ret_667;
    e = expr_ret_667;
  }

  // ModExprList 3
  if (expr_ret_663) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_663 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_663 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_663) {
    daisho_astnode_t* expr_ret_668 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_668 = leaf(VARIDENT);
      expr_ret_668->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_668->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_668 = NULL;
    }

    expr_ret_663 = expr_ret_668;
    item = expr_ret_668;
  }

  // ModExprList 5
  if (expr_ret_663) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_663 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_663 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_663) {
    daisho_astnode_t* expr_ret_669 = NULL;
    expr_ret_669 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_663 = expr_ret_669;
    in = expr_ret_669;
  }

  // ModExprList 7
  if (expr_ret_663) {
    daisho_astnode_t* expr_ret_670 = NULL;
    daisho_astnode_t* expr_ret_671 = NULL;
    rec(mod_671);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_671 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_671 = NULL;
    }

    // ModExprList 1
    if (expr_ret_671) {
      daisho_astnode_t* expr_ret_672 = NULL;
      expr_ret_672 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_671 = expr_ret_672;
      cond = expr_ret_672;
    }

    // ModExprList end
    if (!expr_ret_671) rew(mod_671);
    expr_ret_670 = expr_ret_671;
    // optional
    if (!expr_ret_670)
      expr_ret_670 = SUCC;
    expr_ret_663 = expr_ret_670;
  }

  // ModExprList 8
  if (expr_ret_663) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_663 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_663 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_663) {
    // CodeExpr
    #define ret expr_ret_663
    ret = SUCC;
    rule = list(LISTCOMP);
              if (en) add(rule, node(COMPENUMERATE, en));
              add(rule, e);add(rule, item);add(rule, in);
              if (cond) add(rule, node(COMPCOND, cond));;
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_663) rew(mod_663);
  expr_ret_662 = expr_ret_663;
  if (!rule) rule = expr_ret_662;
  if (!expr_ret_662) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_673
  daisho_astnode_t* expr_ret_673 = NULL;
  daisho_astnode_t* expr_ret_674 = NULL;
  daisho_astnode_t* expr_ret_675 = NULL;

  // SlashExpr 0
  if (!expr_ret_675) {
    daisho_astnode_t* expr_ret_676 = NULL;
    rec(mod_676);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_676 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_676 = NULL;
    }

    // ModExprList 1
    if (expr_ret_676) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Not capturing EXCL.
        expr_ret_676 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_676 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_676) {
      daisho_astnode_t* expr_ret_677 = NULL;
      expr_ret_677 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_676 = expr_ret_677;
      r = expr_ret_677;
    }

    // ModExprList 3
    if (expr_ret_676) {
      // CodeExpr
      #define ret expr_ret_676
      ret = SUCC;
      rule=node(EXCL, r);
      #undef ret
    }

    // ModExprList 4
    if (expr_ret_676) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_676 = leaf(CLOSE);
        expr_ret_676->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_676->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_676 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_676) rew(mod_676);
    expr_ret_675 = expr_ret_676;
  }

  // SlashExpr 1
  if (!expr_ret_675) {
    daisho_astnode_t* expr_ret_678 = NULL;
    rec(mod_678);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_678 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_678 = NULL;
    }

    // ModExprList 1
    if (expr_ret_678) {
      daisho_astnode_t* expr_ret_679 = NULL;
      expr_ret_679 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_678 = expr_ret_679;
      r = expr_ret_679;
    }

    // ModExprList 2
    if (expr_ret_678) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_678 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_678 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_678) {
      // CodeExpr
      #define ret expr_ret_678
      ret = SUCC;
      rule=r;
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_678) rew(mod_678);
    expr_ret_675 = expr_ret_678;
  }

  // SlashExpr end
  expr_ret_674 = expr_ret_675;

  if (!rule) rule = expr_ret_674;
  if (!expr_ret_674) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_680
  daisho_astnode_t* expr_ret_680 = NULL;
  daisho_astnode_t* expr_ret_681 = NULL;
  daisho_astnode_t* expr_ret_682 = NULL;
  rec(mod_682);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_682 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_682 = NULL;
  }

  // ModExprList 1
  if (expr_ret_682) {
    daisho_astnode_t* expr_ret_683 = NULL;
    expr_ret_683 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_682 = expr_ret_683;
    rule = expr_ret_683;
  }

  // ModExprList 2
  if (expr_ret_682) {
    // CodeExpr
    #define ret expr_ret_682
    ret = SUCC;
    rule->kind = kind(LISTLIT);
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_682) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_682 = leaf(RSBRACK);
      expr_ret_682->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_682->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_682 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_682) rew(mod_682);
  expr_ret_681 = expr_ret_682;
  if (!rule) rule = expr_ret_681;
  if (!expr_ret_681) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_684
  daisho_astnode_t* expr_ret_684 = NULL;
  daisho_astnode_t* expr_ret_685 = NULL;
  daisho_astnode_t* expr_ret_686 = NULL;
  rec(mod_686);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_686 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_686 = NULL;
  }

  // ModExprList 1
  if (expr_ret_686) {
    daisho_astnode_t* expr_ret_687 = NULL;
    expr_ret_687 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_686 = expr_ret_687;
    rule = expr_ret_687;
  }

  // ModExprList 2
  if (expr_ret_686) {
    // CodeExpr
    #define ret expr_ret_686
    ret = SUCC;
    rule->kind = kind(TUPLELIT);
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_686) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_686 = leaf(CLOSE);
      expr_ret_686->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_686->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_686 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_686) rew(mod_686);
  expr_ret_685 = expr_ret_686;
  if (!rule) rule = expr_ret_685;
  if (!expr_ret_685) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_688
  daisho_astnode_t* expr_ret_688 = NULL;
  daisho_astnode_t* expr_ret_689 = NULL;
  daisho_astnode_t* expr_ret_690 = NULL;
  rec(mod_690);
  // ModExprList 0
  daisho_astnode_t* expr_ret_691 = NULL;
  expr_ret_691 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_690 = expr_ret_691;
  t = expr_ret_691;
  // ModExprList 1
  if (expr_ret_690) {
    daisho_astnode_t* expr_ret_692 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_692 = leaf(VARIDENT);
      expr_ret_692->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_692->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_692 = NULL;
    }

    expr_ret_690 = expr_ret_692;
    i = expr_ret_692;
  }

  // ModExprList 2
  if (expr_ret_690) {
    // CodeExpr
    #define ret expr_ret_690
    ret = SUCC;
    rule=node(VARDECL, t, i);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_690) rew(mod_690);
  expr_ret_689 = expr_ret_690;
  if (!rule) rule = expr_ret_689;
  if (!expr_ret_689) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_693
  daisho_astnode_t* expr_ret_693 = NULL;
  daisho_astnode_t* expr_ret_694 = NULL;
  daisho_astnode_t* expr_ret_695 = NULL;

  // SlashExpr 0
  if (!expr_ret_695) {
    daisho_astnode_t* expr_ret_696 = NULL;
    rec(mod_696);
    // ModExprList Forwarding
    expr_ret_696 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_696) rew(mod_696);
    expr_ret_695 = expr_ret_696;
  }

  // SlashExpr 1
  if (!expr_ret_695) {
    daisho_astnode_t* expr_ret_697 = NULL;
    rec(mod_697);
    // ModExprList Forwarding
    expr_ret_697 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_697) rew(mod_697);
    expr_ret_695 = expr_ret_697;
  }

  // SlashExpr end
  expr_ret_694 = expr_ret_695;

  if (!rule) rule = expr_ret_694;
  if (!expr_ret_694) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_698
  daisho_astnode_t* expr_ret_698 = NULL;
  daisho_astnode_t* expr_ret_699 = NULL;
  daisho_astnode_t* expr_ret_700 = NULL;
  rec(mod_700);
  // ModExprList 0
  daisho_astnode_t* expr_ret_701 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_701 = leaf(STRLIT);
    expr_ret_701->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_701->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_701 = NULL;
  }

  expr_ret_700 = expr_ret_701;
  s = expr_ret_701;
  // ModExprList 1
  if (expr_ret_700) {
    // CodeExpr
    #define ret expr_ret_700
    ret = SUCC;
    rule=list(SSTR); add(rule, s);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_700) {
    daisho_astnode_t* expr_ret_702 = NULL;
    daisho_astnode_t* expr_ret_703 = SUCC;
    while (expr_ret_703)
    {
      rec(kleene_rew_702);
      daisho_astnode_t* expr_ret_704 = NULL;
      rec(mod_704);
      // ModExprList 0
      daisho_astnode_t* expr_ret_705 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_705 = leaf(STRLIT);
        expr_ret_705->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_705->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_705 = NULL;
      }

      expr_ret_704 = expr_ret_705;
      s = expr_ret_705;
      // ModExprList 1
      if (expr_ret_704) {
        // CodeExpr
        #define ret expr_ret_704
        ret = SUCC;
        add(rule, s);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_704) rew(mod_704);
      expr_ret_703 = expr_ret_704;
    }

    expr_ret_702 = SUCC;
    expr_ret_700 = expr_ret_702;
  }

  // ModExprList end
  if (!expr_ret_700) rew(mod_700);
  expr_ret_699 = expr_ret_700;
  if (!rule) rule = expr_ret_699;
  if (!expr_ret_699) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_706
  daisho_astnode_t* expr_ret_706 = NULL;
  daisho_astnode_t* expr_ret_707 = NULL;
  daisho_astnode_t* expr_ret_708 = NULL;
  rec(mod_708);
  // ModExprList 0
  daisho_astnode_t* expr_ret_709 = NULL;
  expr_ret_709 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_708 = expr_ret_709;
  f = expr_ret_709;
  // ModExprList 1
  if (expr_ret_708) {
    // CodeExpr
    #define ret expr_ret_708
    ret = SUCC;
    rule=list(FSTR); add(rule, f);
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_708) {
    daisho_astnode_t* expr_ret_710 = NULL;
    daisho_astnode_t* expr_ret_711 = SUCC;
    while (expr_ret_711)
    {
      rec(kleene_rew_710);
      daisho_astnode_t* expr_ret_712 = NULL;
      rec(mod_712);
      // ModExprList 0
      daisho_astnode_t* expr_ret_713 = NULL;
      expr_ret_713 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_712 = expr_ret_713;
      f = expr_ret_713;
      // ModExprList 1
      if (expr_ret_712) {
        // CodeExpr
        #define ret expr_ret_712
        ret = SUCC;
        add(rule, f);
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_712) rew(mod_712);
      expr_ret_711 = expr_ret_712;
    }

    expr_ret_710 = SUCC;
    expr_ret_708 = expr_ret_710;
  }

  // ModExprList end
  if (!expr_ret_708) rew(mod_708);
  expr_ret_707 = expr_ret_708;
  if (!rule) rule = expr_ret_707;
  if (!expr_ret_707) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_714
  daisho_astnode_t* expr_ret_714 = NULL;
  daisho_astnode_t* expr_ret_715 = NULL;
  daisho_astnode_t* expr_ret_716 = NULL;

  // SlashExpr 0
  if (!expr_ret_716) {
    daisho_astnode_t* expr_ret_717 = NULL;
    rec(mod_717);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_717 = leaf(STRLIT);
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
    // ModExprList 0
    daisho_astnode_t* expr_ret_719 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_719 = leaf(FSTRLITSTART);
      expr_ret_719->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_719->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_719 = NULL;
    }

    expr_ret_718 = expr_ret_719;
    s = expr_ret_719;
    // ModExprList 1
    if (expr_ret_718) {
      // CodeExpr
      #define ret expr_ret_718
      ret = SUCC;
      rule=list(FSTRFRAG); add(rule, s);
      #undef ret
    }

    // ModExprList 2
    if (expr_ret_718) {
      daisho_astnode_t* expr_ret_720 = NULL;
      expr_ret_720 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_718 = expr_ret_720;
      x = expr_ret_720;
    }

    // ModExprList 3
    if (expr_ret_718) {
      // CodeExpr
      #define ret expr_ret_718
      ret = SUCC;
      add(rule, x);
      #undef ret
    }

    // ModExprList 4
    if (expr_ret_718) {
      daisho_astnode_t* expr_ret_721 = NULL;
      daisho_astnode_t* expr_ret_722 = SUCC;
      while (expr_ret_722)
      {
        rec(kleene_rew_721);
        daisho_astnode_t* expr_ret_723 = NULL;
        rec(mod_723);
        // ModExprList 0
        daisho_astnode_t* expr_ret_724 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_724 = leaf(FSTRLITMID);
          expr_ret_724->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_724->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_724 = NULL;
        }

        expr_ret_723 = expr_ret_724;
        m = expr_ret_724;
        // ModExprList 1
        if (expr_ret_723) {
          daisho_astnode_t* expr_ret_725 = NULL;
          expr_ret_725 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_723 = expr_ret_725;
          x = expr_ret_725;
        }

        // ModExprList 2
        if (expr_ret_723) {
          // CodeExpr
          #define ret expr_ret_723
          ret = SUCC;
          add(rule, m); add(rule, x);
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_723) rew(mod_723);
        expr_ret_722 = expr_ret_723;
      }

      expr_ret_721 = SUCC;
      expr_ret_718 = expr_ret_721;
    }

    // ModExprList 5
    if (expr_ret_718) {
      daisho_astnode_t* expr_ret_726 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_726 = leaf(FSTRLITEND);
        expr_ret_726->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_726->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_726 = NULL;
      }

      expr_ret_718 = expr_ret_726;
      e = expr_ret_726;
    }

    // ModExprList 6
    if (expr_ret_718) {
      // CodeExpr
      #define ret expr_ret_718
      ret = SUCC;
      add(rule, e);
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_718) rew(mod_718);
    expr_ret_716 = expr_ret_718;
  }

  // SlashExpr end
  expr_ret_715 = expr_ret_716;

  if (!rule) rule = expr_ret_715;
  if (!expr_ret_715) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_727
  daisho_astnode_t* expr_ret_727 = NULL;
  daisho_astnode_t* expr_ret_728 = NULL;
  daisho_astnode_t* expr_ret_729 = NULL;
  rec(mod_729);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_729 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_729 = NULL;
  }

  // ModExprList 1
  if (expr_ret_729) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_729 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_729 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_729) {
    daisho_astnode_t* expr_ret_730 = NULL;
    daisho_astnode_t* expr_ret_731 = NULL;

    // SlashExpr 0
    if (!expr_ret_731) {
      daisho_astnode_t* expr_ret_732 = NULL;
      rec(mod_732);
      // ModExprList Forwarding
      expr_ret_732 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_732) rew(mod_732);
      expr_ret_731 = expr_ret_732;
    }

    // SlashExpr 1
    if (!expr_ret_731) {
      daisho_astnode_t* expr_ret_733 = NULL;
      rec(mod_733);
      // ModExprList Forwarding
      expr_ret_733 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_733) rew(mod_733);
      expr_ret_731 = expr_ret_733;
    }

    // SlashExpr end
    expr_ret_730 = expr_ret_731;

    expr_ret_729 = expr_ret_730;
    te = expr_ret_730;
  }

  // ModExprList 3
  if (expr_ret_729) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_729 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_729 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_729) {
    // CodeExpr
    #define ret expr_ret_729
    ret = SUCC;
    rule=node(SIZEOF, te);
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_729) rew(mod_729);
  expr_ret_728 = expr_ret_729;
  if (!rule) rule = expr_ret_728;
  if (!expr_ret_728) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_number(daisho_parser_ctx* ctx) {
  #define rule expr_ret_734
  daisho_astnode_t* expr_ret_734 = NULL;
  daisho_astnode_t* expr_ret_735 = NULL;
  daisho_astnode_t* expr_ret_736 = NULL;

  // SlashExpr 0
  if (!expr_ret_736) {
    daisho_astnode_t* expr_ret_737 = NULL;
    rec(mod_737);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INTLIT) {
      // Capturing INTLIT.
      expr_ret_737 = leaf(INTLIT);
      expr_ret_737->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_737->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_737 = NULL;
    }

    // ModExprList end
    if (!expr_ret_737) rew(mod_737);
    expr_ret_736 = expr_ret_737;
  }

  // SlashExpr 1
  if (!expr_ret_736) {
    daisho_astnode_t* expr_ret_738 = NULL;
    rec(mod_738);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TINTLIT) {
      // Capturing TINTLIT.
      expr_ret_738 = leaf(TINTLIT);
      expr_ret_738->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_738->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_738 = NULL;
    }

    // ModExprList end
    if (!expr_ret_738) rew(mod_738);
    expr_ret_736 = expr_ret_738;
  }

  // SlashExpr 2
  if (!expr_ret_736) {
    daisho_astnode_t* expr_ret_739 = NULL;
    rec(mod_739);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FLOATLIT) {
      // Capturing FLOATLIT.
      expr_ret_739 = leaf(FLOATLIT);
      expr_ret_739->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_739->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_739 = NULL;
    }

    // ModExprList end
    if (!expr_ret_739) rew(mod_739);
    expr_ret_736 = expr_ret_739;
  }

  // SlashExpr 3
  if (!expr_ret_736) {
    daisho_astnode_t* expr_ret_740 = NULL;
    rec(mod_740);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TFLOATLIT) {
      // Capturing TFLOATLIT.
      expr_ret_740 = leaf(TFLOATLIT);
      expr_ret_740->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_740->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_740 = NULL;
    }

    // ModExprList end
    if (!expr_ret_740) rew(mod_740);
    expr_ret_736 = expr_ret_740;
  }

  // SlashExpr end
  expr_ret_735 = expr_ret_736;

  if (!rule) rule = expr_ret_735;
  if (!expr_ret_735) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_741
  daisho_astnode_t* expr_ret_741 = NULL;
  daisho_astnode_t* expr_ret_742 = NULL;
  daisho_astnode_t* expr_ret_743 = NULL;
  rec(mod_743);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVE) {
    // Not capturing NATIVE.
    expr_ret_743 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_743 = NULL;
  }

  // ModExprList 1
  if (expr_ret_743) {
    daisho_astnode_t* expr_ret_744 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVEBODY) {
      // Capturing NATIVEBODY.
      expr_ret_744 = leaf(NATIVEBODY);
      expr_ret_744->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_744->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_744 = NULL;
    }

    expr_ret_743 = expr_ret_744;
    rule = expr_ret_744;
  }

  // ModExprList end
  if (!expr_ret_743) rew(mod_743);
  expr_ret_742 = expr_ret_743;
  if (!rule) rule = expr_ret_742;
  if (!expr_ret_742) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_745
  daisho_astnode_t* expr_ret_745 = NULL;
  daisho_astnode_t* expr_ret_746 = NULL;
  daisho_astnode_t* expr_ret_747 = NULL;
  rec(mod_747);
  // ModExprList 0
  daisho_astnode_t* expr_ret_748 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
    // Capturing VARIDENT.
    expr_ret_748 = leaf(VARIDENT);
    expr_ret_748->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_748->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_748 = NULL;
  }

  expr_ret_747 = expr_ret_748;
  rule = expr_ret_748;
  // ModExprList 1
  if (expr_ret_747) {
    // CodeExpr
    #define ret expr_ret_747
    ret = SUCC;
    
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
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_747) rew(mod_747);
  expr_ret_746 = expr_ret_747;
  if (!rule) rule = expr_ret_746;
  if (!expr_ret_746) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_bsl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  #define rule expr_ret_749
  daisho_astnode_t* expr_ret_749 = NULL;
  daisho_astnode_t* expr_ret_750 = NULL;
  daisho_astnode_t* expr_ret_751 = NULL;
  rec(mod_751);
  // ModExprList 0
  daisho_astnode_t* expr_ret_752 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
    // Capturing LT.
    expr_ret_752 = leaf(LT);
    expr_ret_752->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_752->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_752 = NULL;
  }

  expr_ret_751 = expr_ret_752;
  l = expr_ret_752;
  // ModExprList 1
  if (expr_ret_751) {
    daisho_astnode_t* expr_ret_753 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_753 = leaf(LT);
      expr_ret_753->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_753->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_753 = NULL;
    }

    expr_ret_751 = expr_ret_753;
    lt = expr_ret_753;
  }

  // ModExprList 2
  if (expr_ret_751) {
    daisho_astnode_t* expr_ret_754 = NULL;
    // CodeExpr
    #define ret expr_ret_754
    ret = SUCC;
    ret=node(BSL, l, lt);
    #undef ret
    expr_ret_751 = expr_ret_754;
    rule = expr_ret_754;
  }

  // ModExprList end
  if (!expr_ret_751) rew(mod_751);
  expr_ret_750 = expr_ret_751;
  if (!rule) rule = expr_ret_750;
  if (!expr_ret_750) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_bsr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  #define rule expr_ret_755
  daisho_astnode_t* expr_ret_755 = NULL;
  daisho_astnode_t* expr_ret_756 = NULL;
  daisho_astnode_t* expr_ret_757 = NULL;
  rec(mod_757);
  // ModExprList 0
  daisho_astnode_t* expr_ret_758 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
    // Capturing GT.
    expr_ret_758 = leaf(GT);
    expr_ret_758->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_758->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_758 = NULL;
  }

  expr_ret_757 = expr_ret_758;
  g = expr_ret_758;
  // ModExprList 1
  if (expr_ret_757) {
    daisho_astnode_t* expr_ret_759 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_759 = leaf(GT);
      expr_ret_759->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_759->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_759 = NULL;
    }

    expr_ret_757 = expr_ret_759;
    gt = expr_ret_759;
  }

  // ModExprList 2
  if (expr_ret_757) {
    daisho_astnode_t* expr_ret_760 = NULL;
    // CodeExpr
    #define ret expr_ret_760
    ret = SUCC;
    ret=node(BSR, g, gt);
    #undef ret
    expr_ret_757 = expr_ret_760;
    rule = expr_ret_760;
  }

  // ModExprList end
  if (!expr_ret_757) rew(mod_757);
  expr_ret_756 = expr_ret_757;
  if (!rule) rule = expr_ret_756;
  if (!expr_ret_756) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_761
  daisho_astnode_t* expr_ret_761 = NULL;
  daisho_astnode_t* expr_ret_762 = NULL;
  daisho_astnode_t* expr_ret_763 = NULL;

  // SlashExpr 0
  if (!expr_ret_763) {
    daisho_astnode_t* expr_ret_764 = NULL;
    rec(mod_764);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_764 = leaf(SEMI);
      expr_ret_764->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_764->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_764 = NULL;
    }

    // ModExprList end
    if (!expr_ret_764) rew(mod_764);
    expr_ret_763 = expr_ret_764;
  }

  // SlashExpr 1
  if (!expr_ret_763) {
    daisho_astnode_t* expr_ret_765 = NULL;
    rec(mod_765);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_765
    ret = SUCC;
    ret = (ctx->pos >= ctx->len ||
                      ctx->tokens[ctx->pos - 1].line < ctx->tokens[ctx->pos].line)
                      ? leaf(SEMI)
                      : NULL;
    #undef ret
    // ModExprList end
    if (!expr_ret_765) rew(mod_765);
    expr_ret_763 = expr_ret_765;
  }

  // SlashExpr end
  expr_ret_762 = expr_ret_763;

  if (!rule) rule = expr_ret_762;
  if (!expr_ret_762) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx) {
  #define rule expr_ret_766
  daisho_astnode_t* expr_ret_766 = NULL;
  daisho_astnode_t* expr_ret_767 = NULL;
  daisho_astnode_t* expr_ret_768 = NULL;

  // SlashExpr 0
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_769 = NULL;
    rec(mod_769);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_769 = leaf(VARIDENT);
      expr_ret_769->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_769->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_769 = NULL;
    }

    // ModExprList end
    if (!expr_ret_769) rew(mod_769);
    expr_ret_768 = expr_ret_769;
  }

  // SlashExpr 1
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_770 = NULL;
    rec(mod_770);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
      // Capturing PLUS.
      expr_ret_770 = leaf(PLUS);
      expr_ret_770->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_770->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_770 = NULL;
    }

    // ModExprList end
    if (!expr_ret_770) rew(mod_770);
    expr_ret_768 = expr_ret_770;
  }

  // SlashExpr 2
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_771 = NULL;
    rec(mod_771);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
      // Capturing MINUS.
      expr_ret_771 = leaf(MINUS);
      expr_ret_771->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_771->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_771 = NULL;
    }

    // ModExprList end
    if (!expr_ret_771) rew(mod_771);
    expr_ret_768 = expr_ret_771;
  }

  // SlashExpr 3
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_772 = NULL;
    rec(mod_772);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
      // Capturing STAR.
      expr_ret_772 = leaf(STAR);
      expr_ret_772->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_772->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_772 = NULL;
    }

    // ModExprList end
    if (!expr_ret_772) rew(mod_772);
    expr_ret_768 = expr_ret_772;
  }

  // SlashExpr 4
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_773 = NULL;
    rec(mod_773);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
      // Capturing POW.
      expr_ret_773 = leaf(POW);
      expr_ret_773->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_773->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_773 = NULL;
    }

    // ModExprList end
    if (!expr_ret_773) rew(mod_773);
    expr_ret_768 = expr_ret_773;
  }

  // SlashExpr 5
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_774 = NULL;
    rec(mod_774);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
      // Capturing DIV.
      expr_ret_774 = leaf(DIV);
      expr_ret_774->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_774->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_774 = NULL;
    }

    // ModExprList end
    if (!expr_ret_774) rew(mod_774);
    expr_ret_768 = expr_ret_774;
  }

  // SlashExpr 6
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_775 = NULL;
    rec(mod_775);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
      // Capturing MOD.
      expr_ret_775 = leaf(MOD);
      expr_ret_775->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_775->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_775 = NULL;
    }

    // ModExprList end
    if (!expr_ret_775) rew(mod_775);
    expr_ret_768 = expr_ret_775;
  }

  // SlashExpr 7
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_776 = NULL;
    rec(mod_776);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
      // Capturing AND.
      expr_ret_776 = leaf(AND);
      expr_ret_776->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_776->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_776 = NULL;
    }

    // ModExprList end
    if (!expr_ret_776) rew(mod_776);
    expr_ret_768 = expr_ret_776;
  }

  // SlashExpr 8
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_777 = NULL;
    rec(mod_777);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
      // Capturing OR.
      expr_ret_777 = leaf(OR);
      expr_ret_777->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_777->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_777 = NULL;
    }

    // ModExprList end
    if (!expr_ret_777) rew(mod_777);
    expr_ret_768 = expr_ret_777;
  }

  // SlashExpr 9
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_778 = NULL;
    rec(mod_778);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
      // Capturing XOR.
      expr_ret_778 = leaf(XOR);
      expr_ret_778->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_778->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_778 = NULL;
    }

    // ModExprList end
    if (!expr_ret_778) rew(mod_778);
    expr_ret_768 = expr_ret_778;
  }

  // SlashExpr 10
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_779 = NULL;
    rec(mod_779);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
      // Capturing EXCL.
      expr_ret_779 = leaf(EXCL);
      expr_ret_779->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_779->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_779 = NULL;
    }

    // ModExprList end
    if (!expr_ret_779) rew(mod_779);
    expr_ret_768 = expr_ret_779;
  }

  // SlashExpr 11
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_780 = NULL;
    rec(mod_780);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BITNOT) {
      // Capturing BITNOT.
      expr_ret_780 = leaf(BITNOT);
      expr_ret_780->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_780->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_780 = NULL;
    }

    // ModExprList end
    if (!expr_ret_780) rew(mod_780);
    expr_ret_768 = expr_ret_780;
  }

  // SlashExpr 12
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_781 = NULL;
    rec(mod_781);
    // ModExprList Forwarding
    expr_ret_781 = daisho_parse_bsl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_781) rew(mod_781);
    expr_ret_768 = expr_ret_781;
  }

  // SlashExpr 13
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_782 = NULL;
    rec(mod_782);
    // ModExprList Forwarding
    expr_ret_782 = daisho_parse_bsr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_782) rew(mod_782);
    expr_ret_768 = expr_ret_782;
  }

  // SlashExpr 14
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_783 = NULL;
    rec(mod_783);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_783 = leaf(LT);
      expr_ret_783->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_783->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_783 = NULL;
    }

    // ModExprList end
    if (!expr_ret_783) rew(mod_783);
    expr_ret_768 = expr_ret_783;
  }

  // SlashExpr 15
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_784 = NULL;
    rec(mod_784);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_784 = leaf(GT);
      expr_ret_784->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_784->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_784 = NULL;
    }

    // ModExprList end
    if (!expr_ret_784) rew(mod_784);
    expr_ret_768 = expr_ret_784;
  }

  // SlashExpr 16
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_785 = NULL;
    rec(mod_785);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_785 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_785 = NULL;
    }

    // ModExprList 1
    if (expr_ret_785) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_785 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_785 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_785) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Capturing RSBRACK.
        expr_ret_785 = leaf(RSBRACK);
        expr_ret_785->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_785->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_785 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_785) rew(mod_785);
    expr_ret_768 = expr_ret_785;
  }

  // SlashExpr 17
  if (!expr_ret_768) {
    daisho_astnode_t* expr_ret_786 = NULL;
    rec(mod_786);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_786 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_786 = NULL;
    }

    // ModExprList 1
    if (expr_ret_786) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_786 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_786 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_786) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
        // Capturing EQ.
        expr_ret_786 = leaf(EQ);
        expr_ret_786->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_786->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_786 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_786) rew(mod_786);
    expr_ret_768 = expr_ret_786;
  }

  // SlashExpr end
  expr_ret_767 = expr_ret_768;

  if (!rule) rule = expr_ret_767;
  if (!expr_ret_767) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_787
  daisho_astnode_t* expr_ret_787 = NULL;
  daisho_astnode_t* expr_ret_788 = NULL;
  daisho_astnode_t* expr_ret_789 = NULL;
  rec(mod_789);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_790 = NULL;
  rec(mod_790);
  // ModExprList 0
  daisho_astnode_t* expr_ret_791 = NULL;
  expr_ret_791 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_790 = expr_ret_791;
  e = expr_ret_791;
  // ModExprList 1
  if (expr_ret_790) {
    // CodeExpr
    #define ret expr_ret_790
    ret = SUCC;
    WARNING("Extra expression."); ret=e;
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_790) rew(mod_790);
  expr_ret_789 = expr_ret_790;
  // ModExprList end
  if (!expr_ret_789) rew(mod_789);
  expr_ret_788 = expr_ret_789;
  if (!rule) rule = expr_ret_788;
  if (!expr_ret_788) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_792
  daisho_astnode_t* expr_ret_792 = NULL;
  daisho_astnode_t* expr_ret_793 = NULL;
  daisho_astnode_t* expr_ret_794 = NULL;
  rec(mod_794);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_795 = NULL;

  // SlashExpr 0
  if (!expr_ret_795) {
    daisho_astnode_t* expr_ret_796 = NULL;
    rec(mod_796);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_796 = leaf(COMMA);
      expr_ret_796->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_796->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_796 = NULL;
    }

    // ModExprList end
    if (!expr_ret_796) rew(mod_796);
    expr_ret_795 = expr_ret_796;
  }

  // SlashExpr 1
  if (!expr_ret_795) {
    daisho_astnode_t* expr_ret_797 = NULL;
    rec(mod_797);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_797
    ret = SUCC;
    WARNING("Missing comma."); ret=leaf(COMMA);
    #undef ret
    // ModExprList end
    if (!expr_ret_797) rew(mod_797);
    expr_ret_795 = expr_ret_797;
  }

  // SlashExpr end
  expr_ret_794 = expr_ret_795;

  // ModExprList end
  if (!expr_ret_794) rew(mod_794);
  expr_ret_793 = expr_ret_794;
  if (!rule) rule = expr_ret_793;
  if (!expr_ret_793) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_798
  daisho_astnode_t* expr_ret_798 = NULL;
  daisho_astnode_t* expr_ret_799 = NULL;
  daisho_astnode_t* expr_ret_800 = NULL;
  rec(mod_800);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_801 = NULL;
  rec(mod_801);
  // ModExprList 0
  daisho_astnode_t* expr_ret_802 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_802 = leaf(COMMA);
    expr_ret_802->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_802->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_802 = NULL;
  }

  expr_ret_801 = expr_ret_802;
  c = expr_ret_802;
  // ModExprList 1
  if (expr_ret_801) {
    // CodeExpr
    #define ret expr_ret_801
    ret = SUCC;
    WARNING("Extra comma."); ret=c;
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_801) rew(mod_801);
  expr_ret_800 = expr_ret_801;
  // ModExprList end
  if (!expr_ret_800) rew(mod_800);
  expr_ret_799 = expr_ret_800;
  if (!rule) rule = expr_ret_799;
  if (!expr_ret_799) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_803
  daisho_astnode_t* expr_ret_803 = NULL;
  daisho_astnode_t* expr_ret_804 = NULL;
  daisho_astnode_t* expr_ret_805 = NULL;
  rec(mod_805);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_806 = NULL;

  // SlashExpr 0
  if (!expr_ret_806) {
    daisho_astnode_t* expr_ret_807 = NULL;
    rec(mod_807);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_807 = leaf(SEMI);
      expr_ret_807->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_807->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_807 = NULL;
    }

    // ModExprList end
    if (!expr_ret_807) rew(mod_807);
    expr_ret_806 = expr_ret_807;
  }

  // SlashExpr 1
  if (!expr_ret_806) {
    daisho_astnode_t* expr_ret_808 = NULL;
    rec(mod_808);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_808
    ret = SUCC;
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #undef ret
    // ModExprList end
    if (!expr_ret_808) rew(mod_808);
    expr_ret_806 = expr_ret_808;
  }

  // SlashExpr end
  expr_ret_805 = expr_ret_806;

  // ModExprList end
  if (!expr_ret_805) rew(mod_805);
  expr_ret_804 = expr_ret_805;
  if (!rule) rule = expr_ret_804;
  if (!expr_ret_804) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_809
  daisho_astnode_t* expr_ret_809 = NULL;
  daisho_astnode_t* expr_ret_810 = NULL;
  daisho_astnode_t* expr_ret_811 = NULL;
  rec(mod_811);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_812 = NULL;
  rec(mod_812);
  // ModExprList 0
  daisho_astnode_t* expr_ret_813 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_813 = leaf(SEMI);
    expr_ret_813->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_813->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_813 = NULL;
  }

  expr_ret_812 = expr_ret_813;
  s = expr_ret_813;
  // ModExprList 1
  if (expr_ret_812) {
    // CodeExpr
    #define ret expr_ret_812
    ret = SUCC;
    WARNING("Extra semicolon."); ret=s;
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_812) rew(mod_812);
  expr_ret_811 = expr_ret_812;
  // ModExprList end
  if (!expr_ret_811) rew(mod_811);
  expr_ret_810 = expr_ret_811;
  if (!rule) rule = expr_ret_810;
  if (!expr_ret_810) rule = NULL;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_814
  daisho_astnode_t* expr_ret_814 = NULL;
  daisho_astnode_t* expr_ret_815 = NULL;
  daisho_astnode_t* expr_ret_816 = NULL;
  rec(mod_816);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_817 = NULL;

  // SlashExpr 0
  if (!expr_ret_817) {
    daisho_astnode_t* expr_ret_818 = NULL;
    rec(mod_818);
    // ModExprList Forwarding
    expr_ret_818 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_818) rew(mod_818);
    expr_ret_817 = expr_ret_818;
  }

  // SlashExpr 1
  if (!expr_ret_817) {
    daisho_astnode_t* expr_ret_819 = NULL;
    rec(mod_819);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_819
    ret = SUCC;
    WARNING("Missing semicolon or newline."); ret=leaf(SEMI);
    #undef ret
    // ModExprList end
    if (!expr_ret_819) rew(mod_819);
    expr_ret_817 = expr_ret_819;
  }

  // SlashExpr end
  expr_ret_816 = expr_ret_817;

  // ModExprList end
  if (!expr_ret_816) rew(mod_816);
  expr_ret_815 = expr_ret_816;
  if (!rule) rule = expr_ret_815;
  if (!expr_ret_815) rule = NULL;
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
#undef PGEN_MIN6
#undef PGEN_MAX6
#undef PGEN_MIN7
#undef PGEN_MAX7
#undef PGEN_MIN8
#undef PGEN_MAX8
#undef PGEN_MIN9
#undef PGEN_MAX9
#undef PGEN_MIN10
#undef PGEN_MAX10

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
