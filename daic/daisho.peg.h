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
// Tokens 1 through 96 are the ones you defined.
// This totals 98 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 98
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
  DAISHO_NODE_TYPE,
  DAISHO_NODE_PTRTYPE,
  DAISHO_NODE_TUPLETYPE,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_DTRAITIDENT,
  DAISHO_NODE_SSTR,
  DAISHO_NODE_FSTR,
  DAISHO_NODE_FSTRFRAG,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 144
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
static inline daisho_astnode_t* daisho_parse_stunmember(daisho_parser_ctx* ctx);
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
    #line 22 "daisho.peg"
    ret=list(NSLIST);
    #line 3818 "daisho.peg.h"

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
      #line 23 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 3840 "daisho.peg.h"

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
        #line 23 "daisho.peg"
        
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
        #line 3878 "daisho.peg.h"

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
    #line 42 "daisho.peg"
    rule=(!has(sh)) ? node(PROGRAM, nses)
                              : node(PROGRAM, nses, sh);
    #line 3902 "daisho.peg.h"

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
    #line 46 "daisho.peg"
    ret=srepr(leaf(TYPEIDENT), "GLOBAL");
    #line 3987 "daisho.peg.h"

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
    #line 47 "daisho.peg"
    ret = list(NSDECLS);
    #line 4017 "daisho.peg.h"

    #undef ret
    expr_ret_12 = expr_ret_20;
    l = expr_ret_20;
  }

  // ModExprList 3
  if (expr_ret_12) {
    // CodeExpr
    #define ret expr_ret_12
    ret = SUCC;
    #line 47 "daisho.peg"
    add(l, t);
    #line 4031 "daisho.peg.h"

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
      #line 48 "daisho.peg"
      ret=(ctx->pos >= ctx->len) ? NULL : SUCC;
      #line 4051 "daisho.peg.h"

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
          #line 49 "daisho.peg"
          t=NULL;
          #line 4086 "daisho.peg.h"

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
            #line 49 "daisho.peg"
            add(l, t);
            #line 4105 "daisho.peg.h"

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
    #line 50 "daisho.peg"
    rule = node(NAMESPACE, name, l);
    #line 4136 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_12) rew(mod_12);
  expr_ret_11 = expr_ret_12;
  if (!rule) rule = expr_ret_11;
  if (!expr_ret_11) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule namespace returned SUCC.\n"), exit(1);
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
    // CodeExpr
    #define ret expr_ret_45
    ret = SUCC;
    #line 66 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4350 "daisho.peg.h"

    #undef ret
    expr_ret_41 = expr_ret_45;
    members = expr_ret_45;
  }

  // ModExprList 7
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_46 = NULL;
    daisho_astnode_t* expr_ret_47 = SUCC;
    while (expr_ret_47)
    {
      rec(kleene_rew_46);
      daisho_astnode_t* expr_ret_48 = NULL;
      rec(mod_48);
      // ModExprList 0
      daisho_astnode_t* expr_ret_49 = NULL;
      expr_ret_49 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_48 = expr_ret_49;
      m = expr_ret_49;
      // ModExprList 1
      if (expr_ret_48) {
        // CodeExpr
        #define ret expr_ret_48
        ret = SUCC;
        #line 67 "daisho.peg"
        add(members, m);
        #line 4379 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_48) rew(mod_48);
      expr_ret_47 = expr_ret_48;
    }

    expr_ret_46 = SUCC;
    expr_ret_41 = expr_ret_46;
  }

  // ModExprList 8
  if (expr_ret_41) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_41) {
    // CodeExpr
    #define ret expr_ret_41
    ret = SUCC;
    #line 69 "daisho.peg"
    rule = node(STRUCT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4412 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_41) rew(mod_41);
  expr_ret_40 = expr_ret_41;
  if (!rule) rule = expr_ret_40;
  if (!expr_ret_40) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule structdecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_50
  daisho_astnode_t* expr_ret_50 = NULL;
  daisho_astnode_t* expr_ret_51 = NULL;
  daisho_astnode_t* expr_ret_52 = NULL;
  rec(mod_52);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_52 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_52 = NULL;
  }

  // ModExprList 1
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_53 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_53 = leaf(TYPEIDENT);
      expr_ret_53->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_53->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_53 = NULL;
    }

    expr_ret_52 = expr_ret_53;
    id = expr_ret_53;
  }

  // ModExprList 2
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_54 = NULL;
    expr_ret_54 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_52 = expr_ret_54;
    tmpl = expr_ret_54;
  }

  // ModExprList 3
  if (expr_ret_52) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_52 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_52 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_55 = NULL;
    // CodeExpr
    #define ret expr_ret_55
    ret = SUCC;
    #line 72 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4492 "daisho.peg.h"

    #undef ret
    expr_ret_52 = expr_ret_55;
    members = expr_ret_55;
  }

  // ModExprList 5
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_56 = NULL;
    daisho_astnode_t* expr_ret_57 = SUCC;
    while (expr_ret_57)
    {
      rec(kleene_rew_56);
      daisho_astnode_t* expr_ret_58 = NULL;
      rec(mod_58);
      // ModExprList 0
      daisho_astnode_t* expr_ret_59 = NULL;
      expr_ret_59 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_58 = expr_ret_59;
      m = expr_ret_59;
      // ModExprList 1
      if (expr_ret_58) {
        // CodeExpr
        #define ret expr_ret_58
        ret = SUCC;
        #line 73 "daisho.peg"
        add(members, m);
        #line 4521 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_58) rew(mod_58);
      expr_ret_57 = expr_ret_58;
    }

    expr_ret_56 = SUCC;
    expr_ret_52 = expr_ret_56;
  }

  // ModExprList 6
  if (expr_ret_52) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_52 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_52 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_52) {
    // CodeExpr
    #define ret expr_ret_52
    ret = SUCC;
    #line 75 "daisho.peg"
    rule = node(UNION, id, tmpl, members);
    #line 4554 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_52) rew(mod_52);
  expr_ret_51 = expr_ret_52;
  if (!rule) rule = expr_ret_51;
  if (!expr_ret_51) rule = NULL;
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
  #define rule expr_ret_60
  daisho_astnode_t* expr_ret_60 = NULL;
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_62 = NULL;
  rec(mod_62);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
    expr_ret_62 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_62 = NULL;
  }

  // ModExprList 1
  if (expr_ret_62) {
    daisho_astnode_t* expr_ret_63 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_63 = leaf(TYPEIDENT);
      expr_ret_63->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_63->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

    expr_ret_62 = expr_ret_63;
    id = expr_ret_63;
  }

  // ModExprList 2
  if (expr_ret_62) {
    daisho_astnode_t* expr_ret_64 = NULL;
    expr_ret_64 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_62 = expr_ret_64;
    tmpl = expr_ret_64;
  }

  // ModExprList 3
  if (expr_ret_62) {
    daisho_astnode_t* expr_ret_65 = NULL;
    daisho_astnode_t* expr_ret_66 = NULL;
    rec(mod_66);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

    // ModExprList 1
    if (expr_ret_66) {
      daisho_astnode_t* expr_ret_67 = NULL;
      expr_ret_67 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_66 = expr_ret_67;
      il = expr_ret_67;
    }

    // ModExprList end
    if (!expr_ret_66) rew(mod_66);
    expr_ret_65 = expr_ret_66;
    // optional
    if (!expr_ret_65)
      expr_ret_65 = SUCC;
    expr_ret_62 = expr_ret_65;
  }

  // ModExprList 4
  if (expr_ret_62) {
    daisho_astnode_t* expr_ret_68 = NULL;
    // CodeExpr
    #define ret expr_ret_68
    ret = SUCC;
    #line 78 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4655 "daisho.peg.h"

    #undef ret
    expr_ret_62 = expr_ret_68;
    members = expr_ret_68;
  }

  // ModExprList 5
  if (expr_ret_62) {
    daisho_astnode_t* expr_ret_69 = NULL;
    daisho_astnode_t* expr_ret_70 = NULL;
    rec(mod_70);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

    // ModExprList 1
    if (expr_ret_70) {
      daisho_astnode_t* expr_ret_71 = NULL;
      daisho_astnode_t* expr_ret_72 = SUCC;
      while (expr_ret_72)
      {
        rec(kleene_rew_71);
        daisho_astnode_t* expr_ret_73 = NULL;
        rec(mod_73);
        // ModExprList 0
        daisho_astnode_t* expr_ret_74 = NULL;
        expr_ret_74 = daisho_parse_fnmember(ctx);
        if (ctx->exit) return NULL;
        expr_ret_73 = expr_ret_74;
        m = expr_ret_74;
        // ModExprList 1
        if (expr_ret_73) {
          // CodeExpr
          #define ret expr_ret_73
          ret = SUCC;
          #line 79 "daisho.peg"
          add(members, m);
          #line 4698 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_73) rew(mod_73);
        expr_ret_72 = expr_ret_73;
      }

      expr_ret_71 = SUCC;
      expr_ret_70 = expr_ret_71;
    }

    // ModExprList 2
    if (expr_ret_70) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
        // Not capturing RCBRACK.
        expr_ret_70 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_70 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_70) rew(mod_70);
    expr_ret_69 = expr_ret_70;
    // optional
    if (!expr_ret_69)
      expr_ret_69 = SUCC;
    expr_ret_62 = expr_ret_69;
  }

  // ModExprList 6
  if (expr_ret_62) {
    // CodeExpr
    #define ret expr_ret_62
    ret = SUCC;
    #line 80 "daisho.peg"
    rule = node(TRAIT, id, tmpl, il ? il : leaf(TYPELIST), members);
    #line 4740 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_62) rew(mod_62);
  expr_ret_61 = expr_ret_62;
  if (!rule) rule = expr_ret_61;
  if (!expr_ret_61) rule = NULL;
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
  #define rule expr_ret_75
  daisho_astnode_t* expr_ret_75 = NULL;
  daisho_astnode_t* expr_ret_76 = NULL;
  daisho_astnode_t* expr_ret_77 = NULL;
  rec(mod_77);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_77 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_77 = NULL;
  }

  // ModExprList 1
  if (expr_ret_77) {
    daisho_astnode_t* expr_ret_78 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_78 = leaf(TYPEIDENT);
      expr_ret_78->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_78->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_78 = NULL;
    }

    expr_ret_77 = expr_ret_78;
    id = expr_ret_78;
  }

  // ModExprList 2
  if (expr_ret_77) {
    daisho_astnode_t* expr_ret_79 = NULL;
    expr_ret_79 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_77 = expr_ret_79;
    tmpl = expr_ret_79;
  }

  // ModExprList 3
  if (expr_ret_77) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_77 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_77 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_77) {
    daisho_astnode_t* expr_ret_80 = NULL;
    expr_ret_80 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_77 = expr_ret_80;
    ft = expr_ret_80;
  }

  // ModExprList 5
  if (expr_ret_77) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_77 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_77 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_77) {
    daisho_astnode_t* expr_ret_81 = NULL;
    // CodeExpr
    #define ret expr_ret_81
    ret = SUCC;
    #line 83 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4842 "daisho.peg.h"

    #undef ret
    expr_ret_77 = expr_ret_81;
    members = expr_ret_81;
  }

  // ModExprList 7
  if (expr_ret_77) {
    daisho_astnode_t* expr_ret_82 = NULL;
    daisho_astnode_t* expr_ret_83 = SUCC;
    while (expr_ret_83)
    {
      rec(kleene_rew_82);
      daisho_astnode_t* expr_ret_84 = NULL;
      rec(mod_84);
      // ModExprList 0
      daisho_astnode_t* expr_ret_85 = NULL;
      expr_ret_85 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_84 = expr_ret_85;
      m = expr_ret_85;
      // ModExprList 1
      if (expr_ret_84) {
        // CodeExpr
        #define ret expr_ret_84
        ret = SUCC;
        #line 84 "daisho.peg"
        add(members, m);
        #line 4871 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_84) rew(mod_84);
      expr_ret_83 = expr_ret_84;
    }

    expr_ret_82 = SUCC;
    expr_ret_77 = expr_ret_82;
  }

  // ModExprList 8
  if (expr_ret_77) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_77 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_77 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_77) {
    // CodeExpr
    #define ret expr_ret_77
    ret = SUCC;
    #line 86 "daisho.peg"
    rule = node(IMPL, id, tmpl, ft, members);
    #line 4904 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_77) rew(mod_77);
  expr_ret_76 = expr_ret_77;
  if (!rule) rule = expr_ret_76;
  if (!expr_ret_76) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule impldecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_86
  daisho_astnode_t* expr_ret_86 = NULL;
  daisho_astnode_t* expr_ret_87 = NULL;
  daisho_astnode_t* expr_ret_88 = NULL;
  rec(mod_88);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_88 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_88 = NULL;
  }

  // ModExprList 1
  if (expr_ret_88) {
    daisho_astnode_t* expr_ret_89 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_89 = leaf(TYPEIDENT);
      expr_ret_89->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_89->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_89 = NULL;
    }

    expr_ret_88 = expr_ret_89;
    id = expr_ret_89;
  }

  // ModExprList 2
  if (expr_ret_88) {
    daisho_astnode_t* expr_ret_90 = NULL;
    expr_ret_90 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_88 = expr_ret_90;
    c = expr_ret_90;
  }

  // ModExprList 3
  if (expr_ret_88) {
    // CodeExpr
    #define ret expr_ret_88
    ret = SUCC;
    #line 89 "daisho.peg"
    rule = node(CTYPE, id, c);
    #line 4969 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_88) rew(mod_88);
  expr_ret_87 = expr_ret_88;
  if (!rule) rule = expr_ret_87;
  if (!expr_ret_87) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ctypedecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* ci = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_91
  daisho_astnode_t* expr_ret_91 = NULL;
  daisho_astnode_t* expr_ret_92 = NULL;
  daisho_astnode_t* expr_ret_93 = NULL;
  rec(mod_93);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_93 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_93 = NULL;
  }

  // ModExprList 1
  if (expr_ret_93) {
    daisho_astnode_t* expr_ret_94 = NULL;
    expr_ret_94 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_93 = expr_ret_94;
    rett = expr_ret_94;
  }

  // ModExprList 2
  if (expr_ret_93) {
    daisho_astnode_t* expr_ret_95 = NULL;
    expr_ret_95 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_93 = expr_ret_95;
    ci = expr_ret_95;
  }

  // ModExprList 3
  if (expr_ret_93) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_93 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_93 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_93) {
    daisho_astnode_t* expr_ret_96 = NULL;
    expr_ret_96 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_93 = expr_ret_96;
    al = expr_ret_96;
  }

  // ModExprList 5
  if (expr_ret_93) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_93 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_93 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_93) {
    expr_ret_93 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 7
  if (expr_ret_93) {
    // CodeExpr
    #define ret expr_ret_93
    ret = SUCC;
    #line 95 "daisho.peg"
    rule = node(CFN, rett, ci, al);
    #line 5066 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_93) rew(mod_93);
  expr_ret_92 = expr_ret_93;
  if (!rule) rule = expr_ret_92;
  if (!expr_ret_92) rule = NULL;
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
  #define rule expr_ret_97
  daisho_astnode_t* expr_ret_97 = NULL;
  daisho_astnode_t* expr_ret_98 = NULL;
  daisho_astnode_t* expr_ret_99 = NULL;
  rec(mod_99);
  // ModExprList 0
  daisho_astnode_t* expr_ret_100 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_100 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_100 = NULL;
  }

  // optional
  if (!expr_ret_100)
    expr_ret_100 = SUCC;
  expr_ret_99 = expr_ret_100;
  // ModExprList 1
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_101 = NULL;
    expr_ret_101 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_99 = expr_ret_101;
    rett = expr_ret_101;
  }

  // ModExprList 2
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_102 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_102 = leaf(VARIDENT);
      expr_ret_102->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_102->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_102 = NULL;
    }

    expr_ret_99 = expr_ret_102;
    name = expr_ret_102;
  }

  // ModExprList 3
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_103 = NULL;
    expr_ret_103 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_99 = expr_ret_103;
    tmpl = expr_ret_103;
  }

  // ModExprList 4
  if (expr_ret_99) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_99 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_99 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_104 = NULL;
    expr_ret_104 = daisho_parse_arglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_99 = expr_ret_104;
    al = expr_ret_104;
  }

  // ModExprList 6
  if (expr_ret_99) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_99 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_99 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_105 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_105 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_105 = NULL;
    }

    // optional
    if (!expr_ret_105)
      expr_ret_105 = SUCC;
    expr_ret_99 = expr_ret_105;
  }

  // ModExprList 8
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_106 = NULL;
    expr_ret_106 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_99 = expr_ret_106;
    e = expr_ret_106;
  }

  // ModExprList 9
  if (expr_ret_99) {
    daisho_astnode_t* expr_ret_107 = NULL;
    expr_ret_107 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_107)
      expr_ret_107 = SUCC;
    expr_ret_99 = expr_ret_107;
  }

  // ModExprList 10
  if (expr_ret_99) {
    // CodeExpr
    #define ret expr_ret_99
    ret = SUCC;
    #line 101 "daisho.peg"
    rule=node(FNDECL, rett, name, tmpl, al, e);
    #line 5218 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_99) rew(mod_99);
  expr_ret_98 = expr_ret_99;
  if (!rule) rule = expr_ret_98;
  if (!expr_ret_98) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fndecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* al = NULL;
  #define rule expr_ret_108
  daisho_astnode_t* expr_ret_108 = NULL;
  daisho_astnode_t* expr_ret_109 = NULL;
  daisho_astnode_t* expr_ret_110 = NULL;
  rec(mod_110);
  // ModExprList 0
  daisho_astnode_t* expr_ret_111 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_111 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_111 = NULL;
  }

  // optional
  if (!expr_ret_111)
    expr_ret_111 = SUCC;
  expr_ret_110 = expr_ret_111;
  // ModExprList 1
  if (expr_ret_110) {
    daisho_astnode_t* expr_ret_112 = NULL;
    expr_ret_112 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_110 = expr_ret_112;
    rett = expr_ret_112;
  }

  // ModExprList 2
  if (expr_ret_110) {
    daisho_astnode_t* expr_ret_113 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_113 = leaf(VARIDENT);
      expr_ret_113->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_113->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_113 = NULL;
    }

    expr_ret_110 = expr_ret_113;
    name = expr_ret_113;
  }

  // ModExprList 3
  if (expr_ret_110) {
    daisho_astnode_t* expr_ret_114 = NULL;
    expr_ret_114 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_110 = expr_ret_114;
    tmpl = expr_ret_114;
  }

  // ModExprList 4
  if (expr_ret_110) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_110 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_110 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_110) {
    daisho_astnode_t* expr_ret_115 = NULL;
    expr_ret_115 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_110 = expr_ret_115;
    al = expr_ret_115;
  }

  // ModExprList 6
  if (expr_ret_110) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_110 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_110 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_110) {
    daisho_astnode_t* expr_ret_116 = NULL;
    expr_ret_116 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_116)
      expr_ret_116 = SUCC;
    expr_ret_110 = expr_ret_116;
  }

  // ModExprList 8
  if (expr_ret_110) {
    // CodeExpr
    #define ret expr_ret_110
    ret = SUCC;
    #line 107 "daisho.peg"
    rule=node(FNPROTO, rett, name, tmpl, al);
    #line 5343 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_110) rew(mod_110);
  expr_ret_109 = expr_ret_110;
  if (!rule) rule = expr_ret_109;
  if (!expr_ret_109) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnproto returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_stunmember(daisho_parser_ctx* ctx) {
  #define rule expr_ret_117
  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_118 = NULL;
  daisho_astnode_t* expr_ret_119 = NULL;

  // SlashExpr 0
  if (!expr_ret_119) {
    daisho_astnode_t* expr_ret_120 = NULL;
    rec(mod_120);
    // ModExprList Forwarding
    expr_ret_120 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_120) rew(mod_120);
    expr_ret_119 = expr_ret_120;
  }

  // SlashExpr 1
  if (!expr_ret_119) {
    daisho_astnode_t* expr_ret_121 = NULL;
    rec(mod_121);
    // ModExprList Forwarding
    expr_ret_121 = daisho_parse_typemember(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_121) rew(mod_121);
    expr_ret_119 = expr_ret_121;
  }

  // SlashExpr end
  expr_ret_118 = expr_ret_119;

  if (!rule) rule = expr_ret_118;
  if (!expr_ret_118) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule stunmember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_122
  daisho_astnode_t* expr_ret_122 = NULL;
  daisho_astnode_t* expr_ret_123 = NULL;
  daisho_astnode_t* expr_ret_124 = NULL;

  // SlashExpr 0
  if (!expr_ret_124) {
    daisho_astnode_t* expr_ret_125 = NULL;
    rec(mod_125);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_126 = NULL;
    expr_ret_126 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_125 = expr_ret_126;
    rule = expr_ret_126;
    // ModExprList end
    if (!expr_ret_125) rew(mod_125);
    expr_ret_124 = expr_ret_125;
  }

  // SlashExpr 1
  if (!expr_ret_124) {
    daisho_astnode_t* expr_ret_127 = NULL;
    rec(mod_127);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_128 = NULL;
    expr_ret_128 = daisho_parse_fnproto(ctx);
    if (ctx->exit) return NULL;
    expr_ret_127 = expr_ret_128;
    rule = expr_ret_128;
    // ModExprList end
    if (!expr_ret_127) rew(mod_127);
    expr_ret_124 = expr_ret_127;
  }

  // SlashExpr end
  expr_ret_123 = expr_ret_124;

  if (!rule) rule = expr_ret_123;
  if (!expr_ret_123) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnmember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_129
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_130 = NULL;
  daisho_astnode_t* expr_ret_131 = NULL;
  rec(mod_131);
  // ModExprList 0
  daisho_astnode_t* expr_ret_132 = NULL;
  expr_ret_132 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_131 = expr_ret_132;
  t = expr_ret_132;
  // ModExprList 1
  if (expr_ret_131) {
    daisho_astnode_t* expr_ret_133 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_133 = leaf(VARIDENT);
      expr_ret_133->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_133->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_133 = NULL;
    }

    expr_ret_131 = expr_ret_133;
    v = expr_ret_133;
  }

  // ModExprList 2
  if (expr_ret_131) {
    expr_ret_131 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 3
  if (expr_ret_131) {
    // CodeExpr
    #define ret expr_ret_131
    ret = SUCC;
    #line 117 "daisho.peg"
    rule=node(TYPEMEMBER, t, v);
    #line 5489 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_131) rew(mod_131);
  expr_ret_130 = expr_ret_131;
  if (!rule) rule = expr_ret_130;
  if (!expr_ret_130) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typemember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_134
  daisho_astnode_t* expr_ret_134 = NULL;
  daisho_astnode_t* expr_ret_135 = NULL;
  daisho_astnode_t* expr_ret_136 = NULL;

  // SlashExpr 0
  if (!expr_ret_136) {
    daisho_astnode_t* expr_ret_137 = NULL;
    rec(mod_137);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_137 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_137 = NULL;
    }

    // ModExprList 1
    if (expr_ret_137) {
      daisho_astnode_t* expr_ret_138 = NULL;
      expr_ret_138 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_137 = expr_ret_138;
      rule = expr_ret_138;
    }

    // ModExprList 2
    if (expr_ret_137) {
      // CodeExpr
      #define ret expr_ret_137
      ret = SUCC;
      #line 119 "daisho.peg"
      rule->kind = kind(TMPLEXPAND);
      #line 5540 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 3
    if (expr_ret_137) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Capturing GT.
        expr_ret_137 = leaf(GT);
        expr_ret_137->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_137->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_137 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_137) rew(mod_137);
    expr_ret_136 = expr_ret_137;
  }

  // SlashExpr 1
  if (!expr_ret_136) {
    daisho_astnode_t* expr_ret_139 = NULL;
    rec(mod_139);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_139
    ret = SUCC;
    #line 120 "daisho.peg"
    rule=leaf(NOEXPAND);
    #line 5574 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_139) rew(mod_139);
    expr_ret_136 = expr_ret_139;
  }

  // SlashExpr end
  expr_ret_135 = expr_ret_136;

  if (!rule) rule = expr_ret_135;
  if (!expr_ret_135) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tmplexpand returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx) {
  #define rule expr_ret_140
  daisho_astnode_t* expr_ret_140 = NULL;
  daisho_astnode_t* expr_ret_141 = NULL;
  daisho_astnode_t* expr_ret_142 = NULL;
  rec(mod_142);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_143 = NULL;

  // SlashExpr 0
  if (!expr_ret_143) {
    daisho_astnode_t* expr_ret_144 = NULL;
    rec(mod_144);
    // ModExprList Forwarding
    expr_ret_144 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_144) rew(mod_144);
    expr_ret_143 = expr_ret_144;
  }

  // SlashExpr 1
  if (!expr_ret_143) {
    daisho_astnode_t* expr_ret_145 = NULL;
    rec(mod_145);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_145
    ret = SUCC;
    #line 122 "daisho.peg"
    ret=leaf(VOIDTYPE);
    #line 5623 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_145) rew(mod_145);
    expr_ret_143 = expr_ret_145;
  }

  // SlashExpr end
  expr_ret_142 = expr_ret_143;

  // ModExprList end
  if (!expr_ret_142) rew(mod_142);
  expr_ret_141 = expr_ret_142;
  if (!rule) rule = expr_ret_141;
  if (!expr_ret_141) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule returntype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_146
  daisho_astnode_t* expr_ret_146 = NULL;
  daisho_astnode_t* expr_ret_147 = NULL;
  daisho_astnode_t* expr_ret_148 = NULL;
  rec(mod_148);
  // ModExprList 0
  rec(mexpr_state_149)
  daisho_astnode_t* expr_ret_149 = NULL;
  daisho_astnode_t* expr_ret_150 = NULL;

  // SlashExpr 0
  if (!expr_ret_150) {
    daisho_astnode_t* expr_ret_151 = NULL;
    rec(mod_151);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_151 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_151 = NULL;
    }

    // ModExprList end
    if (!expr_ret_151) rew(mod_151);
    expr_ret_150 = expr_ret_151;
  }

  // SlashExpr 1
  if (!expr_ret_150) {
    daisho_astnode_t* expr_ret_152 = NULL;
    rec(mod_152);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Not capturing SELFTYPE.
      expr_ret_152 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_152 = NULL;
    }

    // ModExprList end
    if (!expr_ret_152) rew(mod_152);
    expr_ret_150 = expr_ret_152;
  }

  // SlashExpr 2
  if (!expr_ret_150) {
    daisho_astnode_t* expr_ret_153 = NULL;
    rec(mod_153);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Not capturing VOIDTYPE.
      expr_ret_153 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_153 = NULL;
    }

    // ModExprList end
    if (!expr_ret_153) rew(mod_153);
    expr_ret_150 = expr_ret_153;
  }

  // SlashExpr 3
  if (!expr_ret_150) {
    daisho_astnode_t* expr_ret_154 = NULL;
    rec(mod_154);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Not capturing VOIDPTR.
      expr_ret_154 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_154 = NULL;
    }

    // ModExprList end
    if (!expr_ret_154) rew(mod_154);
    expr_ret_150 = expr_ret_154;
  }

  // SlashExpr 4
  if (!expr_ret_150) {
    daisho_astnode_t* expr_ret_155 = NULL;
    rec(mod_155);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_155 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_155 = NULL;
    }

    // ModExprList end
    if (!expr_ret_155) rew(mod_155);
    expr_ret_150 = expr_ret_155;
  }

  // SlashExpr end
  expr_ret_149 = expr_ret_150;

  // rewind
  rew(mexpr_state_149);
  expr_ret_148 = expr_ret_149;
  // ModExprList 1
  if (expr_ret_148) {
    daisho_astnode_t* expr_ret_156 = NULL;
    expr_ret_156 = daisho_parse_fntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_148 = expr_ret_156;
    rule = expr_ret_156;
  }

  // ModExprList end
  if (!expr_ret_148) rew(mod_148);
  expr_ret_147 = expr_ret_148;
  if (!rule) rule = expr_ret_147;
  if (!expr_ret_147) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule type returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* from = NULL;
  daisho_astnode_t* to = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_157
  daisho_astnode_t* expr_ret_157 = NULL;
  daisho_astnode_t* expr_ret_158 = NULL;
  daisho_astnode_t* expr_ret_159 = NULL;
  rec(mod_159);
  // ModExprList 0
  daisho_astnode_t* expr_ret_160 = NULL;
  // CodeExpr
  #define ret expr_ret_160
  ret = SUCC;
  #line 131 "daisho.peg"
  ;
  #line 5787 "daisho.peg.h"

  #undef ret
  expr_ret_159 = expr_ret_160;
  from = expr_ret_160;
  // ModExprList 1
  if (expr_ret_159) {
    daisho_astnode_t* expr_ret_161 = NULL;
    expr_ret_161 = daisho_parse_ptrtype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_159 = expr_ret_161;
    to = expr_ret_161;
  }

  // ModExprList 2
  if (expr_ret_159) {
    daisho_astnode_t* expr_ret_162 = NULL;
    daisho_astnode_t* expr_ret_163 = SUCC;
    while (expr_ret_163)
    {
      rec(kleene_rew_162);
      daisho_astnode_t* expr_ret_164 = NULL;
      rec(mod_164);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_164 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_164 = NULL;
      }

      // ModExprList 1
      if (expr_ret_164) {
        daisho_astnode_t* expr_ret_165 = NULL;
        expr_ret_165 = daisho_parse_ptrtype(ctx);
        if (ctx->exit) return NULL;
        expr_ret_164 = expr_ret_165;
        n = expr_ret_165;
      }

      // ModExprList 2
      if (expr_ret_164) {
        // CodeExpr
        #define ret expr_ret_164
        ret = SUCC;
        #line 133 "daisho.peg"
        if (!has(from)) from = list(TYPELIST);
        #line 5835 "daisho.peg.h"

        #undef ret
      }

      // ModExprList 3
      if (expr_ret_164) {
        // CodeExpr
        #define ret expr_ret_164
        ret = SUCC;
        #line 134 "daisho.peg"
        add(from, to); to = n;
        #line 5847 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_164) rew(mod_164);
      expr_ret_163 = expr_ret_164;
    }

    expr_ret_162 = SUCC;
    expr_ret_159 = expr_ret_162;
  }

  // ModExprList 3
  if (expr_ret_159) {
    // CodeExpr
    #define ret expr_ret_159
    ret = SUCC;
    #line 135 "daisho.peg"
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #line 5868 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_159) rew(mod_159);
  expr_ret_158 = expr_ret_159;
  if (!rule) rule = expr_ret_158;
  if (!expr_ret_158) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fntype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_166
  daisho_astnode_t* expr_ret_166 = NULL;
  daisho_astnode_t* expr_ret_167 = NULL;
  daisho_astnode_t* expr_ret_168 = NULL;
  rec(mod_168);
  // ModExprList 0
  daisho_astnode_t* expr_ret_169 = NULL;
  expr_ret_169 = daisho_parse_basetype(ctx);
  if (ctx->exit) return NULL;
  expr_ret_168 = expr_ret_169;
  rule = expr_ret_169;
  // ModExprList 1
  if (expr_ret_168) {
    daisho_astnode_t* expr_ret_170 = NULL;
    daisho_astnode_t* expr_ret_171 = SUCC;
    while (expr_ret_171)
    {
      rec(kleene_rew_170);
      daisho_astnode_t* expr_ret_172 = NULL;
      rec(mod_172);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_172 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_172 = NULL;
      }

      // ModExprList 1
      if (expr_ret_172) {
        // CodeExpr
        #define ret expr_ret_172
        ret = SUCC;
        #line 137 "daisho.peg"
        rule=node(PTRTYPE, rule);
        #line 5921 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_172) rew(mod_172);
      expr_ret_171 = expr_ret_172;
    }

    expr_ret_170 = SUCC;
    expr_ret_168 = expr_ret_170;
  }

  // ModExprList end
  if (!expr_ret_168) rew(mod_168);
  expr_ret_167 = expr_ret_168;
  if (!rule) rule = expr_ret_167;
  if (!expr_ret_167) rule = NULL;
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
  #define rule expr_ret_173
  daisho_astnode_t* expr_ret_173 = NULL;
  daisho_astnode_t* expr_ret_174 = NULL;
  daisho_astnode_t* expr_ret_175 = NULL;

  // SlashExpr 0
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_176 = NULL;
    rec(mod_176);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_176 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_176 = NULL;
    }

    // ModExprList 1
    if (expr_ret_176) {
      daisho_astnode_t* expr_ret_177 = NULL;
      expr_ret_177 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_176 = expr_ret_177;
      rule = expr_ret_177;
    }

    // ModExprList 2
    if (expr_ret_176) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_176 = leaf(CLOSE);
        expr_ret_176->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_176->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_176 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_176) rew(mod_176);
    expr_ret_175 = expr_ret_176;
  }

  // SlashExpr 1
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_178 = NULL;
    rec(mod_178);
    // ModExprList Forwarding
    expr_ret_178 = daisho_parse_tupletype(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_178) rew(mod_178);
    expr_ret_175 = expr_ret_178;
  }

  // SlashExpr 2
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_179 = NULL;
    rec(mod_179);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Capturing SELFTYPE.
      expr_ret_179 = leaf(SELFTYPE);
      expr_ret_179->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_179->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_179 = NULL;
    }

    // ModExprList end
    if (!expr_ret_179) rew(mod_179);
    expr_ret_175 = expr_ret_179;
  }

  // SlashExpr 3
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_180 = NULL;
    rec(mod_180);
    // ModExprList 0
    daisho_astnode_t* expr_ret_181 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_181 = leaf(VOIDTYPE);
      expr_ret_181->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_181->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_181 = NULL;
    }

    expr_ret_180 = expr_ret_181;
    v = expr_ret_181;
    // ModExprList 1
    if (expr_ret_180) {
      rec(mexpr_state_182)
      daisho_astnode_t* expr_ret_182 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_182 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_182 = NULL;
      }

      // invert
      expr_ret_182 = expr_ret_182 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_182);
      expr_ret_180 = expr_ret_182;
    }

    // ModExprList 2
    if (expr_ret_180) {
      // CodeExpr
      #define ret expr_ret_180
      ret = SUCC;
      #line 144 "daisho.peg"
      rule=v;
      #line 6074 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_180) rew(mod_180);
    expr_ret_175 = expr_ret_180;
  }

  // SlashExpr 4
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_183 = NULL;
    rec(mod_183);
    // ModExprList Forwarding
    expr_ret_183 = daisho_parse_voidptr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_183) rew(mod_183);
    expr_ret_175 = expr_ret_183;
  }

  // SlashExpr 5
  if (!expr_ret_175) {
    daisho_astnode_t* expr_ret_184 = NULL;
    rec(mod_184);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_185 = NULL;
    rec(mod_185);
    // ModExprList 0
    daisho_astnode_t* expr_ret_186 = NULL;
    daisho_astnode_t* expr_ret_187 = NULL;
    rec(mod_187);
    // ModExprList 0
    daisho_astnode_t* expr_ret_188 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_188 = leaf(TYPEIDENT);
      expr_ret_188->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_188->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_188 = NULL;
    }

    expr_ret_187 = expr_ret_188;
    nns = expr_ret_188;
    // ModExprList 1
    if (expr_ret_187) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_187 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_187 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_187) {
      daisho_astnode_t* expr_ret_189 = NULL;
      // CodeExpr
      #define ret expr_ret_189
      ret = SUCC;
      #line 146 "daisho.peg"
      ret=nns;
      #line 6141 "daisho.peg.h"

      #undef ret
      expr_ret_187 = expr_ret_189;
      ns = expr_ret_189;
    }

    // ModExprList end
    if (!expr_ret_187) rew(mod_187);
    expr_ret_186 = expr_ret_187;
    // optional
    if (!expr_ret_186)
      expr_ret_186 = SUCC;
    expr_ret_185 = expr_ret_186;
    ns = expr_ret_186;
    // ModExprList 1
    if (expr_ret_185) {
      // CodeExpr
      #define ret expr_ret_185
      ret = SUCC;
      #line 147 "daisho.peg"
      if (!has(ns)) ns = leaf(CURRENT_NS);
      #line 6163 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_185) {
      daisho_astnode_t* expr_ret_190 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_190 = leaf(TYPEIDENT);
        expr_ret_190->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_190->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_190 = NULL;
      }

      expr_ret_185 = expr_ret_190;
      s = expr_ret_190;
    }

    // ModExprList 3
    if (expr_ret_185) {
      daisho_astnode_t* expr_ret_191 = NULL;
      expr_ret_191 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_185 = expr_ret_191;
      t = expr_ret_191;
    }

    // ModExprList 4
    if (expr_ret_185) {
      // CodeExpr
      #define ret expr_ret_185
      ret = SUCC;
      #line 149 "daisho.peg"
      rule=node(BASETYPE, ns, s, t);
      #line 6201 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_185) rew(mod_185);
    expr_ret_184 = expr_ret_185;
    // ModExprList end
    if (!expr_ret_184) rew(mod_184);
    expr_ret_175 = expr_ret_184;
  }

  // SlashExpr end
  expr_ret_174 = expr_ret_175;

  if (!rule) rule = expr_ret_174;
  if (!expr_ret_174) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule basetype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_192
  daisho_astnode_t* expr_ret_192 = NULL;
  daisho_astnode_t* expr_ret_193 = NULL;
  daisho_astnode_t* expr_ret_194 = NULL;

  // SlashExpr 0
  if (!expr_ret_194) {
    daisho_astnode_t* expr_ret_195 = NULL;
    rec(mod_195);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_195 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_195 = NULL;
    }

    // ModExprList 1
    if (expr_ret_195) {
      daisho_astnode_t* expr_ret_196 = NULL;
      expr_ret_196 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_195 = expr_ret_196;
      t = expr_ret_196;
    }

    // ModExprList 2
    if (expr_ret_195) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_195 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_195 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_195) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_195 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_195 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_195) {
      // CodeExpr
      #define ret expr_ret_195
      ret = SUCC;
      #line 151 "daisho.peg"
      rule=node(TUPLETYPE, t);
      #line 6284 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_195) rew(mod_195);
    expr_ret_194 = expr_ret_195;
  }

  // SlashExpr 1
  if (!expr_ret_194) {
    daisho_astnode_t* expr_ret_197 = NULL;
    rec(mod_197);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_197 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_197 = NULL;
    }

    // ModExprList 1
    if (expr_ret_197) {
      daisho_astnode_t* expr_ret_198 = NULL;
      expr_ret_198 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_197 = expr_ret_198;
      rule = expr_ret_198;
    }

    // ModExprList 2
    if (expr_ret_197) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_197 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_197 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_197) {
      // CodeExpr
      #define ret expr_ret_197
      ret = SUCC;
      #line 152 "daisho.peg"
      rule->kind = kind(TUPLETYPE);
      #line 6335 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_197) rew(mod_197);
    expr_ret_194 = expr_ret_197;
  }

  // SlashExpr end
  expr_ret_193 = expr_ret_194;

  if (!rule) rule = expr_ret_193;
  if (!expr_ret_193) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tupletype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_199
  daisho_astnode_t* expr_ret_199 = NULL;
  daisho_astnode_t* expr_ret_200 = NULL;
  daisho_astnode_t* expr_ret_201 = NULL;

  // SlashExpr 0
  if (!expr_ret_201) {
    daisho_astnode_t* expr_ret_202 = NULL;
    rec(mod_202);
    // ModExprList 0
    daisho_astnode_t* expr_ret_203 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_203 = leaf(VOIDPTR);
      expr_ret_203->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_203->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_203 = NULL;
    }

    expr_ret_202 = expr_ret_203;
    v = expr_ret_203;
    // ModExprList 1
    if (expr_ret_202) {
      // CodeExpr
      #define ret expr_ret_202
      ret = SUCC;
      #line 154 "daisho.peg"
      rule=v;
      #line 6388 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_202) rew(mod_202);
    expr_ret_201 = expr_ret_202;
  }

  // SlashExpr 1
  if (!expr_ret_201) {
    daisho_astnode_t* expr_ret_204 = NULL;
    rec(mod_204);
    // ModExprList 0
    daisho_astnode_t* expr_ret_205 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_205 = leaf(VOIDTYPE);
      expr_ret_205->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_205->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_205 = NULL;
    }

    expr_ret_204 = expr_ret_205;
    v = expr_ret_205;
    // ModExprList 1
    if (expr_ret_204) {
      daisho_astnode_t* expr_ret_206 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_206 = leaf(STAR);
        expr_ret_206->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_206->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_206 = NULL;
      }

      expr_ret_204 = expr_ret_206;
      s = expr_ret_206;
    }

    // ModExprList 2
    if (expr_ret_204) {
      // CodeExpr
      #define ret expr_ret_204
      ret = SUCC;
      #line 155 "daisho.peg"
      rule=leaf(VOIDPTR);
      #line 6440 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_204) rew(mod_204);
    expr_ret_201 = expr_ret_204;
  }

  // SlashExpr end
  expr_ret_200 = expr_ret_201;

  if (!rule) rule = expr_ret_200;
  if (!expr_ret_200) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule voidptr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_207
  daisho_astnode_t* expr_ret_207 = NULL;
  daisho_astnode_t* expr_ret_208 = NULL;
  daisho_astnode_t* expr_ret_209 = NULL;
  rec(mod_209);
  // ModExprList 0
  daisho_astnode_t* expr_ret_210 = NULL;
  expr_ret_210 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_210)
    expr_ret_210 = SUCC;
  expr_ret_209 = expr_ret_210;
  // ModExprList 1
  if (expr_ret_209) {
    // CodeExpr
    #define ret expr_ret_209
    ret = SUCC;
    #line 162 "daisho.peg"
    rule=list(TYPELIST);
    #line 6482 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_209) {
    daisho_astnode_t* expr_ret_211 = NULL;
    expr_ret_211 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_211)
      expr_ret_211 = SUCC;
    expr_ret_209 = expr_ret_211;
    t = expr_ret_211;
  }

  // ModExprList 3
  if (expr_ret_209) {
    // CodeExpr
    #define ret expr_ret_209
    ret = SUCC;
    #line 163 "daisho.peg"
    if has(t) add(rule, t);
    #line 6506 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_209) {
    daisho_astnode_t* expr_ret_212 = NULL;
    daisho_astnode_t* expr_ret_213 = SUCC;
    while (expr_ret_213)
    {
      rec(kleene_rew_212);
      daisho_astnode_t* expr_ret_214 = NULL;
      rec(mod_214);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_214 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_214 = NULL;
      }

      // ModExprList 1
      if (expr_ret_214) {
        daisho_astnode_t* expr_ret_215 = NULL;
        expr_ret_215 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_214 = expr_ret_215;
        t = expr_ret_215;
      }

      // ModExprList 2
      if (expr_ret_214) {
        // CodeExpr
        #define ret expr_ret_214
        ret = SUCC;
        #line 164 "daisho.peg"
        add(rule, t);
        #line 6545 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_214) rew(mod_214);
      expr_ret_213 = expr_ret_214;
    }

    expr_ret_212 = SUCC;
    expr_ret_209 = expr_ret_212;
  }

  // ModExprList 5
  if (expr_ret_209) {
    daisho_astnode_t* expr_ret_216 = NULL;
    expr_ret_216 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_216)
      expr_ret_216 = SUCC;
    expr_ret_209 = expr_ret_216;
  }

  // ModExprList end
  if (!expr_ret_209) rew(mod_209);
  expr_ret_208 = expr_ret_209;
  if (!rule) rule = expr_ret_208;
  if (!expr_ret_208) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typelist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_217
  daisho_astnode_t* expr_ret_217 = NULL;
  daisho_astnode_t* expr_ret_218 = NULL;
  daisho_astnode_t* expr_ret_219 = NULL;
  rec(mod_219);
  // ModExprList 0
  daisho_astnode_t* expr_ret_220 = NULL;
  expr_ret_220 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_220)
    expr_ret_220 = SUCC;
  expr_ret_219 = expr_ret_220;
  // ModExprList 1
  if (expr_ret_219) {
    // CodeExpr
    #define ret expr_ret_219
    ret = SUCC;
    #line 166 "daisho.peg"
    rule=list(EXPRLIST);
    #line 6602 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_219) {
    daisho_astnode_t* expr_ret_221 = NULL;
    expr_ret_221 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_221)
      expr_ret_221 = SUCC;
    expr_ret_219 = expr_ret_221;
    e = expr_ret_221;
  }

  // ModExprList 3
  if (expr_ret_219) {
    // CodeExpr
    #define ret expr_ret_219
    ret = SUCC;
    #line 167 "daisho.peg"
    if has(e) add(rule, e);
    #line 6626 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_219) {
    daisho_astnode_t* expr_ret_222 = NULL;
    daisho_astnode_t* expr_ret_223 = SUCC;
    while (expr_ret_223)
    {
      rec(kleene_rew_222);
      daisho_astnode_t* expr_ret_224 = NULL;
      rec(mod_224);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_224 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_224 = NULL;
      }

      // ModExprList 1
      if (expr_ret_224) {
        daisho_astnode_t* expr_ret_225 = NULL;
        expr_ret_225 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_224 = expr_ret_225;
        e = expr_ret_225;
      }

      // ModExprList 2
      if (expr_ret_224) {
        // CodeExpr
        #define ret expr_ret_224
        ret = SUCC;
        #line 168 "daisho.peg"
        add(rule, e);
        #line 6665 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_224) rew(mod_224);
      expr_ret_223 = expr_ret_224;
    }

    expr_ret_222 = SUCC;
    expr_ret_219 = expr_ret_222;
  }

  // ModExprList 5
  if (expr_ret_219) {
    daisho_astnode_t* expr_ret_226 = NULL;
    expr_ret_226 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_226)
      expr_ret_226 = SUCC;
    expr_ret_219 = expr_ret_226;
  }

  // ModExprList end
  if (!expr_ret_219) rew(mod_219);
  expr_ret_218 = expr_ret_219;
  if (!rule) rule = expr_ret_218;
  if (!expr_ret_218) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule exprlist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_227
  daisho_astnode_t* expr_ret_227 = NULL;
  daisho_astnode_t* expr_ret_228 = NULL;
  daisho_astnode_t* expr_ret_229 = NULL;
  rec(mod_229);
  // ModExprList 0
  daisho_astnode_t* expr_ret_230 = NULL;
  expr_ret_230 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_229 = expr_ret_230;
  t = expr_ret_230;
  // ModExprList 1
  if (expr_ret_229) {
    daisho_astnode_t* expr_ret_231 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_231 = leaf(VARIDENT);
      expr_ret_231->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_231->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_231 = NULL;
    }

    expr_ret_229 = expr_ret_231;
    i = expr_ret_231;
  }

  // ModExprList 2
  if (expr_ret_229) {
    // CodeExpr
    #define ret expr_ret_229
    ret = SUCC;
    #line 171 "daisho.peg"
    rule=node(FNARG, t, i);
    #line 6738 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_229) rew(mod_229);
  expr_ret_228 = expr_ret_229;
  if (!rule) rule = expr_ret_228;
  if (!expr_ret_228) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_232
  daisho_astnode_t* expr_ret_232 = NULL;
  daisho_astnode_t* expr_ret_233 = NULL;
  daisho_astnode_t* expr_ret_234 = NULL;
  rec(mod_234);
  // ModExprList 0
  daisho_astnode_t* expr_ret_235 = NULL;
  expr_ret_235 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_235)
    expr_ret_235 = SUCC;
  expr_ret_234 = expr_ret_235;
  // ModExprList 1
  if (expr_ret_234) {
    // CodeExpr
    #define ret expr_ret_234
    ret = SUCC;
    #line 172 "daisho.peg"
    rule=list(ARGLIST);
    #line 6775 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_234) {
    daisho_astnode_t* expr_ret_236 = NULL;
    expr_ret_236 = daisho_parse_fnarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_236)
      expr_ret_236 = SUCC;
    expr_ret_234 = expr_ret_236;
    a = expr_ret_236;
  }

  // ModExprList 3
  if (expr_ret_234) {
    // CodeExpr
    #define ret expr_ret_234
    ret = SUCC;
    #line 173 "daisho.peg"
    if has(a) add(rule, a);
    #line 6799 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_234) {
    daisho_astnode_t* expr_ret_237 = NULL;
    daisho_astnode_t* expr_ret_238 = SUCC;
    while (expr_ret_238)
    {
      rec(kleene_rew_237);
      daisho_astnode_t* expr_ret_239 = NULL;
      rec(mod_239);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_239 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_239 = NULL;
      }

      // ModExprList 1
      if (expr_ret_239) {
        daisho_astnode_t* expr_ret_240 = NULL;
        expr_ret_240 = daisho_parse_fnarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_239 = expr_ret_240;
        a = expr_ret_240;
      }

      // ModExprList 2
      if (expr_ret_239) {
        // CodeExpr
        #define ret expr_ret_239
        ret = SUCC;
        #line 174 "daisho.peg"
        add(rule, a);
        #line 6838 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_239) rew(mod_239);
      expr_ret_238 = expr_ret_239;
    }

    expr_ret_237 = SUCC;
    expr_ret_234 = expr_ret_237;
  }

  // ModExprList 5
  if (expr_ret_234) {
    daisho_astnode_t* expr_ret_241 = NULL;
    expr_ret_241 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_241)
      expr_ret_241 = SUCC;
    expr_ret_234 = expr_ret_241;
  }

  // ModExprList end
  if (!expr_ret_234) rew(mod_234);
  expr_ret_233 = expr_ret_234;
  if (!rule) rule = expr_ret_233;
  if (!expr_ret_233) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule arglist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_242
  daisho_astnode_t* expr_ret_242 = NULL;
  daisho_astnode_t* expr_ret_243 = NULL;
  daisho_astnode_t* expr_ret_244 = NULL;
  rec(mod_244);
  // ModExprList 0
  daisho_astnode_t* expr_ret_245 = NULL;
  expr_ret_245 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_244 = expr_ret_245;
  t = expr_ret_245;
  // ModExprList 1
  if (expr_ret_244) {
    daisho_astnode_t* expr_ret_246 = NULL;
    daisho_astnode_t* expr_ret_247 = NULL;

    // SlashExpr 0
    if (!expr_ret_247) {
      daisho_astnode_t* expr_ret_248 = NULL;
      rec(mod_248);
      // ModExprList Forwarding
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_248 = leaf(VARIDENT);
        expr_ret_248->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_248->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_248 = NULL;
      }

      // ModExprList end
      if (!expr_ret_248) rew(mod_248);
      expr_ret_247 = expr_ret_248;
    }

    // SlashExpr 1
    if (!expr_ret_247) {
      daisho_astnode_t* expr_ret_249 = NULL;
      rec(mod_249);
      // ModExprList Forwarding
      // CodeExpr
      #define ret expr_ret_249
      ret = SUCC;
      #line 177 "daisho.peg"
      ret=leaf(NOARG);
      #line 6922 "daisho.peg.h"

      #undef ret
      // ModExprList end
      if (!expr_ret_249) rew(mod_249);
      expr_ret_247 = expr_ret_249;
    }

    // SlashExpr end
    expr_ret_246 = expr_ret_247;

    expr_ret_244 = expr_ret_246;
    i = expr_ret_246;
  }

  // ModExprList 2
  if (expr_ret_244) {
    // CodeExpr
    #define ret expr_ret_244
    ret = SUCC;
    #line 178 "daisho.peg"
    rule=node(PROTOARG, t, i);
    #line 6944 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_244) rew(mod_244);
  expr_ret_243 = expr_ret_244;
  if (!rule) rule = expr_ret_243;
  if (!expr_ret_243) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protoarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_250
  daisho_astnode_t* expr_ret_250 = NULL;
  daisho_astnode_t* expr_ret_251 = NULL;
  daisho_astnode_t* expr_ret_252 = NULL;
  rec(mod_252);
  // ModExprList 0
  daisho_astnode_t* expr_ret_253 = NULL;
  expr_ret_253 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_253)
    expr_ret_253 = SUCC;
  expr_ret_252 = expr_ret_253;
  // ModExprList 1
  if (expr_ret_252) {
    // CodeExpr
    #define ret expr_ret_252
    ret = SUCC;
    #line 180 "daisho.peg"
    rule=list(PROTOLIST);
    #line 6981 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_252) {
    daisho_astnode_t* expr_ret_254 = NULL;
    expr_ret_254 = daisho_parse_protoarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_254)
      expr_ret_254 = SUCC;
    expr_ret_252 = expr_ret_254;
    p = expr_ret_254;
  }

  // ModExprList 3
  if (expr_ret_252) {
    // CodeExpr
    #define ret expr_ret_252
    ret = SUCC;
    #line 181 "daisho.peg"
    if has(p) add(rule, p);
    #line 7005 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_252) {
    daisho_astnode_t* expr_ret_255 = NULL;
    daisho_astnode_t* expr_ret_256 = SUCC;
    while (expr_ret_256)
    {
      rec(kleene_rew_255);
      daisho_astnode_t* expr_ret_257 = NULL;
      rec(mod_257);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_257 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_257 = NULL;
      }

      // ModExprList 1
      if (expr_ret_257) {
        daisho_astnode_t* expr_ret_258 = NULL;
        expr_ret_258 = daisho_parse_protoarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_257 = expr_ret_258;
        p = expr_ret_258;
      }

      // ModExprList 2
      if (expr_ret_257) {
        // CodeExpr
        #define ret expr_ret_257
        ret = SUCC;
        #line 182 "daisho.peg"
        add(rule, p);
        #line 7044 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_257) rew(mod_257);
      expr_ret_256 = expr_ret_257;
    }

    expr_ret_255 = SUCC;
    expr_ret_252 = expr_ret_255;
  }

  // ModExprList 5
  if (expr_ret_252) {
    daisho_astnode_t* expr_ret_259 = NULL;
    expr_ret_259 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_259)
      expr_ret_259 = SUCC;
    expr_ret_252 = expr_ret_259;
  }

  // ModExprList end
  if (!expr_ret_252) rew(mod_252);
  expr_ret_251 = expr_ret_252;
  if (!rule) rule = expr_ret_251;
  if (!expr_ret_251) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protoarglist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_260
  daisho_astnode_t* expr_ret_260 = NULL;
  daisho_astnode_t* expr_ret_261 = NULL;
  daisho_astnode_t* expr_ret_262 = NULL;
  rec(mod_262);
  // ModExprList 0
  rec(mexpr_state_263)
  daisho_astnode_t* expr_ret_263 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Not capturing SEMI.
    expr_ret_263 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_263 = NULL;
  }

  // invert
  expr_ret_263 = expr_ret_263 ? NULL : SUCC;
  // rewind
  rew(mexpr_state_263);
  expr_ret_262 = expr_ret_263;
  // ModExprList 1
  if (expr_ret_262) {
    rec(mexpr_state_264)
    daisho_astnode_t* expr_ret_264 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_264 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_264 = NULL;
    }

    // invert
    expr_ret_264 = expr_ret_264 ? NULL : SUCC;
    // rewind
    rew(mexpr_state_264);
    expr_ret_262 = expr_ret_264;
  }

  // ModExprList 2
  if (expr_ret_262) {
    daisho_astnode_t* expr_ret_265 = NULL;
    expr_ret_265 = daisho_parse_preretexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_262 = expr_ret_265;
    rule = expr_ret_265;
  }

  // ModExprList end
  if (!expr_ret_262) rew(mod_262);
  expr_ret_261 = expr_ret_262;
  if (!rule) rule = expr_ret_261;
  if (!expr_ret_261) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule expr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_266
  daisho_astnode_t* expr_ret_266 = NULL;
  daisho_astnode_t* expr_ret_267 = NULL;
  daisho_astnode_t* expr_ret_268 = NULL;

  // SlashExpr 0
  if (!expr_ret_268) {
    daisho_astnode_t* expr_ret_269 = NULL;
    rec(mod_269);
    // ModExprList 0
    daisho_astnode_t* expr_ret_270 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_270 = leaf(RET);
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
      daisho_astnode_t* expr_ret_271 = NULL;
      expr_ret_271 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_269 = expr_ret_271;
      n = expr_ret_271;
    }

    // ModExprList 2
    if (expr_ret_269) {
      // CodeExpr
      #define ret expr_ret_269
      ret = SUCC;
      #line 191 "daisho.peg"
      rule=node(RET, r, n);
      #line 7182 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_269) rew(mod_269);
    expr_ret_268 = expr_ret_269;
  }

  // SlashExpr 1
  if (!expr_ret_268) {
    daisho_astnode_t* expr_ret_272 = NULL;
    rec(mod_272);
    // ModExprList 0
    daisho_astnode_t* expr_ret_273 = NULL;
    expr_ret_273 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_272 = expr_ret_273;
    rule = expr_ret_273;
    // ModExprList 1
    if (expr_ret_272) {
      daisho_astnode_t* expr_ret_274 = NULL;
      daisho_astnode_t* expr_ret_275 = NULL;
      rec(mod_275);
      // ModExprList 0
      daisho_astnode_t* expr_ret_276 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Capturing GRAVE.
        expr_ret_276 = leaf(GRAVE);
        expr_ret_276->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_276->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_276 = NULL;
      }

      expr_ret_275 = expr_ret_276;
      r = expr_ret_276;
      // ModExprList 1
      if (expr_ret_275) {
        // CodeExpr
        #define ret expr_ret_275
        ret = SUCC;
        #line 192 "daisho.peg"
        rule = node(RET, r, rule);
        #line 7228 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_275) rew(mod_275);
      expr_ret_274 = expr_ret_275;
      // optional
      if (!expr_ret_274)
        expr_ret_274 = SUCC;
      expr_ret_272 = expr_ret_274;
    }

    // ModExprList end
    if (!expr_ret_272) rew(mod_272);
    expr_ret_268 = expr_ret_272;
  }

  // SlashExpr end
  expr_ret_267 = expr_ret_268;

  if (!rule) rule = expr_ret_267;
  if (!expr_ret_267) rule = NULL;
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
  #define rule expr_ret_277
  daisho_astnode_t* expr_ret_277 = NULL;
  daisho_astnode_t* expr_ret_278 = NULL;
  daisho_astnode_t* expr_ret_279 = NULL;

  // SlashExpr 0
  if (!expr_ret_279) {
    daisho_astnode_t* expr_ret_280 = NULL;
    rec(mod_280);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_280 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_280 = NULL;
    }

    // ModExprList 1
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_281 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_281 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_281 = NULL;
      }

      // optional
      if (!expr_ret_281)
        expr_ret_281 = SUCC;
      expr_ret_280 = expr_ret_281;
      o = expr_ret_281;
    }

    // ModExprList 2
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_282 = NULL;
      expr_ret_282 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_280 = expr_ret_282;
      f = expr_ret_282;
    }

    // ModExprList 3
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_283 = NULL;

      // SlashExpr 0
      if (!expr_ret_283) {
        daisho_astnode_t* expr_ret_284 = NULL;
        rec(mod_284);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_285 = NULL;

        // SlashExpr 0
        if (!expr_ret_285) {
          daisho_astnode_t* expr_ret_286 = NULL;
          rec(mod_286);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_286 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_286 = NULL;
          }

          // ModExprList end
          if (!expr_ret_286) rew(mod_286);
          expr_ret_285 = expr_ret_286;
        }

        // SlashExpr 1
        if (!expr_ret_285) {
          daisho_astnode_t* expr_ret_287 = NULL;
          rec(mod_287);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_287 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_287 = NULL;
          }

          // ModExprList end
          if (!expr_ret_287) rew(mod_287);
          expr_ret_285 = expr_ret_287;
        }

        // SlashExpr end
        expr_ret_284 = expr_ret_285;

        // ModExprList end
        if (!expr_ret_284) rew(mod_284);
        expr_ret_283 = expr_ret_284;
      }

      // SlashExpr 1
      if (!expr_ret_283) {
        daisho_astnode_t* expr_ret_288 = NULL;
        rec(mod_288);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_289 = NULL;
        rec(mod_289);
        // ModExprList 0
        expr_ret_289 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_289) {
          daisho_astnode_t* expr_ret_290 = NULL;
          expr_ret_290 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_289 = expr_ret_290;
          s = expr_ret_290;
        }

        // ModExprList 2
        if (expr_ret_289) {
          expr_ret_289 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_289) rew(mod_289);
        expr_ret_288 = expr_ret_289;
        // ModExprList end
        if (!expr_ret_288) rew(mod_288);
        expr_ret_283 = expr_ret_288;
      }

      // SlashExpr end
      expr_ret_280 = expr_ret_283;

    }

    // ModExprList 4
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_291 = NULL;
      expr_ret_291 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_280 = expr_ret_291;
      t = expr_ret_291;
    }

    // ModExprList 5
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_292 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_292 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_292 = NULL;
      }

      // optional
      if (!expr_ret_292)
        expr_ret_292 = SUCC;
      expr_ret_280 = expr_ret_292;
      c = expr_ret_292;
    }

    // ModExprList 6
    if (expr_ret_280) {
      // CodeExpr
      #define ret expr_ret_280
      ret = SUCC;
      #line 196 "daisho.peg"
      if (has(o) != has(c)) WARNING("For expression parens mismatch.");
      #line 7436 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 7
    if (expr_ret_280) {
      daisho_astnode_t* expr_ret_293 = NULL;
      expr_ret_293 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_280 = expr_ret_293;
      e = expr_ret_293;
    }

    // ModExprList 8
    if (expr_ret_280) {
      // CodeExpr
      #define ret expr_ret_280
      ret = SUCC;
      #line 198 "daisho.peg"
      rule = has(s) ? node(FOR, f, boolconv(s), t, e)
                    :          node(FOREACH, f, t, e);
      #line 7458 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_280) rew(mod_280);
    expr_ret_279 = expr_ret_280;
  }

  // SlashExpr 1
  if (!expr_ret_279) {
    daisho_astnode_t* expr_ret_294 = NULL;
    rec(mod_294);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_295 = NULL;
    expr_ret_295 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_294 = expr_ret_295;
    rule = expr_ret_295;
    // ModExprList end
    if (!expr_ret_294) rew(mod_294);
    expr_ret_279 = expr_ret_294;
  }

  // SlashExpr end
  expr_ret_278 = expr_ret_279;

  if (!rule) rule = expr_ret_278;
  if (!expr_ret_278) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule forexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_296
  daisho_astnode_t* expr_ret_296 = NULL;
  daisho_astnode_t* expr_ret_297 = NULL;
  daisho_astnode_t* expr_ret_298 = NULL;

  // SlashExpr 0
  if (!expr_ret_298) {
    daisho_astnode_t* expr_ret_299 = NULL;
    rec(mod_299);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_299 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_299 = NULL;
    }

    // ModExprList 1
    if (expr_ret_299) {
      daisho_astnode_t* expr_ret_300 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_300 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_300 = NULL;
      }

      // optional
      if (!expr_ret_300)
        expr_ret_300 = SUCC;
      expr_ret_299 = expr_ret_300;
      o = expr_ret_300;
    }

    // ModExprList 2
    if (expr_ret_299) {
      daisho_astnode_t* expr_ret_301 = NULL;
      expr_ret_301 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_299 = expr_ret_301;
      n = expr_ret_301;
    }

    // ModExprList 3
    if (expr_ret_299) {
      daisho_astnode_t* expr_ret_302 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_302 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_302 = NULL;
      }

      // optional
      if (!expr_ret_302)
        expr_ret_302 = SUCC;
      expr_ret_299 = expr_ret_302;
      c = expr_ret_302;
    }

    // ModExprList 4
    if (expr_ret_299) {
      // CodeExpr
      #define ret expr_ret_299
      ret = SUCC;
      #line 203 "daisho.peg"
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #line 7568 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_299) {
      daisho_astnode_t* expr_ret_303 = NULL;
      expr_ret_303 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_299 = expr_ret_303;
      e = expr_ret_303;
    }

    // ModExprList 6
    if (expr_ret_299) {
      // CodeExpr
      #define ret expr_ret_299
      ret = SUCC;
      #line 204 "daisho.peg"
      rule=node(WHILE, n, e);
      #line 7589 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_299) rew(mod_299);
    expr_ret_298 = expr_ret_299;
  }

  // SlashExpr 1
  if (!expr_ret_298) {
    daisho_astnode_t* expr_ret_304 = NULL;
    rec(mod_304);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_305 = NULL;
    expr_ret_305 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_304 = expr_ret_305;
    rule = expr_ret_305;
    // ModExprList end
    if (!expr_ret_304) rew(mod_304);
    expr_ret_298 = expr_ret_304;
  }

  // SlashExpr end
  expr_ret_297 = expr_ret_298;

  if (!rule) rule = expr_ret_297;
  if (!expr_ret_297) rule = NULL;
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
  #define rule expr_ret_306
  daisho_astnode_t* expr_ret_306 = NULL;
  daisho_astnode_t* expr_ret_307 = NULL;
  daisho_astnode_t* expr_ret_308 = NULL;

  // SlashExpr 0
  if (!expr_ret_308) {
    daisho_astnode_t* expr_ret_309 = NULL;
    rec(mod_309);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_309 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_309 = NULL;
    }

    // ModExprList 1
    if (expr_ret_309) {
      daisho_astnode_t* expr_ret_310 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_310 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_310 = NULL;
      }

      // optional
      if (!expr_ret_310)
        expr_ret_310 = SUCC;
      expr_ret_309 = expr_ret_310;
      o = expr_ret_310;
    }

    // ModExprList 2
    if (expr_ret_309) {
      daisho_astnode_t* expr_ret_311 = NULL;
      expr_ret_311 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_309 = expr_ret_311;
      n = expr_ret_311;
    }

    // ModExprList 3
    if (expr_ret_309) {
      daisho_astnode_t* expr_ret_312 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_312 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_312 = NULL;
      }

      // optional
      if (!expr_ret_312)
        expr_ret_312 = SUCC;
      expr_ret_309 = expr_ret_312;
      c = expr_ret_312;
    }

    // ModExprList 4
    if (expr_ret_309) {
      // CodeExpr
      #define ret expr_ret_309
      ret = SUCC;
      #line 208 "daisho.peg"
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #line 7700 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_309) {
      daisho_astnode_t* expr_ret_313 = NULL;
      expr_ret_313 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_309 = expr_ret_313;
      e = expr_ret_313;
    }

    // ModExprList 6
    if (expr_ret_309) {
      daisho_astnode_t* expr_ret_314 = NULL;
      daisho_astnode_t* expr_ret_315 = NULL;
      rec(mod_315);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_315 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_315 = NULL;
      }

      // ModExprList 1
      if (expr_ret_315) {
        daisho_astnode_t* expr_ret_316 = NULL;
        expr_ret_316 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_315 = expr_ret_316;
        ee = expr_ret_316;
      }

      // ModExprList end
      if (!expr_ret_315) rew(mod_315);
      expr_ret_314 = expr_ret_315;
      // optional
      if (!expr_ret_314)
        expr_ret_314 = SUCC;
      expr_ret_309 = expr_ret_314;
    }

    // ModExprList 7
    if (expr_ret_309) {
      // CodeExpr
      #define ret expr_ret_309
      ret = SUCC;
      #line 211 "daisho.peg"
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #line 7754 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_309) rew(mod_309);
    expr_ret_308 = expr_ret_309;
  }

  // SlashExpr 1
  if (!expr_ret_308) {
    daisho_astnode_t* expr_ret_317 = NULL;
    rec(mod_317);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_318 = NULL;
    expr_ret_318 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_317 = expr_ret_318;
    rule = expr_ret_318;
    // ModExprList end
    if (!expr_ret_317) rew(mod_317);
    expr_ret_308 = expr_ret_317;
  }

  // SlashExpr end
  expr_ret_307 = expr_ret_308;

  if (!rule) rule = expr_ret_307;
  if (!expr_ret_307) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule preifexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_319
  daisho_astnode_t* expr_ret_319 = NULL;
  daisho_astnode_t* expr_ret_320 = NULL;
  daisho_astnode_t* expr_ret_321 = NULL;
  rec(mod_321);
  // ModExprList 0
  daisho_astnode_t* expr_ret_322 = NULL;
  expr_ret_322 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_321 = expr_ret_322;
  n = expr_ret_322;
  // ModExprList 1
  if (expr_ret_321) {
    daisho_astnode_t* expr_ret_323 = NULL;
    daisho_astnode_t* expr_ret_324 = NULL;
    rec(mod_324);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_324 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_324 = NULL;
    }

    // ModExprList 1
    if (expr_ret_324) {
      daisho_astnode_t* expr_ret_325 = NULL;
      expr_ret_325 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_324 = expr_ret_325;
      qe = expr_ret_325;
    }

    // ModExprList 2
    if (expr_ret_324) {
      daisho_astnode_t* expr_ret_326 = NULL;
      daisho_astnode_t* expr_ret_327 = NULL;
      rec(mod_327);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_327 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_327 = NULL;
      }

      // ModExprList 1
      if (expr_ret_327) {
        daisho_astnode_t* expr_ret_328 = NULL;
        expr_ret_328 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_327 = expr_ret_328;
        ce = expr_ret_328;
      }

      // ModExprList end
      if (!expr_ret_327) rew(mod_327);
      expr_ret_326 = expr_ret_327;
      // optional
      if (!expr_ret_326)
        expr_ret_326 = SUCC;
      expr_ret_324 = expr_ret_326;
    }

    // ModExprList end
    if (!expr_ret_324) rew(mod_324);
    expr_ret_323 = expr_ret_324;
    // optional
    if (!expr_ret_323)
      expr_ret_323 = SUCC;
    expr_ret_321 = expr_ret_323;
  }

  // ModExprList 2
  if (expr_ret_321) {
    // CodeExpr
    #define ret expr_ret_321
    ret = SUCC;
    #line 216 "daisho.peg"
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #line 7877 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_321) rew(mod_321);
  expr_ret_320 = expr_ret_321;
  if (!rule) rule = expr_ret_320;
  if (!expr_ret_320) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ternexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_329
  daisho_astnode_t* expr_ret_329 = NULL;
  daisho_astnode_t* expr_ret_330 = NULL;
  daisho_astnode_t* expr_ret_331 = NULL;
  rec(mod_331);
  // ModExprList 0
  daisho_astnode_t* expr_ret_332 = NULL;
  expr_ret_332 = daisho_parse_alsoexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_335 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_335 = NULL;
      }

      // ModExprList 1
      if (expr_ret_335) {
        daisho_astnode_t* expr_ret_336 = NULL;
        expr_ret_336 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_335 = expr_ret_336;
        nn = expr_ret_336;
      }

      // ModExprList 2
      if (expr_ret_335) {
        // CodeExpr
        #define ret expr_ret_335
        ret = SUCC;
        #line 220 "daisho.peg"
        rule=node(THEN, rule, nn);
        #line 7940 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule thenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_337
  daisho_astnode_t* expr_ret_337 = NULL;
  daisho_astnode_t* expr_ret_338 = NULL;
  daisho_astnode_t* expr_ret_339 = NULL;
  rec(mod_339);
  // ModExprList 0
  daisho_astnode_t* expr_ret_340 = NULL;
  expr_ret_340 = daisho_parse_ceqexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_343 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_343 = NULL;
      }

      // ModExprList 1
      if (expr_ret_343) {
        daisho_astnode_t* expr_ret_344 = NULL;
        expr_ret_344 = daisho_parse_ceqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_343 = expr_ret_344;
        nn = expr_ret_344;
      }

      // ModExprList 2
      if (expr_ret_343) {
        // CodeExpr
        #define ret expr_ret_343
        ret = SUCC;
        #line 222 "daisho.peg"
        rule=node(ALSO, rule, nn);
        #line 8012 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule alsoexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_345
  daisho_astnode_t* expr_ret_345 = NULL;
  daisho_astnode_t* expr_ret_346 = NULL;
  daisho_astnode_t* expr_ret_347 = NULL;
  rec(mod_347);
  // ModExprList 0
  daisho_astnode_t* expr_ret_348 = NULL;
  expr_ret_348 = daisho_parse_logorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_347 = expr_ret_348;
  rule = expr_ret_348;
  // ModExprList 1
  if (expr_ret_347) {
    daisho_astnode_t* expr_ret_349 = NULL;
    daisho_astnode_t* expr_ret_350 = SUCC;
    while (expr_ret_350)
    {
      rec(kleene_rew_349);
      daisho_astnode_t* expr_ret_351 = NULL;
      rec(mod_351);
      // ModExprList 0
      daisho_astnode_t* expr_ret_352 = NULL;
      daisho_astnode_t* expr_ret_353 = NULL;

      // SlashExpr 0
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_354 = NULL;
        rec(mod_354);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_354 = leaf(EQ);
          expr_ret_354->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_354->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_354 = NULL;
        }

        // ModExprList end
        if (!expr_ret_354) rew(mod_354);
        expr_ret_353 = expr_ret_354;
      }

      // SlashExpr 1
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_355 = NULL;
        rec(mod_355);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_355 = leaf(PLEQ);
          expr_ret_355->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_355->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_355 = NULL;
        }

        // ModExprList end
        if (!expr_ret_355) rew(mod_355);
        expr_ret_353 = expr_ret_355;
      }

      // SlashExpr 2
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_356 = NULL;
        rec(mod_356);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_356 = leaf(MINEQ);
          expr_ret_356->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_356->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_356 = NULL;
        }

        // ModExprList end
        if (!expr_ret_356) rew(mod_356);
        expr_ret_353 = expr_ret_356;
      }

      // SlashExpr 3
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_357 = NULL;
        rec(mod_357);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_357 = leaf(MULEQ);
          expr_ret_357->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_357->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_357 = NULL;
        }

        // ModExprList end
        if (!expr_ret_357) rew(mod_357);
        expr_ret_353 = expr_ret_357;
      }

      // SlashExpr 4
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_358 = NULL;
        rec(mod_358);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_358 = leaf(DIVEQ);
          expr_ret_358->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_358->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_358 = NULL;
        }

        // ModExprList end
        if (!expr_ret_358) rew(mod_358);
        expr_ret_353 = expr_ret_358;
      }

      // SlashExpr 5
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_359 = NULL;
        rec(mod_359);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_359 = leaf(MODEQ);
          expr_ret_359->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_359->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_359 = NULL;
        }

        // ModExprList end
        if (!expr_ret_359) rew(mod_359);
        expr_ret_353 = expr_ret_359;
      }

      // SlashExpr 6
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_360 = NULL;
        rec(mod_360);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_360 = leaf(ANDEQ);
          expr_ret_360->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_360->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_360 = NULL;
        }

        // ModExprList end
        if (!expr_ret_360) rew(mod_360);
        expr_ret_353 = expr_ret_360;
      }

      // SlashExpr 7
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_361 = NULL;
        rec(mod_361);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_361 = leaf(OREQ);
          expr_ret_361->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_361->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_361 = NULL;
        }

        // ModExprList end
        if (!expr_ret_361) rew(mod_361);
        expr_ret_353 = expr_ret_361;
      }

      // SlashExpr 8
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_362 = NULL;
        rec(mod_362);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_362 = leaf(XOREQ);
          expr_ret_362->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_362->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_362 = NULL;
        }

        // ModExprList end
        if (!expr_ret_362) rew(mod_362);
        expr_ret_353 = expr_ret_362;
      }

      // SlashExpr 9
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_363 = NULL;
        rec(mod_363);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_363 = leaf(BNEQ);
          expr_ret_363->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_363->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_363 = NULL;
        }

        // ModExprList end
        if (!expr_ret_363) rew(mod_363);
        expr_ret_353 = expr_ret_363;
      }

      // SlashExpr 10
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_364 = NULL;
        rec(mod_364);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_364 = leaf(BSREQ);
          expr_ret_364->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_364->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_364 = NULL;
        }

        // ModExprList end
        if (!expr_ret_364) rew(mod_364);
        expr_ret_353 = expr_ret_364;
      }

      // SlashExpr 11
      if (!expr_ret_353) {
        daisho_astnode_t* expr_ret_365 = NULL;
        rec(mod_365);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_365 = leaf(BSLEQ);
          expr_ret_365->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_365->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_365 = NULL;
        }

        // ModExprList end
        if (!expr_ret_365) rew(mod_365);
        expr_ret_353 = expr_ret_365;
      }

      // SlashExpr end
      expr_ret_352 = expr_ret_353;

      expr_ret_351 = expr_ret_352;
      op = expr_ret_352;
      // ModExprList 1
      if (expr_ret_351) {
        daisho_astnode_t* expr_ret_366 = NULL;
        expr_ret_366 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_351 = expr_ret_366;
        t = expr_ret_366;
      }

      // ModExprList 2
      if (expr_ret_351) {
        // CodeExpr
        #define ret expr_ret_351
        ret = SUCC;
        #line 226 "daisho.peg"
        
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
        #line 8338 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_351) rew(mod_351);
      expr_ret_350 = expr_ret_351;
    }

    expr_ret_349 = SUCC;
    expr_ret_347 = expr_ret_349;
  }

  // ModExprList end
  if (!expr_ret_347) rew(mod_347);
  expr_ret_346 = expr_ret_347;
  if (!rule) rule = expr_ret_346;
  if (!expr_ret_346) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ceqexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* lo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_367
  daisho_astnode_t* expr_ret_367 = NULL;
  daisho_astnode_t* expr_ret_368 = NULL;
  daisho_astnode_t* expr_ret_369 = NULL;
  rec(mod_369);
  // ModExprList 0
  daisho_astnode_t* expr_ret_370 = NULL;
  expr_ret_370 = daisho_parse_logandexpr(ctx);
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
      daisho_astnode_t* expr_ret_374 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Capturing LOGOR.
        expr_ret_374 = leaf(LOGOR);
        expr_ret_374->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_374->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_374 = NULL;
      }

      expr_ret_373 = expr_ret_374;
      lo = expr_ret_374;
      // ModExprList 1
      if (expr_ret_373) {
        daisho_astnode_t* expr_ret_375 = NULL;
        expr_ret_375 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_373 = expr_ret_375;
        n = expr_ret_375;
      }

      // ModExprList 2
      if (expr_ret_373) {
        // CodeExpr
        #define ret expr_ret_373
        ret = SUCC;
        #line 241 "daisho.peg"
        rule=binop(lo, rule, n);
        #line 8416 "daisho.peg.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* la = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_376
  daisho_astnode_t* expr_ret_376 = NULL;
  daisho_astnode_t* expr_ret_377 = NULL;
  daisho_astnode_t* expr_ret_378 = NULL;
  rec(mod_378);
  // ModExprList 0
  daisho_astnode_t* expr_ret_379 = NULL;
  expr_ret_379 = daisho_parse_binorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_378 = expr_ret_379;
  rule = expr_ret_379;
  // ModExprList 1
  if (expr_ret_378) {
    daisho_astnode_t* expr_ret_380 = NULL;
    daisho_astnode_t* expr_ret_381 = SUCC;
    while (expr_ret_381)
    {
      rec(kleene_rew_380);
      daisho_astnode_t* expr_ret_382 = NULL;
      rec(mod_382);
      // ModExprList 0
      daisho_astnode_t* expr_ret_383 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Capturing LOGAND.
        expr_ret_383 = leaf(LOGAND);
        expr_ret_383->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_383->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_383 = NULL;
      }

      expr_ret_382 = expr_ret_383;
      la = expr_ret_383;
      // ModExprList 1
      if (expr_ret_382) {
        daisho_astnode_t* expr_ret_384 = NULL;
        expr_ret_384 = daisho_parse_binorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_382 = expr_ret_384;
        n = expr_ret_384;
      }

      // ModExprList 2
      if (expr_ret_382) {
        // CodeExpr
        #define ret expr_ret_382
        ret = SUCC;
        #line 242 "daisho.peg"
        rule=binop(la, rule, n);
        #line 8494 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_382) rew(mod_382);
      expr_ret_381 = expr_ret_382;
    }

    expr_ret_380 = SUCC;
    expr_ret_378 = expr_ret_380;
  }

  // ModExprList end
  if (!expr_ret_378) rew(mod_378);
  expr_ret_377 = expr_ret_378;
  if (!rule) rule = expr_ret_377;
  if (!expr_ret_377) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* ro = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_385
  daisho_astnode_t* expr_ret_385 = NULL;
  daisho_astnode_t* expr_ret_386 = NULL;
  daisho_astnode_t* expr_ret_387 = NULL;
  rec(mod_387);
  // ModExprList 0
  daisho_astnode_t* expr_ret_388 = NULL;
  expr_ret_388 = daisho_parse_binxorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_387 = expr_ret_388;
  rule = expr_ret_388;
  // ModExprList 1
  if (expr_ret_387) {
    daisho_astnode_t* expr_ret_389 = NULL;
    daisho_astnode_t* expr_ret_390 = SUCC;
    while (expr_ret_390)
    {
      rec(kleene_rew_389);
      daisho_astnode_t* expr_ret_391 = NULL;
      rec(mod_391);
      // ModExprList 0
      daisho_astnode_t* expr_ret_392 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Capturing OR.
        expr_ret_392 = leaf(OR);
        expr_ret_392->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_392->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_392 = NULL;
      }

      expr_ret_391 = expr_ret_392;
      ro = expr_ret_392;
      // ModExprList 1
      if (expr_ret_391) {
        daisho_astnode_t* expr_ret_393 = NULL;
        expr_ret_393 = daisho_parse_binxorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_391 = expr_ret_393;
        n = expr_ret_393;
      }

      // ModExprList 2
      if (expr_ret_391) {
        // CodeExpr
        #define ret expr_ret_391
        ret = SUCC;
        #line 243 "daisho.peg"
        rule=binop(ro, rule, n);
        #line 8572 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_391) rew(mod_391);
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* xo = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_394
  daisho_astnode_t* expr_ret_394 = NULL;
  daisho_astnode_t* expr_ret_395 = NULL;
  daisho_astnode_t* expr_ret_396 = NULL;
  rec(mod_396);
  // ModExprList 0
  daisho_astnode_t* expr_ret_397 = NULL;
  expr_ret_397 = daisho_parse_binandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_396 = expr_ret_397;
  rule = expr_ret_397;
  // ModExprList 1
  if (expr_ret_396) {
    daisho_astnode_t* expr_ret_398 = NULL;
    daisho_astnode_t* expr_ret_399 = SUCC;
    while (expr_ret_399)
    {
      rec(kleene_rew_398);
      daisho_astnode_t* expr_ret_400 = NULL;
      rec(mod_400);
      // ModExprList 0
      daisho_astnode_t* expr_ret_401 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Capturing XOR.
        expr_ret_401 = leaf(XOR);
        expr_ret_401->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_401->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_401 = NULL;
      }

      expr_ret_400 = expr_ret_401;
      xo = expr_ret_401;
      // ModExprList 1
      if (expr_ret_400) {
        daisho_astnode_t* expr_ret_402 = NULL;
        expr_ret_402 = daisho_parse_binandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_400 = expr_ret_402;
        n = expr_ret_402;
      }

      // ModExprList 2
      if (expr_ret_400) {
        // CodeExpr
        #define ret expr_ret_400
        ret = SUCC;
        #line 244 "daisho.peg"
        rule=binop(xo, rule, n);
        #line 8650 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_400) rew(mod_400);
      expr_ret_399 = expr_ret_400;
    }

    expr_ret_398 = SUCC;
    expr_ret_396 = expr_ret_398;
  }

  // ModExprList end
  if (!expr_ret_396) rew(mod_396);
  expr_ret_395 = expr_ret_396;
  if (!rule) rule = expr_ret_395;
  if (!expr_ret_395) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binxorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* an = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_403
  daisho_astnode_t* expr_ret_403 = NULL;
  daisho_astnode_t* expr_ret_404 = NULL;
  daisho_astnode_t* expr_ret_405 = NULL;
  rec(mod_405);
  // ModExprList 0
  daisho_astnode_t* expr_ret_406 = NULL;
  expr_ret_406 = daisho_parse_deneqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_405 = expr_ret_406;
  rule = expr_ret_406;
  // ModExprList 1
  if (expr_ret_405) {
    daisho_astnode_t* expr_ret_407 = NULL;
    daisho_astnode_t* expr_ret_408 = SUCC;
    while (expr_ret_408)
    {
      rec(kleene_rew_407);
      daisho_astnode_t* expr_ret_409 = NULL;
      rec(mod_409);
      // ModExprList 0
      daisho_astnode_t* expr_ret_410 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Capturing AND.
        expr_ret_410 = leaf(AND);
        expr_ret_410->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_410->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_410 = NULL;
      }

      expr_ret_409 = expr_ret_410;
      an = expr_ret_410;
      // ModExprList 1
      if (expr_ret_409) {
        daisho_astnode_t* expr_ret_411 = NULL;
        expr_ret_411 = daisho_parse_deneqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_409 = expr_ret_411;
        n = expr_ret_411;
      }

      // ModExprList 2
      if (expr_ret_409) {
        // CodeExpr
        #define ret expr_ret_409
        ret = SUCC;
        #line 245 "daisho.peg"
        rule=binop(an, rule, n);
        #line 8728 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_409) rew(mod_409);
      expr_ret_408 = expr_ret_409;
    }

    expr_ret_407 = SUCC;
    expr_ret_405 = expr_ret_407;
  }

  // ModExprList end
  if (!expr_ret_405) rew(mod_405);
  expr_ret_404 = expr_ret_405;
  if (!rule) rule = expr_ret_404;
  if (!expr_ret_404) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* x = NULL;
  #define rule expr_ret_412
  daisho_astnode_t* expr_ret_412 = NULL;
  daisho_astnode_t* expr_ret_413 = NULL;
  daisho_astnode_t* expr_ret_414 = NULL;
  rec(mod_414);
  // ModExprList 0
  daisho_astnode_t* expr_ret_415 = NULL;
  expr_ret_415 = daisho_parse_cmpexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_414 = expr_ret_415;
  rule = expr_ret_415;
  // ModExprList 1
  if (expr_ret_414) {
    daisho_astnode_t* expr_ret_416 = NULL;
    daisho_astnode_t* expr_ret_417 = SUCC;
    while (expr_ret_417)
    {
      rec(kleene_rew_416);
      daisho_astnode_t* expr_ret_418 = NULL;

      // SlashExpr 0
      if (!expr_ret_418) {
        daisho_astnode_t* expr_ret_419 = NULL;
        rec(mod_419);
        // ModExprList 0
        daisho_astnode_t* expr_ret_420 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Capturing DEQ.
          expr_ret_420 = leaf(DEQ);
          expr_ret_420->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_420->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_420 = NULL;
        }

        expr_ret_419 = expr_ret_420;
        e = expr_ret_420;
        // ModExprList 1
        if (expr_ret_419) {
          daisho_astnode_t* expr_ret_421 = NULL;
          expr_ret_421 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_419 = expr_ret_421;
          n = expr_ret_421;
        }

        // ModExprList 2
        if (expr_ret_419) {
          // CodeExpr
          #define ret expr_ret_419
          ret = SUCC;
          #line 248 "daisho.peg"
          rule=binop(e, rule, n);
          #line 8811 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_419) rew(mod_419);
        expr_ret_418 = expr_ret_419;
      }

      // SlashExpr 1
      if (!expr_ret_418) {
        daisho_astnode_t* expr_ret_422 = NULL;
        rec(mod_422);
        // ModExprList 0
        daisho_astnode_t* expr_ret_423 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Capturing NEQ.
          expr_ret_423 = leaf(NEQ);
          expr_ret_423->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_423->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_423 = NULL;
        }

        expr_ret_422 = expr_ret_423;
        x = expr_ret_423;
        // ModExprList 1
        if (expr_ret_422) {
          daisho_astnode_t* expr_ret_424 = NULL;
          expr_ret_424 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_422 = expr_ret_424;
          n = expr_ret_424;
        }

        // ModExprList 2
        if (expr_ret_422) {
          // CodeExpr
          #define ret expr_ret_422
          ret = SUCC;
          #line 249 "daisho.peg"
          rule=binop(x, rule, n);
          #line 8855 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_422) rew(mod_422);
        expr_ret_418 = expr_ret_422;
      }

      // SlashExpr end
      expr_ret_417 = expr_ret_418;

    }

    expr_ret_416 = SUCC;
    expr_ret_414 = expr_ret_416;
  }

  // ModExprList end
  if (!expr_ret_414) rew(mod_414);
  expr_ret_413 = expr_ret_414;
  if (!rule) rule = expr_ret_413;
  if (!expr_ret_413) rule = NULL;
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
  #define rule expr_ret_425
  daisho_astnode_t* expr_ret_425 = NULL;
  daisho_astnode_t* expr_ret_426 = NULL;
  daisho_astnode_t* expr_ret_427 = NULL;
  rec(mod_427);
  // ModExprList 0
  daisho_astnode_t* expr_ret_428 = NULL;
  expr_ret_428 = daisho_parse_shfexpr(ctx);
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
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_433 = leaf(LT);
          expr_ret_433->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_433->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_433 = NULL;
        }

        expr_ret_432 = expr_ret_433;
        l = expr_ret_433;
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
          #line 252 "daisho.peg"
          rule=binop(l,  rule, n);
          #line 8945 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_432) rew(mod_432);
        expr_ret_431 = expr_ret_432;
      }

      // SlashExpr 1
      if (!expr_ret_431) {
        daisho_astnode_t* expr_ret_435 = NULL;
        rec(mod_435);
        // ModExprList 0
        daisho_astnode_t* expr_ret_436 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_436 = leaf(GT);
          expr_ret_436->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_436->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_436 = NULL;
        }

        expr_ret_435 = expr_ret_436;
        g = expr_ret_436;
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
          #line 253 "daisho.peg"
          rule=binop(g,  rule, n);
          #line 8989 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_435) rew(mod_435);
        expr_ret_431 = expr_ret_435;
      }

      // SlashExpr 2
      if (!expr_ret_431) {
        daisho_astnode_t* expr_ret_438 = NULL;
        rec(mod_438);
        // ModExprList 0
        daisho_astnode_t* expr_ret_439 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Capturing LEQ.
          expr_ret_439 = leaf(LEQ);
          expr_ret_439->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_439->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_439 = NULL;
        }

        expr_ret_438 = expr_ret_439;
        le = expr_ret_439;
        // ModExprList 1
        if (expr_ret_438) {
          daisho_astnode_t* expr_ret_440 = NULL;
          expr_ret_440 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_438 = expr_ret_440;
          n = expr_ret_440;
        }

        // ModExprList 2
        if (expr_ret_438) {
          // CodeExpr
          #define ret expr_ret_438
          ret = SUCC;
          #line 254 "daisho.peg"
          rule=binop(le, rule, n);
          #line 9033 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_438) rew(mod_438);
        expr_ret_431 = expr_ret_438;
      }

      // SlashExpr 3
      if (!expr_ret_431) {
        daisho_astnode_t* expr_ret_441 = NULL;
        rec(mod_441);
        // ModExprList 0
        daisho_astnode_t* expr_ret_442 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Capturing GEQ.
          expr_ret_442 = leaf(GEQ);
          expr_ret_442->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_442->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_442 = NULL;
        }

        expr_ret_441 = expr_ret_442;
        ge = expr_ret_442;
        // ModExprList 1
        if (expr_ret_441) {
          daisho_astnode_t* expr_ret_443 = NULL;
          expr_ret_443 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_441 = expr_ret_443;
          n = expr_ret_443;
        }

        // ModExprList 2
        if (expr_ret_441) {
          // CodeExpr
          #define ret expr_ret_441
          ret = SUCC;
          #line 255 "daisho.peg"
          rule=binop(ge, rule, n);
          #line 9077 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_441) rew(mod_441);
        expr_ret_431 = expr_ret_441;
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cmpexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_444
  daisho_astnode_t* expr_ret_444 = NULL;
  daisho_astnode_t* expr_ret_445 = NULL;
  daisho_astnode_t* expr_ret_446 = NULL;
  rec(mod_446);
  // ModExprList 0
  daisho_astnode_t* expr_ret_447 = NULL;
  expr_ret_447 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_446 = expr_ret_447;
  rule = expr_ret_447;
  // ModExprList 1
  if (expr_ret_446) {
    daisho_astnode_t* expr_ret_448 = NULL;
    daisho_astnode_t* expr_ret_449 = SUCC;
    while (expr_ret_449)
    {
      rec(kleene_rew_448);
      daisho_astnode_t* expr_ret_450 = NULL;

      // SlashExpr 0
      if (!expr_ret_450) {
        daisho_astnode_t* expr_ret_451 = NULL;
        rec(mod_451);
        // ModExprList 0
        daisho_astnode_t* expr_ret_452 = NULL;
        expr_ret_452 = daisho_parse_bsl(ctx);
        if (ctx->exit) return NULL;
        expr_ret_451 = expr_ret_452;
        l = expr_ret_452;
        // ModExprList 1
        if (expr_ret_451) {
          daisho_astnode_t* expr_ret_453 = NULL;
          expr_ret_453 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_451 = expr_ret_453;
          n = expr_ret_453;
        }

        // ModExprList 2
        if (expr_ret_451) {
          // CodeExpr
          #define ret expr_ret_451
          ret = SUCC;
          #line 258 "daisho.peg"
          rule=binop(l, rule, n);
          #line 9157 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_451) rew(mod_451);
        expr_ret_450 = expr_ret_451;
      }

      // SlashExpr 1
      if (!expr_ret_450) {
        daisho_astnode_t* expr_ret_454 = NULL;
        rec(mod_454);
        // ModExprList 0
        daisho_astnode_t* expr_ret_455 = NULL;
        expr_ret_455 = daisho_parse_bsr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_454 = expr_ret_455;
        r = expr_ret_455;
        // ModExprList 1
        if (expr_ret_454) {
          daisho_astnode_t* expr_ret_456 = NULL;
          expr_ret_456 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_454 = expr_ret_456;
          n = expr_ret_456;
        }

        // ModExprList 2
        if (expr_ret_454) {
          // CodeExpr
          #define ret expr_ret_454
          ret = SUCC;
          #line 259 "daisho.peg"
          rule=binop(r, rule, n);
          #line 9193 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_454) rew(mod_454);
        expr_ret_450 = expr_ret_454;
      }

      // SlashExpr end
      expr_ret_449 = expr_ret_450;

    }

    expr_ret_448 = SUCC;
    expr_ret_446 = expr_ret_448;
  }

  // ModExprList end
  if (!expr_ret_446) rew(mod_446);
  expr_ret_445 = expr_ret_446;
  if (!rule) rule = expr_ret_445;
  if (!expr_ret_445) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule shfexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_457
  daisho_astnode_t* expr_ret_457 = NULL;
  daisho_astnode_t* expr_ret_458 = NULL;
  daisho_astnode_t* expr_ret_459 = NULL;
  rec(mod_459);
  // ModExprList 0
  daisho_astnode_t* expr_ret_460 = NULL;
  expr_ret_460 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_459 = expr_ret_460;
  rule = expr_ret_460;
  // ModExprList 1
  if (expr_ret_459) {
    daisho_astnode_t* expr_ret_461 = NULL;
    daisho_astnode_t* expr_ret_462 = SUCC;
    while (expr_ret_462)
    {
      rec(kleene_rew_461);
      daisho_astnode_t* expr_ret_463 = NULL;

      // SlashExpr 0
      if (!expr_ret_463) {
        daisho_astnode_t* expr_ret_464 = NULL;
        rec(mod_464);
        // ModExprList 0
        daisho_astnode_t* expr_ret_465 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_465 = leaf(PLUS);
          expr_ret_465->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_465->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_465 = NULL;
        }

        expr_ret_464 = expr_ret_465;
        p = expr_ret_465;
        // ModExprList 1
        if (expr_ret_464) {
          daisho_astnode_t* expr_ret_466 = NULL;
          expr_ret_466 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_464 = expr_ret_466;
          n = expr_ret_466;
        }

        // ModExprList 2
        if (expr_ret_464) {
          // CodeExpr
          #define ret expr_ret_464
          ret = SUCC;
          #line 262 "daisho.peg"
          rule=binop(p, rule, n);
          #line 9281 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_464) rew(mod_464);
        expr_ret_463 = expr_ret_464;
      }

      // SlashExpr 1
      if (!expr_ret_463) {
        daisho_astnode_t* expr_ret_467 = NULL;
        rec(mod_467);
        // ModExprList 0
        daisho_astnode_t* expr_ret_468 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_468 = leaf(MINUS);
          expr_ret_468->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_468->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_468 = NULL;
        }

        expr_ret_467 = expr_ret_468;
        m = expr_ret_468;
        // ModExprList 1
        if (expr_ret_467) {
          daisho_astnode_t* expr_ret_469 = NULL;
          expr_ret_469 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_467 = expr_ret_469;
          n = expr_ret_469;
        }

        // ModExprList 2
        if (expr_ret_467) {
          // CodeExpr
          #define ret expr_ret_467
          ret = SUCC;
          #line 263 "daisho.peg"
          rule=binop(m, rule, n);
          #line 9325 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_467) rew(mod_467);
        expr_ret_463 = expr_ret_467;
      }

      // SlashExpr end
      expr_ret_462 = expr_ret_463;

    }

    expr_ret_461 = SUCC;
    expr_ret_459 = expr_ret_461;
  }

  // ModExprList end
  if (!expr_ret_459) rew(mod_459);
  expr_ret_458 = expr_ret_459;
  if (!rule) rule = expr_ret_458;
  if (!expr_ret_458) rule = NULL;
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
  #define rule expr_ret_470
  daisho_astnode_t* expr_ret_470 = NULL;
  daisho_astnode_t* expr_ret_471 = NULL;
  daisho_astnode_t* expr_ret_472 = NULL;
  rec(mod_472);
  // ModExprList 0
  daisho_astnode_t* expr_ret_473 = NULL;
  expr_ret_473 = daisho_parse_accexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_472 = expr_ret_473;
  rule = expr_ret_473;
  // ModExprList 1
  if (expr_ret_472) {
    daisho_astnode_t* expr_ret_474 = NULL;
    daisho_astnode_t* expr_ret_475 = SUCC;
    while (expr_ret_475)
    {
      rec(kleene_rew_474);
      daisho_astnode_t* expr_ret_476 = NULL;

      // SlashExpr 0
      if (!expr_ret_476) {
        daisho_astnode_t* expr_ret_477 = NULL;
        rec(mod_477);
        // ModExprList 0
        daisho_astnode_t* expr_ret_478 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Capturing STAR.
          expr_ret_478 = leaf(STAR);
          expr_ret_478->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_478->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_478 = NULL;
        }

        expr_ret_477 = expr_ret_478;
        s = expr_ret_478;
        // ModExprList 1
        if (expr_ret_477) {
          daisho_astnode_t* expr_ret_479 = NULL;
          expr_ret_479 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_477 = expr_ret_479;
          n = expr_ret_479;
        }

        // ModExprList 2
        if (expr_ret_477) {
          // CodeExpr
          #define ret expr_ret_477
          ret = SUCC;
          #line 266 "daisho.peg"
          rule=binop(s, rule, n);
          #line 9415 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_477) rew(mod_477);
        expr_ret_476 = expr_ret_477;
      }

      // SlashExpr 1
      if (!expr_ret_476) {
        daisho_astnode_t* expr_ret_480 = NULL;
        rec(mod_480);
        // ModExprList 0
        daisho_astnode_t* expr_ret_481 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Capturing DIV.
          expr_ret_481 = leaf(DIV);
          expr_ret_481->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_481->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_481 = NULL;
        }

        expr_ret_480 = expr_ret_481;
        d = expr_ret_481;
        // ModExprList 1
        if (expr_ret_480) {
          daisho_astnode_t* expr_ret_482 = NULL;
          expr_ret_482 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_480 = expr_ret_482;
          n = expr_ret_482;
        }

        // ModExprList 2
        if (expr_ret_480) {
          // CodeExpr
          #define ret expr_ret_480
          ret = SUCC;
          #line 267 "daisho.peg"
          rule=binop(d, rule, n);
          #line 9459 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_480) rew(mod_480);
        expr_ret_476 = expr_ret_480;
      }

      // SlashExpr 2
      if (!expr_ret_476) {
        daisho_astnode_t* expr_ret_483 = NULL;
        rec(mod_483);
        // ModExprList 0
        daisho_astnode_t* expr_ret_484 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Capturing MOD.
          expr_ret_484 = leaf(MOD);
          expr_ret_484->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_484->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_484 = NULL;
        }

        expr_ret_483 = expr_ret_484;
        m = expr_ret_484;
        // ModExprList 1
        if (expr_ret_483) {
          daisho_astnode_t* expr_ret_485 = NULL;
          expr_ret_485 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_483 = expr_ret_485;
          n = expr_ret_485;
        }

        // ModExprList 2
        if (expr_ret_483) {
          // CodeExpr
          #define ret expr_ret_483
          ret = SUCC;
          #line 268 "daisho.peg"
          rule=binop(m, rule, n);
          #line 9503 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_483) rew(mod_483);
        expr_ret_476 = expr_ret_483;
      }

      // SlashExpr 3
      if (!expr_ret_476) {
        daisho_astnode_t* expr_ret_486 = NULL;
        rec(mod_486);
        // ModExprList 0
        daisho_astnode_t* expr_ret_487 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Capturing POW.
          expr_ret_487 = leaf(POW);
          expr_ret_487->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_487->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_487 = NULL;
        }

        expr_ret_486 = expr_ret_487;
        p = expr_ret_487;
        // ModExprList 1
        if (expr_ret_486) {
          daisho_astnode_t* expr_ret_488 = NULL;
          expr_ret_488 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_486 = expr_ret_488;
          n = expr_ret_488;
        }

        // ModExprList 2
        if (expr_ret_486) {
          // CodeExpr
          #define ret expr_ret_486
          ret = SUCC;
          #line 269 "daisho.peg"
          rule=binop(p, rule, n);
          #line 9547 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_486) rew(mod_486);
        expr_ret_476 = expr_ret_486;
      }

      // SlashExpr end
      expr_ret_475 = expr_ret_476;

    }

    expr_ret_474 = SUCC;
    expr_ret_472 = expr_ret_474;
  }

  // ModExprList end
  if (!expr_ret_472) rew(mod_472);
  expr_ret_471 = expr_ret_472;
  if (!rule) rule = expr_ret_471;
  if (!expr_ret_471) rule = NULL;
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
  #define rule expr_ret_489
  daisho_astnode_t* expr_ret_489 = NULL;
  daisho_astnode_t* expr_ret_490 = NULL;
  daisho_astnode_t* expr_ret_491 = NULL;
  rec(mod_491);
  // ModExprList 0
  daisho_astnode_t* expr_ret_492 = NULL;
  expr_ret_492 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_491 = expr_ret_492;
  rule = expr_ret_492;
  // ModExprList 1
  if (expr_ret_491) {
    daisho_astnode_t* expr_ret_493 = NULL;
    daisho_astnode_t* expr_ret_494 = SUCC;
    while (expr_ret_494)
    {
      rec(kleene_rew_493);
      daisho_astnode_t* expr_ret_495 = NULL;
      rec(mod_495);
      // ModExprList 0
      daisho_astnode_t* expr_ret_496 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Capturing LSBRACK.
        expr_ret_496 = leaf(LSBRACK);
        expr_ret_496->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_496->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_496 = NULL;
      }

      expr_ret_495 = expr_ret_496;
      l = expr_ret_496;
      // ModExprList 1
      if (expr_ret_495) {
        daisho_astnode_t* expr_ret_497 = NULL;
        expr_ret_497 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_495 = expr_ret_497;
        e = expr_ret_497;
      }

      // ModExprList 2
      if (expr_ret_495) {
        daisho_astnode_t* expr_ret_498 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Capturing RSBRACK.
          expr_ret_498 = leaf(RSBRACK);
          expr_ret_498->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_498->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_498 = NULL;
        }

        expr_ret_495 = expr_ret_498;
        r = expr_ret_498;
      }

      // ModExprList 3
      if (expr_ret_495) {
        daisho_astnode_t* expr_ret_499 = NULL;
        // CodeExpr
        #define ret expr_ret_499
        ret = SUCC;
        #line 272 "daisho.peg"
        ret=node(ARRAYACCESS, l, r);
        #line 9650 "daisho.peg.h"

        #undef ret
        expr_ret_495 = expr_ret_499;
        a = expr_ret_499;
      }

      // ModExprList 4
      if (expr_ret_495) {
        // CodeExpr
        #define ret expr_ret_495
        ret = SUCC;
        #line 273 "daisho.peg"
        rule=binop(a, rule, e);
        #line 9664 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_495) rew(mod_495);
      expr_ret_494 = expr_ret_495;
    }

    expr_ret_493 = SUCC;
    expr_ret_491 = expr_ret_493;
  }

  // ModExprList end
  if (!expr_ret_491) rew(mod_491);
  expr_ret_490 = expr_ret_491;
  if (!rule) rule = expr_ret_490;
  if (!expr_ret_490) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule accexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_500
  daisho_astnode_t* expr_ret_500 = NULL;
  daisho_astnode_t* expr_ret_501 = NULL;
  daisho_astnode_t* expr_ret_502 = NULL;
  rec(mod_502);
  // ModExprList 0
  daisho_astnode_t* expr_ret_503 = NULL;
  expr_ret_503 = daisho_parse_refexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_502 = expr_ret_503;
  rule = expr_ret_503;
  // ModExprList 1
  if (expr_ret_502) {
    daisho_astnode_t* expr_ret_504 = NULL;
    daisho_astnode_t* expr_ret_505 = SUCC;
    while (expr_ret_505)
    {
      rec(kleene_rew_504);
      daisho_astnode_t* expr_ret_506 = NULL;
      rec(mod_506);
      // ModExprList 0
      daisho_astnode_t* expr_ret_507 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Capturing DOT.
        expr_ret_507 = leaf(DOT);
        expr_ret_507->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_507->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_507 = NULL;
      }

      expr_ret_506 = expr_ret_507;
      d = expr_ret_507;
      // ModExprList 1
      if (expr_ret_506) {
        daisho_astnode_t* expr_ret_508 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_508 = leaf(VARIDENT);
          expr_ret_508->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_508->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_508 = NULL;
        }

        expr_ret_506 = expr_ret_508;
        i = expr_ret_508;
      }

      // ModExprList 2
      if (expr_ret_506) {
        // CodeExpr
        #define ret expr_ret_506
        ret = SUCC;
        #line 275 "daisho.peg"
        rule=binop(d, rule, i);
        #line 9750 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_506) rew(mod_506);
      expr_ret_505 = expr_ret_506;
    }

    expr_ret_504 = SUCC;
    expr_ret_502 = expr_ret_504;
  }

  // ModExprList end
  if (!expr_ret_502) rew(mod_502);
  expr_ret_501 = expr_ret_502;
  if (!rule) rule = expr_ret_501;
  if (!expr_ret_501) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule dotexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  #define rule expr_ret_509
  daisho_astnode_t* expr_ret_509 = NULL;
  daisho_astnode_t* expr_ret_510 = NULL;
  daisho_astnode_t* expr_ret_511 = NULL;
  rec(mod_511);
  // ModExprList 0
  daisho_astnode_t* expr_ret_512 = NULL;
  expr_ret_512 = daisho_parse_castexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_511 = expr_ret_512;
  rule = expr_ret_512;
  // ModExprList 1
  if (expr_ret_511) {
    daisho_astnode_t* expr_ret_513 = NULL;
    // CodeExpr
    #define ret expr_ret_513
    ret = SUCC;
    #line 280 "daisho.peg"
    ;
    #line 9798 "daisho.peg.h"

    #undef ret
    expr_ret_511 = expr_ret_513;
    op = expr_ret_513;
  }

  // ModExprList 2
  if (expr_ret_511) {
    daisho_astnode_t* expr_ret_514 = NULL;
    daisho_astnode_t* expr_ret_515 = SUCC;
    while (expr_ret_515)
    {
      rec(kleene_rew_514);
      daisho_astnode_t* expr_ret_516 = NULL;

      // SlashExpr 0
      if (!expr_ret_516) {
        daisho_astnode_t* expr_ret_517 = NULL;
        rec(mod_517);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_517 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_517 = NULL;
        }

        // ModExprList 1
        if (expr_ret_517) {
          // CodeExpr
          #define ret expr_ret_517
          ret = SUCC;
          #line 280 "daisho.peg"
          rd++;
          #line 9834 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_517) rew(mod_517);
        expr_ret_516 = expr_ret_517;
      }

      // SlashExpr 1
      if (!expr_ret_516) {
        daisho_astnode_t* expr_ret_518 = NULL;
        rec(mod_518);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_518 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_518 = NULL;
        }

        // ModExprList 1
        if (expr_ret_518) {
          // CodeExpr
          #define ret expr_ret_518
          ret = SUCC;
          #line 280 "daisho.peg"
          rd--;
          #line 9864 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_518) rew(mod_518);
        expr_ret_516 = expr_ret_518;
      }

      // SlashExpr end
      expr_ret_515 = expr_ret_516;

    }

    expr_ret_514 = SUCC;
    expr_ret_511 = expr_ret_514;
  }

  // ModExprList 3
  if (expr_ret_511) {
    // CodeExpr
    #define ret expr_ret_511
    ret = SUCC;
    #line 281 "daisho.peg"
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                op = rd > 0 ? leaf(REF) : leaf(DEREF);
                rule = unop(op, rule);
              };
    #line 9893 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_511) rew(mod_511);
  expr_ret_510 = expr_ret_511;
  if (!rule) rule = expr_ret_510;
  if (!expr_ret_510) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule refexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_519
  daisho_astnode_t* expr_ret_519 = NULL;
  daisho_astnode_t* expr_ret_520 = NULL;
  daisho_astnode_t* expr_ret_521 = NULL;
  rec(mod_521);
  // ModExprList 0
  daisho_astnode_t* expr_ret_522 = NULL;
  expr_ret_522 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_521 = expr_ret_522;
  rule = expr_ret_522;
  // ModExprList 1
  if (expr_ret_521) {
    daisho_astnode_t* expr_ret_523 = NULL;
    daisho_astnode_t* expr_ret_524 = SUCC;
    while (expr_ret_524)
    {
      rec(kleene_rew_523);
      daisho_astnode_t* expr_ret_525 = NULL;
      rec(mod_525);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_525 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_525 = NULL;
      }

      // ModExprList 1
      if (expr_ret_525) {
        daisho_astnode_t* expr_ret_526 = NULL;
        expr_ret_526 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_525 = expr_ret_526;
        t = expr_ret_526;
      }

      // ModExprList 2
      if (expr_ret_525) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_525 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_525 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_525) {
        // CodeExpr
        #define ret expr_ret_525
        ret = SUCC;
        #line 287 "daisho.peg"
        rule=node(CAST, rule, t);
        #line 9968 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_525) rew(mod_525);
      expr_ret_524 = expr_ret_525;
    }

    expr_ret_523 = SUCC;
    expr_ret_521 = expr_ret_523;
  }

  // ModExprList end
  if (!expr_ret_521) rew(mod_521);
  expr_ret_520 = expr_ret_521;
  if (!rule) rule = expr_ret_520;
  if (!expr_ret_520) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule castexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* te = NULL;
  daisho_astnode_t* el = NULL;
  #define rule expr_ret_527
  daisho_astnode_t* expr_ret_527 = NULL;
  daisho_astnode_t* expr_ret_528 = NULL;
  daisho_astnode_t* expr_ret_529 = NULL;
  rec(mod_529);
  // ModExprList 0
  daisho_astnode_t* expr_ret_530 = NULL;
  expr_ret_530 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_529 = expr_ret_530;
  rule = expr_ret_530;
  // ModExprList 1
  if (expr_ret_529) {
    daisho_astnode_t* expr_ret_531 = NULL;
    daisho_astnode_t* expr_ret_532 = NULL;
    rec(mod_532);
    // ModExprList 0
    // CodeExpr
    #define ret expr_ret_532
    ret = SUCC;
    #line 290 "daisho.peg"
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #line 10018 "daisho.peg.h"

    #undef ret
    // ModExprList 1
    if (expr_ret_532) {
      daisho_astnode_t* expr_ret_533 = NULL;
      expr_ret_533 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_532 = expr_ret_533;
      te = expr_ret_533;
    }

    // ModExprList end
    if (!expr_ret_532) rew(mod_532);
    expr_ret_531 = expr_ret_532;
    // optional
    if (!expr_ret_531)
      expr_ret_531 = SUCC;
    expr_ret_529 = expr_ret_531;
  }

  // ModExprList 2
  if (expr_ret_529) {
    daisho_astnode_t* expr_ret_534 = NULL;
    daisho_astnode_t* expr_ret_535 = SUCC;
    while (expr_ret_535)
    {
      rec(kleene_rew_534);
      daisho_astnode_t* expr_ret_536 = NULL;
      rec(mod_536);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_536 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_536 = NULL;
      }

      // ModExprList 1
      if (expr_ret_536) {
        daisho_astnode_t* expr_ret_537 = NULL;
        expr_ret_537 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_536 = expr_ret_537;
        el = expr_ret_537;
      }

      // ModExprList 2
      if (expr_ret_536) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_536 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_536 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_536) {
        // CodeExpr
        #define ret expr_ret_536
        ret = SUCC;
        #line 292 "daisho.peg"
        rule = node(CALL, rule, te, el); te=NULL;
        #line 10085 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_536) rew(mod_536);
      expr_ret_535 = expr_ret_536;
    }

    expr_ret_534 = SUCC;
    expr_ret_529 = expr_ret_534;
  }

  // ModExprList end
  if (!expr_ret_529) rew(mod_529);
  expr_ret_528 = expr_ret_529;
  if (!rule) rule = expr_ret_528;
  if (!expr_ret_528) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule callexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_538
  daisho_astnode_t* expr_ret_538 = NULL;
  daisho_astnode_t* expr_ret_539 = NULL;
  daisho_astnode_t* expr_ret_540 = NULL;
  rec(mod_540);
  // ModExprList 0
  daisho_astnode_t* expr_ret_541 = NULL;
  expr_ret_541 = daisho_parse_notexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_540 = expr_ret_541;
  rule = expr_ret_541;
  // ModExprList 1
  if (expr_ret_540) {
    daisho_astnode_t* expr_ret_542 = NULL;
    daisho_astnode_t* expr_ret_543 = NULL;

    // SlashExpr 0
    if (!expr_ret_543) {
      daisho_astnode_t* expr_ret_544 = NULL;
      rec(mod_544);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_545 = NULL;
      rec(mod_545);
      // ModExprList 0
      daisho_astnode_t* expr_ret_546 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Capturing INCR.
        expr_ret_546 = leaf(INCR);
        expr_ret_546->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_546->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_546 = NULL;
      }

      expr_ret_545 = expr_ret_546;
      i = expr_ret_546;
      // ModExprList 1
      if (expr_ret_545) {
        // CodeExpr
        #define ret expr_ret_545
        ret = SUCC;
        #line 294 "daisho.peg"
        rule=unop(i, rule);
        #line 10157 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_545) rew(mod_545);
      expr_ret_544 = expr_ret_545;
      // ModExprList end
      if (!expr_ret_544) rew(mod_544);
      expr_ret_543 = expr_ret_544;
    }

    // SlashExpr 1
    if (!expr_ret_543) {
      daisho_astnode_t* expr_ret_547 = NULL;
      rec(mod_547);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_548 = NULL;
      rec(mod_548);
      // ModExprList 0
      daisho_astnode_t* expr_ret_549 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Capturing DECR.
        expr_ret_549 = leaf(DECR);
        expr_ret_549->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_549->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_549 = NULL;
      }

      expr_ret_548 = expr_ret_549;
      d = expr_ret_549;
      // ModExprList 1
      if (expr_ret_548) {
        // CodeExpr
        #define ret expr_ret_548
        ret = SUCC;
        #line 295 "daisho.peg"
        rule=unop(d, rule);
        #line 10198 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_548) rew(mod_548);
      expr_ret_547 = expr_ret_548;
      // ModExprList end
      if (!expr_ret_547) rew(mod_547);
      expr_ret_543 = expr_ret_547;
    }

    // SlashExpr end
    expr_ret_542 = expr_ret_543;

    // optional
    if (!expr_ret_542)
      expr_ret_542 = SUCC;
    expr_ret_540 = expr_ret_542;
  }

  // ModExprList end
  if (!expr_ret_540) rew(mod_540);
  expr_ret_539 = expr_ret_540;
  if (!rule) rule = expr_ret_539;
  if (!expr_ret_539) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule increxpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_notexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_550
  daisho_astnode_t* expr_ret_550 = NULL;
  daisho_astnode_t* expr_ret_551 = NULL;
  daisho_astnode_t* expr_ret_552 = NULL;
  rec(mod_552);
  // ModExprList 0
  daisho_astnode_t* expr_ret_553 = NULL;
  expr_ret_553 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_552 = expr_ret_553;
  rule = expr_ret_553;
  // ModExprList 1
  if (expr_ret_552) {
    daisho_astnode_t* expr_ret_554 = NULL;
    daisho_astnode_t* expr_ret_555 = SUCC;
    while (expr_ret_555)
    {
      rec(kleene_rew_554);
      daisho_astnode_t* expr_ret_556 = NULL;
      rec(mod_556);
      // ModExprList 0
      daisho_astnode_t* expr_ret_557 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Capturing EXCL.
        expr_ret_557 = leaf(EXCL);
        expr_ret_557->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_557->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_557 = NULL;
      }

      expr_ret_556 = expr_ret_557;
      e = expr_ret_557;
      // ModExprList 1
      if (expr_ret_556) {
        // CodeExpr
        #define ret expr_ret_556
        ret = SUCC;
        #line 297 "daisho.peg"
        rule=unop(e, rule);
        #line 10274 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_556) rew(mod_556);
      expr_ret_555 = expr_ret_556;
    }

    expr_ret_554 = SUCC;
    expr_ret_552 = expr_ret_554;
  }

  // ModExprList end
  if (!expr_ret_552) rew(mod_552);
  expr_ret_551 = expr_ret_552;
  if (!rule) rule = expr_ret_551;
  if (!expr_ret_551) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule notexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_558
  daisho_astnode_t* expr_ret_558 = NULL;
  daisho_astnode_t* expr_ret_559 = NULL;
  daisho_astnode_t* expr_ret_560 = NULL;

  // SlashExpr 0
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_561 = NULL;
    rec(mod_561);
    // ModExprList Forwarding
    expr_ret_561 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_561) rew(mod_561);
    expr_ret_560 = expr_ret_561;
  }

  // SlashExpr 1
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_562 = NULL;
    rec(mod_562);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_562 = leaf(VARIDENT);
      expr_ret_562->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_562->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_562 = NULL;
    }

    // ModExprList end
    if (!expr_ret_562) rew(mod_562);
    expr_ret_560 = expr_ret_562;
  }

  // SlashExpr 2
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_563 = NULL;
    rec(mod_563);
    // ModExprList Forwarding
    expr_ret_563 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_563) rew(mod_563);
    expr_ret_560 = expr_ret_563;
  }

  // SlashExpr 3
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_564 = NULL;
    rec(mod_564);
    // ModExprList Forwarding
    expr_ret_564 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_564) rew(mod_564);
    expr_ret_560 = expr_ret_564;
  }

  // SlashExpr 4
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_565 = NULL;
    rec(mod_565);
    // ModExprList Forwarding
    expr_ret_565 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_565) rew(mod_565);
    expr_ret_560 = expr_ret_565;
  }

  // SlashExpr 5
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_566 = NULL;
    rec(mod_566);
    // ModExprList Forwarding
    expr_ret_566 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_566) rew(mod_566);
    expr_ret_560 = expr_ret_566;
  }

  // SlashExpr 6
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_567 = NULL;
    rec(mod_567);
    // ModExprList Forwarding
    expr_ret_567 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_567) rew(mod_567);
    expr_ret_560 = expr_ret_567;
  }

  // SlashExpr 7
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_568 = NULL;
    rec(mod_568);
    // ModExprList Forwarding
    expr_ret_568 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_568) rew(mod_568);
    expr_ret_560 = expr_ret_568;
  }

  // SlashExpr 8
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_569 = NULL;
    rec(mod_569);
    // ModExprList Forwarding
    expr_ret_569 = daisho_parse_number(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_569) rew(mod_569);
    expr_ret_560 = expr_ret_569;
  }

  // SlashExpr 9
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_570 = NULL;
    rec(mod_570);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_570 = leaf(SELFVAR);
      expr_ret_570->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_570->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_570 = NULL;
    }

    // ModExprList end
    if (!expr_ret_570) rew(mod_570);
    expr_ret_560 = expr_ret_570;
  }

  // SlashExpr 10
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_571 = NULL;
    rec(mod_571);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CHARLIT) {
      // Capturing CHARLIT.
      expr_ret_571 = leaf(CHARLIT);
      expr_ret_571->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_571->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_571 = NULL;
    }

    // ModExprList end
    if (!expr_ret_571) rew(mod_571);
    expr_ret_560 = expr_ret_571;
  }

  // SlashExpr 11
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_572 = NULL;
    rec(mod_572);
    // ModExprList Forwarding
    expr_ret_572 = daisho_parse_nativeexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_572) rew(mod_572);
    expr_ret_560 = expr_ret_572;
  }

  // SlashExpr 12
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_573 = NULL;
    rec(mod_573);
    // ModExprList Forwarding
    expr_ret_573 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_573) rew(mod_573);
    expr_ret_560 = expr_ret_573;
  }

  // SlashExpr 13
  if (!expr_ret_560) {
    daisho_astnode_t* expr_ret_574 = NULL;
    rec(mod_574);
    // ModExprList Forwarding
    expr_ret_574 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_574) rew(mod_574);
    expr_ret_560 = expr_ret_574;
  }

  // SlashExpr end
  expr_ret_559 = expr_ret_560;

  if (!rule) rule = expr_ret_559;
  if (!expr_ret_559) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule atomexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  int skip=0;

  daisho_astnode_t* e = NULL;
  #define rule expr_ret_575
  daisho_astnode_t* expr_ret_575 = NULL;
  daisho_astnode_t* expr_ret_576 = NULL;
  daisho_astnode_t* expr_ret_577 = NULL;
  rec(mod_577);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_577 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_577 = NULL;
  }

  // ModExprList 1
  if (expr_ret_577) {
    // CodeExpr
    #define ret expr_ret_577
    ret = SUCC;
    #line 327 "daisho.peg"
    rule=list(BLOCK);
    #line 10531 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_577) {
    daisho_astnode_t* expr_ret_578 = NULL;
    daisho_astnode_t* expr_ret_579 = SUCC;
    while (expr_ret_579)
    {
      rec(kleene_rew_578);
      daisho_astnode_t* expr_ret_580 = NULL;
      rec(mod_580);
      // ModExprList 0
      // CodeExpr
      #define ret expr_ret_580
      ret = SUCC;
      #line 328 "daisho.peg"
      if (skip) ret=NULL;
      #line 10551 "daisho.peg.h"

      #undef ret
      // ModExprList 1
      if (expr_ret_580) {
        rec(mexpr_state_581)
        daisho_astnode_t* expr_ret_581 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
          // Not capturing RCBRACK.
          expr_ret_581 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_581 = NULL;
        }

        // invert
        expr_ret_581 = expr_ret_581 ? NULL : SUCC;
        // rewind
        rew(mexpr_state_581);
        expr_ret_580 = expr_ret_581;
      }

      // ModExprList 2
      if (expr_ret_580) {
        daisho_astnode_t* expr_ret_582 = NULL;
        expr_ret_582 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        // optional
        if (!expr_ret_582)
          expr_ret_582 = SUCC;
        expr_ret_580 = expr_ret_582;
        e = expr_ret_582;
      }

      // ModExprList 3
      if (expr_ret_580) {
        // CodeExpr
        #define ret expr_ret_580
        ret = SUCC;
        #line 329 "daisho.peg"
        if(has(e)) add(rule, e);
        #line 10592 "daisho.peg.h"

        #undef ret
      }

      // ModExprList 4
      if (expr_ret_580) {
        daisho_astnode_t* expr_ret_583 = NULL;

        // SlashExpr 0
        if (!expr_ret_583) {
          daisho_astnode_t* expr_ret_584 = NULL;
          rec(mod_584);
          // ModExprList Forwarding
          expr_ret_584 = daisho_parse_semiornl(ctx);
          if (ctx->exit) return NULL;
          // ModExprList end
          if (!expr_ret_584) rew(mod_584);
          expr_ret_583 = expr_ret_584;
        }

        // SlashExpr 1
        if (!expr_ret_583) {
          daisho_astnode_t* expr_ret_585 = NULL;
          rec(mod_585);
          // ModExprList Forwarding
          // CodeExpr
          #define ret expr_ret_585
          ret = SUCC;
          #line 330 "daisho.peg"
          skip=1;
          #line 10623 "daisho.peg.h"

          #undef ret
          // ModExprList end
          if (!expr_ret_585) rew(mod_585);
          expr_ret_583 = expr_ret_585;
        }

        // SlashExpr end
        expr_ret_580 = expr_ret_583;

      }

      // ModExprList end
      if (!expr_ret_580) rew(mod_580);
      expr_ret_579 = expr_ret_580;
    }

    expr_ret_578 = SUCC;
    expr_ret_577 = expr_ret_578;
  }

  // ModExprList 3
  if (expr_ret_577) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_577 = leaf(RCBRACK);
      expr_ret_577->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_577->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_577 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_577) rew(mod_577);
  expr_ret_576 = expr_ret_577;
  if (!rule) rule = expr_ret_576;
  if (!expr_ret_576) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule blockexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_586
  daisho_astnode_t* expr_ret_586 = NULL;
  daisho_astnode_t* expr_ret_587 = NULL;
  daisho_astnode_t* expr_ret_588 = NULL;
  rec(mod_588);
  // ModExprList 0
  daisho_astnode_t* expr_ret_589 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
    // Capturing TYPEIDENT.
    expr_ret_589 = leaf(TYPEIDENT);
    expr_ret_589->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_589->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_589 = NULL;
  }

  expr_ret_588 = expr_ret_589;
  ns = expr_ret_589;
  // ModExprList 1
  if (expr_ret_588) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
      // Not capturing DOT.
      expr_ret_588 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_588 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_588) {
    daisho_astnode_t* expr_ret_590 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_590 = leaf(VARIDENT);
      expr_ret_590->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_590->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_590 = NULL;
    }

    expr_ret_588 = expr_ret_590;
    v = expr_ret_590;
  }

  // ModExprList 3
  if (expr_ret_588) {
    // CodeExpr
    #define ret expr_ret_588
    ret = SUCC;
    #line 334 "daisho.peg"
    rule=node(NSACCESS, ns, v);
    #line 10727 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_588) rew(mod_588);
  expr_ret_587 = expr_ret_588;
  if (!rule) rule = expr_ret_587;
  if (!expr_ret_587) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nsexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_591
  daisho_astnode_t* expr_ret_591 = NULL;
  daisho_astnode_t* expr_ret_592 = NULL;
  daisho_astnode_t* expr_ret_593 = NULL;
  rec(mod_593);
  // ModExprList 0
  daisho_astnode_t* expr_ret_594 = NULL;
  rec(mod_594);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_594 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_594 = NULL;
  }

  // ModExprList 1
  if (expr_ret_594) {
    daisho_astnode_t* expr_ret_595 = NULL;
    daisho_astnode_t* expr_ret_596 = NULL;

    // SlashExpr 0
    if (!expr_ret_596) {
      daisho_astnode_t* expr_ret_597 = NULL;
      rec(mod_597);
      // ModExprList 0
      rec(mexpr_state_598)
      daisho_astnode_t* expr_ret_598 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_598 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_598 = NULL;
      }

      // invert
      expr_ret_598 = expr_ret_598 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_598);
      expr_ret_597 = expr_ret_598;
      // ModExprList 1
      if (expr_ret_597) {
        daisho_astnode_t* expr_ret_599 = NULL;
        expr_ret_599 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_597 = expr_ret_599;
        al = expr_ret_599;
      }

      // ModExprList end
      if (!expr_ret_597) rew(mod_597);
      expr_ret_596 = expr_ret_597;
    }

    // SlashExpr 1
    if (!expr_ret_596) {
      daisho_astnode_t* expr_ret_600 = NULL;
      rec(mod_600);
      // ModExprList Forwarding
      // CodeExpr
      #define ret expr_ret_600
      ret = SUCC;
      #line 336 "daisho.peg"
      al=leaf(ARGLIST);
      #line 10811 "daisho.peg.h"

      #undef ret
      // ModExprList end
      if (!expr_ret_600) rew(mod_600);
      expr_ret_596 = expr_ret_600;
    }

    // SlashExpr end
    expr_ret_595 = expr_ret_596;

    // optional
    if (!expr_ret_595)
      expr_ret_595 = SUCC;
    expr_ret_594 = expr_ret_595;
  }

  // ModExprList 2
  if (expr_ret_594) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_594 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_594 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_594) rew(mod_594);
  expr_ret_593 = expr_ret_594;
  // ModExprList 1
  if (expr_ret_593) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_593 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_593 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_593) {
    daisho_astnode_t* expr_ret_601 = NULL;
    expr_ret_601 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_593 = expr_ret_601;
    e = expr_ret_601;
  }

  // ModExprList 3
  if (expr_ret_593) {
    // CodeExpr
    #define ret expr_ret_593
    ret = SUCC;
    #line 338 "daisho.peg"
    rule=node(LAMBDA, al, e);
    #line 10871 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_593) rew(mod_593);
  expr_ret_592 = expr_ret_593;
  if (!rule) rule = expr_ret_592;
  if (!expr_ret_592) rule = NULL;
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
  #define rule expr_ret_602
  daisho_astnode_t* expr_ret_602 = NULL;
  daisho_astnode_t* expr_ret_603 = NULL;
  daisho_astnode_t* expr_ret_604 = NULL;
  rec(mod_604);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_604 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_604 = NULL;
  }

  // ModExprList 1
  if (expr_ret_604) {
    daisho_astnode_t* expr_ret_605 = NULL;
    daisho_astnode_t* expr_ret_606 = NULL;
    rec(mod_606);
    // ModExprList 0
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

    expr_ret_606 = expr_ret_607;
    en = expr_ret_607;
    // ModExprList 1
    if (expr_ret_606) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_606 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_606 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_606) rew(mod_606);
    expr_ret_605 = expr_ret_606;
    // optional
    if (!expr_ret_605)
      expr_ret_605 = SUCC;
    expr_ret_604 = expr_ret_605;
  }

  // ModExprList 2
  if (expr_ret_604) {
    daisho_astnode_t* expr_ret_608 = NULL;
    expr_ret_608 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_604 = expr_ret_608;
    e = expr_ret_608;
  }

  // ModExprList 3
  if (expr_ret_604) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_604 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_604 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_604) {
    daisho_astnode_t* expr_ret_609 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_609 = leaf(VARIDENT);
      expr_ret_609->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_609->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_609 = NULL;
    }

    expr_ret_604 = expr_ret_609;
    item = expr_ret_609;
  }

  // ModExprList 5
  if (expr_ret_604) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_604 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_604 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_604) {
    daisho_astnode_t* expr_ret_610 = NULL;
    expr_ret_610 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_604 = expr_ret_610;
    in = expr_ret_610;
  }

  // ModExprList 7
  if (expr_ret_604) {
    daisho_astnode_t* expr_ret_611 = NULL;
    daisho_astnode_t* expr_ret_612 = NULL;
    rec(mod_612);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_612 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_612 = NULL;
    }

    // ModExprList 1
    if (expr_ret_612) {
      daisho_astnode_t* expr_ret_613 = NULL;
      expr_ret_613 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_612 = expr_ret_613;
      cond = expr_ret_613;
    }

    // ModExprList end
    if (!expr_ret_612) rew(mod_612);
    expr_ret_611 = expr_ret_612;
    // optional
    if (!expr_ret_611)
      expr_ret_611 = SUCC;
    expr_ret_604 = expr_ret_611;
  }

  // ModExprList 8
  if (expr_ret_604) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_604 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_604 = NULL;
    }

  }

  // ModExprList 9
  if (expr_ret_604) {
    // CodeExpr
    #define ret expr_ret_604
    ret = SUCC;
    #line 347 "daisho.peg"
    rule = list(LISTCOMP);
              if (en) add(rule, node(COMPENUMERATE, en));
              add(rule, e);add(rule, item);add(rule, in);
              if (cond) add(rule, node(COMPCOND, cond));;
    #line 11059 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_604) rew(mod_604);
  expr_ret_603 = expr_ret_604;
  if (!rule) rule = expr_ret_603;
  if (!expr_ret_603) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listcomp returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_614
  daisho_astnode_t* expr_ret_614 = NULL;
  daisho_astnode_t* expr_ret_615 = NULL;
  daisho_astnode_t* expr_ret_616 = NULL;

  // SlashExpr 0
  if (!expr_ret_616) {
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
        // Not capturing EXCL.
        expr_ret_617 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_617 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_617) {
      daisho_astnode_t* expr_ret_618 = NULL;
      expr_ret_618 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_617 = expr_ret_618;
      r = expr_ret_618;
    }

    // ModExprList 3
    if (expr_ret_617) {
      // CodeExpr
      #define ret expr_ret_617
      ret = SUCC;
      #line 352 "daisho.peg"
      rule=node(EXCL, r);
      #line 11122 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 4
    if (expr_ret_617) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_617 = leaf(CLOSE);
        expr_ret_617->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_617->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_617 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_617) rew(mod_617);
    expr_ret_616 = expr_ret_617;
  }

  // SlashExpr 1
  if (!expr_ret_616) {
    daisho_astnode_t* expr_ret_619 = NULL;
    rec(mod_619);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_619 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_619 = NULL;
    }

    // ModExprList 1
    if (expr_ret_619) {
      daisho_astnode_t* expr_ret_620 = NULL;
      expr_ret_620 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_619 = expr_ret_620;
      r = expr_ret_620;
    }

    // ModExprList 2
    if (expr_ret_619) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_619 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_619 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_619) {
      // CodeExpr
      #define ret expr_ret_619
      ret = SUCC;
      #line 353 "daisho.peg"
      rule=r;
      #line 11187 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_619) rew(mod_619);
    expr_ret_616 = expr_ret_619;
  }

  // SlashExpr end
  expr_ret_615 = expr_ret_616;

  if (!rule) rule = expr_ret_615;
  if (!expr_ret_615) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule parenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_621
  daisho_astnode_t* expr_ret_621 = NULL;
  daisho_astnode_t* expr_ret_622 = NULL;
  daisho_astnode_t* expr_ret_623 = NULL;
  rec(mod_623);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_623 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_623 = NULL;
  }

  // ModExprList 1
  if (expr_ret_623) {
    daisho_astnode_t* expr_ret_624 = NULL;
    expr_ret_624 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_623 = expr_ret_624;
    rule = expr_ret_624;
  }

  // ModExprList 2
  if (expr_ret_623) {
    // CodeExpr
    #define ret expr_ret_623
    ret = SUCC;
    #line 356 "daisho.peg"
    rule->kind = kind(LISTLIT);
    #line 11239 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_623) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_623 = leaf(RSBRACK);
      expr_ret_623->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_623->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_623 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_623) rew(mod_623);
  expr_ret_622 = expr_ret_623;
  if (!rule) rule = expr_ret_622;
  if (!expr_ret_622) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_625
  daisho_astnode_t* expr_ret_625 = NULL;
  daisho_astnode_t* expr_ret_626 = NULL;
  daisho_astnode_t* expr_ret_627 = NULL;
  rec(mod_627);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_627 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_627 = NULL;
  }

  // ModExprList 1
  if (expr_ret_627) {
    daisho_astnode_t* expr_ret_628 = NULL;
    expr_ret_628 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_627 = expr_ret_628;
    rule = expr_ret_628;
  }

  // ModExprList 2
  if (expr_ret_627) {
    // CodeExpr
    #define ret expr_ret_627
    ret = SUCC;
    #line 360 "daisho.peg"
    rule->kind = kind(TUPLELIT);
    #line 11300 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_627) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_627 = leaf(CLOSE);
      expr_ret_627->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_627->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_627 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_627) rew(mod_627);
  expr_ret_626 = expr_ret_627;
  if (!rule) rule = expr_ret_626;
  if (!expr_ret_626) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tuplelit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_629
  daisho_astnode_t* expr_ret_629 = NULL;
  daisho_astnode_t* expr_ret_630 = NULL;
  daisho_astnode_t* expr_ret_631 = NULL;
  rec(mod_631);
  // ModExprList 0
  daisho_astnode_t* expr_ret_632 = NULL;
  expr_ret_632 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_631 = expr_ret_632;
  t = expr_ret_632;
  // ModExprList 1
  if (expr_ret_631) {
    daisho_astnode_t* expr_ret_633 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_633 = leaf(VARIDENT);
      expr_ret_633->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_633->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_633 = NULL;
    }

    expr_ret_631 = expr_ret_633;
    i = expr_ret_633;
  }

  // ModExprList 2
  if (expr_ret_631) {
    // CodeExpr
    #define ret expr_ret_631
    ret = SUCC;
    #line 368 "daisho.peg"
    rule=node(VARDECL, t, i);
    #line 11367 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_631) rew(mod_631);
  expr_ret_630 = expr_ret_631;
  if (!rule) rule = expr_ret_630;
  if (!expr_ret_630) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule vardeclexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_634
  daisho_astnode_t* expr_ret_634 = NULL;
  daisho_astnode_t* expr_ret_635 = NULL;
  daisho_astnode_t* expr_ret_636 = NULL;

  // SlashExpr 0
  if (!expr_ret_636) {
    daisho_astnode_t* expr_ret_637 = NULL;
    rec(mod_637);
    // ModExprList Forwarding
    expr_ret_637 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_637) rew(mod_637);
    expr_ret_636 = expr_ret_637;
  }

  // SlashExpr 1
  if (!expr_ret_636) {
    daisho_astnode_t* expr_ret_638 = NULL;
    rec(mod_638);
    // ModExprList Forwarding
    expr_ret_638 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_638) rew(mod_638);
    expr_ret_636 = expr_ret_638;
  }

  // SlashExpr end
  expr_ret_635 = expr_ret_636;

  if (!rule) rule = expr_ret_635;
  if (!expr_ret_635) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule strlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_639
  daisho_astnode_t* expr_ret_639 = NULL;
  daisho_astnode_t* expr_ret_640 = NULL;
  daisho_astnode_t* expr_ret_641 = NULL;
  rec(mod_641);
  // ModExprList 0
  daisho_astnode_t* expr_ret_642 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_642 = leaf(STRLIT);
    expr_ret_642->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_642->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_642 = NULL;
  }

  expr_ret_641 = expr_ret_642;
  s = expr_ret_642;
  // ModExprList 1
  if (expr_ret_641) {
    // CodeExpr
    #define ret expr_ret_641
    ret = SUCC;
    #line 373 "daisho.peg"
    rule=list(SSTR); add(rule, s);
    #line 11450 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_641) {
    daisho_astnode_t* expr_ret_643 = NULL;
    daisho_astnode_t* expr_ret_644 = SUCC;
    while (expr_ret_644)
    {
      rec(kleene_rew_643);
      daisho_astnode_t* expr_ret_645 = NULL;
      rec(mod_645);
      // ModExprList 0
      daisho_astnode_t* expr_ret_646 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_646 = leaf(STRLIT);
        expr_ret_646->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_646->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_646 = NULL;
      }

      expr_ret_645 = expr_ret_646;
      s = expr_ret_646;
      // ModExprList 1
      if (expr_ret_645) {
        // CodeExpr
        #define ret expr_ret_645
        ret = SUCC;
        #line 374 "daisho.peg"
        add(rule, s);
        #line 11485 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_645) rew(mod_645);
      expr_ret_644 = expr_ret_645;
    }

    expr_ret_643 = SUCC;
    expr_ret_641 = expr_ret_643;
  }

  // ModExprList end
  if (!expr_ret_641) rew(mod_641);
  expr_ret_640 = expr_ret_641;
  if (!rule) rule = expr_ret_640;
  if (!expr_ret_640) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_647
  daisho_astnode_t* expr_ret_647 = NULL;
  daisho_astnode_t* expr_ret_648 = NULL;
  daisho_astnode_t* expr_ret_649 = NULL;
  rec(mod_649);
  // ModExprList 0
  daisho_astnode_t* expr_ret_650 = NULL;
  expr_ret_650 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_649 = expr_ret_650;
  f = expr_ret_650;
  // ModExprList 1
  if (expr_ret_649) {
    // CodeExpr
    #define ret expr_ret_649
    ret = SUCC;
    #line 376 "daisho.peg"
    rule=list(FSTR); add(rule, f);
    #line 11529 "daisho.peg.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_649) {
    daisho_astnode_t* expr_ret_651 = NULL;
    daisho_astnode_t* expr_ret_652 = SUCC;
    while (expr_ret_652)
    {
      rec(kleene_rew_651);
      daisho_astnode_t* expr_ret_653 = NULL;
      rec(mod_653);
      // ModExprList 0
      daisho_astnode_t* expr_ret_654 = NULL;
      expr_ret_654 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_653 = expr_ret_654;
      f = expr_ret_654;
      // ModExprList 1
      if (expr_ret_653) {
        // CodeExpr
        #define ret expr_ret_653
        ret = SUCC;
        #line 377 "daisho.peg"
        add(rule, f);
        #line 11556 "daisho.peg.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_653) rew(mod_653);
      expr_ret_652 = expr_ret_653;
    }

    expr_ret_651 = SUCC;
    expr_ret_649 = expr_ret_651;
  }

  // ModExprList end
  if (!expr_ret_649) rew(mod_649);
  expr_ret_648 = expr_ret_649;
  if (!rule) rule = expr_ret_648;
  if (!expr_ret_648) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_655
  daisho_astnode_t* expr_ret_655 = NULL;
  daisho_astnode_t* expr_ret_656 = NULL;
  daisho_astnode_t* expr_ret_657 = NULL;

  // SlashExpr 0
  if (!expr_ret_657) {
    daisho_astnode_t* expr_ret_658 = NULL;
    rec(mod_658);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_658 = leaf(STRLIT);
      expr_ret_658->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_658->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_658 = NULL;
    }

    // ModExprList end
    if (!expr_ret_658) rew(mod_658);
    expr_ret_657 = expr_ret_658;
  }

  // SlashExpr 1
  if (!expr_ret_657) {
    daisho_astnode_t* expr_ret_659 = NULL;
    rec(mod_659);
    // ModExprList 0
    daisho_astnode_t* expr_ret_660 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_660 = leaf(FSTRLITSTART);
      expr_ret_660->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_660->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_660 = NULL;
    }

    expr_ret_659 = expr_ret_660;
    s = expr_ret_660;
    // ModExprList 1
    if (expr_ret_659) {
      // CodeExpr
      #define ret expr_ret_659
      ret = SUCC;
      #line 380 "daisho.peg"
      rule=list(FSTRFRAG); add(rule, s);
      #line 11635 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_659) {
      daisho_astnode_t* expr_ret_661 = NULL;
      expr_ret_661 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_659 = expr_ret_661;
      x = expr_ret_661;
    }

    // ModExprList 3
    if (expr_ret_659) {
      // CodeExpr
      #define ret expr_ret_659
      ret = SUCC;
      #line 381 "daisho.peg"
      add(rule, x);
      #line 11656 "daisho.peg.h"

      #undef ret
    }

    // ModExprList 4
    if (expr_ret_659) {
      daisho_astnode_t* expr_ret_662 = NULL;
      daisho_astnode_t* expr_ret_663 = SUCC;
      while (expr_ret_663)
      {
        rec(kleene_rew_662);
        daisho_astnode_t* expr_ret_664 = NULL;
        rec(mod_664);
        // ModExprList 0
        daisho_astnode_t* expr_ret_665 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_665 = leaf(FSTRLITMID);
          expr_ret_665->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_665->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_665 = NULL;
        }

        expr_ret_664 = expr_ret_665;
        m = expr_ret_665;
        // ModExprList 1
        if (expr_ret_664) {
          daisho_astnode_t* expr_ret_666 = NULL;
          expr_ret_666 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_664 = expr_ret_666;
          x = expr_ret_666;
        }

        // ModExprList 2
        if (expr_ret_664) {
          // CodeExpr
          #define ret expr_ret_664
          ret = SUCC;
          #line 382 "daisho.peg"
          add(rule, m); add(rule, x);
          #line 11700 "daisho.peg.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_664) rew(mod_664);
        expr_ret_663 = expr_ret_664;
      }

      expr_ret_662 = SUCC;
      expr_ret_659 = expr_ret_662;
    }

    // ModExprList 5
    if (expr_ret_659) {
      daisho_astnode_t* expr_ret_667 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_667 = leaf(FSTRLITEND);
        expr_ret_667->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_667->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_667 = NULL;
      }

      expr_ret_659 = expr_ret_667;
      e = expr_ret_667;
    }

    // ModExprList 6
    if (expr_ret_659) {
      // CodeExpr
      #define ret expr_ret_659
      ret = SUCC;
      #line 383 "daisho.peg"
      add(rule, e);
      #line 11738 "daisho.peg.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_659) rew(mod_659);
    expr_ret_657 = expr_ret_659;
  }

  // SlashExpr end
  expr_ret_656 = expr_ret_657;

  if (!rule) rule = expr_ret_656;
  if (!expr_ret_656) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrfrag returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_668
  daisho_astnode_t* expr_ret_668 = NULL;
  daisho_astnode_t* expr_ret_669 = NULL;
  daisho_astnode_t* expr_ret_670 = NULL;
  rec(mod_670);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_670 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_670 = NULL;
  }

  // ModExprList 1
  if (expr_ret_670) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_670 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_670 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_670) {
    daisho_astnode_t* expr_ret_671 = NULL;
    daisho_astnode_t* expr_ret_672 = NULL;

    // SlashExpr 0
    if (!expr_ret_672) {
      daisho_astnode_t* expr_ret_673 = NULL;
      rec(mod_673);
      // ModExprList Forwarding
      expr_ret_673 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_673) rew(mod_673);
      expr_ret_672 = expr_ret_673;
    }

    // SlashExpr 1
    if (!expr_ret_672) {
      daisho_astnode_t* expr_ret_674 = NULL;
      rec(mod_674);
      // ModExprList Forwarding
      expr_ret_674 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_674) rew(mod_674);
      expr_ret_672 = expr_ret_674;
    }

    // SlashExpr end
    expr_ret_671 = expr_ret_672;

    expr_ret_670 = expr_ret_671;
    te = expr_ret_671;
  }

  // ModExprList 3
  if (expr_ret_670) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_670 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_670 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_670) {
    // CodeExpr
    #define ret expr_ret_670
    ret = SUCC;
    #line 385 "daisho.peg"
    rule=node(SIZEOF, te);
    #line 11841 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_670) rew(mod_670);
  expr_ret_669 = expr_ret_670;
  if (!rule) rule = expr_ret_669;
  if (!expr_ret_669) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sizeofexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_number(daisho_parser_ctx* ctx) {
  #define rule expr_ret_675
  daisho_astnode_t* expr_ret_675 = NULL;
  daisho_astnode_t* expr_ret_676 = NULL;
  daisho_astnode_t* expr_ret_677 = NULL;

  // SlashExpr 0
  if (!expr_ret_677) {
    daisho_astnode_t* expr_ret_678 = NULL;
    rec(mod_678);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INTLIT) {
      // Capturing INTLIT.
      expr_ret_678 = leaf(INTLIT);
      expr_ret_678->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_678->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_678 = NULL;
    }

    // ModExprList end
    if (!expr_ret_678) rew(mod_678);
    expr_ret_677 = expr_ret_678;
  }

  // SlashExpr 1
  if (!expr_ret_677) {
    daisho_astnode_t* expr_ret_679 = NULL;
    rec(mod_679);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TINTLIT) {
      // Capturing TINTLIT.
      expr_ret_679 = leaf(TINTLIT);
      expr_ret_679->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_679->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_679 = NULL;
    }

    // ModExprList end
    if (!expr_ret_679) rew(mod_679);
    expr_ret_677 = expr_ret_679;
  }

  // SlashExpr 2
  if (!expr_ret_677) {
    daisho_astnode_t* expr_ret_680 = NULL;
    rec(mod_680);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FLOATLIT) {
      // Capturing FLOATLIT.
      expr_ret_680 = leaf(FLOATLIT);
      expr_ret_680->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_680->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_680 = NULL;
    }

    // ModExprList end
    if (!expr_ret_680) rew(mod_680);
    expr_ret_677 = expr_ret_680;
  }

  // SlashExpr 3
  if (!expr_ret_677) {
    daisho_astnode_t* expr_ret_681 = NULL;
    rec(mod_681);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TFLOATLIT) {
      // Capturing TFLOATLIT.
      expr_ret_681 = leaf(TFLOATLIT);
      expr_ret_681->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_681->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_681 = NULL;
    }

    // ModExprList end
    if (!expr_ret_681) rew(mod_681);
    expr_ret_677 = expr_ret_681;
  }

  // SlashExpr end
  expr_ret_676 = expr_ret_677;

  if (!rule) rule = expr_ret_676;
  if (!expr_ret_676) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule number returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nativeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_682
  daisho_astnode_t* expr_ret_682 = NULL;
  daisho_astnode_t* expr_ret_683 = NULL;
  daisho_astnode_t* expr_ret_684 = NULL;
  rec(mod_684);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVE) {
    // Not capturing NATIVE.
    expr_ret_684 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_684 = NULL;
  }

  // ModExprList 1
  if (expr_ret_684) {
    daisho_astnode_t* expr_ret_685 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NATIVEBODY) {
      // Capturing NATIVEBODY.
      expr_ret_685 = leaf(NATIVEBODY);
      expr_ret_685->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_685->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_685 = NULL;
    }

    expr_ret_684 = expr_ret_685;
    rule = expr_ret_685;
  }

  // ModExprList end
  if (!expr_ret_684) rew(mod_684);
  expr_ret_683 = expr_ret_684;
  if (!rule) rule = expr_ret_683;
  if (!expr_ret_683) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nativeexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_686
  daisho_astnode_t* expr_ret_686 = NULL;
  daisho_astnode_t* expr_ret_687 = NULL;
  daisho_astnode_t* expr_ret_688 = NULL;
  rec(mod_688);
  // ModExprList 0
  daisho_astnode_t* expr_ret_689 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
    // Capturing VARIDENT.
    expr_ret_689 = leaf(VARIDENT);
    expr_ret_689->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_689->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_689 = NULL;
  }

  expr_ret_688 = expr_ret_689;
  rule = expr_ret_689;
  // ModExprList 1
  if (expr_ret_688) {
    // CodeExpr
    #define ret expr_ret_688
    ret = SUCC;
    #line 420 "daisho.peg"
    
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
    #line 12035 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_688) rew(mod_688);
  expr_ret_687 = expr_ret_688;
  if (!rule) rule = expr_ret_687;
  if (!expr_ret_687) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cident returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_bsl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  #define rule expr_ret_690
  daisho_astnode_t* expr_ret_690 = NULL;
  daisho_astnode_t* expr_ret_691 = NULL;
  daisho_astnode_t* expr_ret_692 = NULL;
  rec(mod_692);
  // ModExprList 0
  daisho_astnode_t* expr_ret_693 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
    // Capturing LT.
    expr_ret_693 = leaf(LT);
    expr_ret_693->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_693->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_693 = NULL;
  }

  expr_ret_692 = expr_ret_693;
  l = expr_ret_693;
  // ModExprList 1
  if (expr_ret_692) {
    daisho_astnode_t* expr_ret_694 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_694 = leaf(LT);
      expr_ret_694->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_694->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_694 = NULL;
    }

    expr_ret_692 = expr_ret_694;
    lt = expr_ret_694;
  }

  // ModExprList 2
  if (expr_ret_692) {
    daisho_astnode_t* expr_ret_695 = NULL;
    // CodeExpr
    #define ret expr_ret_695
    ret = SUCC;
    #line 434 "daisho.peg"
    ret=node(BSL, l, lt);
    #line 12097 "daisho.peg.h"

    #undef ret
    expr_ret_692 = expr_ret_695;
    rule = expr_ret_695;
  }

  // ModExprList end
  if (!expr_ret_692) rew(mod_692);
  expr_ret_691 = expr_ret_692;
  if (!rule) rule = expr_ret_691;
  if (!expr_ret_691) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule bsl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_bsr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  #define rule expr_ret_696
  daisho_astnode_t* expr_ret_696 = NULL;
  daisho_astnode_t* expr_ret_697 = NULL;
  daisho_astnode_t* expr_ret_698 = NULL;
  rec(mod_698);
  // ModExprList 0
  daisho_astnode_t* expr_ret_699 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
    // Capturing GT.
    expr_ret_699 = leaf(GT);
    expr_ret_699->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_699->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_699 = NULL;
  }

  expr_ret_698 = expr_ret_699;
  g = expr_ret_699;
  // ModExprList 1
  if (expr_ret_698) {
    daisho_astnode_t* expr_ret_700 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_700 = leaf(GT);
      expr_ret_700->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_700->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_700 = NULL;
    }

    expr_ret_698 = expr_ret_700;
    gt = expr_ret_700;
  }

  // ModExprList 2
  if (expr_ret_698) {
    daisho_astnode_t* expr_ret_701 = NULL;
    // CodeExpr
    #define ret expr_ret_701
    ret = SUCC;
    #line 436 "daisho.peg"
    ret=node(BSR, g, gt);
    #line 12161 "daisho.peg.h"

    #undef ret
    expr_ret_698 = expr_ret_701;
    rule = expr_ret_701;
  }

  // ModExprList end
  if (!expr_ret_698) rew(mod_698);
  expr_ret_697 = expr_ret_698;
  if (!rule) rule = expr_ret_697;
  if (!expr_ret_697) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule bsr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_702
  daisho_astnode_t* expr_ret_702 = NULL;
  daisho_astnode_t* expr_ret_703 = NULL;
  daisho_astnode_t* expr_ret_704 = NULL;

  // SlashExpr 0
  if (!expr_ret_704) {
    daisho_astnode_t* expr_ret_705 = NULL;
    rec(mod_705);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_705 = leaf(SEMI);
      expr_ret_705->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_705->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_705 = NULL;
    }

    // ModExprList end
    if (!expr_ret_705) rew(mod_705);
    expr_ret_704 = expr_ret_705;
  }

  // SlashExpr 1
  if (!expr_ret_704) {
    daisho_astnode_t* expr_ret_706 = NULL;
    rec(mod_706);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_706
    ret = SUCC;
    #line 439 "daisho.peg"
    ret = (ctx->pos >= ctx->len ||
                      ctx->tokens[ctx->pos - 1].line < ctx->tokens[ctx->pos].line)
                      ? leaf(SEMI)
                      : NULL;
    #line 12217 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_706) rew(mod_706);
    expr_ret_704 = expr_ret_706;
  }

  // SlashExpr end
  expr_ret_703 = expr_ret_704;

  if (!rule) rule = expr_ret_703;
  if (!expr_ret_703) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule semiornl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_overloadable(daisho_parser_ctx* ctx) {
  #define rule expr_ret_707
  daisho_astnode_t* expr_ret_707 = NULL;
  daisho_astnode_t* expr_ret_708 = NULL;
  daisho_astnode_t* expr_ret_709 = NULL;

  // SlashExpr 0
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_710 = NULL;
    rec(mod_710);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_710 = leaf(TYPEIDENT);
      expr_ret_710->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_710->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_710 = NULL;
    }

    // ModExprList end
    if (!expr_ret_710) rew(mod_710);
    expr_ret_709 = expr_ret_710;
  }

  // SlashExpr 1
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_711 = NULL;
    rec(mod_711);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
      // Capturing PLUS.
      expr_ret_711 = leaf(PLUS);
      expr_ret_711->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_711->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_711 = NULL;
    }

    // ModExprList end
    if (!expr_ret_711) rew(mod_711);
    expr_ret_709 = expr_ret_711;
  }

  // SlashExpr 2
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_712 = NULL;
    rec(mod_712);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
      // Capturing MINUS.
      expr_ret_712 = leaf(MINUS);
      expr_ret_712->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_712->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_712 = NULL;
    }

    // ModExprList end
    if (!expr_ret_712) rew(mod_712);
    expr_ret_709 = expr_ret_712;
  }

  // SlashExpr 3
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_713 = NULL;
    rec(mod_713);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
      // Capturing STAR.
      expr_ret_713 = leaf(STAR);
      expr_ret_713->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_713->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_713 = NULL;
    }

    // ModExprList end
    if (!expr_ret_713) rew(mod_713);
    expr_ret_709 = expr_ret_713;
  }

  // SlashExpr 4
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_714 = NULL;
    rec(mod_714);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
      // Capturing POW.
      expr_ret_714 = leaf(POW);
      expr_ret_714->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_714->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_714 = NULL;
    }

    // ModExprList end
    if (!expr_ret_714) rew(mod_714);
    expr_ret_709 = expr_ret_714;
  }

  // SlashExpr 5
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_715 = NULL;
    rec(mod_715);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
      // Capturing DIV.
      expr_ret_715 = leaf(DIV);
      expr_ret_715->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_715->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_715 = NULL;
    }

    // ModExprList end
    if (!expr_ret_715) rew(mod_715);
    expr_ret_709 = expr_ret_715;
  }

  // SlashExpr 6
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_716 = NULL;
    rec(mod_716);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
      // Capturing MOD.
      expr_ret_716 = leaf(MOD);
      expr_ret_716->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_716->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_716 = NULL;
    }

    // ModExprList end
    if (!expr_ret_716) rew(mod_716);
    expr_ret_709 = expr_ret_716;
  }

  // SlashExpr 7
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_717 = NULL;
    rec(mod_717);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
      // Capturing AND.
      expr_ret_717 = leaf(AND);
      expr_ret_717->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_717->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_717 = NULL;
    }

    // ModExprList end
    if (!expr_ret_717) rew(mod_717);
    expr_ret_709 = expr_ret_717;
  }

  // SlashExpr 8
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_718 = NULL;
    rec(mod_718);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
      // Capturing OR.
      expr_ret_718 = leaf(OR);
      expr_ret_718->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_718->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_718 = NULL;
    }

    // ModExprList end
    if (!expr_ret_718) rew(mod_718);
    expr_ret_709 = expr_ret_718;
  }

  // SlashExpr 9
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_719 = NULL;
    rec(mod_719);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
      // Capturing XOR.
      expr_ret_719 = leaf(XOR);
      expr_ret_719->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_719->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_719 = NULL;
    }

    // ModExprList end
    if (!expr_ret_719) rew(mod_719);
    expr_ret_709 = expr_ret_719;
  }

  // SlashExpr 10
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_720 = NULL;
    rec(mod_720);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EXCL) {
      // Capturing EXCL.
      expr_ret_720 = leaf(EXCL);
      expr_ret_720->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_720->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_720 = NULL;
    }

    // ModExprList end
    if (!expr_ret_720) rew(mod_720);
    expr_ret_709 = expr_ret_720;
  }

  // SlashExpr 11
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_721 = NULL;
    rec(mod_721);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BITNOT) {
      // Capturing BITNOT.
      expr_ret_721 = leaf(BITNOT);
      expr_ret_721->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_721->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_721 = NULL;
    }

    // ModExprList end
    if (!expr_ret_721) rew(mod_721);
    expr_ret_709 = expr_ret_721;
  }

  // SlashExpr 12
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_722 = NULL;
    rec(mod_722);
    // ModExprList Forwarding
    expr_ret_722 = daisho_parse_bsl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_722) rew(mod_722);
    expr_ret_709 = expr_ret_722;
  }

  // SlashExpr 13
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_723 = NULL;
    rec(mod_723);
    // ModExprList Forwarding
    expr_ret_723 = daisho_parse_bsr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_723) rew(mod_723);
    expr_ret_709 = expr_ret_723;
  }

  // SlashExpr 14
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_724 = NULL;
    rec(mod_724);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Capturing LT.
      expr_ret_724 = leaf(LT);
      expr_ret_724->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_724->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_724 = NULL;
    }

    // ModExprList end
    if (!expr_ret_724) rew(mod_724);
    expr_ret_709 = expr_ret_724;
  }

  // SlashExpr 15
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_725 = NULL;
    rec(mod_725);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_725 = leaf(GT);
      expr_ret_725->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_725->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_725 = NULL;
    }

    // ModExprList end
    if (!expr_ret_725) rew(mod_725);
    expr_ret_709 = expr_ret_725;
  }

  // SlashExpr 16
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_726 = NULL;
    rec(mod_726);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
      // Not capturing EQ.
      expr_ret_726 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_726 = NULL;
    }

    // ModExprList 1
    if (expr_ret_726) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_726 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_726 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_726) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Capturing RSBRACK.
        expr_ret_726 = leaf(RSBRACK);
        expr_ret_726->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_726->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_726 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_726) rew(mod_726);
    expr_ret_709 = expr_ret_726;
  }

  // SlashExpr 17
  if (!expr_ret_709) {
    daisho_astnode_t* expr_ret_727 = NULL;
    rec(mod_727);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_727 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_727 = NULL;
    }

    // ModExprList 1
    if (expr_ret_727) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_727 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_727 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_727) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
        // Capturing EQ.
        expr_ret_727 = leaf(EQ);
        expr_ret_727->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_727->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_727 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_727) rew(mod_727);
    expr_ret_709 = expr_ret_727;
  }

  // SlashExpr end
  expr_ret_708 = expr_ret_709;

  if (!rule) rule = expr_ret_708;
  if (!expr_ret_708) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule overloadable returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_728
  daisho_astnode_t* expr_ret_728 = NULL;
  daisho_astnode_t* expr_ret_729 = NULL;
  daisho_astnode_t* expr_ret_730 = NULL;
  rec(mod_730);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_731 = NULL;
  rec(mod_731);
  // ModExprList 0
  daisho_astnode_t* expr_ret_732 = NULL;
  expr_ret_732 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_731 = expr_ret_732;
  e = expr_ret_732;
  // ModExprList 1
  if (expr_ret_731) {
    // CodeExpr
    #define ret expr_ret_731
    ret = SUCC;
    #line 465 "daisho.peg"
    WARNING("Extra expression."); ret=e;
    #line 12666 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_731) rew(mod_731);
  expr_ret_730 = expr_ret_731;
  // ModExprList end
  if (!expr_ret_730) rew(mod_730);
  expr_ret_729 = expr_ret_730;
  if (!rule) rule = expr_ret_729;
  if (!expr_ret_729) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule noexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_733
  daisho_astnode_t* expr_ret_733 = NULL;
  daisho_astnode_t* expr_ret_734 = NULL;
  daisho_astnode_t* expr_ret_735 = NULL;
  rec(mod_735);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_736 = NULL;

  // SlashExpr 0
  if (!expr_ret_736) {
    daisho_astnode_t* expr_ret_737 = NULL;
    rec(mod_737);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_737 = leaf(COMMA);
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
    // CodeExpr
    #define ret expr_ret_738
    ret = SUCC;
    #line 466 "daisho.peg"
    WARNING("Missing comma."); ret=leaf(COMMA);
    #line 12723 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_738) rew(mod_738);
    expr_ret_736 = expr_ret_738;
  }

  // SlashExpr end
  expr_ret_735 = expr_ret_736;

  // ModExprList end
  if (!expr_ret_735) rew(mod_735);
  expr_ret_734 = expr_ret_735;
  if (!rule) rule = expr_ret_734;
  if (!expr_ret_734) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wcomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_739
  daisho_astnode_t* expr_ret_739 = NULL;
  daisho_astnode_t* expr_ret_740 = NULL;
  daisho_astnode_t* expr_ret_741 = NULL;
  rec(mod_741);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_742 = NULL;
  rec(mod_742);
  // ModExprList 0
  daisho_astnode_t* expr_ret_743 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_743 = leaf(COMMA);
    expr_ret_743->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_743->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_743 = NULL;
  }

  expr_ret_742 = expr_ret_743;
  c = expr_ret_743;
  // ModExprList 1
  if (expr_ret_742) {
    // CodeExpr
    #define ret expr_ret_742
    ret = SUCC;
    #line 467 "daisho.peg"
    WARNING("Extra comma."); ret=c;
    #line 12775 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_742) rew(mod_742);
  expr_ret_741 = expr_ret_742;
  // ModExprList end
  if (!expr_ret_741) rew(mod_741);
  expr_ret_740 = expr_ret_741;
  if (!rule) rule = expr_ret_740;
  if (!expr_ret_740) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nocomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_744
  daisho_astnode_t* expr_ret_744 = NULL;
  daisho_astnode_t* expr_ret_745 = NULL;
  daisho_astnode_t* expr_ret_746 = NULL;
  rec(mod_746);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_747 = NULL;

  // SlashExpr 0
  if (!expr_ret_747) {
    daisho_astnode_t* expr_ret_748 = NULL;
    rec(mod_748);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_748 = leaf(SEMI);
      expr_ret_748->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_748->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_748 = NULL;
    }

    // ModExprList end
    if (!expr_ret_748) rew(mod_748);
    expr_ret_747 = expr_ret_748;
  }

  // SlashExpr 1
  if (!expr_ret_747) {
    daisho_astnode_t* expr_ret_749 = NULL;
    rec(mod_749);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_749
    ret = SUCC;
    #line 468 "daisho.peg"
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #line 12832 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_749) rew(mod_749);
    expr_ret_747 = expr_ret_749;
  }

  // SlashExpr end
  expr_ret_746 = expr_ret_747;

  // ModExprList end
  if (!expr_ret_746) rew(mod_746);
  expr_ret_745 = expr_ret_746;
  if (!rule) rule = expr_ret_745;
  if (!expr_ret_745) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wsemi returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_750
  daisho_astnode_t* expr_ret_750 = NULL;
  daisho_astnode_t* expr_ret_751 = NULL;
  daisho_astnode_t* expr_ret_752 = NULL;
  rec(mod_752);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_753 = NULL;
  rec(mod_753);
  // ModExprList 0
  daisho_astnode_t* expr_ret_754 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_754 = leaf(SEMI);
    expr_ret_754->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_754->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_754 = NULL;
  }

  expr_ret_753 = expr_ret_754;
  s = expr_ret_754;
  // ModExprList 1
  if (expr_ret_753) {
    // CodeExpr
    #define ret expr_ret_753
    ret = SUCC;
    #line 469 "daisho.peg"
    WARNING("Extra semicolon."); ret=s;
    #line 12884 "daisho.peg.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_753) rew(mod_753);
  expr_ret_752 = expr_ret_753;
  // ModExprList end
  if (!expr_ret_752) rew(mod_752);
  expr_ret_751 = expr_ret_752;
  if (!rule) rule = expr_ret_751;
  if (!expr_ret_751) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nosemi returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_755
  daisho_astnode_t* expr_ret_755 = NULL;
  daisho_astnode_t* expr_ret_756 = NULL;
  daisho_astnode_t* expr_ret_757 = NULL;
  rec(mod_757);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_758 = NULL;

  // SlashExpr 0
  if (!expr_ret_758) {
    daisho_astnode_t* expr_ret_759 = NULL;
    rec(mod_759);
    // ModExprList Forwarding
    expr_ret_759 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_759) rew(mod_759);
    expr_ret_758 = expr_ret_759;
  }

  // SlashExpr 1
  if (!expr_ret_758) {
    daisho_astnode_t* expr_ret_760 = NULL;
    rec(mod_760);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_760
    ret = SUCC;
    #line 470 "daisho.peg"
    WARNING("Missing semicolon or newline."); ret=leaf(SEMI);
    #line 12933 "daisho.peg.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_760) rew(mod_760);
    expr_ret_758 = expr_ret_760;
  }

  // SlashExpr end
  expr_ret_757 = expr_ret_758;

  // ModExprList end
  if (!expr_ret_757) rew(mod_757);
  expr_ret_756 = expr_ret_757;
  if (!rule) rule = expr_ret_756;
  if (!expr_ret_756) rule = NULL;
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
