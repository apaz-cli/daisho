
/* START OF UTF8 LIBRARY */

#ifndef PGEN_UTF8_INCLUDED
#define PGEN_UTF8_INCLUDED
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
struct Symtab;
struct ExprType;

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
  DAISHO_TOK_FSTRLITSTART,
  DAISHO_TOK_FSTRLITMID,
  DAISHO_TOK_FSTRLITEND,
  DAISHO_TOK_WS,
  DAISHO_TOK_MLCOM,
  DAISHO_TOK_SLCOM,
  DAISHO_TOK_SHEBANG,
} daisho_token_kind;

// The 0th token is beginning of stream.
// The 1st token isend of stream.
// Tokens 1 through 88 are the ones you defined.
// This totals 90 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 90
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
  "NOT",
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
  "SEMI",
  "DOT",
  "COMMA",
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
  "CIDENT",
  "NUMLIT",
  "STRLIT",
  "FSTRLITSTART",
  "FSTRLITMID",
  "FSTRLITEND",
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
        else if (c == 35 /*'#'*/) trie_state = 113;
        else if (c == 36 /*'$'*/) trie_state = 115;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 40 /*'('*/) trie_state = 107;
        else if (c == 41 /*')'*/) trie_state = 108;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 106;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 105;
        else if (c == 47 /*'/'*/) trie_state = 5;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 104;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 114;
        else if (c == 70 /*'F'*/) trie_state = 75;
        else if (c == 83 /*'S'*/) trie_state = 84;
        else if (c == 86 /*'V'*/) trie_state = 92;
        else if (c == 91 /*'['*/) trie_state = 111;
        else if (c == 93 /*']'*/) trie_state = 112;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 116;
        else if (c == 97 /*'a'*/) trie_state = 58;
        else if (c == 99 /*'c'*/) trie_state = 77;
        else if (c == 101 /*'e'*/) trie_state = 41;
        else if (c == 102 /*'f'*/) trie_state = 45;
        else if (c == 105 /*'i'*/) trie_state = 39;
        else if (c == 115 /*'s'*/) trie_state = 88;
        else if (c == 116 /*'t'*/) trie_state = 54;
        else if (c == 117 /*'u'*/) trie_state = 65;
        else if (c == 119 /*'w'*/) trie_state = 49;
        else if (c == 123 /*'{'*/) trie_state = 109;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 110;
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
        else if (c == 62 /*'>'*/) trie_state = 117;
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
        else if (c == 62 /*'>'*/) trie_state = 118;
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
      else if (trie_state == 104) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 106) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 107) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 114) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 115) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 116) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 117) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 118) {
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
      else if (((smaut_state_9 >= 0) & (smaut_state_9 <= 2)) &
         ((c >= 48) & (c <= 57))) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 2) &
         (c == 46)) {
          smaut_state_9 = 3;
      }
      else if ((smaut_state_9 == 3) &
         ((c >= 48) & (c <= 57))) {
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
         (c == 123)) {
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

    // Transition FSTRLITSTART State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 34)) {
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

    // Transition FSTRLITMID State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 125)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 123)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 1) &
         (c == 34)) {
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

    // Transition FSTRLITEND State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == 125)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 34)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 1) &
         (c == 123)) {
          smaut_state_13 = -1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 10)) {
          smaut_state_13 = -1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 92)) {
          smaut_state_13 = 3;
      }
      else if ((smaut_state_13 == 1) &
         (1)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 110)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 102)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 98)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 114)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 116)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 101)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 92)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 39)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 34)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 123)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 3) &
         (c == 125)) {
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
  DAISHO_NODE_NOT,
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
  DAISHO_NODE_SEMI,
  DAISHO_NODE_DOT,
  DAISHO_NODE_COMMA,
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
  DAISHO_NODE_CIDENT,
  DAISHO_NODE_NUMLIT,
  DAISHO_NODE_STRLIT,
  DAISHO_NODE_FSTRLITSTART,
  DAISHO_NODE_FSTRLITMID,
  DAISHO_NODE_FSTRLITEND,
  DAISHO_NODE_WS,
  DAISHO_NODE_MLCOM,
  DAISHO_NODE_SLCOM,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_TUPLETYPE,
  DAISHO_NODE_MAPLIT,
  DAISHO_NODE_VARDECL,
  DAISHO_NODE_RECOVERY,
  DAISHO_NODE_PROGRAM,
  DAISHO_NODE_NSLIST,
  DAISHO_NODE_NSDECLS,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_TMPLSTRUCT,
  DAISHO_NODE_TMPLUNION,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_TMPLTYPE,
  DAISHO_NODE_TRAITTYPE,
  DAISHO_NODE_STRUCTTYPE,
  DAISHO_NODE_CTYPEDECL,
  DAISHO_NODE_TMPLEXPAND,
  DAISHO_NODE_TERN,
  DAISHO_NODE_MUL,
  DAISHO_NODE_BSR,
  DAISHO_NODE_BSL,
  DAISHO_NODE_BLOCK,
  DAISHO_NODE_CAST,
  DAISHO_NODE_LAMBDA,
  DAISHO_NODE_FOREACH,
  DAISHO_NODE_CALL,
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
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_DTRAITIDENT,
  DAISHO_NODE_SSTR,
  DAISHO_NODE_FSTR,
  DAISHO_NODE_FSTRFRAG,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 130
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
  "NOT",
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
  "SEMI",
  "DOT",
  "COMMA",
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
  "CIDENT",
  "NUMLIT",
  "STRLIT",
  "FSTRLITSTART",
  "FSTRLITMID",
  "FSTRLITEND",
  "WS",
  "MLCOM",
  "SLCOM",
  "SHEBANG",
  "TUPLETYPE",
  "MAPLIT",
  "VARDECL",
  "RECOVERY",
  "PROGRAM",
  "NSLIST",
  "NSDECLS",
  "MEMBERLIST",
  "TMPLSTRUCT",
  "TMPLUNION",
  "TMPLTRAIT",
  "TMPLTYPE",
  "TRAITTYPE",
  "STRUCTTYPE",
  "CTYPEDECL",
  "TMPLEXPAND",
  "TERN",
  "MUL",
  "BSR",
  "BSL",
  "BLOCK",
  "CAST",
  "LAMBDA",
  "FOREACH",
  "CALL",
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

  // Store node number or tok repr.
  // if (tok_repr) then it's a codepoint string of size len_or_toknum.
  // if (!tok_repr && len_or_toknum) then len_or_toknum is a token offset.
  // if (!tok_repr && !len_or_toknum) then nothing is stored.
  codepoint_t* tok_repr;
  size_t len_or_toknum;
  // Extra data in %extra directives:
  Symtab* symtab; // Anything in the scope created by this expression
  ExprType* type; // The concrete type of this expression
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
  node->len_or_toknum = 0;
  // Extra initialization from %extrainit directives:
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
  node->tok_repr = NULL;
  node->len_or_toknum = 0;
  // Extra initialization from %extrainit directives:
  node->symtab = NULL;
  node->type = NULL;
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
  node->len_or_toknum = 0;
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
  node->len_or_toknum = 0;
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
  node->len_or_toknum = 0;
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
  node->len_or_toknum = 0;
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
  node->len_or_toknum = 0;
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
  node->len_or_toknum = t->len_or_toknum;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_cprepr(daisho_astnode_t* node, codepoint_t* cps, size_t len_or_toknum) {
  node->tok_repr = cps;
  node->len_or_toknum = len_or_toknum;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_srepr(pgen_allocator* allocator, daisho_astnode_t* node, char* s) {
  size_t cpslen = strlen(s);
  codepoint_t* cps = (codepoint_t*)pgen_alloc(allocator, (cpslen + 1) * sizeof(codepoint_t), _Alignof(codepoint_t));
  for (size_t i = 0; i < cpslen; i++) cps[i] = (codepoint_t)s[i];
  cps[cpslen] = 0;
  node->tok_repr = cps;
  node->len_or_toknum = cpslen;
  return node;
}

static inline int daisho_node_print_content(daisho_astnode_t* node, daisho_token* tokens) {
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
  indent(); printf("\"content\": \"");
  daisho_node_print_content(node, tokens); printf("\",\n");
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
#ifndef DAIC_ASTHELPERS_INCLUDE
#include "../asthelpers.h"
#endif
#include <daisho/Daisho.h>

static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_namespace(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_protolist(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_program(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* nses = NULL;
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_0
  daisho_astnode_t* expr_ret_0 = NULL;
  daisho_astnode_t* expr_ret_1 = NULL;
  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList 0
  daisho_astnode_t* expr_ret_3 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
    // Capturing SHEBANG.
    expr_ret_3 = leaf(SHEBANG);
    expr_ret_3->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_3->len_or_toknum = ctx->tokens[ctx->pos].len;
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
    #line 17 "daisho.peg"
    list(NSLIST);
    #line 3300 "daisho_tokenizer_parser.h"

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
      daisho_astnode_t* expr_ret_8 = NULL;
      expr_ret_8 = daisho_parse_namespace(ctx);
      if (ctx->exit) return NULL;
      expr_ret_7 = expr_ret_8;
      f = expr_ret_8;
      // ModExprList 1
      if (expr_ret_7) {
        // CodeExpr
        #define ret expr_ret_7
        ret = SUCC;
        #line 18 "daisho.peg"
        add(nses, f);
        #line 3329 "daisho_tokenizer_parser.h"

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
  if (expr_ret_2) {
    // CodeExpr
    #define ret expr_ret_2
    ret = SUCC;
    #line 18 "daisho.peg"
    rule=node(PROGRAM, sh, nses);
    #line 3350 "daisho_tokenizer_parser.h"

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
  daisho_astnode_t* ns = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_9
  daisho_astnode_t* expr_ret_9 = NULL;
  daisho_astnode_t* expr_ret_10 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  rec(mod_11);
  // ModExprList 0
  daisho_astnode_t* expr_ret_12 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
    // Capturing NAMESPACE.
    expr_ret_12 = leaf(NAMESPACE);
    expr_ret_12->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_12->len_or_toknum = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_12 = NULL;
  }

  expr_ret_11 = expr_ret_12;
  ns = expr_ret_12;
  // ModExprList 1
  if (expr_ret_11) {
    daisho_astnode_t* expr_ret_13 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_13 = leaf(TYPEIDENT);
      expr_ret_13->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_13->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_13 = NULL;
    }

    expr_ret_11 = expr_ret_13;
    name = expr_ret_13;
  }

  // ModExprList 2
  if (expr_ret_11) {
    expr_ret_11 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 3
  if (expr_ret_11) {
    daisho_astnode_t* expr_ret_14 = NULL;
    // CodeExpr
    #define ret expr_ret_14
    ret = SUCC;
    #line 20 "daisho.peg"
    list(NSDECLS);
    #line 3420 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_11 = expr_ret_14;
    l = expr_ret_14;
  }

  // ModExprList 4
  if (expr_ret_11) {
    daisho_astnode_t* expr_ret_15 = NULL;
    expr_ret_15 = daisho_parse_topdecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_11 = expr_ret_15;
    t = expr_ret_15;
  }

  // ModExprList 5
  if (expr_ret_11) {
    // CodeExpr
    #define ret expr_ret_11
    ret = SUCC;
    #line 21 "daisho.peg"
    add(l, t);
    #line 3443 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 6
  if (expr_ret_11) {
    daisho_astnode_t* expr_ret_16 = NULL;
    daisho_astnode_t* expr_ret_17 = SUCC;
    while (expr_ret_17)
    {
      rec(kleene_rew_16);
      daisho_astnode_t* expr_ret_18 = NULL;
      rec(mod_18);
      // ModExprList 0
      expr_ret_18 = daisho_parse_wsemi(ctx);
      if (ctx->exit) return NULL;
      // ModExprList 1
      if (expr_ret_18) {
        daisho_astnode_t* expr_ret_19 = NULL;
        expr_ret_19 = daisho_parse_topdecl(ctx);
        if (ctx->exit) return NULL;
        expr_ret_18 = expr_ret_19;
        t = expr_ret_19;
      }

      // ModExprList 2
      if (expr_ret_18) {
        // CodeExpr
        #define ret expr_ret_18
        ret = SUCC;
        #line 21 "daisho.peg"
        add(l, t);
        #line 3476 "daisho_tokenizer_parser.h"

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
  if (expr_ret_11) {
    // CodeExpr
    #define ret expr_ret_11
    ret = SUCC;
    #line 22 "daisho.peg"
    rule=node(NAMESPACE, name, l);
    #line 3497 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_11) rew(mod_11);
  expr_ret_10 = expr_ret_11;
  if (!rule) rule = expr_ret_10;
  if (!expr_ret_10) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule namespace returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_20
  daisho_astnode_t* expr_ret_20 = NULL;
  daisho_astnode_t* expr_ret_21 = NULL;
  daisho_astnode_t* expr_ret_22 = NULL;

  // SlashExpr 0
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_23 = NULL;
    rec(mod_23);
    // ModExprList Forwarding
    expr_ret_23 = daisho_parse_structdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_23) rew(mod_23);
    expr_ret_22 = expr_ret_23;
  }

  // SlashExpr 1
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_24 = NULL;
    rec(mod_24);
    // ModExprList Forwarding
    expr_ret_24 = daisho_parse_uniondecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_24) rew(mod_24);
    expr_ret_22 = expr_ret_24;
  }

  // SlashExpr 2
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_25 = NULL;
    rec(mod_25);
    // ModExprList Forwarding
    expr_ret_25 = daisho_parse_traitdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_25) rew(mod_25);
    expr_ret_22 = expr_ret_25;
  }

  // SlashExpr 3
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_26 = NULL;
    rec(mod_26);
    // ModExprList Forwarding
    expr_ret_26 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_26) rew(mod_26);
    expr_ret_22 = expr_ret_26;
  }

  // SlashExpr 4
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_27 = NULL;
    rec(mod_27);
    // ModExprList Forwarding
    expr_ret_27 = daisho_parse_impldecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_27) rew(mod_27);
    expr_ret_22 = expr_ret_27;
  }

  // SlashExpr 5
  if (!expr_ret_22) {
    daisho_astnode_t* expr_ret_28 = NULL;
    rec(mod_28);
    // ModExprList Forwarding
    expr_ret_28 = daisho_parse_ctypedecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_28) rew(mod_28);
    expr_ret_22 = expr_ret_28;
  }

  // SlashExpr end
  expr_ret_21 = expr_ret_22;

  if (!rule) rule = expr_ret_21;
  if (!expr_ret_21) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule topdecl returned SUCC.\n"), exit(1);
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
  #define rule expr_ret_29
  daisho_astnode_t* expr_ret_29 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
  rec(mod_31);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
    // Not capturing STRUCT.
    expr_ret_31 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_31 = NULL;
  }

  // ModExprList 1
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_32 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_32 = leaf(TYPEIDENT);
      expr_ret_32->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_32->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

    expr_ret_31 = expr_ret_32;
    id = expr_ret_32;
  }

  // ModExprList 2
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_33 = NULL;
    expr_ret_33 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_33)
      expr_ret_33 = SUCC;
    expr_ret_31 = expr_ret_33;
    tmpl = expr_ret_33;
  }

  // ModExprList 3
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_34 = NULL;
    daisho_astnode_t* expr_ret_35 = NULL;
    rec(mod_35);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_35 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_35 = NULL;
    }

    // ModExprList 1
    if (expr_ret_35) {
      expr_ret_35 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList 2
    if (expr_ret_35) {
      daisho_astnode_t* expr_ret_36 = NULL;
      daisho_astnode_t* expr_ret_37 = SUCC;
      while (expr_ret_37)
      {
        rec(kleene_rew_36);
        daisho_astnode_t* expr_ret_38 = NULL;
        rec(mod_38);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_38 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_38 = NULL;
        }

        // ModExprList 1
        if (expr_ret_38) {
          expr_ret_38 = daisho_parse_type(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_38) rew(mod_38);
        expr_ret_37 = expr_ret_38;
      }

      expr_ret_36 = SUCC;
      expr_ret_35 = expr_ret_36;
    }

    // ModExprList end
    if (!expr_ret_35) rew(mod_35);
    expr_ret_34 = expr_ret_35;
    // optional
    if (!expr_ret_34)
      expr_ret_34 = SUCC;
    expr_ret_31 = expr_ret_34;
    impl = expr_ret_34;
  }

  // ModExprList 4
  if (expr_ret_31) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_31 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_39 = NULL;
    // CodeExpr
    #define ret expr_ret_39
    ret = SUCC;
    #line 75 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 3733 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_31 = expr_ret_39;
    members = expr_ret_39;
  }

  // ModExprList 6
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_40 = NULL;
    daisho_astnode_t* expr_ret_41 = SUCC;
    while (expr_ret_41)
    {
      rec(kleene_rew_40);
      daisho_astnode_t* expr_ret_42 = NULL;
      rec(mod_42);
      // ModExprList 0
      daisho_astnode_t* expr_ret_43 = NULL;
      expr_ret_43 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_42 = expr_ret_43;
      m = expr_ret_43;
      // ModExprList 1
      if (expr_ret_42) {
        // CodeExpr
        #define ret expr_ret_42
        ret = SUCC;
        #line 76 "daisho.peg"
        add(members, m);
        #line 3762 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_42) rew(mod_42);
      expr_ret_41 = expr_ret_42;
    }

    expr_ret_40 = SUCC;
    expr_ret_31 = expr_ret_40;
  }

  // ModExprList 7
  if (expr_ret_31) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_31 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_31 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_31) {
    daisho_astnode_t* expr_ret_44 = NULL;
    // CodeExpr
    #define ret expr_ret_44
    ret = SUCC;
    #line 78 "daisho.peg"
    n = node(STRUCT, id, members);
              rule = has(tmpl) ? node(TMPLSTRUCT, tmpl, n) : n;
    #line 3797 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_31 = expr_ret_44;
    n = expr_ret_44;
  }

  // ModExprList end
  if (!expr_ret_31) rew(mod_31);
  expr_ret_30 = expr_ret_31;
  if (!rule) rule = expr_ret_30;
  if (!expr_ret_30) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule structdecl returned SUCC.\n"), exit(1);
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
  #define rule expr_ret_45
  daisho_astnode_t* expr_ret_45 = NULL;
  daisho_astnode_t* expr_ret_46 = NULL;
  daisho_astnode_t* expr_ret_47 = NULL;
  rec(mod_47);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_47 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_47 = NULL;
  }

  // ModExprList 1
  if (expr_ret_47) {
    daisho_astnode_t* expr_ret_48 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_48 = leaf(TYPEIDENT);
      expr_ret_48->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_48->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_48 = NULL;
    }

    expr_ret_47 = expr_ret_48;
    id = expr_ret_48;
  }

  // ModExprList 2
  if (expr_ret_47) {
    daisho_astnode_t* expr_ret_49 = NULL;
    expr_ret_49 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_49)
      expr_ret_49 = SUCC;
    expr_ret_47 = expr_ret_49;
    tmpl = expr_ret_49;
  }

  // ModExprList 3
  if (expr_ret_47) {
    daisho_astnode_t* expr_ret_50 = NULL;
    daisho_astnode_t* expr_ret_51 = NULL;
    rec(mod_51);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_51 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_51 = NULL;
    }

    // ModExprList 1
    if (expr_ret_51) {
      expr_ret_51 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList 2
    if (expr_ret_51) {
      daisho_astnode_t* expr_ret_52 = NULL;
      daisho_astnode_t* expr_ret_53 = SUCC;
      while (expr_ret_53)
      {
        rec(kleene_rew_52);
        daisho_astnode_t* expr_ret_54 = NULL;
        rec(mod_54);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_54 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_54 = NULL;
        }

        // ModExprList 1
        if (expr_ret_54) {
          expr_ret_54 = daisho_parse_type(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_54) rew(mod_54);
        expr_ret_53 = expr_ret_54;
      }

      expr_ret_52 = SUCC;
      expr_ret_51 = expr_ret_52;
    }

    // ModExprList end
    if (!expr_ret_51) rew(mod_51);
    expr_ret_50 = expr_ret_51;
    // optional
    if (!expr_ret_50)
      expr_ret_50 = SUCC;
    expr_ret_47 = expr_ret_50;
    impl = expr_ret_50;
  }

  // ModExprList 4
  if (expr_ret_47) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_47 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_47 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_47) {
    daisho_astnode_t* expr_ret_55 = NULL;
    // CodeExpr
    #define ret expr_ret_55
    ret = SUCC;
    #line 84 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 3947 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_47 = expr_ret_55;
    members = expr_ret_55;
  }

  // ModExprList 6
  if (expr_ret_47) {
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
        #line 85 "daisho.peg"
        add(members, m);
        #line 3976 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_58) rew(mod_58);
      expr_ret_57 = expr_ret_58;
    }

    expr_ret_56 = SUCC;
    expr_ret_47 = expr_ret_56;
  }

  // ModExprList 7
  if (expr_ret_47) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_47 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_47 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_47) {
    daisho_astnode_t* expr_ret_60 = NULL;
    // CodeExpr
    #define ret expr_ret_60
    ret = SUCC;
    #line 87 "daisho.peg"
    n = node(UNION, id, members);
              rule = has(tmpl) ? node(TMPLUNION, tmpl, n) : n;
    #line 4011 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_47 = expr_ret_60;
    n = expr_ret_60;
  }

  // ModExprList end
  if (!expr_ret_47) rew(mod_47);
  expr_ret_46 = expr_ret_47;
  if (!rule) rule = expr_ret_46;
  if (!expr_ret_46) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule uniondecl returned SUCC.\n"), exit(1);
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
  #define rule expr_ret_61
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_62 = NULL;
  daisho_astnode_t* expr_ret_63 = NULL;
  rec(mod_63);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
    expr_ret_63 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_63 = NULL;
  }

  // ModExprList 1
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_64 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_64 = leaf(TYPEIDENT);
      expr_ret_64->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_64->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_64 = NULL;
    }

    expr_ret_63 = expr_ret_64;
    id = expr_ret_64;
  }

  // ModExprList 2
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_65 = NULL;
    expr_ret_65 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_65)
      expr_ret_65 = SUCC;
    expr_ret_63 = expr_ret_65;
    tmpl = expr_ret_65;
  }

  // ModExprList 3
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_66 = NULL;
    daisho_astnode_t* expr_ret_67 = NULL;
    rec(mod_67);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_67 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_67 = NULL;
    }

    // ModExprList 1
    if (expr_ret_67) {
      expr_ret_67 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList 2
    if (expr_ret_67) {
      daisho_astnode_t* expr_ret_68 = NULL;
      daisho_astnode_t* expr_ret_69 = SUCC;
      while (expr_ret_69)
      {
        rec(kleene_rew_68);
        daisho_astnode_t* expr_ret_70 = NULL;
        rec(mod_70);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_70 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_70 = NULL;
        }

        // ModExprList 1
        if (expr_ret_70) {
          expr_ret_70 = daisho_parse_type(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_70) rew(mod_70);
        expr_ret_69 = expr_ret_70;
      }

      expr_ret_68 = SUCC;
      expr_ret_67 = expr_ret_68;
    }

    // ModExprList end
    if (!expr_ret_67) rew(mod_67);
    expr_ret_66 = expr_ret_67;
    // optional
    if (!expr_ret_66)
      expr_ret_66 = SUCC;
    expr_ret_63 = expr_ret_66;
    impl = expr_ret_66;
  }

  // ModExprList 4
  if (expr_ret_63) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_71 = NULL;
    // CodeExpr
    #define ret expr_ret_71
    ret = SUCC;
    #line 93 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4161 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_63 = expr_ret_71;
    members = expr_ret_71;
  }

  // ModExprList 6
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_72 = NULL;
    daisho_astnode_t* expr_ret_73 = SUCC;
    while (expr_ret_73)
    {
      rec(kleene_rew_72);
      daisho_astnode_t* expr_ret_74 = NULL;
      rec(mod_74);
      // ModExprList 0
      daisho_astnode_t* expr_ret_75 = NULL;
      expr_ret_75 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_74 = expr_ret_75;
      m = expr_ret_75;
      // ModExprList 1
      if (expr_ret_74) {
        // CodeExpr
        #define ret expr_ret_74
        ret = SUCC;
        #line 94 "daisho.peg"
        add(members, m);
        #line 4190 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_74) rew(mod_74);
      expr_ret_73 = expr_ret_74;
    }

    expr_ret_72 = SUCC;
    expr_ret_63 = expr_ret_72;
  }

  // ModExprList 7
  if (expr_ret_63) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_76 = NULL;
    // CodeExpr
    #define ret expr_ret_76
    ret = SUCC;
    #line 96 "daisho.peg"
    n = node(TRAIT, id, members);
              rule = has(tmpl) ? node(TMPLTRAIT, tmpl, n) : n;
    #line 4225 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_63 = expr_ret_76;
    n = expr_ret_76;
  }

  // ModExprList end
  if (!expr_ret_63) rew(mod_63);
  expr_ret_62 = expr_ret_63;
  if (!rule) rule = expr_ret_62;
  if (!expr_ret_62) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule traitdecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_77
  daisho_astnode_t* expr_ret_77 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  daisho_astnode_t* expr_ret_79 = NULL;
  rec(mod_79);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_79 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_79 = NULL;
  }

  // ModExprList 1
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_80 = NULL;
    expr_ret_80 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_79 = expr_ret_80;
    rett = expr_ret_80;
  }

  // ModExprList 2
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_81 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_81 = leaf(VARIDENT);
      expr_ret_81->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_81->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_81 = NULL;
    }

    expr_ret_79 = expr_ret_81;
    name = expr_ret_81;
  }

  // ModExprList 3
  if (expr_ret_79) {
    daisho_astnode_t* expr_ret_82 = NULL;
    expr_ret_82 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_82)
      expr_ret_82 = SUCC;
    expr_ret_79 = expr_ret_82;
    e = expr_ret_82;
  }

  // ModExprList 4
  if (expr_ret_79) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_79) {
    expr_ret_79 = daisho_parse_arglist(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 6
  if (expr_ret_79) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_79 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_79 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_79) {
    expr_ret_79 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList end
  if (!expr_ret_79) rew(mod_79);
  expr_ret_78 = expr_ret_79;
  if (!rule) rule = expr_ret_78;
  if (!expr_ret_78) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fndecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rett = NULL;
  daisho_astnode_t* name = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_83
  daisho_astnode_t* expr_ret_83 = NULL;
  daisho_astnode_t* expr_ret_84 = NULL;
  daisho_astnode_t* expr_ret_85 = NULL;
  rec(mod_85);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_85 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_85 = NULL;
  }

  // ModExprList 1
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_86 = NULL;
    expr_ret_86 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_85 = expr_ret_86;
    rett = expr_ret_86;
  }

  // ModExprList 2
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_87 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_87 = leaf(VARIDENT);
      expr_ret_87->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_87->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_87 = NULL;
    }

    expr_ret_85 = expr_ret_87;
    name = expr_ret_87;
  }

  // ModExprList 3
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_88 = NULL;
    expr_ret_88 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_88)
      expr_ret_88 = SUCC;
    expr_ret_85 = expr_ret_88;
    e = expr_ret_88;
  }

  // ModExprList 4
  if (expr_ret_85) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_85) {
    expr_ret_85 = daisho_parse_protolist(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 6
  if (expr_ret_85) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  // ModExprList 7
  if (expr_ret_85) {
    expr_ret_85 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList end
  if (!expr_ret_85) rew(mod_85);
  expr_ret_84 = expr_ret_85;
  if (!rule) rule = expr_ret_84;
  if (!expr_ret_84) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnproto returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_89
  daisho_astnode_t* expr_ret_89 = NULL;
  daisho_astnode_t* expr_ret_90 = NULL;
  daisho_astnode_t* expr_ret_91 = NULL;
  rec(mod_91);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_91 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_91 = NULL;
  }

  // ModExprList 1
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_92 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_92 = leaf(TYPEIDENT);
      expr_ret_92->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_92->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_92 = NULL;
    }

    expr_ret_91 = expr_ret_92;
    tt = expr_ret_92;
  }

  // ModExprList 2
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_93 = NULL;
    expr_ret_93 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_93)
      expr_ret_93 = SUCC;
    expr_ret_91 = expr_ret_93;
  }

  // ModExprList 3
  if (expr_ret_91) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_91 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_94 = NULL;
    expr_ret_94 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_91 = expr_ret_94;
    ft = expr_ret_94;
  }

  // ModExprList 5
  if (expr_ret_91) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_91 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_95 = NULL;
    // CodeExpr
    #define ret expr_ret_95
    ret = SUCC;
    #line 106 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4534 "daisho_tokenizer_parser.h"

    #undef ret
    expr_ret_91 = expr_ret_95;
    members = expr_ret_95;
  }

  // ModExprList 7
  if (expr_ret_91) {
    daisho_astnode_t* expr_ret_96 = NULL;
    daisho_astnode_t* expr_ret_97 = SUCC;
    while (expr_ret_97)
    {
      rec(kleene_rew_96);
      daisho_astnode_t* expr_ret_98 = NULL;
      rec(mod_98);
      // ModExprList 0
      daisho_astnode_t* expr_ret_99 = NULL;
      expr_ret_99 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_98 = expr_ret_99;
      m = expr_ret_99;
      // ModExprList 1
      if (expr_ret_98) {
        // CodeExpr
        #define ret expr_ret_98
        ret = SUCC;
        #line 107 "daisho.peg"
        add(members, m);
        #line 4563 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_98) rew(mod_98);
      expr_ret_97 = expr_ret_98;
    }

    expr_ret_96 = SUCC;
    expr_ret_91 = expr_ret_96;
  }

  // ModExprList 8
  if (expr_ret_91) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_91 = leaf(RCBRACK);
      expr_ret_91->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_91->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_91 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_91) rew(mod_91);
  expr_ret_90 = expr_ret_91;
  if (!rule) rule = expr_ret_90;
  if (!expr_ret_90) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule impldecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_100
  daisho_astnode_t* expr_ret_100 = NULL;
  daisho_astnode_t* expr_ret_101 = NULL;
  daisho_astnode_t* expr_ret_102 = NULL;
  rec(mod_102);
  // ModExprList 0
  daisho_astnode_t* expr_ret_103 = NULL;
  expr_ret_103 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_102 = expr_ret_103;
  t = expr_ret_103;
  // ModExprList 1
  if (expr_ret_102) {
    daisho_astnode_t* expr_ret_104 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_104 = leaf(VARIDENT);
      expr_ret_104->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_104->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

    expr_ret_102 = expr_ret_104;
    v = expr_ret_104;
  }

  // ModExprList 2
  if (expr_ret_102) {
    // CodeExpr
    #define ret expr_ret_102
    ret = SUCC;
    #line 111 "daisho.peg"
    rule=node(TYPEMEMBER, t, v);
    #line 4639 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_102) rew(mod_102);
  expr_ret_101 = expr_ret_102;
  if (!rule) rule = expr_ret_101;
  if (!expr_ret_101) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typemember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_105
  daisho_astnode_t* expr_ret_105 = NULL;
  daisho_astnode_t* expr_ret_106 = NULL;
  daisho_astnode_t* expr_ret_107 = NULL;

  // SlashExpr 0
  if (!expr_ret_107) {
    daisho_astnode_t* expr_ret_108 = NULL;
    rec(mod_108);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_109 = NULL;
    expr_ret_109 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_108 = expr_ret_109;
    rule = expr_ret_109;
    // ModExprList end
    if (!expr_ret_108) rew(mod_108);
    expr_ret_107 = expr_ret_108;
  }

  // SlashExpr 1
  if (!expr_ret_107) {
    daisho_astnode_t* expr_ret_110 = NULL;
    rec(mod_110);
    // ModExprList 0
    daisho_astnode_t* expr_ret_111 = NULL;
    expr_ret_111 = daisho_parse_fnproto(ctx);
    if (ctx->exit) return NULL;
    expr_ret_110 = expr_ret_111;
    rule = expr_ret_111;
    // ModExprList 1
    if (expr_ret_110) {
      expr_ret_110 = daisho_parse_wsemi(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList end
    if (!expr_ret_110) rew(mod_110);
    expr_ret_107 = expr_ret_110;
  }

  // SlashExpr end
  expr_ret_106 = expr_ret_107;

  if (!rule) rule = expr_ret_106;
  if (!expr_ret_106) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnmember returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_112
  daisho_astnode_t* expr_ret_112 = NULL;
  daisho_astnode_t* expr_ret_113 = NULL;
  daisho_astnode_t* expr_ret_114 = NULL;
  rec(mod_114);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
    // Not capturing LT.
    expr_ret_114 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_114 = NULL;
  }

  // ModExprList 1
  if (expr_ret_114) {
    daisho_astnode_t* expr_ret_115 = NULL;
    expr_ret_115 = daisho_parse_typelist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_114 = expr_ret_115;
    rule = expr_ret_115;
  }

  // ModExprList 2
  if (expr_ret_114) {
    // CodeExpr
    #define ret expr_ret_114
    ret = SUCC;
    #line 116 "daisho.peg"
    rule->kind=kind(TMPLEXPAND);
    #line 4739 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_114) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_114 = leaf(GT);
      expr_ret_114->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_114->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_114 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_114) rew(mod_114);
  expr_ret_113 = expr_ret_114;
  if (!rule) rule = expr_ret_113;
  if (!expr_ret_113) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tmplexpand returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  #define rule expr_ret_116
  daisho_astnode_t* expr_ret_116 = NULL;
  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_118 = NULL;
  rec(mod_118);
  // ModExprList Forwarding
  expr_ret_118 = daisho_parse_fntype(ctx);
  if (ctx->exit) return NULL;
  // ModExprList end
  if (!expr_ret_118) rew(mod_118);
  expr_ret_117 = expr_ret_118;
  if (!rule) rule = expr_ret_117;
  if (!expr_ret_117) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule type returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* from = NULL;
  daisho_astnode_t* to = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_119
  daisho_astnode_t* expr_ret_119 = NULL;
  daisho_astnode_t* expr_ret_120 = NULL;
  daisho_astnode_t* expr_ret_121 = NULL;
  rec(mod_121);
  // ModExprList 0
  daisho_astnode_t* expr_ret_122 = NULL;
  // CodeExpr
  #define ret expr_ret_122
  ret = SUCC;
  #line 146 "daisho.peg"
  ;
  #line 4803 "daisho_tokenizer_parser.h"

  #undef ret
  expr_ret_121 = expr_ret_122;
  from = expr_ret_122;
  // ModExprList 1
  if (expr_ret_121) {
    daisho_astnode_t* expr_ret_123 = NULL;
    expr_ret_123 = daisho_parse_ptrtype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_121 = expr_ret_123;
    to = expr_ret_123;
  }

  // ModExprList 2
  if (expr_ret_121) {
    daisho_astnode_t* expr_ret_124 = NULL;
    daisho_astnode_t* expr_ret_125 = SUCC;
    while (expr_ret_125)
    {
      rec(kleene_rew_124);
      daisho_astnode_t* expr_ret_126 = NULL;
      rec(mod_126);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_126 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_126 = NULL;
      }

      // ModExprList 1
      if (expr_ret_126) {
        daisho_astnode_t* expr_ret_127 = NULL;
        expr_ret_127 = daisho_parse_ptrtype(ctx);
        if (ctx->exit) return NULL;
        expr_ret_126 = expr_ret_127;
        n = expr_ret_127;
      }

      // ModExprList 2
      if (expr_ret_126) {
        // CodeExpr
        #define ret expr_ret_126
        ret = SUCC;
        #line 148 "daisho.peg"
        if (!has(from)) from = list(TYPELIST);
        #line 4851 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList 3
      if (expr_ret_126) {
        // CodeExpr
        #define ret expr_ret_126
        ret = SUCC;
        #line 149 "daisho.peg"
        add(from, to); to = n;
        #line 4863 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_126) rew(mod_126);
      expr_ret_125 = expr_ret_126;
    }

    expr_ret_124 = SUCC;
    expr_ret_121 = expr_ret_124;
  }

  // ModExprList 3
  if (expr_ret_121) {
    // CodeExpr
    #define ret expr_ret_121
    ret = SUCC;
    #line 150 "daisho.peg"
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #line 4884 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_121) rew(mod_121);
  expr_ret_120 = expr_ret_121;
  if (!rule) rule = expr_ret_120;
  if (!expr_ret_120) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fntype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_128
  daisho_astnode_t* expr_ret_128 = NULL;
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_130 = NULL;
  rec(mod_130);
  // ModExprList 0
  daisho_astnode_t* expr_ret_131 = NULL;
  expr_ret_131 = daisho_parse_basetype(ctx);
  if (ctx->exit) return NULL;
  expr_ret_130 = expr_ret_131;
  rule = expr_ret_131;
  // ModExprList 1
  if (expr_ret_130) {
    daisho_astnode_t* expr_ret_132 = NULL;
    daisho_astnode_t* expr_ret_133 = SUCC;
    while (expr_ret_133)
    {
      rec(kleene_rew_132);
      daisho_astnode_t* expr_ret_134 = NULL;
      rec(mod_134);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_134 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_134 = NULL;
      }

      // ModExprList 1
      if (expr_ret_134) {
        // CodeExpr
        #define ret expr_ret_134
        ret = SUCC;
        #line 152 "daisho.peg"
        rule=node(PTRTYPE, rule);
        #line 4937 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_134) rew(mod_134);
      expr_ret_133 = expr_ret_134;
    }

    expr_ret_132 = SUCC;
    expr_ret_130 = expr_ret_132;
  }

  // ModExprList end
  if (!expr_ret_130) rew(mod_130);
  expr_ret_129 = expr_ret_130;
  if (!rule) rule = expr_ret_129;
  if (!expr_ret_129) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ptrtype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_135
  daisho_astnode_t* expr_ret_135 = NULL;
  daisho_astnode_t* expr_ret_136 = NULL;
  daisho_astnode_t* expr_ret_137 = NULL;

  // SlashExpr 0
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_138 = NULL;
    rec(mod_138);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_138 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_138 = NULL;
    }

    // ModExprList 1
    if (expr_ret_138) {
      daisho_astnode_t* expr_ret_139 = NULL;
      expr_ret_139 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_138 = expr_ret_139;
      rule = expr_ret_139;
    }

    // ModExprList 2
    if (expr_ret_138) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_138 = leaf(CLOSE);
        expr_ret_138->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_138->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_138 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_138) rew(mod_138);
    expr_ret_137 = expr_ret_138;
  }

  // SlashExpr 1
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_140 = NULL;
    rec(mod_140);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
      // Capturing SELFTYPE.
      expr_ret_140 = leaf(SELFTYPE);
      expr_ret_140->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_140->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_140 = NULL;
    }

    // ModExprList end
    if (!expr_ret_140) rew(mod_140);
    expr_ret_137 = expr_ret_140;
  }

  // SlashExpr 2
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_141 = NULL;
    rec(mod_141);
    // ModExprList 0
    daisho_astnode_t* expr_ret_142 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_142 = leaf(VOIDTYPE);
      expr_ret_142->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_142->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_142 = NULL;
    }

    expr_ret_141 = expr_ret_142;
    v = expr_ret_142;
    // ModExprList 1
    if (expr_ret_141) {
      rec(mexpr_state_143)
      daisho_astnode_t* expr_ret_143 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_143 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_143 = NULL;
      }

      // invert
      expr_ret_143 = expr_ret_143 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_143);
      expr_ret_141 = expr_ret_143;
    }

    // ModExprList 2
    if (expr_ret_141) {
      // CodeExpr
      #define ret expr_ret_141
      ret = SUCC;
      #line 156 "daisho.peg"
      rule=v;
      #line 5076 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_141) rew(mod_141);
    expr_ret_137 = expr_ret_141;
  }

  // SlashExpr 3
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_144 = NULL;
    rec(mod_144);
    // ModExprList Forwarding
    expr_ret_144 = daisho_parse_voidptr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_144) rew(mod_144);
    expr_ret_137 = expr_ret_144;
  }

  // SlashExpr 4
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_145 = NULL;
    rec(mod_145);
    // ModExprList Forwarding
    expr_ret_145 = daisho_parse_ctypedecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_145) rew(mod_145);
    expr_ret_137 = expr_ret_145;
  }

  // SlashExpr 5
  if (!expr_ret_137) {
    daisho_astnode_t* expr_ret_146 = NULL;
    rec(mod_146);
    // ModExprList 0
    daisho_astnode_t* expr_ret_147 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_147 = leaf(TYPEIDENT);
      expr_ret_147->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_147->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_147 = NULL;
    }

    expr_ret_146 = expr_ret_147;
    s = expr_ret_147;
    // ModExprList 1
    if (expr_ret_146) {
      daisho_astnode_t* expr_ret_148 = NULL;
      expr_ret_148 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      // optional
      if (!expr_ret_148)
        expr_ret_148 = SUCC;
      expr_ret_146 = expr_ret_148;
      t = expr_ret_148;
    }

    // ModExprList 2
    if (expr_ret_146) {
      // CodeExpr
      #define ret expr_ret_146
      ret = SUCC;
      #line 159 "daisho.peg"
      rule=has(t) ? node(TMPLTYPE, t, s) : s;
      #line 5147 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_146) rew(mod_146);
    expr_ret_137 = expr_ret_146;
  }

  // SlashExpr end
  expr_ret_136 = expr_ret_137;

  if (!rule) rule = expr_ret_136;
  if (!expr_ret_136) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule basetype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_149
  daisho_astnode_t* expr_ret_149 = NULL;
  daisho_astnode_t* expr_ret_150 = NULL;
  daisho_astnode_t* expr_ret_151 = NULL;

  // SlashExpr 0
  if (!expr_ret_151) {
    daisho_astnode_t* expr_ret_152 = NULL;
    rec(mod_152);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_152 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_152 = NULL;
    }

    // ModExprList 1
    if (expr_ret_152) {
      daisho_astnode_t* expr_ret_153 = NULL;
      expr_ret_153 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_152 = expr_ret_153;
      t = expr_ret_153;
    }

    // ModExprList 2
    if (expr_ret_152) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_152 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_152 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_152) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_152 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_152 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_152) {
      // CodeExpr
      #define ret expr_ret_152
      ret = SUCC;
      #line 162 "daisho.peg"
      rule=node(TUPLETYPE, t);
      #line 5227 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_152) rew(mod_152);
    expr_ret_151 = expr_ret_152;
  }

  // SlashExpr 1
  if (!expr_ret_151) {
    daisho_astnode_t* expr_ret_154 = NULL;
    rec(mod_154);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_154 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_154 = NULL;
    }

    // ModExprList 1
    if (expr_ret_154) {
      daisho_astnode_t* expr_ret_155 = NULL;
      expr_ret_155 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_154 = expr_ret_155;
      rule = expr_ret_155;
    }

    // ModExprList 2
    if (expr_ret_154) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_154 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_154 = NULL;
      }

    }

    // ModExprList 3
    if (expr_ret_154) {
      // CodeExpr
      #define ret expr_ret_154
      ret = SUCC;
      #line 163 "daisho.peg"
      rule->kind = kind(TUPLETYPE);
      #line 5278 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_154) rew(mod_154);
    expr_ret_151 = expr_ret_154;
  }

  // SlashExpr end
  expr_ret_150 = expr_ret_151;

  if (!rule) rule = expr_ret_150;
  if (!expr_ret_150) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tupletype returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_156
  daisho_astnode_t* expr_ret_156 = NULL;
  daisho_astnode_t* expr_ret_157 = NULL;
  daisho_astnode_t* expr_ret_158 = NULL;

  // SlashExpr 0
  if (!expr_ret_158) {
    daisho_astnode_t* expr_ret_159 = NULL;
    rec(mod_159);
    // ModExprList 0
    daisho_astnode_t* expr_ret_160 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_160 = leaf(VOIDPTR);
      expr_ret_160->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_160->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_160 = NULL;
    }

    expr_ret_159 = expr_ret_160;
    v = expr_ret_160;
    // ModExprList 1
    if (expr_ret_159) {
      // CodeExpr
      #define ret expr_ret_159
      ret = SUCC;
      #line 165 "daisho.peg"
      rule=v;
      #line 5331 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_159) rew(mod_159);
    expr_ret_158 = expr_ret_159;
  }

  // SlashExpr 1
  if (!expr_ret_158) {
    daisho_astnode_t* expr_ret_161 = NULL;
    rec(mod_161);
    // ModExprList 0
    daisho_astnode_t* expr_ret_162 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_162 = leaf(VOIDTYPE);
      expr_ret_162->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_162->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_162 = NULL;
    }

    expr_ret_161 = expr_ret_162;
    v = expr_ret_162;
    // ModExprList 1
    if (expr_ret_161) {
      daisho_astnode_t* expr_ret_163 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_163 = leaf(STAR);
        expr_ret_163->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_163->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_163 = NULL;
      }

      expr_ret_161 = expr_ret_163;
      s = expr_ret_163;
    }

    // ModExprList 2
    if (expr_ret_161) {
      // CodeExpr
      #define ret expr_ret_161
      ret = SUCC;
      #line 166 "daisho.peg"
      rule=leaf(VOIDPTR);
      #line 5383 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_161) rew(mod_161);
    expr_ret_158 = expr_ret_161;
  }

  // SlashExpr end
  expr_ret_157 = expr_ret_158;

  if (!rule) rule = expr_ret_157;
  if (!expr_ret_157) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule voidptr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_164
  daisho_astnode_t* expr_ret_164 = NULL;
  daisho_astnode_t* expr_ret_165 = NULL;
  daisho_astnode_t* expr_ret_166 = NULL;
  rec(mod_166);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_166 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_166 = NULL;
  }

  // ModExprList 1
  if (expr_ret_166) {
    daisho_astnode_t* expr_ret_167 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_167 = leaf(TYPEIDENT);
      expr_ret_167->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_167->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_167 = NULL;
    }

    expr_ret_166 = expr_ret_167;
    i = expr_ret_167;
  }

  // ModExprList 2
  if (expr_ret_166) {
    daisho_astnode_t* expr_ret_168 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Capturing CIDENT.
      expr_ret_168 = leaf(CIDENT);
      expr_ret_168->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_168->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_168 = NULL;
    }

    expr_ret_166 = expr_ret_168;
    c = expr_ret_168;
  }

  // ModExprList 3
  if (expr_ret_166) {
    // CodeExpr
    #define ret expr_ret_166
    ret = SUCC;
    #line 169 "daisho.peg"
    rule=node(CTYPEDECL, i, c);
    #line 5461 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_166) rew(mod_166);
  expr_ret_165 = expr_ret_166;
  if (!rule) rule = expr_ret_165;
  if (!expr_ret_165) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ctypedecl returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_169
  daisho_astnode_t* expr_ret_169 = NULL;
  daisho_astnode_t* expr_ret_170 = NULL;
  daisho_astnode_t* expr_ret_171 = NULL;
  rec(mod_171);
  // ModExprList 0
  daisho_astnode_t* expr_ret_172 = NULL;
  expr_ret_172 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_172)
    expr_ret_172 = SUCC;
  expr_ret_171 = expr_ret_172;
  // ModExprList 1
  if (expr_ret_171) {
    // CodeExpr
    #define ret expr_ret_171
    ret = SUCC;
    #line 239 "daisho.peg"
    rule=list(TYPELIST);
    #line 5498 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_171) {
    daisho_astnode_t* expr_ret_173 = NULL;
    expr_ret_173 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_173)
      expr_ret_173 = SUCC;
    expr_ret_171 = expr_ret_173;
    t = expr_ret_173;
  }

  // ModExprList 3
  if (expr_ret_171) {
    // CodeExpr
    #define ret expr_ret_171
    ret = SUCC;
    #line 240 "daisho.peg"
    if has(t) add(rule, t);
    #line 5522 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_171) {
    daisho_astnode_t* expr_ret_174 = NULL;
    daisho_astnode_t* expr_ret_175 = SUCC;
    while (expr_ret_175)
    {
      rec(kleene_rew_174);
      daisho_astnode_t* expr_ret_176 = NULL;
      rec(mod_176);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
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
        t = expr_ret_177;
      }

      // ModExprList 2
      if (expr_ret_176) {
        // CodeExpr
        #define ret expr_ret_176
        ret = SUCC;
        #line 241 "daisho.peg"
        add(rule, t);
        #line 5561 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_176) rew(mod_176);
      expr_ret_175 = expr_ret_176;
    }

    expr_ret_174 = SUCC;
    expr_ret_171 = expr_ret_174;
  }

  // ModExprList 5
  if (expr_ret_171) {
    daisho_astnode_t* expr_ret_178 = NULL;
    expr_ret_178 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_178)
      expr_ret_178 = SUCC;
    expr_ret_171 = expr_ret_178;
  }

  // ModExprList end
  if (!expr_ret_171) rew(mod_171);
  expr_ret_170 = expr_ret_171;
  if (!rule) rule = expr_ret_170;
  if (!expr_ret_170) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule typelist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_179
  daisho_astnode_t* expr_ret_179 = NULL;
  daisho_astnode_t* expr_ret_180 = NULL;
  daisho_astnode_t* expr_ret_181 = NULL;
  rec(mod_181);
  // ModExprList 0
  daisho_astnode_t* expr_ret_182 = NULL;
  expr_ret_182 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_182)
    expr_ret_182 = SUCC;
  expr_ret_181 = expr_ret_182;
  // ModExprList 1
  if (expr_ret_181) {
    // CodeExpr
    #define ret expr_ret_181
    ret = SUCC;
    #line 243 "daisho.peg"
    rule=list(EXPRLIST);
    #line 5618 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_181) {
    daisho_astnode_t* expr_ret_183 = NULL;
    expr_ret_183 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_183)
      expr_ret_183 = SUCC;
    expr_ret_181 = expr_ret_183;
    e = expr_ret_183;
  }

  // ModExprList 3
  if (expr_ret_181) {
    // CodeExpr
    #define ret expr_ret_181
    ret = SUCC;
    #line 244 "daisho.peg"
    if has(e) add(rule, e);
    #line 5642 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_181) {
    daisho_astnode_t* expr_ret_184 = NULL;
    daisho_astnode_t* expr_ret_185 = SUCC;
    while (expr_ret_185)
    {
      rec(kleene_rew_184);
      daisho_astnode_t* expr_ret_186 = NULL;
      rec(mod_186);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_186 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_186 = NULL;
      }

      // ModExprList 1
      if (expr_ret_186) {
        daisho_astnode_t* expr_ret_187 = NULL;
        expr_ret_187 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_186 = expr_ret_187;
        e = expr_ret_187;
      }

      // ModExprList 2
      if (expr_ret_186) {
        // CodeExpr
        #define ret expr_ret_186
        ret = SUCC;
        #line 245 "daisho.peg"
        add(rule, e);
        #line 5681 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_186) rew(mod_186);
      expr_ret_185 = expr_ret_186;
    }

    expr_ret_184 = SUCC;
    expr_ret_181 = expr_ret_184;
  }

  // ModExprList 5
  if (expr_ret_181) {
    daisho_astnode_t* expr_ret_188 = NULL;
    expr_ret_188 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_188)
      expr_ret_188 = SUCC;
    expr_ret_181 = expr_ret_188;
  }

  // ModExprList end
  if (!expr_ret_181) rew(mod_181);
  expr_ret_180 = expr_ret_181;
  if (!rule) rule = expr_ret_180;
  if (!expr_ret_180) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule exprlist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_189
  daisho_astnode_t* expr_ret_189 = NULL;
  daisho_astnode_t* expr_ret_190 = NULL;
  daisho_astnode_t* expr_ret_191 = NULL;
  rec(mod_191);
  // ModExprList 0
  daisho_astnode_t* expr_ret_192 = NULL;
  expr_ret_192 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_191 = expr_ret_192;
  t = expr_ret_192;
  // ModExprList 1
  if (expr_ret_191) {
    daisho_astnode_t* expr_ret_193 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_193 = leaf(VARIDENT);
      expr_ret_193->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_193->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_193 = NULL;
    }

    expr_ret_191 = expr_ret_193;
    i = expr_ret_193;
  }

  // ModExprList 2
  if (expr_ret_191) {
    // CodeExpr
    #define ret expr_ret_191
    ret = SUCC;
    #line 248 "daisho.peg"
    rule=node(FNARG, t, i);
    #line 5754 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_191) rew(mod_191);
  expr_ret_190 = expr_ret_191;
  if (!rule) rule = expr_ret_190;
  if (!expr_ret_190) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fnarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_194
  daisho_astnode_t* expr_ret_194 = NULL;
  daisho_astnode_t* expr_ret_195 = NULL;
  daisho_astnode_t* expr_ret_196 = NULL;
  rec(mod_196);
  // ModExprList 0
  daisho_astnode_t* expr_ret_197 = NULL;
  expr_ret_197 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_197)
    expr_ret_197 = SUCC;
  expr_ret_196 = expr_ret_197;
  // ModExprList 1
  if (expr_ret_196) {
    // CodeExpr
    #define ret expr_ret_196
    ret = SUCC;
    #line 249 "daisho.peg"
    rule=list(ARGLIST);
    #line 5791 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_196) {
    daisho_astnode_t* expr_ret_198 = NULL;
    expr_ret_198 = daisho_parse_fnarg(ctx);
    if (ctx->exit) return NULL;
    expr_ret_196 = expr_ret_198;
    a = expr_ret_198;
  }

  // ModExprList 3
  if (expr_ret_196) {
    // CodeExpr
    #define ret expr_ret_196
    ret = SUCC;
    #line 250 "daisho.peg"
    if has(a) add(rule, a);
    #line 5812 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_196) {
    daisho_astnode_t* expr_ret_199 = NULL;
    daisho_astnode_t* expr_ret_200 = SUCC;
    while (expr_ret_200)
    {
      rec(kleene_rew_199);
      daisho_astnode_t* expr_ret_201 = NULL;
      rec(mod_201);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_201 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_201 = NULL;
      }

      // ModExprList 1
      if (expr_ret_201) {
        daisho_astnode_t* expr_ret_202 = NULL;
        expr_ret_202 = daisho_parse_fnarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_201 = expr_ret_202;
        a = expr_ret_202;
      }

      // ModExprList 2
      if (expr_ret_201) {
        // CodeExpr
        #define ret expr_ret_201
        ret = SUCC;
        #line 251 "daisho.peg"
        add(rule, a);
        #line 5851 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_201) rew(mod_201);
      expr_ret_200 = expr_ret_201;
    }

    expr_ret_199 = SUCC;
    expr_ret_196 = expr_ret_199;
  }

  // ModExprList 5
  if (expr_ret_196) {
    daisho_astnode_t* expr_ret_203 = NULL;
    expr_ret_203 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_203)
      expr_ret_203 = SUCC;
    expr_ret_196 = expr_ret_203;
  }

  // ModExprList end
  if (!expr_ret_196) rew(mod_196);
  expr_ret_195 = expr_ret_196;
  if (!rule) rule = expr_ret_195;
  if (!expr_ret_195) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule arglist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_204
  daisho_astnode_t* expr_ret_204 = NULL;
  daisho_astnode_t* expr_ret_205 = NULL;
  daisho_astnode_t* expr_ret_206 = NULL;
  rec(mod_206);
  // ModExprList 0
  daisho_astnode_t* expr_ret_207 = NULL;
  expr_ret_207 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_206 = expr_ret_207;
  t = expr_ret_207;
  // ModExprList 1
  if (expr_ret_206) {
    daisho_astnode_t* expr_ret_208 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_208 = leaf(VARIDENT);
      expr_ret_208->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_208->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_208 = NULL;
    }

    // optional
    if (!expr_ret_208)
      expr_ret_208 = SUCC;
    expr_ret_206 = expr_ret_208;
    i = expr_ret_208;
  }

  // ModExprList 2
  if (expr_ret_206) {
    // CodeExpr
    #define ret expr_ret_206
    ret = SUCC;
    #line 254 "daisho.peg"
    rule=has(i) ? node(PROTOARG, t, i) : node(PROTOARG, t);
    #line 5927 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_206) rew(mod_206);
  expr_ret_205 = expr_ret_206;
  if (!rule) rule = expr_ret_205;
  if (!expr_ret_205) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protoarg returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protolist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_209
  daisho_astnode_t* expr_ret_209 = NULL;
  daisho_astnode_t* expr_ret_210 = NULL;
  daisho_astnode_t* expr_ret_211 = NULL;
  rec(mod_211);
  // ModExprList 0
  daisho_astnode_t* expr_ret_212 = NULL;
  expr_ret_212 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_212)
    expr_ret_212 = SUCC;
  expr_ret_211 = expr_ret_212;
  // ModExprList 1
  if (expr_ret_211) {
    // CodeExpr
    #define ret expr_ret_211
    ret = SUCC;
    #line 255 "daisho.peg"
    rule=list(PROTOLIST);
    #line 5964 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_211) {
    daisho_astnode_t* expr_ret_213 = NULL;
    expr_ret_213 = daisho_parse_protoarg(ctx);
    if (ctx->exit) return NULL;
    expr_ret_211 = expr_ret_213;
    p = expr_ret_213;
  }

  // ModExprList 3
  if (expr_ret_211) {
    // CodeExpr
    #define ret expr_ret_211
    ret = SUCC;
    #line 256 "daisho.peg"
    if has(p) add(rule, p);
    #line 5985 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_211) {
    daisho_astnode_t* expr_ret_214 = NULL;
    daisho_astnode_t* expr_ret_215 = SUCC;
    while (expr_ret_215)
    {
      rec(kleene_rew_214);
      daisho_astnode_t* expr_ret_216 = NULL;
      rec(mod_216);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_216 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_216 = NULL;
      }

      // ModExprList 1
      if (expr_ret_216) {
        daisho_astnode_t* expr_ret_217 = NULL;
        expr_ret_217 = daisho_parse_protoarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_216 = expr_ret_217;
        p = expr_ret_217;
      }

      // ModExprList 2
      if (expr_ret_216) {
        // CodeExpr
        #define ret expr_ret_216
        ret = SUCC;
        #line 257 "daisho.peg"
        add(rule, p);
        #line 6024 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_216) rew(mod_216);
      expr_ret_215 = expr_ret_216;
    }

    expr_ret_214 = SUCC;
    expr_ret_211 = expr_ret_214;
  }

  // ModExprList 5
  if (expr_ret_211) {
    daisho_astnode_t* expr_ret_218 = NULL;
    expr_ret_218 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_218)
      expr_ret_218 = SUCC;
    expr_ret_211 = expr_ret_218;
  }

  // ModExprList end
  if (!expr_ret_211) rew(mod_211);
  expr_ret_210 = expr_ret_211;
  if (!rule) rule = expr_ret_210;
  if (!expr_ret_210) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule protolist returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_219
  daisho_astnode_t* expr_ret_219 = NULL;
  daisho_astnode_t* expr_ret_220 = NULL;
  daisho_astnode_t* expr_ret_221 = NULL;
  rec(mod_221);
  // ModExprList Forwarding
  expr_ret_221 = daisho_parse_preretexpr(ctx);
  if (ctx->exit) return NULL;
  // ModExprList end
  if (!expr_ret_221) rew(mod_221);
  expr_ret_220 = expr_ret_221;
  if (!rule) rule = expr_ret_220;
  if (!expr_ret_220) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule expr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_222
  daisho_astnode_t* expr_ret_222 = NULL;
  daisho_astnode_t* expr_ret_223 = NULL;
  daisho_astnode_t* expr_ret_224 = NULL;

  // SlashExpr 0
  if (!expr_ret_224) {
    daisho_astnode_t* expr_ret_225 = NULL;
    rec(mod_225);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Not capturing RET.
      expr_ret_225 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_225 = NULL;
    }

    // ModExprList 1
    if (expr_ret_225) {
      daisho_astnode_t* expr_ret_226 = NULL;
      expr_ret_226 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_225 = expr_ret_226;
      n = expr_ret_226;
    }

    // ModExprList 2
    if (expr_ret_225) {
      // CodeExpr
      #define ret expr_ret_225
      ret = SUCC;
      #line 305 "daisho.peg"
      rule=node(RET, n);
      #line 6114 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_225) rew(mod_225);
    expr_ret_224 = expr_ret_225;
  }

  // SlashExpr 1
  if (!expr_ret_224) {
    daisho_astnode_t* expr_ret_227 = NULL;
    rec(mod_227);
    // ModExprList 0
    daisho_astnode_t* expr_ret_228 = NULL;
    expr_ret_228 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_227 = expr_ret_228;
    rule = expr_ret_228;
    // ModExprList 1
    if (expr_ret_227) {
      daisho_astnode_t* expr_ret_229 = NULL;
      daisho_astnode_t* expr_ret_230 = NULL;
      rec(mod_230);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Not capturing GRAVE.
        expr_ret_230 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_230 = NULL;
      }

      // ModExprList 1
      if (expr_ret_230) {
        // CodeExpr
        #define ret expr_ret_230
        ret = SUCC;
        #line 306 "daisho.peg"
        rule = node(RET, rule);
        #line 6155 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_230) rew(mod_230);
      expr_ret_229 = expr_ret_230;
      // optional
      if (!expr_ret_229)
        expr_ret_229 = SUCC;
      expr_ret_227 = expr_ret_229;
    }

    // ModExprList end
    if (!expr_ret_227) rew(mod_227);
    expr_ret_224 = expr_ret_227;
  }

  // SlashExpr end
  expr_ret_223 = expr_ret_224;

  if (!rule) rule = expr_ret_223;
  if (!expr_ret_223) rule = NULL;
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
  #define rule expr_ret_231
  daisho_astnode_t* expr_ret_231 = NULL;
  daisho_astnode_t* expr_ret_232 = NULL;
  daisho_astnode_t* expr_ret_233 = NULL;

  // SlashExpr 0
  if (!expr_ret_233) {
    daisho_astnode_t* expr_ret_234 = NULL;
    rec(mod_234);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_234 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_234 = NULL;
    }

    // ModExprList 1
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_235 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_235 = leaf(OPEN);
        expr_ret_235->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_235->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_235 = NULL;
      }

      // optional
      if (!expr_ret_235)
        expr_ret_235 = SUCC;
      expr_ret_234 = expr_ret_235;
      o = expr_ret_235;
    }

    // ModExprList 2
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_236 = NULL;
      expr_ret_236 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_234 = expr_ret_236;
      f = expr_ret_236;
    }

    // ModExprList 3
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_237 = NULL;

      // SlashExpr 0
      if (!expr_ret_237) {
        daisho_astnode_t* expr_ret_238 = NULL;
        rec(mod_238);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_239 = NULL;

        // SlashExpr 0
        if (!expr_ret_239) {
          daisho_astnode_t* expr_ret_240 = NULL;
          rec(mod_240);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_240 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_240 = NULL;
          }

          // ModExprList end
          if (!expr_ret_240) rew(mod_240);
          expr_ret_239 = expr_ret_240;
        }

        // SlashExpr 1
        if (!expr_ret_239) {
          daisho_astnode_t* expr_ret_241 = NULL;
          rec(mod_241);
          // ModExprList Forwarding
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_241 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_241 = NULL;
          }

          // ModExprList end
          if (!expr_ret_241) rew(mod_241);
          expr_ret_239 = expr_ret_241;
        }

        // SlashExpr end
        expr_ret_238 = expr_ret_239;

        // ModExprList end
        if (!expr_ret_238) rew(mod_238);
        expr_ret_237 = expr_ret_238;
      }

      // SlashExpr 1
      if (!expr_ret_237) {
        daisho_astnode_t* expr_ret_242 = NULL;
        rec(mod_242);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_243 = NULL;
        rec(mod_243);
        // ModExprList 0
        expr_ret_243 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_243) {
          daisho_astnode_t* expr_ret_244 = NULL;
          expr_ret_244 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_243 = expr_ret_244;
          s = expr_ret_244;
        }

        // ModExprList 2
        if (expr_ret_243) {
          expr_ret_243 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_243) rew(mod_243);
        expr_ret_242 = expr_ret_243;
        // ModExprList end
        if (!expr_ret_242) rew(mod_242);
        expr_ret_237 = expr_ret_242;
      }

      // SlashExpr end
      expr_ret_234 = expr_ret_237;

    }

    // ModExprList 4
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_245 = NULL;
      expr_ret_245 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_234 = expr_ret_245;
      t = expr_ret_245;
    }

    // ModExprList 5
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_246 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_246 = leaf(CLOSE);
        expr_ret_246->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_246->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_246 = NULL;
      }

      // optional
      if (!expr_ret_246)
        expr_ret_246 = SUCC;
      expr_ret_234 = expr_ret_246;
      c = expr_ret_246;
    }

    // ModExprList 6
    if (expr_ret_234) {
      // CodeExpr
      #define ret expr_ret_234
      ret = SUCC;
      #line 310 "daisho.peg"
      if (has(o) != has(c)) WARNING("For expression parens mismatch.");
      #line 6367 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList 7
    if (expr_ret_234) {
      daisho_astnode_t* expr_ret_247 = NULL;
      expr_ret_247 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_234 = expr_ret_247;
      e = expr_ret_247;
    }

    // ModExprList 8
    if (expr_ret_234) {
      // CodeExpr
      #define ret expr_ret_234
      ret = SUCC;
      #line 312 "daisho.peg"
      rule = has(s) ? node(FOR, f, s, t, e)
                    :          node(FOREACH, f, t, e);
      #line 6389 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_234) rew(mod_234);
    expr_ret_233 = expr_ret_234;
  }

  // SlashExpr 1
  if (!expr_ret_233) {
    daisho_astnode_t* expr_ret_248 = NULL;
    rec(mod_248);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_249 = NULL;
    expr_ret_249 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_248 = expr_ret_249;
    rule = expr_ret_249;
    // ModExprList end
    if (!expr_ret_248) rew(mod_248);
    expr_ret_233 = expr_ret_248;
  }

  // SlashExpr end
  expr_ret_232 = expr_ret_233;

  if (!rule) rule = expr_ret_232;
  if (!expr_ret_232) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule forexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_250
  daisho_astnode_t* expr_ret_250 = NULL;
  daisho_astnode_t* expr_ret_251 = NULL;
  daisho_astnode_t* expr_ret_252 = NULL;

  // SlashExpr 0
  if (!expr_ret_252) {
    daisho_astnode_t* expr_ret_253 = NULL;
    rec(mod_253);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_253 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_253 = NULL;
    }

    // ModExprList 1
    if (expr_ret_253) {
      daisho_astnode_t* expr_ret_254 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_254 = leaf(OPEN);
        expr_ret_254->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_254->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_254 = NULL;
      }

      // optional
      if (!expr_ret_254)
        expr_ret_254 = SUCC;
      expr_ret_253 = expr_ret_254;
      o = expr_ret_254;
    }

    // ModExprList 2
    if (expr_ret_253) {
      daisho_astnode_t* expr_ret_255 = NULL;
      expr_ret_255 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_253 = expr_ret_255;
      n = expr_ret_255;
    }

    // ModExprList 3
    if (expr_ret_253) {
      daisho_astnode_t* expr_ret_256 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_256 = leaf(CLOSE);
        expr_ret_256->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_256->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_256 = NULL;
      }

      // optional
      if (!expr_ret_256)
        expr_ret_256 = SUCC;
      expr_ret_253 = expr_ret_256;
      c = expr_ret_256;
    }

    // ModExprList 4
    if (expr_ret_253) {
      // CodeExpr
      #define ret expr_ret_253
      ret = SUCC;
      #line 317 "daisho.peg"
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #line 6503 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_253) {
      daisho_astnode_t* expr_ret_257 = NULL;
      expr_ret_257 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_253 = expr_ret_257;
      e = expr_ret_257;
    }

    // ModExprList 6
    if (expr_ret_253) {
      // CodeExpr
      #define ret expr_ret_253
      ret = SUCC;
      #line 318 "daisho.peg"
      rule=node(WHILE, n, e);
      #line 6524 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_253) rew(mod_253);
    expr_ret_252 = expr_ret_253;
  }

  // SlashExpr 1
  if (!expr_ret_252) {
    daisho_astnode_t* expr_ret_258 = NULL;
    rec(mod_258);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_259 = NULL;
    expr_ret_259 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_258 = expr_ret_259;
    rule = expr_ret_259;
    // ModExprList end
    if (!expr_ret_258) rew(mod_258);
    expr_ret_252 = expr_ret_258;
  }

  // SlashExpr end
  expr_ret_251 = expr_ret_252;

  if (!rule) rule = expr_ret_251;
  if (!expr_ret_251) rule = NULL;
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
  #define rule expr_ret_260
  daisho_astnode_t* expr_ret_260 = NULL;
  daisho_astnode_t* expr_ret_261 = NULL;
  daisho_astnode_t* expr_ret_262 = NULL;

  // SlashExpr 0
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_263 = NULL;
    rec(mod_263);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_263 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_263 = NULL;
    }

    // ModExprList 1
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_264 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_264 = leaf(OPEN);
        expr_ret_264->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_264->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_264 = NULL;
      }

      // optional
      if (!expr_ret_264)
        expr_ret_264 = SUCC;
      expr_ret_263 = expr_ret_264;
      o = expr_ret_264;
    }

    // ModExprList 2
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_265 = NULL;
      expr_ret_265 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_263 = expr_ret_265;
      n = expr_ret_265;
    }

    // ModExprList 3
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_266 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_266 = leaf(CLOSE);
        expr_ret_266->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_266->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_266 = NULL;
      }

      // optional
      if (!expr_ret_266)
        expr_ret_266 = SUCC;
      expr_ret_263 = expr_ret_266;
      c = expr_ret_266;
    }

    // ModExprList 4
    if (expr_ret_263) {
      // CodeExpr
      #define ret expr_ret_263
      ret = SUCC;
      #line 322 "daisho.peg"
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #line 6639 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_267 = NULL;
      expr_ret_267 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_263 = expr_ret_267;
      e = expr_ret_267;
    }

    // ModExprList 6
    if (expr_ret_263) {
      daisho_astnode_t* expr_ret_268 = NULL;
      daisho_astnode_t* expr_ret_269 = NULL;
      rec(mod_269);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_269 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_269 = NULL;
      }

      // ModExprList 1
      if (expr_ret_269) {
        daisho_astnode_t* expr_ret_270 = NULL;
        expr_ret_270 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_269 = expr_ret_270;
        ee = expr_ret_270;
      }

      // ModExprList end
      if (!expr_ret_269) rew(mod_269);
      expr_ret_268 = expr_ret_269;
      // optional
      if (!expr_ret_268)
        expr_ret_268 = SUCC;
      expr_ret_263 = expr_ret_268;
    }

    // ModExprList 7
    if (expr_ret_263) {
      // CodeExpr
      #define ret expr_ret_263
      ret = SUCC;
      #line 325 "daisho.peg"
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #line 6693 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_263) rew(mod_263);
    expr_ret_262 = expr_ret_263;
  }

  // SlashExpr 1
  if (!expr_ret_262) {
    daisho_astnode_t* expr_ret_271 = NULL;
    rec(mod_271);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_272 = NULL;
    expr_ret_272 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_271 = expr_ret_272;
    rule = expr_ret_272;
    // ModExprList end
    if (!expr_ret_271) rew(mod_271);
    expr_ret_262 = expr_ret_271;
  }

  // SlashExpr end
  expr_ret_261 = expr_ret_262;

  if (!rule) rule = expr_ret_261;
  if (!expr_ret_261) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule preifexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_273
  daisho_astnode_t* expr_ret_273 = NULL;
  daisho_astnode_t* expr_ret_274 = NULL;
  daisho_astnode_t* expr_ret_275 = NULL;
  rec(mod_275);
  // ModExprList 0
  daisho_astnode_t* expr_ret_276 = NULL;
  expr_ret_276 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_275 = expr_ret_276;
  n = expr_ret_276;
  // ModExprList 1
  if (expr_ret_275) {
    daisho_astnode_t* expr_ret_277 = NULL;
    daisho_astnode_t* expr_ret_278 = NULL;
    rec(mod_278);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_278 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_278 = NULL;
    }

    // ModExprList 1
    if (expr_ret_278) {
      daisho_astnode_t* expr_ret_279 = NULL;
      expr_ret_279 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_278 = expr_ret_279;
      qe = expr_ret_279;
    }

    // ModExprList 2
    if (expr_ret_278) {
      daisho_astnode_t* expr_ret_280 = NULL;
      daisho_astnode_t* expr_ret_281 = NULL;
      rec(mod_281);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_281 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_281 = NULL;
      }

      // ModExprList 1
      if (expr_ret_281) {
        daisho_astnode_t* expr_ret_282 = NULL;
        expr_ret_282 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_281 = expr_ret_282;
        ce = expr_ret_282;
      }

      // ModExprList end
      if (!expr_ret_281) rew(mod_281);
      expr_ret_280 = expr_ret_281;
      // optional
      if (!expr_ret_280)
        expr_ret_280 = SUCC;
      expr_ret_278 = expr_ret_280;
    }

    // ModExprList end
    if (!expr_ret_278) rew(mod_278);
    expr_ret_277 = expr_ret_278;
    // optional
    if (!expr_ret_277)
      expr_ret_277 = SUCC;
    expr_ret_275 = expr_ret_277;
  }

  // ModExprList 2
  if (expr_ret_275) {
    // CodeExpr
    #define ret expr_ret_275
    ret = SUCC;
    #line 330 "daisho.peg"
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #line 6816 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_275) rew(mod_275);
  expr_ret_274 = expr_ret_275;
  if (!rule) rule = expr_ret_274;
  if (!expr_ret_274) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ternexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_283
  daisho_astnode_t* expr_ret_283 = NULL;
  daisho_astnode_t* expr_ret_284 = NULL;
  daisho_astnode_t* expr_ret_285 = NULL;
  rec(mod_285);
  // ModExprList 0
  daisho_astnode_t* expr_ret_286 = NULL;
  expr_ret_286 = daisho_parse_alsoexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_285 = expr_ret_286;
  rule = expr_ret_286;
  // ModExprList 1
  if (expr_ret_285) {
    daisho_astnode_t* expr_ret_287 = NULL;
    daisho_astnode_t* expr_ret_288 = SUCC;
    while (expr_ret_288)
    {
      rec(kleene_rew_287);
      daisho_astnode_t* expr_ret_289 = NULL;
      rec(mod_289);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_289 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_289 = NULL;
      }

      // ModExprList 1
      if (expr_ret_289) {
        daisho_astnode_t* expr_ret_290 = NULL;
        expr_ret_290 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_289 = expr_ret_290;
        nn = expr_ret_290;
      }

      // ModExprList 2
      if (expr_ret_289) {
        // CodeExpr
        #define ret expr_ret_289
        ret = SUCC;
        #line 334 "daisho.peg"
        rule=node(THEN, rule, nn);
        #line 6879 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_289) rew(mod_289);
      expr_ret_288 = expr_ret_289;
    }

    expr_ret_287 = SUCC;
    expr_ret_285 = expr_ret_287;
  }

  // ModExprList end
  if (!expr_ret_285) rew(mod_285);
  expr_ret_284 = expr_ret_285;
  if (!rule) rule = expr_ret_284;
  if (!expr_ret_284) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule thenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_291
  daisho_astnode_t* expr_ret_291 = NULL;
  daisho_astnode_t* expr_ret_292 = NULL;
  daisho_astnode_t* expr_ret_293 = NULL;
  rec(mod_293);
  // ModExprList 0
  daisho_astnode_t* expr_ret_294 = NULL;
  expr_ret_294 = daisho_parse_ceqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_293 = expr_ret_294;
  rule = expr_ret_294;
  // ModExprList 1
  if (expr_ret_293) {
    daisho_astnode_t* expr_ret_295 = NULL;
    daisho_astnode_t* expr_ret_296 = SUCC;
    while (expr_ret_296)
    {
      rec(kleene_rew_295);
      daisho_astnode_t* expr_ret_297 = NULL;
      rec(mod_297);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_297 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_297 = NULL;
      }

      // ModExprList 1
      if (expr_ret_297) {
        daisho_astnode_t* expr_ret_298 = NULL;
        expr_ret_298 = daisho_parse_ceqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_297 = expr_ret_298;
        nn = expr_ret_298;
      }

      // ModExprList 2
      if (expr_ret_297) {
        // CodeExpr
        #define ret expr_ret_297
        ret = SUCC;
        #line 336 "daisho.peg"
        rule=node(ALSO, rule, nn);
        #line 6951 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule alsoexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ceqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_299
  daisho_astnode_t* expr_ret_299 = NULL;
  daisho_astnode_t* expr_ret_300 = NULL;
  daisho_astnode_t* expr_ret_301 = NULL;
  rec(mod_301);
  // ModExprList 0
  daisho_astnode_t* expr_ret_302 = NULL;
  expr_ret_302 = daisho_parse_logorexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_301 = expr_ret_302;
  rule = expr_ret_302;
  // ModExprList 1
  if (expr_ret_301) {
    daisho_astnode_t* expr_ret_303 = NULL;
    daisho_astnode_t* expr_ret_304 = SUCC;
    while (expr_ret_304)
    {
      rec(kleene_rew_303);
      daisho_astnode_t* expr_ret_305 = NULL;
      rec(mod_305);
      // ModExprList 0
      daisho_astnode_t* expr_ret_306 = NULL;
      daisho_astnode_t* expr_ret_307 = NULL;

      // SlashExpr 0
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_308 = NULL;
        rec(mod_308);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_308 = leaf(EQ);
          expr_ret_308->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_308->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_308 = NULL;
        }

        // ModExprList end
        if (!expr_ret_308) rew(mod_308);
        expr_ret_307 = expr_ret_308;
      }

      // SlashExpr 1
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_309 = NULL;
        rec(mod_309);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_309 = leaf(PLEQ);
          expr_ret_309->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_309->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_309 = NULL;
        }

        // ModExprList end
        if (!expr_ret_309) rew(mod_309);
        expr_ret_307 = expr_ret_309;
      }

      // SlashExpr 2
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_310 = NULL;
        rec(mod_310);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_310 = leaf(MINEQ);
          expr_ret_310->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_310->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_310 = NULL;
        }

        // ModExprList end
        if (!expr_ret_310) rew(mod_310);
        expr_ret_307 = expr_ret_310;
      }

      // SlashExpr 3
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_311 = NULL;
        rec(mod_311);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_311 = leaf(MULEQ);
          expr_ret_311->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_311->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_311 = NULL;
        }

        // ModExprList end
        if (!expr_ret_311) rew(mod_311);
        expr_ret_307 = expr_ret_311;
      }

      // SlashExpr 4
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_312 = NULL;
        rec(mod_312);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_312 = leaf(DIVEQ);
          expr_ret_312->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_312->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_312 = NULL;
        }

        // ModExprList end
        if (!expr_ret_312) rew(mod_312);
        expr_ret_307 = expr_ret_312;
      }

      // SlashExpr 5
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_313 = NULL;
        rec(mod_313);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_313 = leaf(MODEQ);
          expr_ret_313->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_313->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_313 = NULL;
        }

        // ModExprList end
        if (!expr_ret_313) rew(mod_313);
        expr_ret_307 = expr_ret_313;
      }

      // SlashExpr 6
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_314 = NULL;
        rec(mod_314);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_314 = leaf(ANDEQ);
          expr_ret_314->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_314->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_314 = NULL;
        }

        // ModExprList end
        if (!expr_ret_314) rew(mod_314);
        expr_ret_307 = expr_ret_314;
      }

      // SlashExpr 7
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_315 = NULL;
        rec(mod_315);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_315 = leaf(OREQ);
          expr_ret_315->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_315->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_315 = NULL;
        }

        // ModExprList end
        if (!expr_ret_315) rew(mod_315);
        expr_ret_307 = expr_ret_315;
      }

      // SlashExpr 8
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_316 = NULL;
        rec(mod_316);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_316 = leaf(XOREQ);
          expr_ret_316->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_316->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_316 = NULL;
        }

        // ModExprList end
        if (!expr_ret_316) rew(mod_316);
        expr_ret_307 = expr_ret_316;
      }

      // SlashExpr 9
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_317 = NULL;
        rec(mod_317);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_317 = leaf(BNEQ);
          expr_ret_317->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_317->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_317 = NULL;
        }

        // ModExprList end
        if (!expr_ret_317) rew(mod_317);
        expr_ret_307 = expr_ret_317;
      }

      // SlashExpr 10
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_318 = NULL;
        rec(mod_318);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_318 = leaf(BSREQ);
          expr_ret_318->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_318->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_318 = NULL;
        }

        // ModExprList end
        if (!expr_ret_318) rew(mod_318);
        expr_ret_307 = expr_ret_318;
      }

      // SlashExpr 11
      if (!expr_ret_307) {
        daisho_astnode_t* expr_ret_319 = NULL;
        rec(mod_319);
        // ModExprList Forwarding
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_319 = leaf(BSLEQ);
          expr_ret_319->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_319->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_319 = NULL;
        }

        // ModExprList end
        if (!expr_ret_319) rew(mod_319);
        expr_ret_307 = expr_ret_319;
      }

      // SlashExpr end
      expr_ret_306 = expr_ret_307;

      expr_ret_305 = expr_ret_306;
      op = expr_ret_306;
      // ModExprList 1
      if (expr_ret_305) {
        daisho_astnode_t* expr_ret_320 = NULL;
        expr_ret_320 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_305 = expr_ret_320;
        t = expr_ret_320;
      }

      // ModExprList 2
      if (expr_ret_305) {
        // CodeExpr
        #define ret expr_ret_305
        ret = SUCC;
        #line 342 "daisho.peg"
        
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
        #line 7277 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule ceqexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_321
  daisho_astnode_t* expr_ret_321 = NULL;
  daisho_astnode_t* expr_ret_322 = NULL;
  daisho_astnode_t* expr_ret_323 = NULL;
  rec(mod_323);
  // ModExprList 0
  daisho_astnode_t* expr_ret_324 = NULL;
  expr_ret_324 = daisho_parse_logandexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Not capturing LOGOR.
        expr_ret_327 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_327 = NULL;
      }

      // ModExprList 1
      if (expr_ret_327) {
        daisho_astnode_t* expr_ret_328 = NULL;
        expr_ret_328 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_327 = expr_ret_328;
        n = expr_ret_328;
      }

      // ModExprList 2
      if (expr_ret_327) {
        // CodeExpr
        #define ret expr_ret_327
        ret = SUCC;
        #line 357 "daisho.peg"
        rule=node(LOGOR,  rule, n);
        #line 7349 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_329
  daisho_astnode_t* expr_ret_329 = NULL;
  daisho_astnode_t* expr_ret_330 = NULL;
  daisho_astnode_t* expr_ret_331 = NULL;
  rec(mod_331);
  // ModExprList 0
  daisho_astnode_t* expr_ret_332 = NULL;
  expr_ret_332 = daisho_parse_binorexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Not capturing LOGAND.
        expr_ret_335 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_335 = NULL;
      }

      // ModExprList 1
      if (expr_ret_335) {
        daisho_astnode_t* expr_ret_336 = NULL;
        expr_ret_336 = daisho_parse_binorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_335 = expr_ret_336;
        n = expr_ret_336;
      }

      // ModExprList 2
      if (expr_ret_335) {
        // CodeExpr
        #define ret expr_ret_335
        ret = SUCC;
        #line 358 "daisho.peg"
        rule=node(LOGAND, rule, n);
        #line 7421 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule logandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_337
  daisho_astnode_t* expr_ret_337 = NULL;
  daisho_astnode_t* expr_ret_338 = NULL;
  daisho_astnode_t* expr_ret_339 = NULL;
  rec(mod_339);
  // ModExprList 0
  daisho_astnode_t* expr_ret_340 = NULL;
  expr_ret_340 = daisho_parse_binxorexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Not capturing OR.
        expr_ret_343 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_343 = NULL;
      }

      // ModExprList 1
      if (expr_ret_343) {
        daisho_astnode_t* expr_ret_344 = NULL;
        expr_ret_344 = daisho_parse_binxorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_343 = expr_ret_344;
        n = expr_ret_344;
      }

      // ModExprList 2
      if (expr_ret_343) {
        // CodeExpr
        #define ret expr_ret_343
        ret = SUCC;
        #line 359 "daisho.peg"
        rule=node(OR,     rule, n);
        #line 7493 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_345
  daisho_astnode_t* expr_ret_345 = NULL;
  daisho_astnode_t* expr_ret_346 = NULL;
  daisho_astnode_t* expr_ret_347 = NULL;
  rec(mod_347);
  // ModExprList 0
  daisho_astnode_t* expr_ret_348 = NULL;
  expr_ret_348 = daisho_parse_binandexpr(ctx);
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
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Not capturing XOR.
        expr_ret_351 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_351 = NULL;
      }

      // ModExprList 1
      if (expr_ret_351) {
        daisho_astnode_t* expr_ret_352 = NULL;
        expr_ret_352 = daisho_parse_binandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_351 = expr_ret_352;
        n = expr_ret_352;
      }

      // ModExprList 2
      if (expr_ret_351) {
        // CodeExpr
        #define ret expr_ret_351
        ret = SUCC;
        #line 360 "daisho.peg"
        rule=node(XOR,    rule, n);
        #line 7565 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binxorexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_353
  daisho_astnode_t* expr_ret_353 = NULL;
  daisho_astnode_t* expr_ret_354 = NULL;
  daisho_astnode_t* expr_ret_355 = NULL;
  rec(mod_355);
  // ModExprList 0
  daisho_astnode_t* expr_ret_356 = NULL;
  expr_ret_356 = daisho_parse_deneqexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_355 = expr_ret_356;
  rule = expr_ret_356;
  // ModExprList 1
  if (expr_ret_355) {
    daisho_astnode_t* expr_ret_357 = NULL;
    daisho_astnode_t* expr_ret_358 = SUCC;
    while (expr_ret_358)
    {
      rec(kleene_rew_357);
      daisho_astnode_t* expr_ret_359 = NULL;
      rec(mod_359);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Not capturing AND.
        expr_ret_359 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_359 = NULL;
      }

      // ModExprList 1
      if (expr_ret_359) {
        daisho_astnode_t* expr_ret_360 = NULL;
        expr_ret_360 = daisho_parse_deneqexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_359 = expr_ret_360;
        n = expr_ret_360;
      }

      // ModExprList 2
      if (expr_ret_359) {
        // CodeExpr
        #define ret expr_ret_359
        ret = SUCC;
        #line 361 "daisho.peg"
        rule=node(AND,    rule, n);
        #line 7637 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_359) rew(mod_359);
      expr_ret_358 = expr_ret_359;
    }

    expr_ret_357 = SUCC;
    expr_ret_355 = expr_ret_357;
  }

  // ModExprList end
  if (!expr_ret_355) rew(mod_355);
  expr_ret_354 = expr_ret_355;
  if (!rule) rule = expr_ret_354;
  if (!expr_ret_354) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule binandexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_361
  daisho_astnode_t* expr_ret_361 = NULL;
  daisho_astnode_t* expr_ret_362 = NULL;
  daisho_astnode_t* expr_ret_363 = NULL;
  rec(mod_363);
  // ModExprList 0
  daisho_astnode_t* expr_ret_364 = NULL;
  expr_ret_364 = daisho_parse_cmpexpr(ctx);
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

      // SlashExpr 0
      if (!expr_ret_367) {
        daisho_astnode_t* expr_ret_368 = NULL;
        rec(mod_368);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Not capturing DEQ.
          expr_ret_368 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_368 = NULL;
        }

        // ModExprList 1
        if (expr_ret_368) {
          daisho_astnode_t* expr_ret_369 = NULL;
          expr_ret_369 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_368 = expr_ret_369;
          n = expr_ret_369;
        }

        // ModExprList 2
        if (expr_ret_368) {
          // CodeExpr
          #define ret expr_ret_368
          ret = SUCC;
          #line 364 "daisho.peg"
          rule=node(DEQ, rule, n);
          #line 7713 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_368) rew(mod_368);
        expr_ret_367 = expr_ret_368;
      }

      // SlashExpr 1
      if (!expr_ret_367) {
        daisho_astnode_t* expr_ret_370 = NULL;
        rec(mod_370);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Not capturing NEQ.
          expr_ret_370 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_370 = NULL;
        }

        // ModExprList 1
        if (expr_ret_370) {
          daisho_astnode_t* expr_ret_371 = NULL;
          expr_ret_371 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_370 = expr_ret_371;
          n = expr_ret_371;
        }

        // ModExprList 2
        if (expr_ret_370) {
          // CodeExpr
          #define ret expr_ret_370
          ret = SUCC;
          #line 365 "daisho.peg"
          rule=node(NEQ, rule, n);
          #line 7752 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_370) rew(mod_370);
        expr_ret_367 = expr_ret_370;
      }

      // SlashExpr end
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule deneqexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_372
  daisho_astnode_t* expr_ret_372 = NULL;
  daisho_astnode_t* expr_ret_373 = NULL;
  daisho_astnode_t* expr_ret_374 = NULL;
  rec(mod_374);
  // ModExprList 0
  daisho_astnode_t* expr_ret_375 = NULL;
  expr_ret_375 = daisho_parse_shfexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_374 = expr_ret_375;
  rule = expr_ret_375;
  // ModExprList 1
  if (expr_ret_374) {
    daisho_astnode_t* expr_ret_376 = NULL;
    daisho_astnode_t* expr_ret_377 = SUCC;
    while (expr_ret_377)
    {
      rec(kleene_rew_376);
      daisho_astnode_t* expr_ret_378 = NULL;

      // SlashExpr 0
      if (!expr_ret_378) {
        daisho_astnode_t* expr_ret_379 = NULL;
        rec(mod_379);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Not capturing LT.
          expr_ret_379 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_379 = NULL;
        }

        // ModExprList 1
        if (expr_ret_379) {
          daisho_astnode_t* expr_ret_380 = NULL;
          expr_ret_380 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_379 = expr_ret_380;
          n = expr_ret_380;
        }

        // ModExprList 2
        if (expr_ret_379) {
          // CodeExpr
          #define ret expr_ret_379
          ret = SUCC;
          #line 368 "daisho.peg"
          rule=node(LT,  rule, n);
          #line 7833 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_379) rew(mod_379);
        expr_ret_378 = expr_ret_379;
      }

      // SlashExpr 1
      if (!expr_ret_378) {
        daisho_astnode_t* expr_ret_381 = NULL;
        rec(mod_381);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Not capturing GT.
          expr_ret_381 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_381 = NULL;
        }

        // ModExprList 1
        if (expr_ret_381) {
          daisho_astnode_t* expr_ret_382 = NULL;
          expr_ret_382 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_381 = expr_ret_382;
          n = expr_ret_382;
        }

        // ModExprList 2
        if (expr_ret_381) {
          // CodeExpr
          #define ret expr_ret_381
          ret = SUCC;
          #line 369 "daisho.peg"
          rule=node(GT,  rule, n);
          #line 7872 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_381) rew(mod_381);
        expr_ret_378 = expr_ret_381;
      }

      // SlashExpr 2
      if (!expr_ret_378) {
        daisho_astnode_t* expr_ret_383 = NULL;
        rec(mod_383);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Not capturing LEQ.
          expr_ret_383 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_383 = NULL;
        }

        // ModExprList 1
        if (expr_ret_383) {
          daisho_astnode_t* expr_ret_384 = NULL;
          expr_ret_384 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_383 = expr_ret_384;
          n = expr_ret_384;
        }

        // ModExprList 2
        if (expr_ret_383) {
          // CodeExpr
          #define ret expr_ret_383
          ret = SUCC;
          #line 370 "daisho.peg"
          rule=node(LEQ, rule, n);
          #line 7911 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_383) rew(mod_383);
        expr_ret_378 = expr_ret_383;
      }

      // SlashExpr 3
      if (!expr_ret_378) {
        daisho_astnode_t* expr_ret_385 = NULL;
        rec(mod_385);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Not capturing GEQ.
          expr_ret_385 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_385 = NULL;
        }

        // ModExprList 1
        if (expr_ret_385) {
          daisho_astnode_t* expr_ret_386 = NULL;
          expr_ret_386 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_385 = expr_ret_386;
          n = expr_ret_386;
        }

        // ModExprList 2
        if (expr_ret_385) {
          // CodeExpr
          #define ret expr_ret_385
          ret = SUCC;
          #line 371 "daisho.peg"
          rule=node(GEQ, rule, n);
          #line 7950 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_385) rew(mod_385);
        expr_ret_378 = expr_ret_385;
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cmpexpr returned SUCC.\n"), exit(1);
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
  #define rule expr_ret_387
  daisho_astnode_t* expr_ret_387 = NULL;
  daisho_astnode_t* expr_ret_388 = NULL;
  daisho_astnode_t* expr_ret_389 = NULL;
  rec(mod_389);
  // ModExprList 0
  daisho_astnode_t* expr_ret_390 = NULL;
  expr_ret_390 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_389 = expr_ret_390;
  rule = expr_ret_390;
  // ModExprList 1
  if (expr_ret_389) {
    daisho_astnode_t* expr_ret_391 = NULL;
    daisho_astnode_t* expr_ret_392 = SUCC;
    while (expr_ret_392)
    {
      rec(kleene_rew_391);
      daisho_astnode_t* expr_ret_393 = NULL;

      // SlashExpr 0
      if (!expr_ret_393) {
        daisho_astnode_t* expr_ret_394 = NULL;
        rec(mod_394);
        // ModExprList 0
        daisho_astnode_t* expr_ret_395 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_395 = leaf(LT);
          expr_ret_395->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_395->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_395 = NULL;
        }

        expr_ret_394 = expr_ret_395;
        l = expr_ret_395;
        // ModExprList 1
        if (expr_ret_394) {
          daisho_astnode_t* expr_ret_396 = NULL;
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_396 = leaf(LT);
            expr_ret_396->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_396->len_or_toknum = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_396 = NULL;
          }

          expr_ret_394 = expr_ret_396;
          lt = expr_ret_396;
        }

        // ModExprList 2
        if (expr_ret_394) {
          daisho_astnode_t* expr_ret_397 = NULL;
          expr_ret_397 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_394 = expr_ret_397;
          n = expr_ret_397;
        }

        // ModExprList 3
        if (expr_ret_394) {
          // CodeExpr
          #define ret expr_ret_394
          ret = SUCC;
          #line 374 "daisho.peg"
          rule=node(BSL, l, lt, rule, n);
          #line 8057 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_394) rew(mod_394);
        expr_ret_393 = expr_ret_394;
      }

      // SlashExpr 1
      if (!expr_ret_393) {
        daisho_astnode_t* expr_ret_398 = NULL;
        rec(mod_398);
        // ModExprList 0
        daisho_astnode_t* expr_ret_399 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_399 = leaf(GT);
          expr_ret_399->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_399->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_399 = NULL;
        }

        expr_ret_398 = expr_ret_399;
        g = expr_ret_399;
        // ModExprList 1
        if (expr_ret_398) {
          daisho_astnode_t* expr_ret_400 = NULL;
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_400 = leaf(GT);
            expr_ret_400->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_400->len_or_toknum = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_400 = NULL;
          }

          expr_ret_398 = expr_ret_400;
          gt = expr_ret_400;
        }

        // ModExprList 2
        if (expr_ret_398) {
          daisho_astnode_t* expr_ret_401 = NULL;
          expr_ret_401 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_398 = expr_ret_401;
          n = expr_ret_401;
        }

        // ModExprList 3
        if (expr_ret_398) {
          // CodeExpr
          #define ret expr_ret_398
          ret = SUCC;
          #line 375 "daisho.peg"
          rule=node(BSR, g, gt, rule, n);
          #line 8118 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_398) rew(mod_398);
        expr_ret_393 = expr_ret_398;
      }

      // SlashExpr end
      expr_ret_392 = expr_ret_393;

    }

    expr_ret_391 = SUCC;
    expr_ret_389 = expr_ret_391;
  }

  // ModExprList end
  if (!expr_ret_389) rew(mod_389);
  expr_ret_388 = expr_ret_389;
  if (!rule) rule = expr_ret_388;
  if (!expr_ret_388) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule shfexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_402
  daisho_astnode_t* expr_ret_402 = NULL;
  daisho_astnode_t* expr_ret_403 = NULL;
  daisho_astnode_t* expr_ret_404 = NULL;
  rec(mod_404);
  // ModExprList 0
  daisho_astnode_t* expr_ret_405 = NULL;
  expr_ret_405 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_404 = expr_ret_405;
  rule = expr_ret_405;
  // ModExprList 1
  if (expr_ret_404) {
    daisho_astnode_t* expr_ret_406 = NULL;
    daisho_astnode_t* expr_ret_407 = SUCC;
    while (expr_ret_407)
    {
      rec(kleene_rew_406);
      daisho_astnode_t* expr_ret_408 = NULL;

      // SlashExpr 0
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_409 = NULL;
        rec(mod_409);
        // ModExprList 0
        daisho_astnode_t* expr_ret_410 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_410 = leaf(PLUS);
          expr_ret_410->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_410->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_410 = NULL;
        }

        expr_ret_409 = expr_ret_410;
        p = expr_ret_410;
        // ModExprList 1
        if (expr_ret_409) {
          daisho_astnode_t* expr_ret_411 = NULL;
          expr_ret_411 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_409 = expr_ret_411;
          n = expr_ret_411;
        }

        // ModExprList 2
        if (expr_ret_409) {
          // CodeExpr
          #define ret expr_ret_409
          ret = SUCC;
          #line 378 "daisho.peg"
          rule=node(PLUS, rule, n);
          #line 8206 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_409) rew(mod_409);
        expr_ret_408 = expr_ret_409;
      }

      // SlashExpr 1
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_412 = NULL;
        rec(mod_412);
        // ModExprList 0
        daisho_astnode_t* expr_ret_413 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_413 = leaf(MINUS);
          expr_ret_413->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_413->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_413 = NULL;
        }

        expr_ret_412 = expr_ret_413;
        m = expr_ret_413;
        // ModExprList 1
        if (expr_ret_412) {
          daisho_astnode_t* expr_ret_414 = NULL;
          expr_ret_414 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_412 = expr_ret_414;
          n = expr_ret_414;
        }

        // ModExprList 2
        if (expr_ret_412) {
          // CodeExpr
          #define ret expr_ret_412
          ret = SUCC;
          #line 379 "daisho.peg"
          rule=node(MINUS, rule, n);
          #line 8250 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_412) rew(mod_412);
        expr_ret_408 = expr_ret_412;
      }

      // SlashExpr end
      expr_ret_407 = expr_ret_408;

    }

    expr_ret_406 = SUCC;
    expr_ret_404 = expr_ret_406;
  }

  // ModExprList end
  if (!expr_ret_404) rew(mod_404);
  expr_ret_403 = expr_ret_404;
  if (!rule) rule = expr_ret_403;
  if (!expr_ret_403) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sumexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_415
  daisho_astnode_t* expr_ret_415 = NULL;
  daisho_astnode_t* expr_ret_416 = NULL;
  daisho_astnode_t* expr_ret_417 = NULL;
  rec(mod_417);
  // ModExprList 0
  daisho_astnode_t* expr_ret_418 = NULL;
  expr_ret_418 = daisho_parse_accexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_417 = expr_ret_418;
  rule = expr_ret_418;
  // ModExprList 1
  if (expr_ret_417) {
    daisho_astnode_t* expr_ret_419 = NULL;
    daisho_astnode_t* expr_ret_420 = SUCC;
    while (expr_ret_420)
    {
      rec(kleene_rew_419);
      daisho_astnode_t* expr_ret_421 = NULL;

      // SlashExpr 0
      if (!expr_ret_421) {
        daisho_astnode_t* expr_ret_422 = NULL;
        rec(mod_422);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_422 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_422 = NULL;
        }

        // ModExprList 1
        if (expr_ret_422) {
          daisho_astnode_t* expr_ret_423 = NULL;
          expr_ret_423 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_422 = expr_ret_423;
          n = expr_ret_423;
        }

        // ModExprList 2
        if (expr_ret_422) {
          // CodeExpr
          #define ret expr_ret_422
          ret = SUCC;
          #line 382 "daisho.peg"
          rule=node(STAR, rule, n);
          #line 8331 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_422) rew(mod_422);
        expr_ret_421 = expr_ret_422;
      }

      // SlashExpr 1
      if (!expr_ret_421) {
        daisho_astnode_t* expr_ret_424 = NULL;
        rec(mod_424);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Not capturing DIV.
          expr_ret_424 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_424 = NULL;
        }

        // ModExprList 1
        if (expr_ret_424) {
          daisho_astnode_t* expr_ret_425 = NULL;
          expr_ret_425 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_424 = expr_ret_425;
          n = expr_ret_425;
        }

        // ModExprList 2
        if (expr_ret_424) {
          // CodeExpr
          #define ret expr_ret_424
          ret = SUCC;
          #line 383 "daisho.peg"
          rule=node(DIV,  rule, n);
          #line 8370 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_424) rew(mod_424);
        expr_ret_421 = expr_ret_424;
      }

      // SlashExpr 2
      if (!expr_ret_421) {
        daisho_astnode_t* expr_ret_426 = NULL;
        rec(mod_426);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Not capturing MOD.
          expr_ret_426 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_426 = NULL;
        }

        // ModExprList 1
        if (expr_ret_426) {
          daisho_astnode_t* expr_ret_427 = NULL;
          expr_ret_427 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_426 = expr_ret_427;
          n = expr_ret_427;
        }

        // ModExprList 2
        if (expr_ret_426) {
          // CodeExpr
          #define ret expr_ret_426
          ret = SUCC;
          #line 384 "daisho.peg"
          rule=node(MOD,  rule, n);
          #line 8409 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_426) rew(mod_426);
        expr_ret_421 = expr_ret_426;
      }

      // SlashExpr 3
      if (!expr_ret_421) {
        daisho_astnode_t* expr_ret_428 = NULL;
        rec(mod_428);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_428 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_428 = NULL;
        }

        // ModExprList 1
        if (expr_ret_428) {
          daisho_astnode_t* expr_ret_429 = NULL;
          expr_ret_429 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_428 = expr_ret_429;
          n = expr_ret_429;
        }

        // ModExprList 2
        if (expr_ret_428) {
          // CodeExpr
          #define ret expr_ret_428
          ret = SUCC;
          #line 385 "daisho.peg"
          rule=node(POW,  rule, n);
          #line 8448 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_428) rew(mod_428);
        expr_ret_421 = expr_ret_428;
      }

      // SlashExpr end
      expr_ret_420 = expr_ret_421;

    }

    expr_ret_419 = SUCC;
    expr_ret_417 = expr_ret_419;
  }

  // ModExprList end
  if (!expr_ret_417) rew(mod_417);
  expr_ret_416 = expr_ret_417;
  if (!rule) rule = expr_ret_416;
  if (!expr_ret_416) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule multexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_430
  daisho_astnode_t* expr_ret_430 = NULL;
  daisho_astnode_t* expr_ret_431 = NULL;
  daisho_astnode_t* expr_ret_432 = NULL;
  rec(mod_432);
  // ModExprList 0
  daisho_astnode_t* expr_ret_433 = NULL;
  expr_ret_433 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_432 = expr_ret_433;
  rule = expr_ret_433;
  // ModExprList 1
  if (expr_ret_432) {
    daisho_astnode_t* expr_ret_434 = NULL;
    daisho_astnode_t* expr_ret_435 = SUCC;
    while (expr_ret_435)
    {
      rec(kleene_rew_434);
      daisho_astnode_t* expr_ret_436 = NULL;
      rec(mod_436);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_436 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_436 = NULL;
      }

      // ModExprList 1
      if (expr_ret_436) {
        daisho_astnode_t* expr_ret_437 = NULL;
        expr_ret_437 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_436 = expr_ret_437;
        e = expr_ret_437;
      }

      // ModExprList 2
      if (expr_ret_436) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_436 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_436 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_436) {
        // CodeExpr
        #define ret expr_ret_436
        ret = SUCC;
        #line 387 "daisho.peg"
        rule=node(ACCESS, rule, e);
        #line 8537 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_436) rew(mod_436);
      expr_ret_435 = expr_ret_436;
    }

    expr_ret_434 = SUCC;
    expr_ret_432 = expr_ret_434;
  }

  // ModExprList end
  if (!expr_ret_432) rew(mod_432);
  expr_ret_431 = expr_ret_432;
  if (!rule) rule = expr_ret_431;
  if (!expr_ret_431) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule accexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_438
  daisho_astnode_t* expr_ret_438 = NULL;
  daisho_astnode_t* expr_ret_439 = NULL;
  daisho_astnode_t* expr_ret_440 = NULL;
  rec(mod_440);
  // ModExprList 0
  daisho_astnode_t* expr_ret_441 = NULL;
  expr_ret_441 = daisho_parse_refexpr(ctx);
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
      rec(mod_444);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_444 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_444 = NULL;
      }

      // ModExprList 1
      if (expr_ret_444) {
        daisho_astnode_t* expr_ret_445 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_445 = leaf(VARIDENT);
          expr_ret_445->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_445->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_445 = NULL;
        }

        expr_ret_444 = expr_ret_445;
        i = expr_ret_445;
      }

      // ModExprList 2
      if (expr_ret_444) {
        // CodeExpr
        #define ret expr_ret_444
        ret = SUCC;
        #line 389 "daisho.peg"
        rule=node(DOT, rule, i);
        #line 8617 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_444) rew(mod_444);
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
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule dotexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_446
  daisho_astnode_t* expr_ret_446 = NULL;
  daisho_astnode_t* expr_ret_447 = NULL;
  daisho_astnode_t* expr_ret_448 = NULL;
  rec(mod_448);
  // ModExprList 0
  daisho_astnode_t* expr_ret_449 = NULL;
  expr_ret_449 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_448 = expr_ret_449;
  rule = expr_ret_449;
  // ModExprList 1
  if (expr_ret_448) {
    daisho_astnode_t* expr_ret_450 = NULL;
    daisho_astnode_t* expr_ret_451 = SUCC;
    while (expr_ret_451)
    {
      rec(kleene_rew_450);
      daisho_astnode_t* expr_ret_452 = NULL;

      // SlashExpr 0
      if (!expr_ret_452) {
        daisho_astnode_t* expr_ret_453 = NULL;
        rec(mod_453);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_453 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_453 = NULL;
        }

        // ModExprList 1
        if (expr_ret_453) {
          // CodeExpr
          #define ret expr_ret_453
          ret = SUCC;
          #line 392 "daisho.peg"
          rd++;
          #line 8685 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_453) rew(mod_453);
        expr_ret_452 = expr_ret_453;
      }

      // SlashExpr 1
      if (!expr_ret_452) {
        daisho_astnode_t* expr_ret_454 = NULL;
        rec(mod_454);
        // ModExprList 0
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_454 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_454 = NULL;
        }

        // ModExprList 1
        if (expr_ret_454) {
          // CodeExpr
          #define ret expr_ret_454
          ret = SUCC;
          #line 392 "daisho.peg"
          rd--;
          #line 8715 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_454) rew(mod_454);
        expr_ret_452 = expr_ret_454;
      }

      // SlashExpr end
      expr_ret_451 = expr_ret_452;

    }

    expr_ret_450 = SUCC;
    expr_ret_448 = expr_ret_450;
  }

  // ModExprList 2
  if (expr_ret_448) {
    // CodeExpr
    #define ret expr_ret_448
    ret = SUCC;
    #line 393 "daisho.peg"
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                rule = rd > 0 ? node(REF, rule) : node(DEREF, rule);
              };
    #line 8743 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_448) rew(mod_448);
  expr_ret_447 = expr_ret_448;
  if (!rule) rule = expr_ret_447;
  if (!expr_ret_447) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule refexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* te = NULL;
  daisho_astnode_t* el = NULL;
  #define rule expr_ret_455
  daisho_astnode_t* expr_ret_455 = NULL;
  daisho_astnode_t* expr_ret_456 = NULL;
  daisho_astnode_t* expr_ret_457 = NULL;
  rec(mod_457);
  // ModExprList 0
  daisho_astnode_t* expr_ret_458 = NULL;
  expr_ret_458 = daisho_parse_castexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_457 = expr_ret_458;
  rule = expr_ret_458;
  // ModExprList 1
  if (expr_ret_457) {
    daisho_astnode_t* expr_ret_459 = NULL;
    daisho_astnode_t* expr_ret_460 = NULL;
    rec(mod_460);
    // ModExprList 0
    // CodeExpr
    #define ret expr_ret_460
    ret = SUCC;
    #line 398 "daisho.peg"
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #line 8784 "daisho_tokenizer_parser.h"

    #undef ret
    // ModExprList 1
    if (expr_ret_460) {
      daisho_astnode_t* expr_ret_461 = NULL;
      expr_ret_461 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_460 = expr_ret_461;
      te = expr_ret_461;
    }

    // ModExprList end
    if (!expr_ret_460) rew(mod_460);
    expr_ret_459 = expr_ret_460;
    // optional
    if (!expr_ret_459)
      expr_ret_459 = SUCC;
    expr_ret_457 = expr_ret_459;
  }

  // ModExprList 2
  if (expr_ret_457) {
    daisho_astnode_t* expr_ret_462 = NULL;
    daisho_astnode_t* expr_ret_463 = SUCC;
    while (expr_ret_463)
    {
      rec(kleene_rew_462);
      daisho_astnode_t* expr_ret_464 = NULL;
      rec(mod_464);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_464 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_464 = NULL;
      }

      // ModExprList 1
      if (expr_ret_464) {
        daisho_astnode_t* expr_ret_465 = NULL;
        expr_ret_465 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_464 = expr_ret_465;
        el = expr_ret_465;
      }

      // ModExprList 2
      if (expr_ret_464) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_464 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_464 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_464) {
        // CodeExpr
        #define ret expr_ret_464
        ret = SUCC;
        #line 400 "daisho.peg"
        rule = !has(te) ? node(CALL, rule, el)
                    :            node(CALL, rule, te, el);
        #line 8852 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_464) rew(mod_464);
      expr_ret_463 = expr_ret_464;
    }

    expr_ret_462 = SUCC;
    expr_ret_457 = expr_ret_462;
  }

  // ModExprList end
  if (!expr_ret_457) rew(mod_457);
  expr_ret_456 = expr_ret_457;
  if (!rule) rule = expr_ret_456;
  if (!expr_ret_456) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule callexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_466
  daisho_astnode_t* expr_ret_466 = NULL;
  daisho_astnode_t* expr_ret_467 = NULL;
  daisho_astnode_t* expr_ret_468 = NULL;
  rec(mod_468);
  // ModExprList 0
  daisho_astnode_t* expr_ret_469 = NULL;
  expr_ret_469 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_468 = expr_ret_469;
  rule = expr_ret_469;
  // ModExprList 1
  if (expr_ret_468) {
    daisho_astnode_t* expr_ret_470 = NULL;
    daisho_astnode_t* expr_ret_471 = SUCC;
    while (expr_ret_471)
    {
      rec(kleene_rew_470);
      daisho_astnode_t* expr_ret_472 = NULL;
      rec(mod_472);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_472 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_472 = NULL;
      }

      // ModExprList 1
      if (expr_ret_472) {
        daisho_astnode_t* expr_ret_473 = NULL;
        expr_ret_473 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_472 = expr_ret_473;
        t = expr_ret_473;
      }

      // ModExprList 2
      if (expr_ret_472) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_472 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_472 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_472) {
        // CodeExpr
        #define ret expr_ret_472
        ret = SUCC;
        #line 403 "daisho.peg"
        rule=node(CAST, rule, t);
        #line 8936 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_472) rew(mod_472);
      expr_ret_471 = expr_ret_472;
    }

    expr_ret_470 = SUCC;
    expr_ret_468 = expr_ret_470;
  }

  // ModExprList end
  if (!expr_ret_468) rew(mod_468);
  expr_ret_467 = expr_ret_468;
  if (!rule) rule = expr_ret_467;
  if (!expr_ret_467) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule castexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_474
  daisho_astnode_t* expr_ret_474 = NULL;
  daisho_astnode_t* expr_ret_475 = NULL;
  daisho_astnode_t* expr_ret_476 = NULL;
  rec(mod_476);
  // ModExprList 0
  daisho_astnode_t* expr_ret_477 = NULL;
  expr_ret_477 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_476 = expr_ret_477;
  rule = expr_ret_477;
  // ModExprList 1
  if (expr_ret_476) {
    daisho_astnode_t* expr_ret_478 = NULL;
    daisho_astnode_t* expr_ret_479 = NULL;

    // SlashExpr 0
    if (!expr_ret_479) {
      daisho_astnode_t* expr_ret_480 = NULL;
      rec(mod_480);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_481 = NULL;
      rec(mod_481);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Not capturing INCR.
        expr_ret_481 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_481 = NULL;
      }

      // ModExprList 1
      if (expr_ret_481) {
        // CodeExpr
        #define ret expr_ret_481
        ret = SUCC;
        #line 405 "daisho.peg"
        rule=node(INCR, rule);
        #line 9001 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_481) rew(mod_481);
      expr_ret_480 = expr_ret_481;
      // ModExprList end
      if (!expr_ret_480) rew(mod_480);
      expr_ret_479 = expr_ret_480;
    }

    // SlashExpr 1
    if (!expr_ret_479) {
      daisho_astnode_t* expr_ret_482 = NULL;
      rec(mod_482);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_483 = NULL;
      rec(mod_483);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Not capturing DECR.
        expr_ret_483 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_483 = NULL;
      }

      // ModExprList 1
      if (expr_ret_483) {
        // CodeExpr
        #define ret expr_ret_483
        ret = SUCC;
        #line 406 "daisho.peg"
        rule=node(DECR, rule);
        #line 9037 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_483) rew(mod_483);
      expr_ret_482 = expr_ret_483;
      // ModExprList end
      if (!expr_ret_482) rew(mod_482);
      expr_ret_479 = expr_ret_482;
    }

    // SlashExpr end
    expr_ret_478 = expr_ret_479;

    // optional
    if (!expr_ret_478)
      expr_ret_478 = SUCC;
    expr_ret_476 = expr_ret_478;
  }

  // ModExprList end
  if (!expr_ret_476) rew(mod_476);
  expr_ret_475 = expr_ret_476;
  if (!rule) rule = expr_ret_475;
  if (!expr_ret_475) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule increxpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_484
  daisho_astnode_t* expr_ret_484 = NULL;
  daisho_astnode_t* expr_ret_485 = NULL;
  daisho_astnode_t* expr_ret_486 = NULL;

  // SlashExpr 0
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_487 = NULL;
    rec(mod_487);
    // ModExprList Forwarding
    expr_ret_487 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_487) rew(mod_487);
    expr_ret_486 = expr_ret_487;
  }

  // SlashExpr 1
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_488 = NULL;
    rec(mod_488);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_488 = leaf(VARIDENT);
      expr_ret_488->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_488->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_488 = NULL;
    }

    // ModExprList end
    if (!expr_ret_488) rew(mod_488);
    expr_ret_486 = expr_ret_488;
  }

  // SlashExpr 2
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_489 = NULL;
    rec(mod_489);
    // ModExprList Forwarding
    expr_ret_489 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_489) rew(mod_489);
    expr_ret_486 = expr_ret_489;
  }

  // SlashExpr 3
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_490 = NULL;
    rec(mod_490);
    // ModExprList Forwarding
    expr_ret_490 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_490) rew(mod_490);
    expr_ret_486 = expr_ret_490;
  }

  // SlashExpr 4
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_491 = NULL;
    rec(mod_491);
    // ModExprList Forwarding
    expr_ret_491 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_491) rew(mod_491);
    expr_ret_486 = expr_ret_491;
  }

  // SlashExpr 5
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_492 = NULL;
    rec(mod_492);
    // ModExprList Forwarding
    expr_ret_492 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_492) rew(mod_492);
    expr_ret_486 = expr_ret_492;
  }

  // SlashExpr 6
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_493 = NULL;
    rec(mod_493);
    // ModExprList Forwarding
    expr_ret_493 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_493) rew(mod_493);
    expr_ret_486 = expr_ret_493;
  }

  // SlashExpr 7
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_494 = NULL;
    rec(mod_494);
    // ModExprList Forwarding
    expr_ret_494 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_494) rew(mod_494);
    expr_ret_486 = expr_ret_494;
  }

  // SlashExpr 8
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_495 = NULL;
    rec(mod_495);
    // ModExprList Forwarding
    expr_ret_495 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_495) rew(mod_495);
    expr_ret_486 = expr_ret_495;
  }

  // SlashExpr 9
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_496 = NULL;
    rec(mod_496);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_496 = leaf(NUMLIT);
      expr_ret_496->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_496->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_496 = NULL;
    }

    // ModExprList end
    if (!expr_ret_496) rew(mod_496);
    expr_ret_486 = expr_ret_496;
  }

  // SlashExpr 10
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_497 = NULL;
    rec(mod_497);
    // ModExprList Forwarding
    expr_ret_497 = daisho_parse_cfuncexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_497) rew(mod_497);
    expr_ret_486 = expr_ret_497;
  }

  // SlashExpr 11
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_498 = NULL;
    rec(mod_498);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_498 = leaf(SELFVAR);
      expr_ret_498->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_498->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_498 = NULL;
    }

    // ModExprList end
    if (!expr_ret_498) rew(mod_498);
    expr_ret_486 = expr_ret_498;
  }

  // SlashExpr 12
  if (!expr_ret_486) {
    daisho_astnode_t* expr_ret_499 = NULL;
    rec(mod_499);
    // ModExprList Forwarding
    expr_ret_499 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_499) rew(mod_499);
    expr_ret_486 = expr_ret_499;
  }

  // SlashExpr end
  expr_ret_485 = expr_ret_486;

  if (!rule) rule = expr_ret_485;
  if (!expr_ret_485) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule atomexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_500
  daisho_astnode_t* expr_ret_500 = NULL;
  daisho_astnode_t* expr_ret_501 = NULL;
  daisho_astnode_t* expr_ret_502 = NULL;
  rec(mod_502);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_502 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_502 = NULL;
  }

  // ModExprList 1
  if (expr_ret_502) {
    // CodeExpr
    #define ret expr_ret_502
    ret = SUCC;
    #line 526 "daisho.peg"
    rule=list(BLOCK);
    #line 9288 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_502) {
    daisho_astnode_t* expr_ret_503 = NULL;
    daisho_astnode_t* expr_ret_504 = SUCC;
    while (expr_ret_504)
    {
      rec(kleene_rew_503);
      daisho_astnode_t* expr_ret_505 = NULL;
      rec(mod_505);
      // ModExprList 0
      rec(mexpr_state_506)
      daisho_astnode_t* expr_ret_506 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
        // Not capturing RCBRACK.
        expr_ret_506 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_506 = NULL;
      }

      // invert
      expr_ret_506 = expr_ret_506 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_506);
      expr_ret_505 = expr_ret_506;
      // ModExprList 1
      if (expr_ret_505) {
        daisho_astnode_t* expr_ret_507 = NULL;
        expr_ret_507 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_505 = expr_ret_507;
        e = expr_ret_507;
      }

      // ModExprList 2
      if (expr_ret_505) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
          // Not capturing SEMI.
          expr_ret_505 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_505 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_505) {
        // CodeExpr
        #define ret expr_ret_505
        ret = SUCC;
        #line 527 "daisho.peg"
        add(rule, e);
        #line 9346 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_505) rew(mod_505);
      expr_ret_504 = expr_ret_505;
    }

    expr_ret_503 = SUCC;
    expr_ret_502 = expr_ret_503;
  }

  // ModExprList 3
  if (expr_ret_502) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_502 = leaf(RCBRACK);
      expr_ret_502->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_502->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_502 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_502) rew(mod_502);
  expr_ret_501 = expr_ret_502;
  if (!rule) rule = expr_ret_501;
  if (!expr_ret_501) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule blockexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* args = NULL;
  #define rule expr_ret_508
  daisho_astnode_t* expr_ret_508 = NULL;
  daisho_astnode_t* expr_ret_509 = NULL;
  daisho_astnode_t* expr_ret_510 = NULL;
  rec(mod_510);
  // ModExprList 0
  daisho_astnode_t* expr_ret_511 = NULL;
  // CodeExpr
  #define ret expr_ret_511
  ret = SUCC;
  #line 530 "daisho.peg"
  ;
  #line 9398 "daisho_tokenizer_parser.h"

  #undef ret
  expr_ret_510 = expr_ret_511;
  args = expr_ret_511;
  // ModExprList 1
  if (expr_ret_510) {
    daisho_astnode_t* expr_ret_512 = NULL;

    // SlashExpr 0
    if (!expr_ret_512) {
      daisho_astnode_t* expr_ret_513 = NULL;
      rec(mod_513);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_514 = NULL;
      rec(mod_514);
      // ModExprList Forwarding
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_514 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_514 = NULL;
      }

      // ModExprList end
      if (!expr_ret_514) rew(mod_514);
      expr_ret_513 = expr_ret_514;
      // ModExprList end
      if (!expr_ret_513) rew(mod_513);
      expr_ret_512 = expr_ret_513;
    }

    // SlashExpr 1
    if (!expr_ret_512) {
      daisho_astnode_t* expr_ret_515 = NULL;
      rec(mod_515);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_516 = NULL;
      rec(mod_516);
      // ModExprList 0
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_516 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_516 = NULL;
      }

      // ModExprList 1
      if (expr_ret_516) {
        expr_ret_516 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
      }

      // ModExprList 2
      if (expr_ret_516) {
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_516 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_516 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_516) rew(mod_516);
      expr_ret_515 = expr_ret_516;
      // ModExprList end
      if (!expr_ret_515) rew(mod_515);
      expr_ret_512 = expr_ret_515;
    }

    // SlashExpr end
    expr_ret_510 = expr_ret_512;

  }

  // ModExprList 2
  if (expr_ret_510) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_510 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_510 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_510) {
    expr_ret_510 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList end
  if (!expr_ret_510) rew(mod_510);
  expr_ret_509 = expr_ret_510;
  if (!rule) rule = expr_ret_509;
  if (!expr_ret_509) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule lambdaexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  #define rule expr_ret_517
  daisho_astnode_t* expr_ret_517 = NULL;
  daisho_astnode_t* expr_ret_518 = NULL;
  daisho_astnode_t* expr_ret_519 = NULL;
  rec(mod_519);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_519 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_519 = NULL;
  }

  // ModExprList 1
  if (expr_ret_519) {
    daisho_astnode_t* expr_ret_520 = NULL;
    daisho_astnode_t* expr_ret_521 = NULL;
    rec(mod_521);
    // ModExprList 0
    daisho_astnode_t* expr_ret_522 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_522 = leaf(VARIDENT);
      expr_ret_522->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_522->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_522 = NULL;
    }

    expr_ret_521 = expr_ret_522;
    cnt = expr_ret_522;
    // ModExprList 1
    if (expr_ret_521) {
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_521 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_521 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_521) rew(mod_521);
    expr_ret_520 = expr_ret_521;
    // optional
    if (!expr_ret_520)
      expr_ret_520 = SUCC;
    expr_ret_519 = expr_ret_520;
  }

  // ModExprList 2
  if (expr_ret_519) {
    expr_ret_519 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 3
  if (expr_ret_519) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_519 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_519 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_519) {
    daisho_astnode_t* expr_ret_523 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_523 = leaf(VARIDENT);
      expr_ret_523->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_523->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_523 = NULL;
    }

    expr_ret_519 = expr_ret_523;
    item = expr_ret_523;
  }

  // ModExprList 5
  if (expr_ret_519) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_519 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_519 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_519) {
    expr_ret_519 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 7
  if (expr_ret_519) {
    daisho_astnode_t* expr_ret_524 = NULL;
    daisho_astnode_t* expr_ret_525 = NULL;
    rec(mod_525);
    // ModExprList 0
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_525 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_525 = NULL;
    }

    // ModExprList 1
    if (expr_ret_525) {
      expr_ret_525 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
    }

    // ModExprList end
    if (!expr_ret_525) rew(mod_525);
    expr_ret_524 = expr_ret_525;
    // optional
    if (!expr_ret_524)
      expr_ret_524 = SUCC;
    expr_ret_519 = expr_ret_524;
  }

  // ModExprList 8
  if (expr_ret_519) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_519 = leaf(RSBRACK);
      expr_ret_519->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_519->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_519 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_519) rew(mod_519);
  expr_ret_518 = expr_ret_519;
  if (!rule) rule = expr_ret_518;
  if (!expr_ret_518) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listcomp returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_526
  daisho_astnode_t* expr_ret_526 = NULL;
  daisho_astnode_t* expr_ret_527 = NULL;
  daisho_astnode_t* expr_ret_528 = NULL;
  rec(mod_528);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_528 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_528 = NULL;
  }

  // ModExprList 1
  if (expr_ret_528) {
    daisho_astnode_t* expr_ret_529 = NULL;
    expr_ret_529 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_528 = expr_ret_529;
    rule = expr_ret_529;
  }

  // ModExprList 2
  if (expr_ret_528) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_528 = leaf(CLOSE);
      expr_ret_528->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_528->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_528 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_528) rew(mod_528);
  expr_ret_527 = expr_ret_528;
  if (!rule) rule = expr_ret_527;
  if (!expr_ret_527) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule parenexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_530
  daisho_astnode_t* expr_ret_530 = NULL;
  daisho_astnode_t* expr_ret_531 = NULL;
  daisho_astnode_t* expr_ret_532 = NULL;
  rec(mod_532);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_532 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_532 = NULL;
  }

  // ModExprList 1
  if (expr_ret_532) {
    daisho_astnode_t* expr_ret_533 = NULL;
    expr_ret_533 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_532 = expr_ret_533;
    rule = expr_ret_533;
  }

  // ModExprList 2
  if (expr_ret_532) {
    // CodeExpr
    #define ret expr_ret_532
    ret = SUCC;
    #line 546 "daisho.peg"
    rule->kind = kind(LISTLIT);
    #line 9750 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_532) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_532 = leaf(RSBRACK);
      expr_ret_532->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_532->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_532 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_532) rew(mod_532);
  expr_ret_531 = expr_ret_532;
  if (!rule) rule = expr_ret_531;
  if (!expr_ret_531) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule listlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_534
  daisho_astnode_t* expr_ret_534 = NULL;
  daisho_astnode_t* expr_ret_535 = NULL;
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
    rule = expr_ret_537;
  }

  // ModExprList 2
  if (expr_ret_536) {
    // CodeExpr
    #define ret expr_ret_536
    ret = SUCC;
    #line 550 "daisho.peg"
    rule->kind = kind(TUPLELIT);
    #line 9811 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 3
  if (expr_ret_536) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_536 = leaf(CLOSE);
      expr_ret_536->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_536->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_536 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_536) rew(mod_536);
  expr_ret_535 = expr_ret_536;
  if (!rule) rule = expr_ret_535;
  if (!expr_ret_535) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule tuplelit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_538
  daisho_astnode_t* expr_ret_538 = NULL;
  daisho_astnode_t* expr_ret_539 = NULL;
  daisho_astnode_t* expr_ret_540 = NULL;
  rec(mod_540);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_540 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_540 = NULL;
  }

  // ModExprList 1
  if (expr_ret_540) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Capturing CIDENT.
      expr_ret_540 = leaf(CIDENT);
      expr_ret_540->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_540->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_540 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_540) rew(mod_540);
  expr_ret_539 = expr_ret_540;
  if (!rule) rule = expr_ret_539;
  if (!expr_ret_539) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule cfuncexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_541
  daisho_astnode_t* expr_ret_541 = NULL;
  daisho_astnode_t* expr_ret_542 = NULL;
  daisho_astnode_t* expr_ret_543 = NULL;
  rec(mod_543);
  // ModExprList 0
  daisho_astnode_t* expr_ret_544 = NULL;
  expr_ret_544 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_543 = expr_ret_544;
  t = expr_ret_544;
  // ModExprList 1
  if (expr_ret_543) {
    daisho_astnode_t* expr_ret_545 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_545 = leaf(VARIDENT);
      expr_ret_545->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_545->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_545 = NULL;
    }

    expr_ret_543 = expr_ret_545;
    i = expr_ret_545;
  }

  // ModExprList 2
  if (expr_ret_543) {
    // CodeExpr
    #define ret expr_ret_543
    ret = SUCC;
    #line 560 "daisho.peg"
    rule=node(VARDECL, t, i);
    #line 9917 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_543) rew(mod_543);
  expr_ret_542 = expr_ret_543;
  if (!rule) rule = expr_ret_542;
  if (!expr_ret_542) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule vardeclexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_546
  daisho_astnode_t* expr_ret_546 = NULL;
  daisho_astnode_t* expr_ret_547 = NULL;
  daisho_astnode_t* expr_ret_548 = NULL;

  // SlashExpr 0
  if (!expr_ret_548) {
    daisho_astnode_t* expr_ret_549 = NULL;
    rec(mod_549);
    // ModExprList Forwarding
    expr_ret_549 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_549) rew(mod_549);
    expr_ret_548 = expr_ret_549;
  }

  // SlashExpr 1
  if (!expr_ret_548) {
    daisho_astnode_t* expr_ret_550 = NULL;
    rec(mod_550);
    // ModExprList Forwarding
    expr_ret_550 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_550) rew(mod_550);
    expr_ret_548 = expr_ret_550;
  }

  // SlashExpr end
  expr_ret_547 = expr_ret_548;

  if (!rule) rule = expr_ret_547;
  if (!expr_ret_547) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule strlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_551
  daisho_astnode_t* expr_ret_551 = NULL;
  daisho_astnode_t* expr_ret_552 = NULL;
  daisho_astnode_t* expr_ret_553 = NULL;
  rec(mod_553);
  // ModExprList 0
  daisho_astnode_t* expr_ret_554 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_554 = leaf(STRLIT);
    expr_ret_554->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_554->len_or_toknum = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_554 = NULL;
  }

  expr_ret_553 = expr_ret_554;
  s = expr_ret_554;
  // ModExprList 1
  if (expr_ret_553) {
    // CodeExpr
    #define ret expr_ret_553
    ret = SUCC;
    #line 565 "daisho.peg"
    rule=list(SSTR); add(rule, s);
    #line 10000 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_553) {
    daisho_astnode_t* expr_ret_555 = NULL;
    daisho_astnode_t* expr_ret_556 = SUCC;
    while (expr_ret_556)
    {
      rec(kleene_rew_555);
      daisho_astnode_t* expr_ret_557 = NULL;
      rec(mod_557);
      // ModExprList 0
      daisho_astnode_t* expr_ret_558 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_558 = leaf(STRLIT);
        expr_ret_558->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_558->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_558 = NULL;
      }

      expr_ret_557 = expr_ret_558;
      s = expr_ret_558;
      // ModExprList 1
      if (expr_ret_557) {
        // CodeExpr
        #define ret expr_ret_557
        ret = SUCC;
        #line 566 "daisho.peg"
        add(rule, s);
        #line 10035 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_557) rew(mod_557);
      expr_ret_556 = expr_ret_557;
    }

    expr_ret_555 = SUCC;
    expr_ret_553 = expr_ret_555;
  }

  // ModExprList end
  if (!expr_ret_553) rew(mod_553);
  expr_ret_552 = expr_ret_553;
  if (!rule) rule = expr_ret_552;
  if (!expr_ret_552) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_559
  daisho_astnode_t* expr_ret_559 = NULL;
  daisho_astnode_t* expr_ret_560 = NULL;
  daisho_astnode_t* expr_ret_561 = NULL;
  rec(mod_561);
  // ModExprList 0
  daisho_astnode_t* expr_ret_562 = NULL;
  expr_ret_562 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_561 = expr_ret_562;
  f = expr_ret_562;
  // ModExprList 1
  if (expr_ret_561) {
    // CodeExpr
    #define ret expr_ret_561
    ret = SUCC;
    #line 568 "daisho.peg"
    rule=list(FSTR); add(rule, f);
    #line 10079 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_561) {
    daisho_astnode_t* expr_ret_563 = NULL;
    daisho_astnode_t* expr_ret_564 = SUCC;
    while (expr_ret_564)
    {
      rec(kleene_rew_563);
      daisho_astnode_t* expr_ret_565 = NULL;
      rec(mod_565);
      // ModExprList 0
      daisho_astnode_t* expr_ret_566 = NULL;
      expr_ret_566 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_565 = expr_ret_566;
      f = expr_ret_566;
      // ModExprList 1
      if (expr_ret_565) {
        // CodeExpr
        #define ret expr_ret_565
        ret = SUCC;
        #line 569 "daisho.peg"
        add(rule, f);
        #line 10106 "daisho_tokenizer_parser.h"

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_565) rew(mod_565);
      expr_ret_564 = expr_ret_565;
    }

    expr_ret_563 = SUCC;
    expr_ret_561 = expr_ret_563;
  }

  // ModExprList end
  if (!expr_ret_561) rew(mod_561);
  expr_ret_560 = expr_ret_561;
  if (!rule) rule = expr_ret_560;
  if (!expr_ret_560) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrlit returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrfrag(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* x = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_567
  daisho_astnode_t* expr_ret_567 = NULL;
  daisho_astnode_t* expr_ret_568 = NULL;
  daisho_astnode_t* expr_ret_569 = NULL;

  // SlashExpr 0
  if (!expr_ret_569) {
    daisho_astnode_t* expr_ret_570 = NULL;
    rec(mod_570);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_570 = leaf(STRLIT);
      expr_ret_570->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_570->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_570 = NULL;
    }

    // ModExprList end
    if (!expr_ret_570) rew(mod_570);
    expr_ret_569 = expr_ret_570;
  }

  // SlashExpr 1
  if (!expr_ret_569) {
    daisho_astnode_t* expr_ret_571 = NULL;
    rec(mod_571);
    // ModExprList 0
    daisho_astnode_t* expr_ret_572 = NULL;
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_572 = leaf(FSTRLITSTART);
      expr_ret_572->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_572->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_572 = NULL;
    }

    expr_ret_571 = expr_ret_572;
    s = expr_ret_572;
    // ModExprList 1
    if (expr_ret_571) {
      // CodeExpr
      #define ret expr_ret_571
      ret = SUCC;
      #line 572 "daisho.peg"
      rule=list(FSTRFRAG); add(rule, s);
      #line 10185 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_571) {
      daisho_astnode_t* expr_ret_573 = NULL;
      expr_ret_573 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_571 = expr_ret_573;
      x = expr_ret_573;
    }

    // ModExprList 3
    if (expr_ret_571) {
      // CodeExpr
      #define ret expr_ret_571
      ret = SUCC;
      #line 573 "daisho.peg"
      add(rule, x);
      #line 10206 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList 4
    if (expr_ret_571) {
      daisho_astnode_t* expr_ret_574 = NULL;
      daisho_astnode_t* expr_ret_575 = SUCC;
      while (expr_ret_575)
      {
        rec(kleene_rew_574);
        daisho_astnode_t* expr_ret_576 = NULL;
        rec(mod_576);
        // ModExprList 0
        daisho_astnode_t* expr_ret_577 = NULL;
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_577 = leaf(FSTRLITMID);
          expr_ret_577->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_577->len_or_toknum = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_577 = NULL;
        }

        expr_ret_576 = expr_ret_577;
        m = expr_ret_577;
        // ModExprList 1
        if (expr_ret_576) {
          daisho_astnode_t* expr_ret_578 = NULL;
          expr_ret_578 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_576 = expr_ret_578;
          x = expr_ret_578;
        }

        // ModExprList 2
        if (expr_ret_576) {
          // CodeExpr
          #define ret expr_ret_576
          ret = SUCC;
          #line 574 "daisho.peg"
          add(rule, m); add(rule, x);
          #line 10250 "daisho_tokenizer_parser.h"

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_576) rew(mod_576);
        expr_ret_575 = expr_ret_576;
      }

      expr_ret_574 = SUCC;
      expr_ret_571 = expr_ret_574;
    }

    // ModExprList 5
    if (expr_ret_571) {
      daisho_astnode_t* expr_ret_579 = NULL;
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_579 = leaf(FSTRLITEND);
        expr_ret_579->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_579->len_or_toknum = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_579 = NULL;
      }

      expr_ret_571 = expr_ret_579;
      e = expr_ret_579;
    }

    // ModExprList 6
    if (expr_ret_571) {
      // CodeExpr
      #define ret expr_ret_571
      ret = SUCC;
      #line 575 "daisho.peg"
      add(rule, e);
      #line 10288 "daisho_tokenizer_parser.h"

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_571) rew(mod_571);
    expr_ret_569 = expr_ret_571;
  }

  // SlashExpr end
  expr_ret_568 = expr_ret_569;

  if (!rule) rule = expr_ret_568;
  if (!expr_ret_568) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule fstrfrag returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_580
  daisho_astnode_t* expr_ret_580 = NULL;
  daisho_astnode_t* expr_ret_581 = NULL;
  daisho_astnode_t* expr_ret_582 = NULL;
  rec(mod_582);
  // ModExprList 0
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_582 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_582 = NULL;
  }

  // ModExprList 1
  if (expr_ret_582) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_582 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_582 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_582) {
    daisho_astnode_t* expr_ret_583 = NULL;
    daisho_astnode_t* expr_ret_584 = NULL;

    // SlashExpr 0
    if (!expr_ret_584) {
      daisho_astnode_t* expr_ret_585 = NULL;
      rec(mod_585);
      // ModExprList Forwarding
      expr_ret_585 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_585) rew(mod_585);
      expr_ret_584 = expr_ret_585;
    }

    // SlashExpr 1
    if (!expr_ret_584) {
      daisho_astnode_t* expr_ret_586 = NULL;
      rec(mod_586);
      // ModExprList Forwarding
      expr_ret_586 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_586) rew(mod_586);
      expr_ret_584 = expr_ret_586;
    }

    // SlashExpr end
    expr_ret_583 = expr_ret_584;

    expr_ret_582 = expr_ret_583;
    te = expr_ret_583;
  }

  // ModExprList 3
  if (expr_ret_582) {
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_582 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_582 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_582) {
    // CodeExpr
    #define ret expr_ret_582
    ret = SUCC;
    #line 577 "daisho.peg"
    rule=node(SIZEOF, te);
    #line 10391 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_582) rew(mod_582);
  expr_ret_581 = expr_ret_582;
  if (!rule) rule = expr_ret_581;
  if (!expr_ret_581) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule sizeofexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_587
  daisho_astnode_t* expr_ret_587 = NULL;
  daisho_astnode_t* expr_ret_588 = NULL;
  daisho_astnode_t* expr_ret_589 = NULL;
  rec(mod_589);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_590 = NULL;

  // SlashExpr 0
  if (!expr_ret_590) {
    daisho_astnode_t* expr_ret_591 = NULL;
    rec(mod_591);
    // ModExprList Forwarding
    expr_ret_591 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_591) rew(mod_591);
    expr_ret_590 = expr_ret_591;
  }

  // SlashExpr 1
  if (!expr_ret_590) {
    daisho_astnode_t* expr_ret_592 = NULL;
    rec(mod_592);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_592
    ret = SUCC;
    #line 632 "daisho.peg"
    WARNING("Missing expression."); ret=leaf(RECOVERY);
    #line 10437 "daisho_tokenizer_parser.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_592) rew(mod_592);
    expr_ret_590 = expr_ret_592;
  }

  // SlashExpr end
  expr_ret_589 = expr_ret_590;

  // ModExprList end
  if (!expr_ret_589) rew(mod_589);
  expr_ret_588 = expr_ret_589;
  if (!rule) rule = expr_ret_588;
  if (!expr_ret_588) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_593
  daisho_astnode_t* expr_ret_593 = NULL;
  daisho_astnode_t* expr_ret_594 = NULL;
  daisho_astnode_t* expr_ret_595 = NULL;
  rec(mod_595);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_596 = NULL;
  rec(mod_596);
  // ModExprList 0
  daisho_astnode_t* expr_ret_597 = NULL;
  expr_ret_597 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_596 = expr_ret_597;
  e = expr_ret_597;
  // ModExprList 1
  if (expr_ret_596) {
    // CodeExpr
    #define ret expr_ret_596
    ret = SUCC;
    #line 633 "daisho.peg"
    WARNING("Extra expression."); ret=e;
    #line 10481 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_596) rew(mod_596);
  expr_ret_595 = expr_ret_596;
  // ModExprList end
  if (!expr_ret_595) rew(mod_595);
  expr_ret_594 = expr_ret_595;
  if (!rule) rule = expr_ret_594;
  if (!expr_ret_594) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule noexpr returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_598
  daisho_astnode_t* expr_ret_598 = NULL;
  daisho_astnode_t* expr_ret_599 = NULL;
  daisho_astnode_t* expr_ret_600 = NULL;
  rec(mod_600);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_601 = NULL;

  // SlashExpr 0
  if (!expr_ret_601) {
    daisho_astnode_t* expr_ret_602 = NULL;
    rec(mod_602);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_602 = leaf(COMMA);
      expr_ret_602->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_602->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_602 = NULL;
    }

    // ModExprList end
    if (!expr_ret_602) rew(mod_602);
    expr_ret_601 = expr_ret_602;
  }

  // SlashExpr 1
  if (!expr_ret_601) {
    daisho_astnode_t* expr_ret_603 = NULL;
    rec(mod_603);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_603
    ret = SUCC;
    #line 634 "daisho.peg"
    WARNING("Missing comma."); ret=leaf(COMMA);
    #line 10538 "daisho_tokenizer_parser.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_603) rew(mod_603);
    expr_ret_601 = expr_ret_603;
  }

  // SlashExpr end
  expr_ret_600 = expr_ret_601;

  // ModExprList end
  if (!expr_ret_600) rew(mod_600);
  expr_ret_599 = expr_ret_600;
  if (!rule) rule = expr_ret_599;
  if (!expr_ret_599) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wcomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_604
  daisho_astnode_t* expr_ret_604 = NULL;
  daisho_astnode_t* expr_ret_605 = NULL;
  daisho_astnode_t* expr_ret_606 = NULL;
  rec(mod_606);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_607 = NULL;
  rec(mod_607);
  // ModExprList 0
  daisho_astnode_t* expr_ret_608 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_608 = leaf(COMMA);
    expr_ret_608->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_608->len_or_toknum = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_608 = NULL;
  }

  expr_ret_607 = expr_ret_608;
  c = expr_ret_608;
  // ModExprList 1
  if (expr_ret_607) {
    // CodeExpr
    #define ret expr_ret_607
    ret = SUCC;
    #line 635 "daisho.peg"
    WARNING("Extra comma."); ret=c;
    #line 10590 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_607) rew(mod_607);
  expr_ret_606 = expr_ret_607;
  // ModExprList end
  if (!expr_ret_606) rew(mod_606);
  expr_ret_605 = expr_ret_606;
  if (!rule) rule = expr_ret_605;
  if (!expr_ret_605) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nocomma returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_609
  daisho_astnode_t* expr_ret_609 = NULL;
  daisho_astnode_t* expr_ret_610 = NULL;
  daisho_astnode_t* expr_ret_611 = NULL;
  rec(mod_611);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_612 = NULL;

  // SlashExpr 0
  if (!expr_ret_612) {
    daisho_astnode_t* expr_ret_613 = NULL;
    rec(mod_613);
    // ModExprList Forwarding
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_613 = leaf(SEMI);
      expr_ret_613->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_613->len_or_toknum = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_613 = NULL;
    }

    // ModExprList end
    if (!expr_ret_613) rew(mod_613);
    expr_ret_612 = expr_ret_613;
  }

  // SlashExpr 1
  if (!expr_ret_612) {
    daisho_astnode_t* expr_ret_614 = NULL;
    rec(mod_614);
    // ModExprList Forwarding
    // CodeExpr
    #define ret expr_ret_614
    ret = SUCC;
    #line 636 "daisho.peg"
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #line 10647 "daisho_tokenizer_parser.h"

    #undef ret
    // ModExprList end
    if (!expr_ret_614) rew(mod_614);
    expr_ret_612 = expr_ret_614;
  }

  // SlashExpr end
  expr_ret_611 = expr_ret_612;

  // ModExprList end
  if (!expr_ret_611) rew(mod_611);
  expr_ret_610 = expr_ret_611;
  if (!rule) rule = expr_ret_610;
  if (!expr_ret_610) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule wsemi returned SUCC.\n"), exit(1);
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_615
  daisho_astnode_t* expr_ret_615 = NULL;
  daisho_astnode_t* expr_ret_616 = NULL;
  daisho_astnode_t* expr_ret_617 = NULL;
  rec(mod_617);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_618 = NULL;
  rec(mod_618);
  // ModExprList 0
  daisho_astnode_t* expr_ret_619 = NULL;
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_619 = leaf(SEMI);
    expr_ret_619->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_619->len_or_toknum = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_619 = NULL;
  }

  expr_ret_618 = expr_ret_619;
  s = expr_ret_619;
  // ModExprList 1
  if (expr_ret_618) {
    // CodeExpr
    #define ret expr_ret_618
    ret = SUCC;
    #line 637 "daisho.peg"
    WARNING("Extra semicolon."); ret=s;
    #line 10699 "daisho_tokenizer_parser.h"

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_618) rew(mod_618);
  expr_ret_617 = expr_ret_618;
  // ModExprList end
  if (!expr_ret_617) rew(mod_617);
  expr_ret_616 = expr_ret_617;
  if (!rule) rule = expr_ret_616;
  if (!expr_ret_616) rule = NULL;
  if (rule==SUCC) fprintf(stderr, "ERROR: Rule nosemi returned SUCC.\n"), exit(1);
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

