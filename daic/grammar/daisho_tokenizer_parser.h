
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
// Tokens 1 through 89 are the ones you defined.
// This totals 91 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 91
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
         ((c >= 65) & (c <= 90))) {
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

    // Transition NUMLIT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 >= 0) & (smaut_state_7 <= 2)) &
         ((c >= 48) & (c <= 57))) {
          smaut_state_7 = 2;
      }
      else if ((smaut_state_7 == 2) &
         (c == 46)) {
          smaut_state_7 = 3;
      }
      else if ((smaut_state_7 == 3) &
         ((c >= 48) & (c <= 57))) {
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
         (c == 123)) {
          smaut_state_8 = -1;
      }
      else if ((smaut_state_8 == 1) &
         (c == 10)) {
          smaut_state_8 = -1;
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
      else if ((smaut_state_8 == 3) &
         (c == 123)) {
          smaut_state_8 = 1;
      }
      else if ((smaut_state_8 == 3) &
         (c == 125)) {
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

    // Transition FSTRLITSTART State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         (c == 34)) {
          smaut_state_9 = 1;
      }
      else if ((smaut_state_9 == 1) &
         (c == 123)) {
          smaut_state_9 = 2;
      }
      else if ((smaut_state_9 == 1) &
         (c == 34)) {
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

    // Transition FSTRLITMID State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         (c == 125)) {
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

    // Transition FSTRLITEND State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 125)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 34)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 1) &
         (c == 123)) {
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

    // Transition CHARLIT State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 39)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 10)) {
          smaut_state_12 = -1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 92)) {
          smaut_state_12 = 4;
      }
      else if ((smaut_state_12 == 1) &
         (1)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 110)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 102)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 98)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 114)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 116)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 101)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 92)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 4) &
         (c == 39)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (c == 39)) {
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

    // Transition WS State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if (((smaut_state_13 == 0) | (smaut_state_13 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_13 = 1;
      }
      else {
        smaut_state_13 = -1;
      }

      // Check accept
      if (smaut_state_13 == 1) {
        smaut_munch_size_13 = iidx + 1;
      }
    }

    // Transition MLCOM State Machine
    if (smaut_state_14 != -1) {
      all_dead = 0;

      if ((smaut_state_14 == 0) &
         (c == 47)) {
          smaut_state_14 = 1;
      }
      else if ((smaut_state_14 == 1) &
         (c == 42)) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 2) &
         (c == 42)) {
          smaut_state_14 = 3;
      }
      else if ((smaut_state_14 == 2) &
         (1)) {
          smaut_state_14 = 2;
      }
      else if ((smaut_state_14 == 3) &
         (c == 42)) {
          smaut_state_14 = 3;
      }
      else if ((smaut_state_14 == 3) &
         (c == 47)) {
          smaut_state_14 = 4;
      }
      else if ((smaut_state_14 == 3) &
         (1)) {
          smaut_state_14 = 2;
      }
      else {
        smaut_state_14 = -1;
      }

      // Check accept
      if (smaut_state_14 == 4) {
        smaut_munch_size_14 = iidx + 1;
      }
    }

    // Transition SLCOM State Machine
    if (smaut_state_15 != -1) {
      all_dead = 0;

      if ((smaut_state_15 == 0) &
         (c == 47)) {
          smaut_state_15 = 1;
      }
      else if ((smaut_state_15 == 1) &
         (c == 47)) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 2) &
         (!(c == 10))) {
          smaut_state_15 = 2;
      }
      else if ((smaut_state_15 == 2) &
         (c == 10)) {
          smaut_state_15 = 3;
      }
      else {
        smaut_state_15 = -1;
      }

      // Check accept
      if ((smaut_state_15 == 2) | (smaut_state_15 == 3)) {
        smaut_munch_size_15 = iidx + 1;
      }
    }

    // Transition SHEBANG State Machine
    if (smaut_state_16 != -1) {
      all_dead = 0;

      if ((smaut_state_16 == 0) &
         (c == 35)) {
          smaut_state_16 = 1;
      }
      else if ((smaut_state_16 == 1) &
         (c == 33)) {
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
      if (smaut_state_16 == 3) {
        smaut_munch_size_16 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

  // Determine what token was accepted, if any.
  daisho_token_kind kind = DAISHO_TOK_STREAMEND;
  size_t max_munch = 0;
  if (smaut_munch_size_16 >= max_munch) {
    kind = DAISHO_TOK_SHEBANG;
    max_munch = smaut_munch_size_16;
  }
  if (smaut_munch_size_15 >= max_munch) {
    kind = DAISHO_TOK_SLCOM;
    max_munch = smaut_munch_size_15;
  }
  if (smaut_munch_size_14 >= max_munch) {
    kind = DAISHO_TOK_MLCOM;
    max_munch = smaut_munch_size_14;
  }
  if (smaut_munch_size_13 >= max_munch) {
    kind = DAISHO_TOK_WS;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_CHARLIT;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITEND;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITMID;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_FSTRLITSTART;
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
  DAISHO_NODE_RECOVERY,
  DAISHO_NODE_PROGRAM,
  DAISHO_NODE_NSLIST,
  DAISHO_NODE_NSDECLS,
  DAISHO_NODE_GLOBAL,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_IMPLLIST,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_FNHEAD,
  DAISHO_NODE_FNDECL,
  DAISHO_NODE_FNPROTO,
  DAISHO_NODE_TMPLEXPAND,
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

#define DAISHO_NUM_NODEKINDS 132
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
  "RECOVERY",
  "PROGRAM",
  "NSLIST",
  "NSDECLS",
  "GLOBAL",
  "MEMBERLIST",
  "IMPLLIST",
  "TMPLTRAIT",
  "FNHEAD",
  "FNDECL",
  "FNPROTO",
  "TMPLEXPAND",
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
  node->repr_len = 0;
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
  node->repr_len = 0;
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
#ifndef DAIC_ASTHELPERS_INCLUDE
#include "../asthelpers.h"
#endif
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
static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impllist(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
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
    // Capturing SHEBANG.
    expr_ret_3 = leaf(SHEBANG);
    expr_ret_3->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_3->repr_len = ctx->tokens[ctx->pos].len;
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
    #line 3396 "daisho_tokenizer_parser.h"

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
    #line 3413 "daisho_tokenizer_parser.h"

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
    #line 3430 "daisho_tokenizer_parser.h"

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
      daisho_astnode_t* expr_ret_10 = NULL;
      expr_ret_10 = daisho_parse_namespace(ctx);
      if (ctx->exit) return NULL;
      expr_ret_9 = expr_ret_10;
      ns = expr_ret_10;
      // ModExprList 1
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
                  if (cpstr_equals(current->children[0]->tok_repr, current->children[0]->repr_len,
                                   ns->children[0]->tok_repr, ns->children[0]->repr_len)) {
                    for (size_t j = 0; j < ns->children[1]->num_children; j++)
                      add(current->children[1], ns->children[1]->children[j]);
                    found = 1;
                    break;
                  }
                }
                if (!found)
                  add(nses, ns);
              ;
        #line 3477 "daisho_tokenizer_parser.h"

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
    #line 34 "daisho.peg"
    rule=(!has(sh)) ? node(PROGRAM, nses)
                              : node(PROGRAM, nses, sh);
    #line 3503 "daisho_tokenizer_parser.h"

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
    #line 38 "daisho.peg"
    ret=srepr(leaf(TYPEIDENT), "GLOBAL");
    #line 3597 "daisho_tokenizer_parser.h"

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
    #line 39 "daisho.peg"
    ret = list(NSDECLS);
    #line 3629 "daisho_tokenizer_parser.h"

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
    #line 39 "daisho.peg"
    add(l, t);
    #line 3645 "daisho_tokenizer_parser.h"

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
      daisho_astnode_t* expr_ret_26 = NULL;
      intr_enter(ctx, "SEMI", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
        // Not capturing SEMI.
        expr_ret_26 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_26 = NULL;
      }

      if (expr_ret_26) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
      // optional
      if (!expr_ret_26)
        expr_ret_26 = SUCC;
      expr_ret_25 = expr_ret_26;
      // ModExprList 1
      if (expr_ret_25) {
        daisho_astnode_t* expr_ret_27 = NULL;
        expr_ret_27 = daisho_parse_topdecl(ctx);
        if (ctx->exit) return NULL;
        expr_ret_25 = expr_ret_27;
        t = expr_ret_27;
      }

      // ModExprList 2
      if (expr_ret_25) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_25
        ret = SUCC;
        #line 40 "daisho.peg"
        add(l, t);
        #line 3693 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
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
    daisho_astnode_t* expr_ret_28 = NULL;
    intr_enter(ctx, "SEMI", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_28 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_28 = NULL;
    }

    if (expr_ret_28) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
    // optional
    if (!expr_ret_28)
      expr_ret_28 = SUCC;
    expr_ret_14 = expr_ret_28;
  }

  // ModExprList 6
  if (expr_ret_14) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_14
    ret = SUCC;
    #line 42 "daisho.peg"
    rule = node(NAMESPACE, name, l);
    #line 3735 "daisho_tokenizer_parser.h"

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
  #define rule expr_ret_29
  daisho_astnode_t* expr_ret_29 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;
  intr_enter(ctx, "topdecl", ctx->pos);
  daisho_astnode_t* expr_ret_31 = NULL;

  // SlashExpr 0
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_32 = NULL;
    rec(mod_32);
    // ModExprList Forwarding
    expr_ret_32 = daisho_parse_structdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_32) rew(mod_32);
    expr_ret_31 = expr_ret_32;
  }

  // SlashExpr 1
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_33 = NULL;
    rec(mod_33);
    // ModExprList Forwarding
    expr_ret_33 = daisho_parse_uniondecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_33) rew(mod_33);
    expr_ret_31 = expr_ret_33;
  }

  // SlashExpr 2
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_34 = NULL;
    rec(mod_34);
    // ModExprList Forwarding
    expr_ret_34 = daisho_parse_traitdecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_34) rew(mod_34);
    expr_ret_31 = expr_ret_34;
  }

  // SlashExpr 3
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_35 = NULL;
    rec(mod_35);
    // ModExprList Forwarding
    expr_ret_35 = daisho_parse_impldecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_35) rew(mod_35);
    expr_ret_31 = expr_ret_35;
  }

  // SlashExpr 4
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_36 = NULL;
    rec(mod_36);
    // ModExprList Forwarding
    expr_ret_36 = daisho_parse_ctypedecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_36) rew(mod_36);
    expr_ret_31 = expr_ret_36;
  }

  // SlashExpr 5
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_37 = NULL;
    rec(mod_37);
    // ModExprList Forwarding
    expr_ret_37 = daisho_parse_cfndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_37) rew(mod_37);
    expr_ret_31 = expr_ret_37;
  }

  // SlashExpr 6
  if (!expr_ret_31) {
    daisho_astnode_t* expr_ret_38 = NULL;
    rec(mod_38);
    // ModExprList Forwarding
    expr_ret_38 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_38) rew(mod_38);
    expr_ret_31 = expr_ret_38;
  }

  // SlashExpr end
  expr_ret_30 = expr_ret_31;

  if (!rule) rule = expr_ret_30;
  if (!expr_ret_30) rule = NULL;
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
  #define rule expr_ret_39
  daisho_astnode_t* expr_ret_39 = NULL;
  daisho_astnode_t* expr_ret_40 = NULL;
  intr_enter(ctx, "structdecl", ctx->pos);
  daisho_astnode_t* expr_ret_41 = NULL;
  rec(mod_41);
  // ModExprList 0
  intr_enter(ctx, "STRUCT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
    // Not capturing STRUCT.
    expr_ret_41 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_41 = NULL;
  }

  if (expr_ret_41) intr_accept(ctx, "STRUCT"); else intr_reject(ctx, "STRUCT");
  // ModExprList 1
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_42 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_42 = leaf(TYPEIDENT);
      expr_ret_42->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_42->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_42 = NULL;
    }

    if (expr_ret_42) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
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
    daisho_astnode_t* expr_ret_44 = NULL;
    expr_ret_44 = daisho_parse_impllist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_41 = expr_ret_44;
    il = expr_ret_44;
  }

  // ModExprList 4
  if (expr_ret_41) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

    if (expr_ret_41) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_41) {
    daisho_astnode_t* expr_ret_45 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_45
    ret = SUCC;
    #line 99 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 3939 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_41 = expr_ret_45;
    members = expr_ret_45;
  }

  // ModExprList 6
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
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_48
        ret = SUCC;
        #line 100 "daisho.peg"
        add(members, m);
        #line 3970 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_48) rew(mod_48);
      expr_ret_47 = expr_ret_48;
    }

    expr_ret_46 = SUCC;
    expr_ret_41 = expr_ret_46;
  }

  // ModExprList 7
  if (expr_ret_41) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_41 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_41 = NULL;
    }

    if (expr_ret_41) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_41) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_41
    ret = SUCC;
    #line 102 "daisho.peg"
    rule = node(STRUCT, id, tmpl, il, members);
    #line 4007 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_41) rew(mod_41);
  expr_ret_40 = expr_ret_41;
  if (!rule) rule = expr_ret_40;
  if (!expr_ret_40) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "structdecl");
  else if (rule) intr_accept(ctx, "structdecl");
  else intr_reject(ctx, "structdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* il = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_50
  daisho_astnode_t* expr_ret_50 = NULL;
  daisho_astnode_t* expr_ret_51 = NULL;
  intr_enter(ctx, "uniondecl", ctx->pos);
  daisho_astnode_t* expr_ret_52 = NULL;
  rec(mod_52);
  // ModExprList 0
  intr_enter(ctx, "UNION", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
    // Not capturing UNION.
    expr_ret_52 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_52 = NULL;
  }

  if (expr_ret_52) intr_accept(ctx, "UNION"); else intr_reject(ctx, "UNION");
  // ModExprList 1
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_53 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_53 = leaf(TYPEIDENT);
      expr_ret_53->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_53->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_53 = NULL;
    }

    if (expr_ret_53) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
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
    daisho_astnode_t* expr_ret_55 = NULL;
    expr_ret_55 = daisho_parse_impllist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_52 = expr_ret_55;
    il = expr_ret_55;
  }

  // ModExprList 4
  if (expr_ret_52) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_52 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_52 = NULL;
    }

    if (expr_ret_52) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_56 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_56
    ret = SUCC;
    #line 105 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4108 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_52 = expr_ret_56;
    members = expr_ret_56;
  }

  // ModExprList 6
  if (expr_ret_52) {
    daisho_astnode_t* expr_ret_57 = NULL;
    daisho_astnode_t* expr_ret_58 = SUCC;
    while (expr_ret_58)
    {
      rec(kleene_rew_57);
      daisho_astnode_t* expr_ret_59 = NULL;
      rec(mod_59);
      // ModExprList 0
      daisho_astnode_t* expr_ret_60 = NULL;
      expr_ret_60 = daisho_parse_typemember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_59 = expr_ret_60;
      m = expr_ret_60;
      // ModExprList 1
      if (expr_ret_59) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_59
        ret = SUCC;
        #line 106 "daisho.peg"
        add(members, m);
        #line 4139 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_59) rew(mod_59);
      expr_ret_58 = expr_ret_59;
    }

    expr_ret_57 = SUCC;
    expr_ret_52 = expr_ret_57;
  }

  // ModExprList 7
  if (expr_ret_52) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_52 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_52 = NULL;
    }

    if (expr_ret_52) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_52) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_52
    ret = SUCC;
    #line 108 "daisho.peg"
    rule = node(UNION, id, tmpl, il, members);
    #line 4176 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_52) rew(mod_52);
  expr_ret_51 = expr_ret_52;
  if (!rule) rule = expr_ret_51;
  if (!expr_ret_51) rule = NULL;
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
  #define rule expr_ret_61
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_62 = NULL;
  intr_enter(ctx, "traitdecl", ctx->pos);
  daisho_astnode_t* expr_ret_63 = NULL;
  rec(mod_63);
  // ModExprList 0
  intr_enter(ctx, "TRAIT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
    // Not capturing TRAIT.
    expr_ret_63 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_63 = NULL;
  }

  if (expr_ret_63) intr_accept(ctx, "TRAIT"); else intr_reject(ctx, "TRAIT");
  // ModExprList 1
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_64 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_64 = leaf(TYPEIDENT);
      expr_ret_64->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_64->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_64 = NULL;
    }

    if (expr_ret_64) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_63 = expr_ret_64;
    id = expr_ret_64;
  }

  // ModExprList 2
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_65 = NULL;
    expr_ret_65 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_63 = expr_ret_65;
    tmpl = expr_ret_65;
  }

  // ModExprList 3
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_66 = NULL;
    expr_ret_66 = daisho_parse_impllist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_63 = expr_ret_66;
    il = expr_ret_66;
  }

  // ModExprList 4
  if (expr_ret_63) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

    if (expr_ret_63) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_67 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_67
    ret = SUCC;
    #line 111 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4277 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_63 = expr_ret_67;
    members = expr_ret_67;
  }

  // ModExprList 6
  if (expr_ret_63) {
    daisho_astnode_t* expr_ret_68 = NULL;
    daisho_astnode_t* expr_ret_69 = SUCC;
    while (expr_ret_69)
    {
      rec(kleene_rew_68);
      daisho_astnode_t* expr_ret_70 = NULL;
      rec(mod_70);
      // ModExprList 0
      daisho_astnode_t* expr_ret_71 = NULL;
      expr_ret_71 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_70 = expr_ret_71;
      m = expr_ret_71;
      // ModExprList 1
      if (expr_ret_70) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_70
        ret = SUCC;
        #line 112 "daisho.peg"
        add(members, m);
        #line 4308 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_70) rew(mod_70);
      expr_ret_69 = expr_ret_70;
    }

    expr_ret_68 = SUCC;
    expr_ret_63 = expr_ret_68;
  }

  // ModExprList 7
  if (expr_ret_63) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_63 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_63 = NULL;
    }

    if (expr_ret_63) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_63) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_63
    ret = SUCC;
    #line 114 "daisho.peg"
    rule = node(TRAIT, id, tmpl, il, members);
    #line 4345 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_63) rew(mod_63);
  expr_ret_62 = expr_ret_63;
  if (!rule) rule = expr_ret_62;
  if (!expr_ret_62) rule = NULL;
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
  #define rule expr_ret_72
  daisho_astnode_t* expr_ret_72 = NULL;
  daisho_astnode_t* expr_ret_73 = NULL;
  intr_enter(ctx, "impldecl", ctx->pos);
  daisho_astnode_t* expr_ret_74 = NULL;
  rec(mod_74);
  // ModExprList 0
  intr_enter(ctx, "IMPL", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
    // Not capturing IMPL.
    expr_ret_74 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_74 = NULL;
  }

  if (expr_ret_74) intr_accept(ctx, "IMPL"); else intr_reject(ctx, "IMPL");
  // ModExprList 1
  if (expr_ret_74) {
    daisho_astnode_t* expr_ret_75 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_75 = leaf(TYPEIDENT);
      expr_ret_75->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_75->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_75 = NULL;
    }

    if (expr_ret_75) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_74 = expr_ret_75;
    id = expr_ret_75;
  }

  // ModExprList 2
  if (expr_ret_74) {
    daisho_astnode_t* expr_ret_76 = NULL;
    expr_ret_76 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_74 = expr_ret_76;
    tmpl = expr_ret_76;
  }

  // ModExprList 3
  if (expr_ret_74) {
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_74 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_74 = NULL;
    }

    if (expr_ret_74) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_74) {
    daisho_astnode_t* expr_ret_77 = NULL;
    expr_ret_77 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    expr_ret_74 = expr_ret_77;
    ft = expr_ret_77;
  }

  // ModExprList 5
  if (expr_ret_74) {
    intr_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_74 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_74 = NULL;
    }

    if (expr_ret_74) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  }

  // ModExprList 6
  if (expr_ret_74) {
    daisho_astnode_t* expr_ret_78 = NULL;
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_78
    ret = SUCC;
    #line 117 "daisho.peg"
    ret=list(MEMBERLIST);
    #line 4460 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_74 = expr_ret_78;
    members = expr_ret_78;
  }

  // ModExprList 7
  if (expr_ret_74) {
    daisho_astnode_t* expr_ret_79 = NULL;
    daisho_astnode_t* expr_ret_80 = SUCC;
    while (expr_ret_80)
    {
      rec(kleene_rew_79);
      daisho_astnode_t* expr_ret_81 = NULL;
      rec(mod_81);
      // ModExprList 0
      daisho_astnode_t* expr_ret_82 = NULL;
      expr_ret_82 = daisho_parse_fnmember(ctx);
      if (ctx->exit) return NULL;
      expr_ret_81 = expr_ret_82;
      m = expr_ret_82;
      // ModExprList 1
      if (expr_ret_81) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_81
        ret = SUCC;
        #line 118 "daisho.peg"
        add(members, m);
        #line 4491 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_81) rew(mod_81);
      expr_ret_80 = expr_ret_81;
    }

    expr_ret_79 = SUCC;
    expr_ret_74 = expr_ret_79;
  }

  // ModExprList 8
  if (expr_ret_74) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_74 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_74 = NULL;
    }

    if (expr_ret_74) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList 9
  if (expr_ret_74) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_74
    ret = SUCC;
    #line 120 "daisho.peg"
    rule = node(IMPL, id, tmpl, ft, members);
    #line 4528 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_74) rew(mod_74);
  expr_ret_73 = expr_ret_74;
  if (!rule) rule = expr_ret_73;
  if (!expr_ret_73) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "impldecl");
  else if (rule) intr_accept(ctx, "impldecl");
  else intr_reject(ctx, "impldecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_83
  daisho_astnode_t* expr_ret_83 = NULL;
  daisho_astnode_t* expr_ret_84 = NULL;
  intr_enter(ctx, "ctypedecl", ctx->pos);
  daisho_astnode_t* expr_ret_85 = NULL;
  rec(mod_85);
  // ModExprList 0
  intr_enter(ctx, "CTYPE", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
    // Not capturing CTYPE.
    expr_ret_85 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_85 = NULL;
  }

  if (expr_ret_85) intr_accept(ctx, "CTYPE"); else intr_reject(ctx, "CTYPE");
  // ModExprList 1
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_86 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_86 = leaf(TYPEIDENT);
      expr_ret_86->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_86->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_86 = NULL;
    }

    if (expr_ret_86) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_85 = expr_ret_86;
    id = expr_ret_86;
  }

  // ModExprList 2
  if (expr_ret_85) {
    daisho_astnode_t* expr_ret_87 = NULL;
    expr_ret_87 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_85 = expr_ret_87;
    c = expr_ret_87;
  }

  // ModExprList 3
  if (expr_ret_85) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_85
    ret = SUCC;
    #line 123 "daisho.peg"
    rule = node(CTYPE, id, c);
    #line 4602 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_85) rew(mod_85);
  expr_ret_84 = expr_ret_85;
  if (!rule) rule = expr_ret_84;
  if (!expr_ret_84) rule = NULL;
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
  #define rule expr_ret_88
  daisho_astnode_t* expr_ret_88 = NULL;
  daisho_astnode_t* expr_ret_89 = NULL;
  intr_enter(ctx, "cfndecl", ctx->pos);
  daisho_astnode_t* expr_ret_90 = NULL;
  rec(mod_90);
  // ModExprList 0
  intr_enter(ctx, "CFN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
    // Not capturing CFN.
    expr_ret_90 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_90 = NULL;
  }

  if (expr_ret_90) intr_accept(ctx, "CFN"); else intr_reject(ctx, "CFN");
  // ModExprList 1
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_91 = NULL;
    expr_ret_91 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_90 = expr_ret_91;
    rett = expr_ret_91;
  }

  // ModExprList 2
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_92 = NULL;
    expr_ret_92 = daisho_parse_cident(ctx);
    if (ctx->exit) return NULL;
    expr_ret_90 = expr_ret_92;
    ci = expr_ret_92;
  }

  // ModExprList 3
  if (expr_ret_90) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_90 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_90 = NULL;
    }

    if (expr_ret_90) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 4
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_93 = NULL;
    expr_ret_93 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_90 = expr_ret_93;
    al = expr_ret_93;
  }

  // ModExprList 5
  if (expr_ret_90) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_90 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_90 = NULL;
    }

    if (expr_ret_90) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 6
  if (expr_ret_90) {
    daisho_astnode_t* expr_ret_94 = NULL;
    expr_ret_94 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_94)
      expr_ret_94 = SUCC;
    expr_ret_90 = expr_ret_94;
  }

  // ModExprList 7
  if (expr_ret_90) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_90
    ret = SUCC;
    #line 129 "daisho.peg"
    rule = node(CFN, rett, ci, al);
    #line 4715 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_90) rew(mod_90);
  expr_ret_89 = expr_ret_90;
  if (!rule) rule = expr_ret_89;
  if (!expr_ret_89) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "cfndecl");
  else if (rule) intr_accept(ctx, "cfndecl");
  else intr_reject(ctx, "cfndecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cident(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_95
  daisho_astnode_t* expr_ret_95 = NULL;
  daisho_astnode_t* expr_ret_96 = NULL;
  intr_enter(ctx, "cident", ctx->pos);
  daisho_astnode_t* expr_ret_97 = NULL;
  rec(mod_97);
  // ModExprList 0
  daisho_astnode_t* expr_ret_98 = NULL;
  intr_enter(ctx, "VARIDENT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
    // Capturing VARIDENT.
    expr_ret_98 = leaf(VARIDENT);
    expr_ret_98->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_98->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_98 = NULL;
  }

  if (expr_ret_98) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
  expr_ret_97 = expr_ret_98;
  rule = expr_ret_98;
  // ModExprList 1
  if (expr_ret_97) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_97
    ret = SUCC;
    #line 131 "daisho.peg"
    
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
    #line 4777 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_97) rew(mod_97);
  expr_ret_96 = expr_ret_97;
  if (!rule) rule = expr_ret_96;
  if (!expr_ret_96) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "cident");
  else if (rule) intr_accept(ctx, "cident");
  else intr_reject(ctx, "cident");
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
    expr_ret_107 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_101 = expr_ret_107;
    e = expr_ret_107;
  }

  // ModExprList 8
  if (expr_ret_101) {
    daisho_astnode_t* expr_ret_108 = NULL;
    expr_ret_108 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_108)
      expr_ret_108 = SUCC;
    expr_ret_101 = expr_ret_108;
  }

  // ModExprList 9
  if (expr_ret_101) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_101
    ret = SUCC;
    #line 149 "daisho.peg"
    rule=node(FNDECL, rett, name, tmpl, al, e);
    #line 4925 "daisho_tokenizer_parser.h"

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
  #define rule expr_ret_109
  daisho_astnode_t* expr_ret_109 = NULL;
  daisho_astnode_t* expr_ret_110 = NULL;
  intr_enter(ctx, "fnproto", ctx->pos);
  daisho_astnode_t* expr_ret_111 = NULL;
  rec(mod_111);
  // ModExprList 0
  daisho_astnode_t* expr_ret_112 = NULL;
  intr_enter(ctx, "FN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
    // Not capturing FN.
    expr_ret_112 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_112 = NULL;
  }

  if (expr_ret_112) intr_accept(ctx, "FN"); else intr_reject(ctx, "FN");
  // optional
  if (!expr_ret_112)
    expr_ret_112 = SUCC;
  expr_ret_111 = expr_ret_112;
  // ModExprList 1
  if (expr_ret_111) {
    daisho_astnode_t* expr_ret_113 = NULL;
    expr_ret_113 = daisho_parse_returntype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_111 = expr_ret_113;
    rett = expr_ret_113;
  }

  // ModExprList 2
  if (expr_ret_111) {
    daisho_astnode_t* expr_ret_114 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_114 = leaf(VARIDENT);
      expr_ret_114->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_114->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_114 = NULL;
    }

    if (expr_ret_114) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_111 = expr_ret_114;
    name = expr_ret_114;
  }

  // ModExprList 3
  if (expr_ret_111) {
    daisho_astnode_t* expr_ret_115 = NULL;
    expr_ret_115 = daisho_parse_tmplexpand(ctx);
    if (ctx->exit) return NULL;
    expr_ret_111 = expr_ret_115;
    tmpl = expr_ret_115;
  }

  // ModExprList 4
  if (expr_ret_111) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_111 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_111 = NULL;
    }

    if (expr_ret_111) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 5
  if (expr_ret_111) {
    daisho_astnode_t* expr_ret_116 = NULL;
    expr_ret_116 = daisho_parse_protoarglist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_111 = expr_ret_116;
    al = expr_ret_116;
  }

  // ModExprList 6
  if (expr_ret_111) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_111 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_111 = NULL;
    }

    if (expr_ret_111) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 7
  if (expr_ret_111) {
    daisho_astnode_t* expr_ret_117 = NULL;
    expr_ret_117 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_117)
      expr_ret_117 = SUCC;
    expr_ret_111 = expr_ret_117;
  }

  // ModExprList 8
  if (expr_ret_111) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_111
    ret = SUCC;
    #line 155 "daisho.peg"
    rule=node(FNPROTO, rett, name, tmpl, al);
    #line 5063 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_111) rew(mod_111);
  expr_ret_110 = expr_ret_111;
  if (!rule) rule = expr_ret_110;
  if (!expr_ret_110) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnproto");
  else if (rule) intr_accept(ctx, "fnproto");
  else intr_reject(ctx, "fnproto");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_118
  daisho_astnode_t* expr_ret_118 = NULL;
  daisho_astnode_t* expr_ret_119 = NULL;
  intr_enter(ctx, "fnmember", ctx->pos);
  daisho_astnode_t* expr_ret_120 = NULL;

  // SlashExpr 0
  if (!expr_ret_120) {
    daisho_astnode_t* expr_ret_121 = NULL;
    rec(mod_121);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_122 = NULL;
    expr_ret_122 = daisho_parse_fndecl(ctx);
    if (ctx->exit) return NULL;
    expr_ret_121 = expr_ret_122;
    rule = expr_ret_122;
    // ModExprList end
    if (!expr_ret_121) rew(mod_121);
    expr_ret_120 = expr_ret_121;
  }

  // SlashExpr 1
  if (!expr_ret_120) {
    daisho_astnode_t* expr_ret_123 = NULL;
    rec(mod_123);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_124 = NULL;
    expr_ret_124 = daisho_parse_fnproto(ctx);
    if (ctx->exit) return NULL;
    expr_ret_123 = expr_ret_124;
    rule = expr_ret_124;
    // ModExprList end
    if (!expr_ret_123) rew(mod_123);
    expr_ret_120 = expr_ret_123;
  }

  // SlashExpr end
  expr_ret_119 = expr_ret_120;

  if (!rule) rule = expr_ret_119;
  if (!expr_ret_119) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnmember");
  else if (rule) intr_accept(ctx, "fnmember");
  else intr_reject(ctx, "fnmember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_125
  daisho_astnode_t* expr_ret_125 = NULL;
  daisho_astnode_t* expr_ret_126 = NULL;
  intr_enter(ctx, "typemember", ctx->pos);
  daisho_astnode_t* expr_ret_127 = NULL;
  rec(mod_127);
  // ModExprList 0
  daisho_astnode_t* expr_ret_128 = NULL;
  expr_ret_128 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_127 = expr_ret_128;
  t = expr_ret_128;
  // ModExprList 1
  if (expr_ret_127) {
    daisho_astnode_t* expr_ret_129 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_129 = leaf(VARIDENT);
      expr_ret_129->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_129->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_129 = NULL;
    }

    if (expr_ret_129) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_127 = expr_ret_129;
    v = expr_ret_129;
  }

  // ModExprList 2
  if (expr_ret_127) {
    expr_ret_127 = daisho_parse_wsemi(ctx);
    if (ctx->exit) return NULL;
  }

  // ModExprList 3
  if (expr_ret_127) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_127
    ret = SUCC;
    #line 161 "daisho.peg"
    rule=node(TYPEMEMBER, t, v);
    #line 5179 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_127) rew(mod_127);
  expr_ret_126 = expr_ret_127;
  if (!rule) rule = expr_ret_126;
  if (!expr_ret_126) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "typemember");
  else if (rule) intr_accept(ctx, "typemember");
  else intr_reject(ctx, "typemember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impllist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_130
  daisho_astnode_t* expr_ret_130 = NULL;
  daisho_astnode_t* expr_ret_131 = NULL;
  intr_enter(ctx, "impllist", ctx->pos);
  daisho_astnode_t* expr_ret_132 = NULL;
  rec(mod_132);
  // ModExprList 0
  daisho_astnode_t* expr_ret_133 = NULL;
  // CodeExpr
  intr_enter(ctx, "CodeExpr", ctx->pos);
  #define ret expr_ret_133
  ret = SUCC;
  #line 163 "daisho.peg"
  ret=list(IMPLLIST);
  #line 5214 "daisho_tokenizer_parser.h"

  if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
  #undef ret
  expr_ret_132 = expr_ret_133;
  rule = expr_ret_133;
  // ModExprList 1
  if (expr_ret_132) {
    daisho_astnode_t* expr_ret_134 = NULL;
    expr_ret_134 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_134)
      expr_ret_134 = SUCC;
    expr_ret_132 = expr_ret_134;
  }

  // ModExprList 2
  if (expr_ret_132) {
    daisho_astnode_t* expr_ret_135 = NULL;
    expr_ret_135 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_135)
      expr_ret_135 = SUCC;
    expr_ret_132 = expr_ret_135;
    t = expr_ret_135;
  }

  // ModExprList 3
  if (expr_ret_132) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_132
    ret = SUCC;
    #line 164 "daisho.peg"
    if (has(t)) add(rule, t);
    #line 5251 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_132) {
    daisho_astnode_t* expr_ret_136 = NULL;
    daisho_astnode_t* expr_ret_137 = SUCC;
    while (expr_ret_137)
    {
      rec(kleene_rew_136);
      daisho_astnode_t* expr_ret_138 = NULL;
      rec(mod_138);
      // ModExprList 0
      daisho_astnode_t* expr_ret_139 = NULL;
      expr_ret_139 = daisho_parse_wcomma(ctx);
      if (ctx->exit) return NULL;
      // optional
      if (!expr_ret_139)
        expr_ret_139 = SUCC;
      expr_ret_138 = expr_ret_139;
      // ModExprList 1
      if (expr_ret_138) {
        daisho_astnode_t* expr_ret_140 = NULL;
        expr_ret_140 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_138 = expr_ret_140;
        t = expr_ret_140;
      }

      // ModExprList 2
      if (expr_ret_138) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_138
        ret = SUCC;
        #line 165 "daisho.peg"
        add(rule, t);
        #line 5291 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_138) rew(mod_138);
      expr_ret_137 = expr_ret_138;
    }

    expr_ret_136 = SUCC;
    expr_ret_132 = expr_ret_136;
  }

  // ModExprList 5
  if (expr_ret_132) {
    daisho_astnode_t* expr_ret_141 = NULL;
    expr_ret_141 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_141)
      expr_ret_141 = SUCC;
    expr_ret_132 = expr_ret_141;
  }

  // ModExprList end
  if (!expr_ret_132) rew(mod_132);
  expr_ret_131 = expr_ret_132;
  if (!rule) rule = expr_ret_131;
  if (!expr_ret_131) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "impllist");
  else if (rule) intr_accept(ctx, "impllist");
  else intr_reject(ctx, "impllist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_142
  daisho_astnode_t* expr_ret_142 = NULL;
  daisho_astnode_t* expr_ret_143 = NULL;
  intr_enter(ctx, "tmplexpand", ctx->pos);
  daisho_astnode_t* expr_ret_144 = NULL;
  rec(mod_144);
  // ModExprList 0
  intr_enter(ctx, "LT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
    // Not capturing LT.
    expr_ret_144 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_144 = NULL;
  }

  if (expr_ret_144) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
  // ModExprList 1
  if (expr_ret_144) {
    daisho_astnode_t* expr_ret_145 = NULL;
    expr_ret_145 = daisho_parse_typelist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_144 = expr_ret_145;
    rule = expr_ret_145;
  }

  // ModExprList 2
  if (expr_ret_144) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_144
    ret = SUCC;
    #line 168 "daisho.peg"
    rule->kind = kind(TMPLEXPAND);
    #line 5365 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_144) {
    intr_enter(ctx, "GT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Capturing GT.
      expr_ret_144 = leaf(GT);
      expr_ret_144->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_144->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_144 = NULL;
    }

    if (expr_ret_144) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
  }

  // ModExprList end
  if (!expr_ret_144) rew(mod_144);
  expr_ret_143 = expr_ret_144;
  if (!rule) rule = expr_ret_143;
  if (!expr_ret_143) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tmplexpand");
  else if (rule) intr_accept(ctx, "tmplexpand");
  else intr_reject(ctx, "tmplexpand");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_returntype(daisho_parser_ctx* ctx) {
  #define rule expr_ret_146
  daisho_astnode_t* expr_ret_146 = NULL;
  daisho_astnode_t* expr_ret_147 = NULL;
  intr_enter(ctx, "returntype", ctx->pos);
  daisho_astnode_t* expr_ret_148 = NULL;
  rec(mod_148);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_149 = NULL;

  // SlashExpr 0
  if (!expr_ret_149) {
    daisho_astnode_t* expr_ret_150 = NULL;
    rec(mod_150);
    // ModExprList Forwarding
    expr_ret_150 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_150) rew(mod_150);
    expr_ret_149 = expr_ret_150;
  }

  // SlashExpr 1
  if (!expr_ret_149) {
    daisho_astnode_t* expr_ret_151 = NULL;
    rec(mod_151);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_151
    ret = SUCC;
    #line 171 "daisho.peg"
    ret=leaf(VOIDTYPE);
    #line 5432 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_151) rew(mod_151);
    expr_ret_149 = expr_ret_151;
  }

  // SlashExpr end
  expr_ret_148 = expr_ret_149;

  // ModExprList end
  if (!expr_ret_148) rew(mod_148);
  expr_ret_147 = expr_ret_148;
  if (!rule) rule = expr_ret_147;
  if (!expr_ret_147) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "returntype");
  else if (rule) intr_accept(ctx, "returntype");
  else intr_reject(ctx, "returntype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  #define rule expr_ret_152
  daisho_astnode_t* expr_ret_152 = NULL;
  daisho_astnode_t* expr_ret_153 = NULL;
  intr_enter(ctx, "type", ctx->pos);
  daisho_astnode_t* expr_ret_154 = NULL;
  rec(mod_154);
  // ModExprList Forwarding
  expr_ret_154 = daisho_parse_fntype(ctx);
  if (ctx->exit) return NULL;
  // ModExprList end
  if (!expr_ret_154) rew(mod_154);
  expr_ret_153 = expr_ret_154;
  if (!rule) rule = expr_ret_153;
  if (!expr_ret_153) rule = NULL;
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
  #define rule expr_ret_155
  daisho_astnode_t* expr_ret_155 = NULL;
  daisho_astnode_t* expr_ret_156 = NULL;
  intr_enter(ctx, "fntype", ctx->pos);
  daisho_astnode_t* expr_ret_157 = NULL;
  rec(mod_157);
  // ModExprList 0
  daisho_astnode_t* expr_ret_158 = NULL;
  // CodeExpr
  intr_enter(ctx, "CodeExpr", ctx->pos);
  #define ret expr_ret_158
  ret = SUCC;
  #line 200 "daisho.peg"
  ;
  #line 5496 "daisho_tokenizer_parser.h"

  if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
  #undef ret
  expr_ret_157 = expr_ret_158;
  from = expr_ret_158;
  // ModExprList 1
  if (expr_ret_157) {
    daisho_astnode_t* expr_ret_159 = NULL;
    expr_ret_159 = daisho_parse_ptrtype(ctx);
    if (ctx->exit) return NULL;
    expr_ret_157 = expr_ret_159;
    to = expr_ret_159;
  }

  // ModExprList 2
  if (expr_ret_157) {
    daisho_astnode_t* expr_ret_160 = NULL;
    daisho_astnode_t* expr_ret_161 = SUCC;
    while (expr_ret_161)
    {
      rec(kleene_rew_160);
      daisho_astnode_t* expr_ret_162 = NULL;
      rec(mod_162);
      // ModExprList 0
      intr_enter(ctx, "ARROW", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_162 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_162 = NULL;
      }

      if (expr_ret_162) intr_accept(ctx, "ARROW"); else intr_reject(ctx, "ARROW");
      // ModExprList 1
      if (expr_ret_162) {
        daisho_astnode_t* expr_ret_163 = NULL;
        expr_ret_163 = daisho_parse_ptrtype(ctx);
        if (ctx->exit) return NULL;
        expr_ret_162 = expr_ret_163;
        n = expr_ret_163;
      }

      // ModExprList 2
      if (expr_ret_162) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_162
        ret = SUCC;
        #line 202 "daisho.peg"
        if (!has(from)) from = list(TYPELIST);
        #line 5548 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 3
      if (expr_ret_162) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_162
        ret = SUCC;
        #line 203 "daisho.peg"
        add(from, to); to = n;
        #line 5562 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_162) rew(mod_162);
      expr_ret_161 = expr_ret_162;
    }

    expr_ret_160 = SUCC;
    expr_ret_157 = expr_ret_160;
  }

  // ModExprList 3
  if (expr_ret_157) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_157
    ret = SUCC;
    #line 204 "daisho.peg"
    rule=has(from) ? node(FNTYPE, from, to) : to;
    #line 5585 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_157) rew(mod_157);
  expr_ret_156 = expr_ret_157;
  if (!rule) rule = expr_ret_156;
  if (!expr_ret_156) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fntype");
  else if (rule) intr_accept(ctx, "fntype");
  else intr_reject(ctx, "fntype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ptrtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_164
  daisho_astnode_t* expr_ret_164 = NULL;
  daisho_astnode_t* expr_ret_165 = NULL;
  intr_enter(ctx, "ptrtype", ctx->pos);
  daisho_astnode_t* expr_ret_166 = NULL;
  rec(mod_166);
  // ModExprList 0
  daisho_astnode_t* expr_ret_167 = NULL;
  expr_ret_167 = daisho_parse_basetype(ctx);
  if (ctx->exit) return NULL;
  expr_ret_166 = expr_ret_167;
  rule = expr_ret_167;
  // ModExprList 1
  if (expr_ret_166) {
    daisho_astnode_t* expr_ret_168 = NULL;
    daisho_astnode_t* expr_ret_169 = SUCC;
    while (expr_ret_169)
    {
      rec(kleene_rew_168);
      daisho_astnode_t* expr_ret_170 = NULL;
      rec(mod_170);
      // ModExprList 0
      intr_enter(ctx, "STAR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_170 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_170 = NULL;
      }

      if (expr_ret_170) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
      // ModExprList 1
      if (expr_ret_170) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_170
        ret = SUCC;
        #line 206 "daisho.peg"
        rule=node(PTRTYPE, rule);
        #line 5645 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_170) rew(mod_170);
      expr_ret_169 = expr_ret_170;
    }

    expr_ret_168 = SUCC;
    expr_ret_166 = expr_ret_168;
  }

  // ModExprList end
  if (!expr_ret_166) rew(mod_166);
  expr_ret_165 = expr_ret_166;
  if (!rule) rule = expr_ret_165;
  if (!expr_ret_165) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ptrtype");
  else if (rule) intr_accept(ctx, "ptrtype");
  else intr_reject(ctx, "ptrtype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_basetype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_171
  daisho_astnode_t* expr_ret_171 = NULL;
  daisho_astnode_t* expr_ret_172 = NULL;
  intr_enter(ctx, "basetype", ctx->pos);
  daisho_astnode_t* expr_ret_173 = NULL;

  // SlashExpr 0
  if (!expr_ret_173) {
    daisho_astnode_t* expr_ret_174 = NULL;
    rec(mod_174);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_174 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_174 = NULL;
    }

    if (expr_ret_174) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_174) {
      daisho_astnode_t* expr_ret_175 = NULL;
      expr_ret_175 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_174 = expr_ret_175;
      rule = expr_ret_175;
    }

    // ModExprList 2
    if (expr_ret_174) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_174 = leaf(CLOSE);
        expr_ret_174->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_174->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_174 = NULL;
      }

      if (expr_ret_174) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList end
    if (!expr_ret_174) rew(mod_174);
    expr_ret_173 = expr_ret_174;
  }

  // SlashExpr 1
  if (!expr_ret_173) {
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
    expr_ret_173 = expr_ret_176;
  }

  // SlashExpr 2
  if (!expr_ret_173) {
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
      #line 210 "daisho.peg"
      rule=v;
      #line 5799 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_177) rew(mod_177);
    expr_ret_173 = expr_ret_177;
  }

  // SlashExpr 3
  if (!expr_ret_173) {
    daisho_astnode_t* expr_ret_180 = NULL;
    rec(mod_180);
    // ModExprList Forwarding
    expr_ret_180 = daisho_parse_voidptr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_180) rew(mod_180);
    expr_ret_173 = expr_ret_180;
  }

  // SlashExpr 4
  if (!expr_ret_173) {
    daisho_astnode_t* expr_ret_181 = NULL;
    rec(mod_181);
    // ModExprList 0
    daisho_astnode_t* expr_ret_182 = NULL;
    intr_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_182 = leaf(TYPEIDENT);
      expr_ret_182->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_182->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_182 = NULL;
    }

    if (expr_ret_182) intr_accept(ctx, "TYPEIDENT"); else intr_reject(ctx, "TYPEIDENT");
    expr_ret_181 = expr_ret_182;
    s = expr_ret_182;
    // ModExprList 1
    if (expr_ret_181) {
      daisho_astnode_t* expr_ret_183 = NULL;
      expr_ret_183 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_181 = expr_ret_183;
      t = expr_ret_183;
    }

    // ModExprList 2
    if (expr_ret_181) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_181
      ret = SUCC;
      #line 212 "daisho.peg"
      rule=has(t) ? node(TMPLEXPAND, t, s) : s;
      #line 5859 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_181) rew(mod_181);
    expr_ret_173 = expr_ret_181;
  }

  // SlashExpr end
  expr_ret_172 = expr_ret_173;

  if (!rule) rule = expr_ret_172;
  if (!expr_ret_172) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "basetype");
  else if (rule) intr_accept(ctx, "basetype");
  else intr_reject(ctx, "basetype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tupletype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_184
  daisho_astnode_t* expr_ret_184 = NULL;
  daisho_astnode_t* expr_ret_185 = NULL;
  intr_enter(ctx, "tupletype", ctx->pos);
  daisho_astnode_t* expr_ret_186 = NULL;

  // SlashExpr 0
  if (!expr_ret_186) {
    daisho_astnode_t* expr_ret_187 = NULL;
    rec(mod_187);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_187 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_187 = NULL;
    }

    if (expr_ret_187) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_187) {
      daisho_astnode_t* expr_ret_188 = NULL;
      expr_ret_188 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      expr_ret_187 = expr_ret_188;
      t = expr_ret_188;
    }

    // ModExprList 2
    if (expr_ret_187) {
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_187 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_187 = NULL;
      }

      if (expr_ret_187) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    }

    // ModExprList 3
    if (expr_ret_187) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_187 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_187 = NULL;
      }

      if (expr_ret_187) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList 4
    if (expr_ret_187) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_187
      ret = SUCC;
      #line 214 "daisho.peg"
      rule=node(TUPLETYPE, t);
      #line 5950 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_187) rew(mod_187);
    expr_ret_186 = expr_ret_187;
  }

  // SlashExpr 1
  if (!expr_ret_186) {
    daisho_astnode_t* expr_ret_189 = NULL;
    rec(mod_189);
    // ModExprList 0
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_189 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_189 = NULL;
    }

    if (expr_ret_189) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
    // ModExprList 1
    if (expr_ret_189) {
      daisho_astnode_t* expr_ret_190 = NULL;
      expr_ret_190 = daisho_parse_typelist(ctx);
      if (ctx->exit) return NULL;
      expr_ret_189 = expr_ret_190;
      rule = expr_ret_190;
    }

    // ModExprList 2
    if (expr_ret_189) {
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_189 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_189 = NULL;
      }

      if (expr_ret_189) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
    }

    // ModExprList 3
    if (expr_ret_189) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_189
      ret = SUCC;
      #line 215 "daisho.peg"
      rule->kind = kind(TUPLETYPE);
      #line 6007 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_189) rew(mod_189);
    expr_ret_186 = expr_ret_189;
  }

  // SlashExpr end
  expr_ret_185 = expr_ret_186;

  if (!rule) rule = expr_ret_185;
  if (!expr_ret_185) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tupletype");
  else if (rule) intr_accept(ctx, "tupletype");
  else intr_reject(ctx, "tupletype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_191
  daisho_astnode_t* expr_ret_191 = NULL;
  daisho_astnode_t* expr_ret_192 = NULL;
  intr_enter(ctx, "voidptr", ctx->pos);
  daisho_astnode_t* expr_ret_193 = NULL;

  // SlashExpr 0
  if (!expr_ret_193) {
    daisho_astnode_t* expr_ret_194 = NULL;
    rec(mod_194);
    // ModExprList 0
    daisho_astnode_t* expr_ret_195 = NULL;
    intr_enter(ctx, "VOIDPTR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
      // Capturing VOIDPTR.
      expr_ret_195 = leaf(VOIDPTR);
      expr_ret_195->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_195->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_195 = NULL;
    }

    if (expr_ret_195) intr_accept(ctx, "VOIDPTR"); else intr_reject(ctx, "VOIDPTR");
    expr_ret_194 = expr_ret_195;
    v = expr_ret_195;
    // ModExprList 1
    if (expr_ret_194) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_194
      ret = SUCC;
      #line 217 "daisho.peg"
      rule=v;
      #line 6067 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_194) rew(mod_194);
    expr_ret_193 = expr_ret_194;
  }

  // SlashExpr 1
  if (!expr_ret_193) {
    daisho_astnode_t* expr_ret_196 = NULL;
    rec(mod_196);
    // ModExprList 0
    daisho_astnode_t* expr_ret_197 = NULL;
    intr_enter(ctx, "VOIDTYPE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
      // Capturing VOIDTYPE.
      expr_ret_197 = leaf(VOIDTYPE);
      expr_ret_197->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_197->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_197 = NULL;
    }

    if (expr_ret_197) intr_accept(ctx, "VOIDTYPE"); else intr_reject(ctx, "VOIDTYPE");
    expr_ret_196 = expr_ret_197;
    v = expr_ret_197;
    // ModExprList 1
    if (expr_ret_196) {
      daisho_astnode_t* expr_ret_198 = NULL;
      intr_enter(ctx, "STAR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_198 = leaf(STAR);
        expr_ret_198->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_198->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_198 = NULL;
      }

      if (expr_ret_198) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
      expr_ret_196 = expr_ret_198;
      s = expr_ret_198;
    }

    // ModExprList 2
    if (expr_ret_196) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_196
      ret = SUCC;
      #line 218 "daisho.peg"
      rule=leaf(VOIDPTR);
      #line 6125 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_196) rew(mod_196);
    expr_ret_193 = expr_ret_196;
  }

  // SlashExpr end
  expr_ret_192 = expr_ret_193;

  if (!rule) rule = expr_ret_192;
  if (!expr_ret_192) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "voidptr");
  else if (rule) intr_accept(ctx, "voidptr");
  else intr_reject(ctx, "voidptr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typelist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_199
  daisho_astnode_t* expr_ret_199 = NULL;
  daisho_astnode_t* expr_ret_200 = NULL;
  intr_enter(ctx, "typelist", ctx->pos);
  daisho_astnode_t* expr_ret_201 = NULL;
  rec(mod_201);
  // ModExprList 0
  daisho_astnode_t* expr_ret_202 = NULL;
  expr_ret_202 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_202)
    expr_ret_202 = SUCC;
  expr_ret_201 = expr_ret_202;
  // ModExprList 1
  if (expr_ret_201) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_201
    ret = SUCC;
    #line 288 "daisho.peg"
    rule=list(TYPELIST);
    #line 6172 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_201) {
    daisho_astnode_t* expr_ret_203 = NULL;
    expr_ret_203 = daisho_parse_type(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_203)
      expr_ret_203 = SUCC;
    expr_ret_201 = expr_ret_203;
    t = expr_ret_203;
  }

  // ModExprList 3
  if (expr_ret_201) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_201
    ret = SUCC;
    #line 289 "daisho.peg"
    if has(t) add(rule, t);
    #line 6198 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_201) {
    daisho_astnode_t* expr_ret_204 = NULL;
    daisho_astnode_t* expr_ret_205 = SUCC;
    while (expr_ret_205)
    {
      rec(kleene_rew_204);
      daisho_astnode_t* expr_ret_206 = NULL;
      rec(mod_206);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_206 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_206 = NULL;
      }

      if (expr_ret_206) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_206) {
        daisho_astnode_t* expr_ret_207 = NULL;
        expr_ret_207 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_206 = expr_ret_207;
        t = expr_ret_207;
      }

      // ModExprList 2
      if (expr_ret_206) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_206
        ret = SUCC;
        #line 290 "daisho.peg"
        add(rule, t);
        #line 6241 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_206) rew(mod_206);
      expr_ret_205 = expr_ret_206;
    }

    expr_ret_204 = SUCC;
    expr_ret_201 = expr_ret_204;
  }

  // ModExprList 5
  if (expr_ret_201) {
    daisho_astnode_t* expr_ret_208 = NULL;
    expr_ret_208 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_208)
      expr_ret_208 = SUCC;
    expr_ret_201 = expr_ret_208;
  }

  // ModExprList end
  if (!expr_ret_201) rew(mod_201);
  expr_ret_200 = expr_ret_201;
  if (!rule) rule = expr_ret_200;
  if (!expr_ret_200) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "typelist");
  else if (rule) intr_accept(ctx, "typelist");
  else intr_reject(ctx, "typelist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_exprlist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_209
  daisho_astnode_t* expr_ret_209 = NULL;
  daisho_astnode_t* expr_ret_210 = NULL;
  intr_enter(ctx, "exprlist", ctx->pos);
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
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_211
    ret = SUCC;
    #line 292 "daisho.peg"
    rule=list(EXPRLIST);
    #line 6303 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_211) {
    daisho_astnode_t* expr_ret_213 = NULL;
    expr_ret_213 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_213)
      expr_ret_213 = SUCC;
    expr_ret_211 = expr_ret_213;
    e = expr_ret_213;
  }

  // ModExprList 3
  if (expr_ret_211) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_211
    ret = SUCC;
    #line 293 "daisho.peg"
    if has(e) add(rule, e);
    #line 6329 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
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
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_216 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_216 = NULL;
      }

      if (expr_ret_216) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_216) {
        daisho_astnode_t* expr_ret_217 = NULL;
        expr_ret_217 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_216 = expr_ret_217;
        e = expr_ret_217;
      }

      // ModExprList 2
      if (expr_ret_216) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_216
        ret = SUCC;
        #line 294 "daisho.peg"
        add(rule, e);
        #line 6372 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
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
  if (rule==SUCC) intr_succ(ctx, "exprlist");
  else if (rule) intr_accept(ctx, "exprlist");
  else intr_reject(ctx, "exprlist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_219
  daisho_astnode_t* expr_ret_219 = NULL;
  daisho_astnode_t* expr_ret_220 = NULL;
  intr_enter(ctx, "fnarg", ctx->pos);
  daisho_astnode_t* expr_ret_221 = NULL;
  rec(mod_221);
  // ModExprList 0
  daisho_astnode_t* expr_ret_222 = NULL;
  expr_ret_222 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_221 = expr_ret_222;
  t = expr_ret_222;
  // ModExprList 1
  if (expr_ret_221) {
    daisho_astnode_t* expr_ret_223 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_223 = leaf(VARIDENT);
      expr_ret_223->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_223->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_223 = NULL;
    }

    if (expr_ret_223) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_221 = expr_ret_223;
    i = expr_ret_223;
  }

  // ModExprList 2
  if (expr_ret_221) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_221
    ret = SUCC;
    #line 297 "daisho.peg"
    rule=node(FNARG, t, i);
    #line 6452 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_221) rew(mod_221);
  expr_ret_220 = expr_ret_221;
  if (!rule) rule = expr_ret_220;
  if (!expr_ret_220) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fnarg");
  else if (rule) intr_accept(ctx, "fnarg");
  else intr_reject(ctx, "fnarg");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_arglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* a = NULL;
  #define rule expr_ret_224
  daisho_astnode_t* expr_ret_224 = NULL;
  daisho_astnode_t* expr_ret_225 = NULL;
  intr_enter(ctx, "arglist", ctx->pos);
  daisho_astnode_t* expr_ret_226 = NULL;
  rec(mod_226);
  // ModExprList 0
  daisho_astnode_t* expr_ret_227 = NULL;
  expr_ret_227 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_227)
    expr_ret_227 = SUCC;
  expr_ret_226 = expr_ret_227;
  // ModExprList 1
  if (expr_ret_226) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_226
    ret = SUCC;
    #line 298 "daisho.peg"
    rule=list(ARGLIST);
    #line 6494 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_226) {
    daisho_astnode_t* expr_ret_228 = NULL;
    expr_ret_228 = daisho_parse_fnarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_228)
      expr_ret_228 = SUCC;
    expr_ret_226 = expr_ret_228;
    a = expr_ret_228;
  }

  // ModExprList 3
  if (expr_ret_226) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_226
    ret = SUCC;
    #line 299 "daisho.peg"
    if has(a) add(rule, a);
    #line 6520 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_226) {
    daisho_astnode_t* expr_ret_229 = NULL;
    daisho_astnode_t* expr_ret_230 = SUCC;
    while (expr_ret_230)
    {
      rec(kleene_rew_229);
      daisho_astnode_t* expr_ret_231 = NULL;
      rec(mod_231);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_231 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_231 = NULL;
      }

      if (expr_ret_231) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_231) {
        daisho_astnode_t* expr_ret_232 = NULL;
        expr_ret_232 = daisho_parse_fnarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_231 = expr_ret_232;
        a = expr_ret_232;
      }

      // ModExprList 2
      if (expr_ret_231) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_231
        ret = SUCC;
        #line 300 "daisho.peg"
        add(rule, a);
        #line 6563 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_231) rew(mod_231);
      expr_ret_230 = expr_ret_231;
    }

    expr_ret_229 = SUCC;
    expr_ret_226 = expr_ret_229;
  }

  // ModExprList 5
  if (expr_ret_226) {
    daisho_astnode_t* expr_ret_233 = NULL;
    expr_ret_233 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_233)
      expr_ret_233 = SUCC;
    expr_ret_226 = expr_ret_233;
  }

  // ModExprList end
  if (!expr_ret_226) rew(mod_226);
  expr_ret_225 = expr_ret_226;
  if (!rule) rule = expr_ret_225;
  if (!expr_ret_225) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "arglist");
  else if (rule) intr_accept(ctx, "arglist");
  else intr_reject(ctx, "arglist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_234
  daisho_astnode_t* expr_ret_234 = NULL;
  daisho_astnode_t* expr_ret_235 = NULL;
  intr_enter(ctx, "protoarg", ctx->pos);
  daisho_astnode_t* expr_ret_236 = NULL;
  rec(mod_236);
  // ModExprList 0
  daisho_astnode_t* expr_ret_237 = NULL;
  expr_ret_237 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_236 = expr_ret_237;
  t = expr_ret_237;
  // ModExprList 1
  if (expr_ret_236) {
    daisho_astnode_t* expr_ret_238 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_238 = leaf(VARIDENT);
      expr_ret_238->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_238->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_238 = NULL;
    }

    if (expr_ret_238) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    // optional
    if (!expr_ret_238)
      expr_ret_238 = SUCC;
    expr_ret_236 = expr_ret_238;
    i = expr_ret_238;
  }

  // ModExprList 2
  if (expr_ret_236) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_236
    ret = SUCC;
    #line 303 "daisho.peg"
    rule=node(PROTOARG, t);
    #line 6646 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_236) rew(mod_236);
  expr_ret_235 = expr_ret_236;
  if (!rule) rule = expr_ret_235;
  if (!expr_ret_235) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "protoarg");
  else if (rule) intr_accept(ctx, "protoarg");
  else intr_reject(ctx, "protoarg");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_protoarglist(daisho_parser_ctx* ctx) {
  daisho_astnode_t* p = NULL;
  #define rule expr_ret_239
  daisho_astnode_t* expr_ret_239 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
  intr_enter(ctx, "protoarglist", ctx->pos);
  daisho_astnode_t* expr_ret_241 = NULL;
  rec(mod_241);
  // ModExprList 0
  daisho_astnode_t* expr_ret_242 = NULL;
  expr_ret_242 = daisho_parse_nocomma(ctx);
  if (ctx->exit) return NULL;
  // optional
  if (!expr_ret_242)
    expr_ret_242 = SUCC;
  expr_ret_241 = expr_ret_242;
  // ModExprList 1
  if (expr_ret_241) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_241
    ret = SUCC;
    #line 305 "daisho.peg"
    rule=list(PROTOLIST);
    #line 6688 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_241) {
    daisho_astnode_t* expr_ret_243 = NULL;
    expr_ret_243 = daisho_parse_protoarg(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_243)
      expr_ret_243 = SUCC;
    expr_ret_241 = expr_ret_243;
    p = expr_ret_243;
  }

  // ModExprList 3
  if (expr_ret_241) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_241
    ret = SUCC;
    #line 306 "daisho.peg"
    if has(p) add(rule, p);
    #line 6714 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_241) {
    daisho_astnode_t* expr_ret_244 = NULL;
    daisho_astnode_t* expr_ret_245 = SUCC;
    while (expr_ret_245)
    {
      rec(kleene_rew_244);
      daisho_astnode_t* expr_ret_246 = NULL;
      rec(mod_246);
      // ModExprList 0
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_246 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_246 = NULL;
      }

      if (expr_ret_246) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
      // ModExprList 1
      if (expr_ret_246) {
        daisho_astnode_t* expr_ret_247 = NULL;
        expr_ret_247 = daisho_parse_protoarg(ctx);
        if (ctx->exit) return NULL;
        expr_ret_246 = expr_ret_247;
        p = expr_ret_247;
      }

      // ModExprList 2
      if (expr_ret_246) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_246
        ret = SUCC;
        #line 307 "daisho.peg"
        add(rule, p);
        #line 6757 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_246) rew(mod_246);
      expr_ret_245 = expr_ret_246;
    }

    expr_ret_244 = SUCC;
    expr_ret_241 = expr_ret_244;
  }

  // ModExprList 5
  if (expr_ret_241) {
    daisho_astnode_t* expr_ret_248 = NULL;
    expr_ret_248 = daisho_parse_nocomma(ctx);
    if (ctx->exit) return NULL;
    // optional
    if (!expr_ret_248)
      expr_ret_248 = SUCC;
    expr_ret_241 = expr_ret_248;
  }

  // ModExprList end
  if (!expr_ret_241) rew(mod_241);
  expr_ret_240 = expr_ret_241;
  if (!rule) rule = expr_ret_240;
  if (!expr_ret_240) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "protoarglist");
  else if (rule) intr_accept(ctx, "protoarglist");
  else intr_reject(ctx, "protoarglist");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_249
  daisho_astnode_t* expr_ret_249 = NULL;
  daisho_astnode_t* expr_ret_250 = NULL;
  intr_enter(ctx, "expr", ctx->pos);
  daisho_astnode_t* expr_ret_251 = NULL;
  rec(mod_251);
  // ModExprList Forwarding
  expr_ret_251 = daisho_parse_preretexpr(ctx);
  if (ctx->exit) return NULL;
  // ModExprList end
  if (!expr_ret_251) rew(mod_251);
  expr_ret_250 = expr_ret_251;
  if (!rule) rule = expr_ret_250;
  if (!expr_ret_250) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "expr");
  else if (rule) intr_accept(ctx, "expr");
  else intr_reject(ctx, "expr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_252
  daisho_astnode_t* expr_ret_252 = NULL;
  daisho_astnode_t* expr_ret_253 = NULL;
  intr_enter(ctx, "preretexpr", ctx->pos);
  daisho_astnode_t* expr_ret_254 = NULL;

  // SlashExpr 0
  if (!expr_ret_254) {
    daisho_astnode_t* expr_ret_255 = NULL;
    rec(mod_255);
    // ModExprList 0
    intr_enter(ctx, "RET", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Not capturing RET.
      expr_ret_255 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_255 = NULL;
    }

    if (expr_ret_255) intr_accept(ctx, "RET"); else intr_reject(ctx, "RET");
    // ModExprList 1
    if (expr_ret_255) {
      daisho_astnode_t* expr_ret_256 = NULL;
      expr_ret_256 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_255 = expr_ret_256;
      n = expr_ret_256;
    }

    // ModExprList 2
    if (expr_ret_255) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_255
      ret = SUCC;
      #line 355 "daisho.peg"
      rule=node(RET, n);
      #line 6857 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_255) rew(mod_255);
    expr_ret_254 = expr_ret_255;
  }

  // SlashExpr 1
  if (!expr_ret_254) {
    daisho_astnode_t* expr_ret_257 = NULL;
    rec(mod_257);
    // ModExprList 0
    daisho_astnode_t* expr_ret_258 = NULL;
    expr_ret_258 = daisho_parse_forexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_257 = expr_ret_258;
    rule = expr_ret_258;
    // ModExprList 1
    if (expr_ret_257) {
      daisho_astnode_t* expr_ret_259 = NULL;
      daisho_astnode_t* expr_ret_260 = NULL;
      rec(mod_260);
      // ModExprList 0
      intr_enter(ctx, "GRAVE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
        // Not capturing GRAVE.
        expr_ret_260 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_260 = NULL;
      }

      if (expr_ret_260) intr_accept(ctx, "GRAVE"); else intr_reject(ctx, "GRAVE");
      // ModExprList 1
      if (expr_ret_260) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_260
        ret = SUCC;
        #line 356 "daisho.peg"
        rule = node(RET, rule);
        #line 6902 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_260) rew(mod_260);
      expr_ret_259 = expr_ret_260;
      // optional
      if (!expr_ret_259)
        expr_ret_259 = SUCC;
      expr_ret_257 = expr_ret_259;
    }

    // ModExprList end
    if (!expr_ret_257) rew(mod_257);
    expr_ret_254 = expr_ret_257;
  }

  // SlashExpr end
  expr_ret_253 = expr_ret_254;

  if (!rule) rule = expr_ret_253;
  if (!expr_ret_253) rule = NULL;
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
  #define rule expr_ret_261
  daisho_astnode_t* expr_ret_261 = NULL;
  daisho_astnode_t* expr_ret_262 = NULL;
  intr_enter(ctx, "forexpr", ctx->pos);
  daisho_astnode_t* expr_ret_263 = NULL;

  // SlashExpr 0
  if (!expr_ret_263) {
    daisho_astnode_t* expr_ret_264 = NULL;
    rec(mod_264);
    // ModExprList 0
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_264 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_264 = NULL;
    }

    if (expr_ret_264) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
    // ModExprList 1
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_265 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_265 = leaf(OPEN);
        expr_ret_265->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_265->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_265 = NULL;
      }

      if (expr_ret_265) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_265)
        expr_ret_265 = SUCC;
      expr_ret_264 = expr_ret_265;
      o = expr_ret_265;
    }

    // ModExprList 2
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_266 = NULL;
      expr_ret_266 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_264 = expr_ret_266;
      f = expr_ret_266;
    }

    // ModExprList 3
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_267 = NULL;

      // SlashExpr 0
      if (!expr_ret_267) {
        daisho_astnode_t* expr_ret_268 = NULL;
        rec(mod_268);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_269 = NULL;

        // SlashExpr 0
        if (!expr_ret_269) {
          daisho_astnode_t* expr_ret_270 = NULL;
          rec(mod_270);
          // ModExprList Forwarding
          intr_enter(ctx, "COLON", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_270 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_270 = NULL;
          }

          if (expr_ret_270) intr_accept(ctx, "COLON"); else intr_reject(ctx, "COLON");
          // ModExprList end
          if (!expr_ret_270) rew(mod_270);
          expr_ret_269 = expr_ret_270;
        }

        // SlashExpr 1
        if (!expr_ret_269) {
          daisho_astnode_t* expr_ret_271 = NULL;
          rec(mod_271);
          // ModExprList Forwarding
          intr_enter(ctx, "IN", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_271 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_271 = NULL;
          }

          if (expr_ret_271) intr_accept(ctx, "IN"); else intr_reject(ctx, "IN");
          // ModExprList end
          if (!expr_ret_271) rew(mod_271);
          expr_ret_269 = expr_ret_271;
        }

        // SlashExpr end
        expr_ret_268 = expr_ret_269;

        // ModExprList end
        if (!expr_ret_268) rew(mod_268);
        expr_ret_267 = expr_ret_268;
      }

      // SlashExpr 1
      if (!expr_ret_267) {
        daisho_astnode_t* expr_ret_272 = NULL;
        rec(mod_272);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_273 = NULL;
        rec(mod_273);
        // ModExprList 0
        expr_ret_273 = daisho_parse_wsemi(ctx);
        if (ctx->exit) return NULL;
        // ModExprList 1
        if (expr_ret_273) {
          daisho_astnode_t* expr_ret_274 = NULL;
          expr_ret_274 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_273 = expr_ret_274;
          s = expr_ret_274;
        }

        // ModExprList 2
        if (expr_ret_273) {
          expr_ret_273 = daisho_parse_wsemi(ctx);
          if (ctx->exit) return NULL;
        }

        // ModExprList end
        if (!expr_ret_273) rew(mod_273);
        expr_ret_272 = expr_ret_273;
        // ModExprList end
        if (!expr_ret_272) rew(mod_272);
        expr_ret_267 = expr_ret_272;
      }

      // SlashExpr end
      expr_ret_264 = expr_ret_267;

    }

    // ModExprList 4
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_275 = NULL;
      expr_ret_275 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_264 = expr_ret_275;
      t = expr_ret_275;
    }

    // ModExprList 5
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_276 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_276 = leaf(CLOSE);
        expr_ret_276->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_276->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_276 = NULL;
      }

      if (expr_ret_276) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_276)
        expr_ret_276 = SUCC;
      expr_ret_264 = expr_ret_276;
      c = expr_ret_276;
    }

    // ModExprList 6
    if (expr_ret_264) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_264
      ret = SUCC;
      #line 360 "daisho.peg"
      if (has(o) != has(c)) WARNING("For expression parens mismatch.");
      #line 7129 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 7
    if (expr_ret_264) {
      daisho_astnode_t* expr_ret_277 = NULL;
      expr_ret_277 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_264 = expr_ret_277;
      e = expr_ret_277;
    }

    // ModExprList 8
    if (expr_ret_264) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_264
      ret = SUCC;
      #line 362 "daisho.peg"
      rule = has(s) ? node(FOR, f, s, t, e)
                    :          node(FOREACH, f, t, e);
      #line 7153 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_264) rew(mod_264);
    expr_ret_263 = expr_ret_264;
  }

  // SlashExpr 1
  if (!expr_ret_263) {
    daisho_astnode_t* expr_ret_278 = NULL;
    rec(mod_278);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_279 = NULL;
    expr_ret_279 = daisho_parse_whileexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_278 = expr_ret_279;
    rule = expr_ret_279;
    // ModExprList end
    if (!expr_ret_278) rew(mod_278);
    expr_ret_263 = expr_ret_278;
  }

  // SlashExpr end
  expr_ret_262 = expr_ret_263;

  if (!rule) rule = expr_ret_262;
  if (!expr_ret_262) rule = NULL;
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
  #define rule expr_ret_280
  daisho_astnode_t* expr_ret_280 = NULL;
  daisho_astnode_t* expr_ret_281 = NULL;
  intr_enter(ctx, "whileexpr", ctx->pos);
  daisho_astnode_t* expr_ret_282 = NULL;

  // SlashExpr 0
  if (!expr_ret_282) {
    daisho_astnode_t* expr_ret_283 = NULL;
    rec(mod_283);
    // ModExprList 0
    intr_enter(ctx, "WHILE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_283 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_283 = NULL;
    }

    if (expr_ret_283) intr_accept(ctx, "WHILE"); else intr_reject(ctx, "WHILE");
    // ModExprList 1
    if (expr_ret_283) {
      daisho_astnode_t* expr_ret_284 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_284 = leaf(OPEN);
        expr_ret_284->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_284->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_284 = NULL;
      }

      if (expr_ret_284) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_284)
        expr_ret_284 = SUCC;
      expr_ret_283 = expr_ret_284;
      o = expr_ret_284;
    }

    // ModExprList 2
    if (expr_ret_283) {
      daisho_astnode_t* expr_ret_285 = NULL;
      expr_ret_285 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_283 = expr_ret_285;
      n = expr_ret_285;
    }

    // ModExprList 3
    if (expr_ret_283) {
      daisho_astnode_t* expr_ret_286 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_286 = leaf(CLOSE);
        expr_ret_286->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_286->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_286 = NULL;
      }

      if (expr_ret_286) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_286)
        expr_ret_286 = SUCC;
      expr_ret_283 = expr_ret_286;
      c = expr_ret_286;
    }

    // ModExprList 4
    if (expr_ret_283) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_283
      ret = SUCC;
      #line 367 "daisho.peg"
      if (has(o) != has(c)) FATAL("While expression parens mismatch.");
      #line 7278 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_283) {
      daisho_astnode_t* expr_ret_287 = NULL;
      expr_ret_287 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_283 = expr_ret_287;
      e = expr_ret_287;
    }

    // ModExprList 6
    if (expr_ret_283) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_283
      ret = SUCC;
      #line 368 "daisho.peg"
      rule=node(WHILE, n, e);
      #line 7301 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_283) rew(mod_283);
    expr_ret_282 = expr_ret_283;
  }

  // SlashExpr 1
  if (!expr_ret_282) {
    daisho_astnode_t* expr_ret_288 = NULL;
    rec(mod_288);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_289 = NULL;
    expr_ret_289 = daisho_parse_preifexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_288 = expr_ret_289;
    rule = expr_ret_289;
    // ModExprList end
    if (!expr_ret_288) rew(mod_288);
    expr_ret_282 = expr_ret_288;
  }

  // SlashExpr end
  expr_ret_281 = expr_ret_282;

  if (!rule) rule = expr_ret_281;
  if (!expr_ret_281) rule = NULL;
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
  #define rule expr_ret_290
  daisho_astnode_t* expr_ret_290 = NULL;
  daisho_astnode_t* expr_ret_291 = NULL;
  intr_enter(ctx, "preifexpr", ctx->pos);
  daisho_astnode_t* expr_ret_292 = NULL;

  // SlashExpr 0
  if (!expr_ret_292) {
    daisho_astnode_t* expr_ret_293 = NULL;
    rec(mod_293);
    // ModExprList 0
    intr_enter(ctx, "IF", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
      // Not capturing IF.
      expr_ret_293 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_293 = NULL;
    }

    if (expr_ret_293) intr_accept(ctx, "IF"); else intr_reject(ctx, "IF");
    // ModExprList 1
    if (expr_ret_293) {
      daisho_astnode_t* expr_ret_294 = NULL;
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_294 = leaf(OPEN);
        expr_ret_294->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_294->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_294 = NULL;
      }

      if (expr_ret_294) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
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
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_296 = leaf(CLOSE);
        expr_ret_296->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_296->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_296 = NULL;
      }

      if (expr_ret_296) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_296)
        expr_ret_296 = SUCC;
      expr_ret_293 = expr_ret_296;
      c = expr_ret_296;
    }

    // ModExprList 4
    if (expr_ret_293) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_293
      ret = SUCC;
      #line 372 "daisho.peg"
      if (has(o) != has(c)) FATAL("If expression parens mismatch.");
      #line 7427 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
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
      daisho_astnode_t* expr_ret_298 = NULL;
      daisho_astnode_t* expr_ret_299 = NULL;
      rec(mod_299);
      // ModExprList 0
      intr_enter(ctx, "ELSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
        // Not capturing ELSE.
        expr_ret_299 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_299 = NULL;
      }

      if (expr_ret_299) intr_accept(ctx, "ELSE"); else intr_reject(ctx, "ELSE");
      // ModExprList 1
      if (expr_ret_299) {
        daisho_astnode_t* expr_ret_300 = NULL;
        expr_ret_300 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_299 = expr_ret_300;
        ee = expr_ret_300;
      }

      // ModExprList end
      if (!expr_ret_299) rew(mod_299);
      expr_ret_298 = expr_ret_299;
      // optional
      if (!expr_ret_298)
        expr_ret_298 = SUCC;
      expr_ret_293 = expr_ret_298;
    }

    // ModExprList 7
    if (expr_ret_293) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_293
      ret = SUCC;
      #line 375 "daisho.peg"
      rule = !has(ee) ? node(IF, n, e)
                    :            node(TERN, n, e, ee);
      #line 7485 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_293) rew(mod_293);
    expr_ret_292 = expr_ret_293;
  }

  // SlashExpr 1
  if (!expr_ret_292) {
    daisho_astnode_t* expr_ret_301 = NULL;
    rec(mod_301);
    // ModExprList Forwarding
    daisho_astnode_t* expr_ret_302 = NULL;
    expr_ret_302 = daisho_parse_ternexpr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_301 = expr_ret_302;
    rule = expr_ret_302;
    // ModExprList end
    if (!expr_ret_301) rew(mod_301);
    expr_ret_292 = expr_ret_301;
  }

  // SlashExpr end
  expr_ret_291 = expr_ret_292;

  if (!rule) rule = expr_ret_291;
  if (!expr_ret_291) rule = NULL;
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
  #define rule expr_ret_303
  daisho_astnode_t* expr_ret_303 = NULL;
  daisho_astnode_t* expr_ret_304 = NULL;
  intr_enter(ctx, "ternexpr", ctx->pos);
  daisho_astnode_t* expr_ret_305 = NULL;
  rec(mod_305);
  // ModExprList 0
  daisho_astnode_t* expr_ret_306 = NULL;
  expr_ret_306 = daisho_parse_thenexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_305 = expr_ret_306;
  n = expr_ret_306;
  // ModExprList 1
  if (expr_ret_305) {
    daisho_astnode_t* expr_ret_307 = NULL;
    daisho_astnode_t* expr_ret_308 = NULL;
    rec(mod_308);
    // ModExprList 0
    intr_enter(ctx, "QUEST", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_308 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_308 = NULL;
    }

    if (expr_ret_308) intr_accept(ctx, "QUEST"); else intr_reject(ctx, "QUEST");
    // ModExprList 1
    if (expr_ret_308) {
      daisho_astnode_t* expr_ret_309 = NULL;
      expr_ret_309 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_308 = expr_ret_309;
      qe = expr_ret_309;
    }

    // ModExprList 2
    if (expr_ret_308) {
      daisho_astnode_t* expr_ret_310 = NULL;
      daisho_astnode_t* expr_ret_311 = NULL;
      rec(mod_311);
      // ModExprList 0
      intr_enter(ctx, "COLON", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_311 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_311 = NULL;
      }

      if (expr_ret_311) intr_accept(ctx, "COLON"); else intr_reject(ctx, "COLON");
      // ModExprList 1
      if (expr_ret_311) {
        daisho_astnode_t* expr_ret_312 = NULL;
        expr_ret_312 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_311 = expr_ret_312;
        ce = expr_ret_312;
      }

      // ModExprList end
      if (!expr_ret_311) rew(mod_311);
      expr_ret_310 = expr_ret_311;
      // optional
      if (!expr_ret_310)
        expr_ret_310 = SUCC;
      expr_ret_308 = expr_ret_310;
    }

    // ModExprList end
    if (!expr_ret_308) rew(mod_308);
    expr_ret_307 = expr_ret_308;
    // optional
    if (!expr_ret_307)
      expr_ret_307 = SUCC;
    expr_ret_305 = expr_ret_307;
  }

  // ModExprList 2
  if (expr_ret_305) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_305
    ret = SUCC;
    #line 380 "daisho.peg"
    rule = !has(qe) ? n
                    : !has(ce) ? node(IF, n, qe)
                    :            node(TERN, n, qe, ce);
    #line 7617 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_305) rew(mod_305);
  expr_ret_304 = expr_ret_305;
  if (!rule) rule = expr_ret_304;
  if (!expr_ret_304) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "ternexpr");
  else if (rule) intr_accept(ctx, "ternexpr");
  else intr_reject(ctx, "ternexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_313
  daisho_astnode_t* expr_ret_313 = NULL;
  daisho_astnode_t* expr_ret_314 = NULL;
  intr_enter(ctx, "thenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_315 = NULL;
  rec(mod_315);
  // ModExprList 0
  daisho_astnode_t* expr_ret_316 = NULL;
  expr_ret_316 = daisho_parse_alsoexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_315 = expr_ret_316;
  rule = expr_ret_316;
  // ModExprList 1
  if (expr_ret_315) {
    daisho_astnode_t* expr_ret_317 = NULL;
    daisho_astnode_t* expr_ret_318 = SUCC;
    while (expr_ret_318)
    {
      rec(kleene_rew_317);
      daisho_astnode_t* expr_ret_319 = NULL;
      rec(mod_319);
      // ModExprList 0
      intr_enter(ctx, "THEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_319 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_319 = NULL;
      }

      if (expr_ret_319) intr_accept(ctx, "THEN"); else intr_reject(ctx, "THEN");
      // ModExprList 1
      if (expr_ret_319) {
        daisho_astnode_t* expr_ret_320 = NULL;
        expr_ret_320 = daisho_parse_alsoexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_319 = expr_ret_320;
        nn = expr_ret_320;
      }

      // ModExprList 2
      if (expr_ret_319) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_319
        ret = SUCC;
        #line 384 "daisho.peg"
        rule=node(THEN, rule, nn);
        #line 7687 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_319) rew(mod_319);
      expr_ret_318 = expr_ret_319;
    }

    expr_ret_317 = SUCC;
    expr_ret_315 = expr_ret_317;
  }

  // ModExprList end
  if (!expr_ret_315) rew(mod_315);
  expr_ret_314 = expr_ret_315;
  if (!rule) rule = expr_ret_314;
  if (!expr_ret_314) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "thenexpr");
  else if (rule) intr_accept(ctx, "thenexpr");
  else intr_reject(ctx, "thenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_321
  daisho_astnode_t* expr_ret_321 = NULL;
  daisho_astnode_t* expr_ret_322 = NULL;
  intr_enter(ctx, "alsoexpr", ctx->pos);
  daisho_astnode_t* expr_ret_323 = NULL;
  rec(mod_323);
  // ModExprList 0
  daisho_astnode_t* expr_ret_324 = NULL;
  expr_ret_324 = daisho_parse_ceqexpr(ctx);
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
      intr_enter(ctx, "ALSO", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_327 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_327 = NULL;
      }

      if (expr_ret_327) intr_accept(ctx, "ALSO"); else intr_reject(ctx, "ALSO");
      // ModExprList 1
      if (expr_ret_327) {
        daisho_astnode_t* expr_ret_328 = NULL;
        expr_ret_328 = daisho_parse_ceqexpr(ctx);
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
        #line 386 "daisho.peg"
        rule=node(ALSO, rule, nn);
        #line 7766 "daisho_tokenizer_parser.h"

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
  #define rule expr_ret_329
  daisho_astnode_t* expr_ret_329 = NULL;
  daisho_astnode_t* expr_ret_330 = NULL;
  intr_enter(ctx, "ceqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_331 = NULL;
  rec(mod_331);
  // ModExprList 0
  daisho_astnode_t* expr_ret_332 = NULL;
  expr_ret_332 = daisho_parse_logorexpr(ctx);
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
      daisho_astnode_t* expr_ret_336 = NULL;
      daisho_astnode_t* expr_ret_337 = NULL;

      // SlashExpr 0
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_338 = NULL;
        rec(mod_338);
        // ModExprList Forwarding
        intr_enter(ctx, "EQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
          // Capturing EQ.
          expr_ret_338 = leaf(EQ);
          expr_ret_338->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_338->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_338 = NULL;
        }

        if (expr_ret_338) intr_accept(ctx, "EQ"); else intr_reject(ctx, "EQ");
        // ModExprList end
        if (!expr_ret_338) rew(mod_338);
        expr_ret_337 = expr_ret_338;
      }

      // SlashExpr 1
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_339 = NULL;
        rec(mod_339);
        // ModExprList Forwarding
        intr_enter(ctx, "PLEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
          // Capturing PLEQ.
          expr_ret_339 = leaf(PLEQ);
          expr_ret_339->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_339->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_339 = NULL;
        }

        if (expr_ret_339) intr_accept(ctx, "PLEQ"); else intr_reject(ctx, "PLEQ");
        // ModExprList end
        if (!expr_ret_339) rew(mod_339);
        expr_ret_337 = expr_ret_339;
      }

      // SlashExpr 2
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_340 = NULL;
        rec(mod_340);
        // ModExprList Forwarding
        intr_enter(ctx, "MINEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
          // Capturing MINEQ.
          expr_ret_340 = leaf(MINEQ);
          expr_ret_340->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_340->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_340 = NULL;
        }

        if (expr_ret_340) intr_accept(ctx, "MINEQ"); else intr_reject(ctx, "MINEQ");
        // ModExprList end
        if (!expr_ret_340) rew(mod_340);
        expr_ret_337 = expr_ret_340;
      }

      // SlashExpr 3
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_341 = NULL;
        rec(mod_341);
        // ModExprList Forwarding
        intr_enter(ctx, "MULEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
          // Capturing MULEQ.
          expr_ret_341 = leaf(MULEQ);
          expr_ret_341->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_341->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_341 = NULL;
        }

        if (expr_ret_341) intr_accept(ctx, "MULEQ"); else intr_reject(ctx, "MULEQ");
        // ModExprList end
        if (!expr_ret_341) rew(mod_341);
        expr_ret_337 = expr_ret_341;
      }

      // SlashExpr 4
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_342 = NULL;
        rec(mod_342);
        // ModExprList Forwarding
        intr_enter(ctx, "DIVEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
          // Capturing DIVEQ.
          expr_ret_342 = leaf(DIVEQ);
          expr_ret_342->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_342->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_342 = NULL;
        }

        if (expr_ret_342) intr_accept(ctx, "DIVEQ"); else intr_reject(ctx, "DIVEQ");
        // ModExprList end
        if (!expr_ret_342) rew(mod_342);
        expr_ret_337 = expr_ret_342;
      }

      // SlashExpr 5
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_343 = NULL;
        rec(mod_343);
        // ModExprList Forwarding
        intr_enter(ctx, "MODEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
          // Capturing MODEQ.
          expr_ret_343 = leaf(MODEQ);
          expr_ret_343->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_343->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_343 = NULL;
        }

        if (expr_ret_343) intr_accept(ctx, "MODEQ"); else intr_reject(ctx, "MODEQ");
        // ModExprList end
        if (!expr_ret_343) rew(mod_343);
        expr_ret_337 = expr_ret_343;
      }

      // SlashExpr 6
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_344 = NULL;
        rec(mod_344);
        // ModExprList Forwarding
        intr_enter(ctx, "ANDEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
          // Capturing ANDEQ.
          expr_ret_344 = leaf(ANDEQ);
          expr_ret_344->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_344->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_344 = NULL;
        }

        if (expr_ret_344) intr_accept(ctx, "ANDEQ"); else intr_reject(ctx, "ANDEQ");
        // ModExprList end
        if (!expr_ret_344) rew(mod_344);
        expr_ret_337 = expr_ret_344;
      }

      // SlashExpr 7
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_345 = NULL;
        rec(mod_345);
        // ModExprList Forwarding
        intr_enter(ctx, "OREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
          // Capturing OREQ.
          expr_ret_345 = leaf(OREQ);
          expr_ret_345->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_345->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_345 = NULL;
        }

        if (expr_ret_345) intr_accept(ctx, "OREQ"); else intr_reject(ctx, "OREQ");
        // ModExprList end
        if (!expr_ret_345) rew(mod_345);
        expr_ret_337 = expr_ret_345;
      }

      // SlashExpr 8
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_346 = NULL;
        rec(mod_346);
        // ModExprList Forwarding
        intr_enter(ctx, "XOREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
          // Capturing XOREQ.
          expr_ret_346 = leaf(XOREQ);
          expr_ret_346->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_346->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_346 = NULL;
        }

        if (expr_ret_346) intr_accept(ctx, "XOREQ"); else intr_reject(ctx, "XOREQ");
        // ModExprList end
        if (!expr_ret_346) rew(mod_346);
        expr_ret_337 = expr_ret_346;
      }

      // SlashExpr 9
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_347 = NULL;
        rec(mod_347);
        // ModExprList Forwarding
        intr_enter(ctx, "BNEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
          // Capturing BNEQ.
          expr_ret_347 = leaf(BNEQ);
          expr_ret_347->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_347->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_347 = NULL;
        }

        if (expr_ret_347) intr_accept(ctx, "BNEQ"); else intr_reject(ctx, "BNEQ");
        // ModExprList end
        if (!expr_ret_347) rew(mod_347);
        expr_ret_337 = expr_ret_347;
      }

      // SlashExpr 10
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_348 = NULL;
        rec(mod_348);
        // ModExprList Forwarding
        intr_enter(ctx, "BSREQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
          // Capturing BSREQ.
          expr_ret_348 = leaf(BSREQ);
          expr_ret_348->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_348->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_348 = NULL;
        }

        if (expr_ret_348) intr_accept(ctx, "BSREQ"); else intr_reject(ctx, "BSREQ");
        // ModExprList end
        if (!expr_ret_348) rew(mod_348);
        expr_ret_337 = expr_ret_348;
      }

      // SlashExpr 11
      if (!expr_ret_337) {
        daisho_astnode_t* expr_ret_349 = NULL;
        rec(mod_349);
        // ModExprList Forwarding
        intr_enter(ctx, "BSLEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
          // Capturing BSLEQ.
          expr_ret_349 = leaf(BSLEQ);
          expr_ret_349->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_349->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_349 = NULL;
        }

        if (expr_ret_349) intr_accept(ctx, "BSLEQ"); else intr_reject(ctx, "BSLEQ");
        // ModExprList end
        if (!expr_ret_349) rew(mod_349);
        expr_ret_337 = expr_ret_349;
      }

      // SlashExpr end
      expr_ret_336 = expr_ret_337;

      expr_ret_335 = expr_ret_336;
      op = expr_ret_336;
      // ModExprList 1
      if (expr_ret_335) {
        daisho_astnode_t* expr_ret_350 = NULL;
        expr_ret_350 = daisho_parse_logorexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_335 = expr_ret_350;
        t = expr_ret_350;
      }

      // ModExprList 2
      if (expr_ret_335) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_335
        ret = SUCC;
        #line 392 "daisho.peg"
        
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
        #line 8121 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "ceqexpr");
  else if (rule) intr_accept(ctx, "ceqexpr");
  else intr_reject(ctx, "ceqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_351
  daisho_astnode_t* expr_ret_351 = NULL;
  daisho_astnode_t* expr_ret_352 = NULL;
  intr_enter(ctx, "logorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_353 = NULL;
  rec(mod_353);
  // ModExprList 0
  daisho_astnode_t* expr_ret_354 = NULL;
  expr_ret_354 = daisho_parse_logandexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_353 = expr_ret_354;
  rule = expr_ret_354;
  // ModExprList 1
  if (expr_ret_353) {
    daisho_astnode_t* expr_ret_355 = NULL;
    daisho_astnode_t* expr_ret_356 = SUCC;
    while (expr_ret_356)
    {
      rec(kleene_rew_355);
      daisho_astnode_t* expr_ret_357 = NULL;
      rec(mod_357);
      // ModExprList 0
      intr_enter(ctx, "LOGOR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
        // Not capturing LOGOR.
        expr_ret_357 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_357 = NULL;
      }

      if (expr_ret_357) intr_accept(ctx, "LOGOR"); else intr_reject(ctx, "LOGOR");
      // ModExprList 1
      if (expr_ret_357) {
        daisho_astnode_t* expr_ret_358 = NULL;
        expr_ret_358 = daisho_parse_logandexpr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_357 = expr_ret_358;
        n = expr_ret_358;
      }

      // ModExprList 2
      if (expr_ret_357) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_357
        ret = SUCC;
        #line 407 "daisho.peg"
        rule=node(LOGOR,  rule, n);
        #line 8200 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_357) rew(mod_357);
      expr_ret_356 = expr_ret_357;
    }

    expr_ret_355 = SUCC;
    expr_ret_353 = expr_ret_355;
  }

  // ModExprList end
  if (!expr_ret_353) rew(mod_353);
  expr_ret_352 = expr_ret_353;
  if (!rule) rule = expr_ret_352;
  if (!expr_ret_352) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "logorexpr");
  else if (rule) intr_accept(ctx, "logorexpr");
  else intr_reject(ctx, "logorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_359
  daisho_astnode_t* expr_ret_359 = NULL;
  daisho_astnode_t* expr_ret_360 = NULL;
  intr_enter(ctx, "logandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_361 = NULL;
  rec(mod_361);
  // ModExprList 0
  daisho_astnode_t* expr_ret_362 = NULL;
  expr_ret_362 = daisho_parse_binorexpr(ctx);
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
      intr_enter(ctx, "LOGAND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
        // Not capturing LOGAND.
        expr_ret_365 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_365 = NULL;
      }

      if (expr_ret_365) intr_accept(ctx, "LOGAND"); else intr_reject(ctx, "LOGAND");
      // ModExprList 1
      if (expr_ret_365) {
        daisho_astnode_t* expr_ret_366 = NULL;
        expr_ret_366 = daisho_parse_binorexpr(ctx);
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
        #line 408 "daisho.peg"
        rule=node(LOGAND, rule, n);
        #line 8279 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "logandexpr");
  else if (rule) intr_accept(ctx, "logandexpr");
  else intr_reject(ctx, "logandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_367
  daisho_astnode_t* expr_ret_367 = NULL;
  daisho_astnode_t* expr_ret_368 = NULL;
  intr_enter(ctx, "binorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_369 = NULL;
  rec(mod_369);
  // ModExprList 0
  daisho_astnode_t* expr_ret_370 = NULL;
  expr_ret_370 = daisho_parse_binxorexpr(ctx);
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
      intr_enter(ctx, "OR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
        // Not capturing OR.
        expr_ret_373 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_373 = NULL;
      }

      if (expr_ret_373) intr_accept(ctx, "OR"); else intr_reject(ctx, "OR");
      // ModExprList 1
      if (expr_ret_373) {
        daisho_astnode_t* expr_ret_374 = NULL;
        expr_ret_374 = daisho_parse_binxorexpr(ctx);
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
        #line 409 "daisho.peg"
        rule=node(OR,     rule, n);
        #line 8358 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "binorexpr");
  else if (rule) intr_accept(ctx, "binorexpr");
  else intr_reject(ctx, "binorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_375
  daisho_astnode_t* expr_ret_375 = NULL;
  daisho_astnode_t* expr_ret_376 = NULL;
  intr_enter(ctx, "binxorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_377 = NULL;
  rec(mod_377);
  // ModExprList 0
  daisho_astnode_t* expr_ret_378 = NULL;
  expr_ret_378 = daisho_parse_binandexpr(ctx);
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
      intr_enter(ctx, "XOR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
        // Not capturing XOR.
        expr_ret_381 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_381 = NULL;
      }

      if (expr_ret_381) intr_accept(ctx, "XOR"); else intr_reject(ctx, "XOR");
      // ModExprList 1
      if (expr_ret_381) {
        daisho_astnode_t* expr_ret_382 = NULL;
        expr_ret_382 = daisho_parse_binandexpr(ctx);
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
        #line 410 "daisho.peg"
        rule=node(XOR,    rule, n);
        #line 8437 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "binxorexpr");
  else if (rule) intr_accept(ctx, "binxorexpr");
  else intr_reject(ctx, "binxorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_383
  daisho_astnode_t* expr_ret_383 = NULL;
  daisho_astnode_t* expr_ret_384 = NULL;
  intr_enter(ctx, "binandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_385 = NULL;
  rec(mod_385);
  // ModExprList 0
  daisho_astnode_t* expr_ret_386 = NULL;
  expr_ret_386 = daisho_parse_deneqexpr(ctx);
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
      intr_enter(ctx, "AND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
        // Not capturing AND.
        expr_ret_389 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_389 = NULL;
      }

      if (expr_ret_389) intr_accept(ctx, "AND"); else intr_reject(ctx, "AND");
      // ModExprList 1
      if (expr_ret_389) {
        daisho_astnode_t* expr_ret_390 = NULL;
        expr_ret_390 = daisho_parse_deneqexpr(ctx);
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
        #line 411 "daisho.peg"
        rule=node(AND,    rule, n);
        #line 8516 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "binandexpr");
  else if (rule) intr_accept(ctx, "binandexpr");
  else intr_reject(ctx, "binandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_391
  daisho_astnode_t* expr_ret_391 = NULL;
  daisho_astnode_t* expr_ret_392 = NULL;
  intr_enter(ctx, "deneqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_393 = NULL;
  rec(mod_393);
  // ModExprList 0
  daisho_astnode_t* expr_ret_394 = NULL;
  expr_ret_394 = daisho_parse_cmpexpr(ctx);
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

      // SlashExpr 0
      if (!expr_ret_397) {
        daisho_astnode_t* expr_ret_398 = NULL;
        rec(mod_398);
        // ModExprList 0
        intr_enter(ctx, "DEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
          // Not capturing DEQ.
          expr_ret_398 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_398 = NULL;
        }

        if (expr_ret_398) intr_accept(ctx, "DEQ"); else intr_reject(ctx, "DEQ");
        // ModExprList 1
        if (expr_ret_398) {
          daisho_astnode_t* expr_ret_399 = NULL;
          expr_ret_399 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_398 = expr_ret_399;
          n = expr_ret_399;
        }

        // ModExprList 2
        if (expr_ret_398) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_398
          ret = SUCC;
          #line 414 "daisho.peg"
          rule=node(DEQ, rule, n);
          #line 8599 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_398) rew(mod_398);
        expr_ret_397 = expr_ret_398;
      }

      // SlashExpr 1
      if (!expr_ret_397) {
        daisho_astnode_t* expr_ret_400 = NULL;
        rec(mod_400);
        // ModExprList 0
        intr_enter(ctx, "NEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
          // Not capturing NEQ.
          expr_ret_400 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_400 = NULL;
        }

        if (expr_ret_400) intr_accept(ctx, "NEQ"); else intr_reject(ctx, "NEQ");
        // ModExprList 1
        if (expr_ret_400) {
          daisho_astnode_t* expr_ret_401 = NULL;
          expr_ret_401 = daisho_parse_cmpexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_400 = expr_ret_401;
          n = expr_ret_401;
        }

        // ModExprList 2
        if (expr_ret_400) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_400
          ret = SUCC;
          #line 415 "daisho.peg"
          rule=node(NEQ, rule, n);
          #line 8642 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_400) rew(mod_400);
        expr_ret_397 = expr_ret_400;
      }

      // SlashExpr end
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
  if (rule==SUCC) intr_succ(ctx, "deneqexpr");
  else if (rule) intr_accept(ctx, "deneqexpr");
  else intr_reject(ctx, "deneqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_402
  daisho_astnode_t* expr_ret_402 = NULL;
  daisho_astnode_t* expr_ret_403 = NULL;
  intr_enter(ctx, "cmpexpr", ctx->pos);
  daisho_astnode_t* expr_ret_404 = NULL;
  rec(mod_404);
  // ModExprList 0
  daisho_astnode_t* expr_ret_405 = NULL;
  expr_ret_405 = daisho_parse_shfexpr(ctx);
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
        intr_enter(ctx, "LT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Not capturing LT.
          expr_ret_409 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_409 = NULL;
        }

        if (expr_ret_409) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
        // ModExprList 1
        if (expr_ret_409) {
          daisho_astnode_t* expr_ret_410 = NULL;
          expr_ret_410 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_409 = expr_ret_410;
          n = expr_ret_410;
        }

        // ModExprList 2
        if (expr_ret_409) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_409
          ret = SUCC;
          #line 418 "daisho.peg"
          rule=node(LT,  rule, n);
          #line 8730 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_409) rew(mod_409);
        expr_ret_408 = expr_ret_409;
      }

      // SlashExpr 1
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_411 = NULL;
        rec(mod_411);
        // ModExprList 0
        intr_enter(ctx, "GT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Not capturing GT.
          expr_ret_411 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_411 = NULL;
        }

        if (expr_ret_411) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
        // ModExprList 1
        if (expr_ret_411) {
          daisho_astnode_t* expr_ret_412 = NULL;
          expr_ret_412 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_411 = expr_ret_412;
          n = expr_ret_412;
        }

        // ModExprList 2
        if (expr_ret_411) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_411
          ret = SUCC;
          #line 419 "daisho.peg"
          rule=node(GT,  rule, n);
          #line 8773 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_411) rew(mod_411);
        expr_ret_408 = expr_ret_411;
      }

      // SlashExpr 2
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_413 = NULL;
        rec(mod_413);
        // ModExprList 0
        intr_enter(ctx, "LEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
          // Not capturing LEQ.
          expr_ret_413 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_413 = NULL;
        }

        if (expr_ret_413) intr_accept(ctx, "LEQ"); else intr_reject(ctx, "LEQ");
        // ModExprList 1
        if (expr_ret_413) {
          daisho_astnode_t* expr_ret_414 = NULL;
          expr_ret_414 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_413 = expr_ret_414;
          n = expr_ret_414;
        }

        // ModExprList 2
        if (expr_ret_413) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_413
          ret = SUCC;
          #line 420 "daisho.peg"
          rule=node(LEQ, rule, n);
          #line 8816 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_413) rew(mod_413);
        expr_ret_408 = expr_ret_413;
      }

      // SlashExpr 3
      if (!expr_ret_408) {
        daisho_astnode_t* expr_ret_415 = NULL;
        rec(mod_415);
        // ModExprList 0
        intr_enter(ctx, "GEQ", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
          // Not capturing GEQ.
          expr_ret_415 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_415 = NULL;
        }

        if (expr_ret_415) intr_accept(ctx, "GEQ"); else intr_reject(ctx, "GEQ");
        // ModExprList 1
        if (expr_ret_415) {
          daisho_astnode_t* expr_ret_416 = NULL;
          expr_ret_416 = daisho_parse_shfexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_415 = expr_ret_416;
          n = expr_ret_416;
        }

        // ModExprList 2
        if (expr_ret_415) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_415
          ret = SUCC;
          #line 421 "daisho.peg"
          rule=node(GEQ, rule, n);
          #line 8859 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_415) rew(mod_415);
        expr_ret_408 = expr_ret_415;
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
  #define rule expr_ret_417
  daisho_astnode_t* expr_ret_417 = NULL;
  daisho_astnode_t* expr_ret_418 = NULL;
  intr_enter(ctx, "shfexpr", ctx->pos);
  daisho_astnode_t* expr_ret_419 = NULL;
  rec(mod_419);
  // ModExprList 0
  daisho_astnode_t* expr_ret_420 = NULL;
  expr_ret_420 = daisho_parse_sumexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_419 = expr_ret_420;
  rule = expr_ret_420;
  // ModExprList 1
  if (expr_ret_419) {
    daisho_astnode_t* expr_ret_421 = NULL;
    daisho_astnode_t* expr_ret_422 = SUCC;
    while (expr_ret_422)
    {
      rec(kleene_rew_421);
      daisho_astnode_t* expr_ret_423 = NULL;

      // SlashExpr 0
      if (!expr_ret_423) {
        daisho_astnode_t* expr_ret_424 = NULL;
        rec(mod_424);
        // ModExprList 0
        daisho_astnode_t* expr_ret_425 = NULL;
        intr_enter(ctx, "LT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
          // Capturing LT.
          expr_ret_425 = leaf(LT);
          expr_ret_425->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_425->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_425 = NULL;
        }

        if (expr_ret_425) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
        expr_ret_424 = expr_ret_425;
        l = expr_ret_425;
        // ModExprList 1
        if (expr_ret_424) {
          daisho_astnode_t* expr_ret_426 = NULL;
          intr_enter(ctx, "LT", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_426 = leaf(LT);
            expr_ret_426->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_426->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_426 = NULL;
          }

          if (expr_ret_426) intr_accept(ctx, "LT"); else intr_reject(ctx, "LT");
          expr_ret_424 = expr_ret_426;
          lt = expr_ret_426;
        }

        // ModExprList 2
        if (expr_ret_424) {
          daisho_astnode_t* expr_ret_427 = NULL;
          expr_ret_427 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_424 = expr_ret_427;
          n = expr_ret_427;
        }

        // ModExprList 3
        if (expr_ret_424) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_424
          ret = SUCC;
          #line 424 "daisho.peg"
          rule=node(BSL, l, lt, rule, n);
          #line 8975 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_424) rew(mod_424);
        expr_ret_423 = expr_ret_424;
      }

      // SlashExpr 1
      if (!expr_ret_423) {
        daisho_astnode_t* expr_ret_428 = NULL;
        rec(mod_428);
        // ModExprList 0
        daisho_astnode_t* expr_ret_429 = NULL;
        intr_enter(ctx, "GT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
          // Capturing GT.
          expr_ret_429 = leaf(GT);
          expr_ret_429->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_429->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_429 = NULL;
        }

        if (expr_ret_429) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
        expr_ret_428 = expr_ret_429;
        g = expr_ret_429;
        // ModExprList 1
        if (expr_ret_428) {
          daisho_astnode_t* expr_ret_430 = NULL;
          intr_enter(ctx, "GT", ctx->pos);
          if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_430 = leaf(GT);
            expr_ret_430->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_430->repr_len = ctx->tokens[ctx->pos].len;
            ctx->pos++;
          } else {
            expr_ret_430 = NULL;
          }

          if (expr_ret_430) intr_accept(ctx, "GT"); else intr_reject(ctx, "GT");
          expr_ret_428 = expr_ret_430;
          gt = expr_ret_430;
        }

        // ModExprList 2
        if (expr_ret_428) {
          daisho_astnode_t* expr_ret_431 = NULL;
          expr_ret_431 = daisho_parse_sumexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_428 = expr_ret_431;
          n = expr_ret_431;
        }

        // ModExprList 3
        if (expr_ret_428) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_428
          ret = SUCC;
          #line 425 "daisho.peg"
          rule=node(BSR, g, gt, rule, n);
          #line 9042 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_428) rew(mod_428);
        expr_ret_423 = expr_ret_428;
      }

      // SlashExpr end
      expr_ret_422 = expr_ret_423;

    }

    expr_ret_421 = SUCC;
    expr_ret_419 = expr_ret_421;
  }

  // ModExprList end
  if (!expr_ret_419) rew(mod_419);
  expr_ret_418 = expr_ret_419;
  if (!rule) rule = expr_ret_418;
  if (!expr_ret_418) rule = NULL;
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
  #define rule expr_ret_432
  daisho_astnode_t* expr_ret_432 = NULL;
  daisho_astnode_t* expr_ret_433 = NULL;
  intr_enter(ctx, "sumexpr", ctx->pos);
  daisho_astnode_t* expr_ret_434 = NULL;
  rec(mod_434);
  // ModExprList 0
  daisho_astnode_t* expr_ret_435 = NULL;
  expr_ret_435 = daisho_parse_multexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_434 = expr_ret_435;
  rule = expr_ret_435;
  // ModExprList 1
  if (expr_ret_434) {
    daisho_astnode_t* expr_ret_436 = NULL;
    daisho_astnode_t* expr_ret_437 = SUCC;
    while (expr_ret_437)
    {
      rec(kleene_rew_436);
      daisho_astnode_t* expr_ret_438 = NULL;

      // SlashExpr 0
      if (!expr_ret_438) {
        daisho_astnode_t* expr_ret_439 = NULL;
        rec(mod_439);
        // ModExprList 0
        daisho_astnode_t* expr_ret_440 = NULL;
        intr_enter(ctx, "PLUS", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
          // Capturing PLUS.
          expr_ret_440 = leaf(PLUS);
          expr_ret_440->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_440->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_440 = NULL;
        }

        if (expr_ret_440) intr_accept(ctx, "PLUS"); else intr_reject(ctx, "PLUS");
        expr_ret_439 = expr_ret_440;
        p = expr_ret_440;
        // ModExprList 1
        if (expr_ret_439) {
          daisho_astnode_t* expr_ret_441 = NULL;
          expr_ret_441 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_439 = expr_ret_441;
          n = expr_ret_441;
        }

        // ModExprList 2
        if (expr_ret_439) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_439
          ret = SUCC;
          #line 428 "daisho.peg"
          rule=node(PLUS, rule, n);
          #line 9137 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_439) rew(mod_439);
        expr_ret_438 = expr_ret_439;
      }

      // SlashExpr 1
      if (!expr_ret_438) {
        daisho_astnode_t* expr_ret_442 = NULL;
        rec(mod_442);
        // ModExprList 0
        daisho_astnode_t* expr_ret_443 = NULL;
        intr_enter(ctx, "MINUS", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
          // Capturing MINUS.
          expr_ret_443 = leaf(MINUS);
          expr_ret_443->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_443->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_443 = NULL;
        }

        if (expr_ret_443) intr_accept(ctx, "MINUS"); else intr_reject(ctx, "MINUS");
        expr_ret_442 = expr_ret_443;
        m = expr_ret_443;
        // ModExprList 1
        if (expr_ret_442) {
          daisho_astnode_t* expr_ret_444 = NULL;
          expr_ret_444 = daisho_parse_multexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_442 = expr_ret_444;
          n = expr_ret_444;
        }

        // ModExprList 2
        if (expr_ret_442) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_442
          ret = SUCC;
          #line 429 "daisho.peg"
          rule=node(MINUS, rule, n);
          #line 9185 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_442) rew(mod_442);
        expr_ret_438 = expr_ret_442;
      }

      // SlashExpr end
      expr_ret_437 = expr_ret_438;

    }

    expr_ret_436 = SUCC;
    expr_ret_434 = expr_ret_436;
  }

  // ModExprList end
  if (!expr_ret_434) rew(mod_434);
  expr_ret_433 = expr_ret_434;
  if (!rule) rule = expr_ret_433;
  if (!expr_ret_433) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sumexpr");
  else if (rule) intr_accept(ctx, "sumexpr");
  else intr_reject(ctx, "sumexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_445
  daisho_astnode_t* expr_ret_445 = NULL;
  daisho_astnode_t* expr_ret_446 = NULL;
  intr_enter(ctx, "multexpr", ctx->pos);
  daisho_astnode_t* expr_ret_447 = NULL;
  rec(mod_447);
  // ModExprList 0
  daisho_astnode_t* expr_ret_448 = NULL;
  expr_ret_448 = daisho_parse_accexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_447 = expr_ret_448;
  rule = expr_ret_448;
  // ModExprList 1
  if (expr_ret_447) {
    daisho_astnode_t* expr_ret_449 = NULL;
    daisho_astnode_t* expr_ret_450 = SUCC;
    while (expr_ret_450)
    {
      rec(kleene_rew_449);
      daisho_astnode_t* expr_ret_451 = NULL;

      // SlashExpr 0
      if (!expr_ret_451) {
        daisho_astnode_t* expr_ret_452 = NULL;
        rec(mod_452);
        // ModExprList 0
        intr_enter(ctx, "STAR", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_452 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_452 = NULL;
        }

        if (expr_ret_452) intr_accept(ctx, "STAR"); else intr_reject(ctx, "STAR");
        // ModExprList 1
        if (expr_ret_452) {
          daisho_astnode_t* expr_ret_453 = NULL;
          expr_ret_453 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_452 = expr_ret_453;
          n = expr_ret_453;
        }

        // ModExprList 2
        if (expr_ret_452) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_452
          ret = SUCC;
          #line 432 "daisho.peg"
          rule=node(STAR, rule, n);
          #line 9273 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_452) rew(mod_452);
        expr_ret_451 = expr_ret_452;
      }

      // SlashExpr 1
      if (!expr_ret_451) {
        daisho_astnode_t* expr_ret_454 = NULL;
        rec(mod_454);
        // ModExprList 0
        intr_enter(ctx, "DIV", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
          // Not capturing DIV.
          expr_ret_454 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_454 = NULL;
        }

        if (expr_ret_454) intr_accept(ctx, "DIV"); else intr_reject(ctx, "DIV");
        // ModExprList 1
        if (expr_ret_454) {
          daisho_astnode_t* expr_ret_455 = NULL;
          expr_ret_455 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_454 = expr_ret_455;
          n = expr_ret_455;
        }

        // ModExprList 2
        if (expr_ret_454) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_454
          ret = SUCC;
          #line 433 "daisho.peg"
          rule=node(DIV,  rule, n);
          #line 9316 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_454) rew(mod_454);
        expr_ret_451 = expr_ret_454;
      }

      // SlashExpr 2
      if (!expr_ret_451) {
        daisho_astnode_t* expr_ret_456 = NULL;
        rec(mod_456);
        // ModExprList 0
        intr_enter(ctx, "MOD", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
          // Not capturing MOD.
          expr_ret_456 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_456 = NULL;
        }

        if (expr_ret_456) intr_accept(ctx, "MOD"); else intr_reject(ctx, "MOD");
        // ModExprList 1
        if (expr_ret_456) {
          daisho_astnode_t* expr_ret_457 = NULL;
          expr_ret_457 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_456 = expr_ret_457;
          n = expr_ret_457;
        }

        // ModExprList 2
        if (expr_ret_456) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_456
          ret = SUCC;
          #line 434 "daisho.peg"
          rule=node(MOD,  rule, n);
          #line 9359 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_456) rew(mod_456);
        expr_ret_451 = expr_ret_456;
      }

      // SlashExpr 3
      if (!expr_ret_451) {
        daisho_astnode_t* expr_ret_458 = NULL;
        rec(mod_458);
        // ModExprList 0
        intr_enter(ctx, "POW", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_458 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_458 = NULL;
        }

        if (expr_ret_458) intr_accept(ctx, "POW"); else intr_reject(ctx, "POW");
        // ModExprList 1
        if (expr_ret_458) {
          daisho_astnode_t* expr_ret_459 = NULL;
          expr_ret_459 = daisho_parse_accexpr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_458 = expr_ret_459;
          n = expr_ret_459;
        }

        // ModExprList 2
        if (expr_ret_458) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_458
          ret = SUCC;
          #line 435 "daisho.peg"
          rule=node(POW,  rule, n);
          #line 9402 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_458) rew(mod_458);
        expr_ret_451 = expr_ret_458;
      }

      // SlashExpr end
      expr_ret_450 = expr_ret_451;

    }

    expr_ret_449 = SUCC;
    expr_ret_447 = expr_ret_449;
  }

  // ModExprList end
  if (!expr_ret_447) rew(mod_447);
  expr_ret_446 = expr_ret_447;
  if (!rule) rule = expr_ret_446;
  if (!expr_ret_446) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "multexpr");
  else if (rule) intr_accept(ctx, "multexpr");
  else intr_reject(ctx, "multexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_accexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_460
  daisho_astnode_t* expr_ret_460 = NULL;
  daisho_astnode_t* expr_ret_461 = NULL;
  intr_enter(ctx, "accexpr", ctx->pos);
  daisho_astnode_t* expr_ret_462 = NULL;
  rec(mod_462);
  // ModExprList 0
  daisho_astnode_t* expr_ret_463 = NULL;
  expr_ret_463 = daisho_parse_dotexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_462 = expr_ret_463;
  rule = expr_ret_463;
  // ModExprList 1
  if (expr_ret_462) {
    daisho_astnode_t* expr_ret_464 = NULL;
    daisho_astnode_t* expr_ret_465 = SUCC;
    while (expr_ret_465)
    {
      rec(kleene_rew_464);
      daisho_astnode_t* expr_ret_466 = NULL;
      rec(mod_466);
      // ModExprList 0
      intr_enter(ctx, "LSBRACK", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_466 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_466 = NULL;
      }

      if (expr_ret_466) intr_accept(ctx, "LSBRACK"); else intr_reject(ctx, "LSBRACK");
      // ModExprList 1
      if (expr_ret_466) {
        daisho_astnode_t* expr_ret_467 = NULL;
        expr_ret_467 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        expr_ret_466 = expr_ret_467;
        e = expr_ret_467;
      }

      // ModExprList 2
      if (expr_ret_466) {
        intr_enter(ctx, "RSBRACK", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
          // Not capturing RSBRACK.
          expr_ret_466 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_466 = NULL;
        }

        if (expr_ret_466) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
      }

      // ModExprList 3
      if (expr_ret_466) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_466
        ret = SUCC;
        #line 437 "daisho.peg"
        rule=node(ACCESS, rule, e);
        #line 9500 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_466) rew(mod_466);
      expr_ret_465 = expr_ret_466;
    }

    expr_ret_464 = SUCC;
    expr_ret_462 = expr_ret_464;
  }

  // ModExprList end
  if (!expr_ret_462) rew(mod_462);
  expr_ret_461 = expr_ret_462;
  if (!rule) rule = expr_ret_461;
  if (!expr_ret_461) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "accexpr");
  else if (rule) intr_accept(ctx, "accexpr");
  else intr_reject(ctx, "accexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_dotexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_468
  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_469 = NULL;
  intr_enter(ctx, "dotexpr", ctx->pos);
  daisho_astnode_t* expr_ret_470 = NULL;
  rec(mod_470);
  // ModExprList 0
  daisho_astnode_t* expr_ret_471 = NULL;
  expr_ret_471 = daisho_parse_refexpr(ctx);
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
      intr_enter(ctx, "DOT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DOT) {
        // Not capturing DOT.
        expr_ret_474 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_474 = NULL;
      }

      if (expr_ret_474) intr_accept(ctx, "DOT"); else intr_reject(ctx, "DOT");
      // ModExprList 1
      if (expr_ret_474) {
        daisho_astnode_t* expr_ret_475 = NULL;
        intr_enter(ctx, "VARIDENT", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_475 = leaf(VARIDENT);
          expr_ret_475->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_475->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_475 = NULL;
        }

        if (expr_ret_475) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
        expr_ret_474 = expr_ret_475;
        i = expr_ret_475;
      }

      // ModExprList 2
      if (expr_ret_474) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_474
        ret = SUCC;
        #line 439 "daisho.peg"
        rule=node(DOT, rule, i);
        #line 9589 "daisho_tokenizer_parser.h"

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
  if (rule==SUCC) intr_succ(ctx, "dotexpr");
  else if (rule) intr_accept(ctx, "dotexpr");
  else intr_reject(ctx, "dotexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  int32_t rd = 0;

  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_476
  daisho_astnode_t* expr_ret_476 = NULL;
  daisho_astnode_t* expr_ret_477 = NULL;
  intr_enter(ctx, "refexpr", ctx->pos);
  daisho_astnode_t* expr_ret_478 = NULL;
  rec(mod_478);
  // ModExprList 0
  daisho_astnode_t* expr_ret_479 = NULL;
  expr_ret_479 = daisho_parse_castexpr(ctx);
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

      // SlashExpr 0
      if (!expr_ret_482) {
        daisho_astnode_t* expr_ret_483 = NULL;
        rec(mod_483);
        // ModExprList 0
        intr_enter(ctx, "REF", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
          // Not capturing REF.
          expr_ret_483 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_483 = NULL;
        }

        if (expr_ret_483) intr_accept(ctx, "REF"); else intr_reject(ctx, "REF");
        // ModExprList 1
        if (expr_ret_483) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_483
          ret = SUCC;
          #line 442 "daisho.peg"
          rd++;
          #line 9664 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_483) rew(mod_483);
        expr_ret_482 = expr_ret_483;
      }

      // SlashExpr 1
      if (!expr_ret_482) {
        daisho_astnode_t* expr_ret_484 = NULL;
        rec(mod_484);
        // ModExprList 0
        intr_enter(ctx, "DEREF", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
          // Not capturing DEREF.
          expr_ret_484 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_484 = NULL;
        }

        if (expr_ret_484) intr_accept(ctx, "DEREF"); else intr_reject(ctx, "DEREF");
        // ModExprList 1
        if (expr_ret_484) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_484
          ret = SUCC;
          #line 442 "daisho.peg"
          rd--;
          #line 9698 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_484) rew(mod_484);
        expr_ret_482 = expr_ret_484;
      }

      // SlashExpr end
      expr_ret_481 = expr_ret_482;

    }

    expr_ret_480 = SUCC;
    expr_ret_478 = expr_ret_480;
  }

  // ModExprList 2
  if (expr_ret_478) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_478
    ret = SUCC;
    #line 443 "daisho.peg"
    for (int64_t i = 0; i < (rd > 0 ? rd : -rd); i++) {
                rule = rd > 0 ? node(REF, rule) : node(DEREF, rule);
              };
    #line 9728 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_478) rew(mod_478);
  expr_ret_477 = expr_ret_478;
  if (!rule) rule = expr_ret_477;
  if (!expr_ret_477) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "refexpr");
  else if (rule) intr_accept(ctx, "refexpr");
  else intr_reject(ctx, "refexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_485
  daisho_astnode_t* expr_ret_485 = NULL;
  daisho_astnode_t* expr_ret_486 = NULL;
  intr_enter(ctx, "castexpr", ctx->pos);
  daisho_astnode_t* expr_ret_487 = NULL;
  rec(mod_487);
  // ModExprList 0
  daisho_astnode_t* expr_ret_488 = NULL;
  expr_ret_488 = daisho_parse_callexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_487 = expr_ret_488;
  rule = expr_ret_488;
  // ModExprList 1
  if (expr_ret_487) {
    daisho_astnode_t* expr_ret_489 = NULL;
    daisho_astnode_t* expr_ret_490 = SUCC;
    while (expr_ret_490)
    {
      rec(kleene_rew_489);
      daisho_astnode_t* expr_ret_491 = NULL;
      rec(mod_491);
      // ModExprList 0
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_491 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_491 = NULL;
      }

      if (expr_ret_491) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // ModExprList 1
      if (expr_ret_491) {
        daisho_astnode_t* expr_ret_492 = NULL;
        expr_ret_492 = daisho_parse_type(ctx);
        if (ctx->exit) return NULL;
        expr_ret_491 = expr_ret_492;
        t = expr_ret_492;
      }

      // ModExprList 2
      if (expr_ret_491) {
        intr_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_491 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_491 = NULL;
        }

        if (expr_ret_491) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      }

      // ModExprList 3
      if (expr_ret_491) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_491
        ret = SUCC;
        #line 447 "daisho.peg"
        rule=node(CAST, rule, t);
        #line 9812 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_491) rew(mod_491);
      expr_ret_490 = expr_ret_491;
    }

    expr_ret_489 = SUCC;
    expr_ret_487 = expr_ret_489;
  }

  // ModExprList end
  if (!expr_ret_487) rew(mod_487);
  expr_ret_486 = expr_ret_487;
  if (!rule) rule = expr_ret_486;
  if (!expr_ret_486) rule = NULL;
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
  #define rule expr_ret_493
  daisho_astnode_t* expr_ret_493 = NULL;
  daisho_astnode_t* expr_ret_494 = NULL;
  intr_enter(ctx, "callexpr", ctx->pos);
  daisho_astnode_t* expr_ret_495 = NULL;
  rec(mod_495);
  // ModExprList 0
  daisho_astnode_t* expr_ret_496 = NULL;
  expr_ret_496 = daisho_parse_increxpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_495 = expr_ret_496;
  rule = expr_ret_496;
  // ModExprList 1
  if (expr_ret_495) {
    daisho_astnode_t* expr_ret_497 = NULL;
    daisho_astnode_t* expr_ret_498 = NULL;
    rec(mod_498);
    // ModExprList 0
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_498
    ret = SUCC;
    #line 450 "daisho.peg"
    ret=rule->kind == kind(VARIDENT) ? SUCC : NULL;
    #line 9867 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList 1
    if (expr_ret_498) {
      daisho_astnode_t* expr_ret_499 = NULL;
      expr_ret_499 = daisho_parse_tmplexpand(ctx);
      if (ctx->exit) return NULL;
      expr_ret_498 = expr_ret_499;
      te = expr_ret_499;
    }

    // ModExprList end
    if (!expr_ret_498) rew(mod_498);
    expr_ret_497 = expr_ret_498;
    // optional
    if (!expr_ret_497)
      expr_ret_497 = SUCC;
    expr_ret_495 = expr_ret_497;
  }

  // ModExprList 2
  if (expr_ret_495) {
    daisho_astnode_t* expr_ret_500 = NULL;
    daisho_astnode_t* expr_ret_501 = SUCC;
    while (expr_ret_501)
    {
      rec(kleene_rew_500);
      daisho_astnode_t* expr_ret_502 = NULL;
      rec(mod_502);
      // ModExprList 0
      intr_enter(ctx, "OPEN", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_502 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_502 = NULL;
      }

      if (expr_ret_502) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
      // ModExprList 1
      if (expr_ret_502) {
        daisho_astnode_t* expr_ret_503 = NULL;
        expr_ret_503 = daisho_parse_exprlist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_502 = expr_ret_503;
        el = expr_ret_503;
      }

      // ModExprList 2
      if (expr_ret_502) {
        intr_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_502 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_502 = NULL;
        }

        if (expr_ret_502) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      }

      // ModExprList 3
      if (expr_ret_502) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_502
        ret = SUCC;
        #line 452 "daisho.peg"
        rule = !has(te) ? node(CALL, rule, el)
                    :            node(CALL, rule, te, el);
        #line 9941 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_502) rew(mod_502);
      expr_ret_501 = expr_ret_502;
    }

    expr_ret_500 = SUCC;
    expr_ret_495 = expr_ret_500;
  }

  // ModExprList end
  if (!expr_ret_495) rew(mod_495);
  expr_ret_494 = expr_ret_495;
  if (!rule) rule = expr_ret_494;
  if (!expr_ret_494) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "callexpr");
  else if (rule) intr_accept(ctx, "callexpr");
  else intr_reject(ctx, "callexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_increxpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_504
  daisho_astnode_t* expr_ret_504 = NULL;
  daisho_astnode_t* expr_ret_505 = NULL;
  intr_enter(ctx, "increxpr", ctx->pos);
  daisho_astnode_t* expr_ret_506 = NULL;
  rec(mod_506);
  // ModExprList 0
  daisho_astnode_t* expr_ret_507 = NULL;
  expr_ret_507 = daisho_parse_atomexpr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_506 = expr_ret_507;
  rule = expr_ret_507;
  // ModExprList 1
  if (expr_ret_506) {
    daisho_astnode_t* expr_ret_508 = NULL;
    daisho_astnode_t* expr_ret_509 = NULL;

    // SlashExpr 0
    if (!expr_ret_509) {
      daisho_astnode_t* expr_ret_510 = NULL;
      rec(mod_510);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_511 = NULL;
      rec(mod_511);
      // ModExprList 0
      intr_enter(ctx, "INCR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_INCR) {
        // Not capturing INCR.
        expr_ret_511 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_511 = NULL;
      }

      if (expr_ret_511) intr_accept(ctx, "INCR"); else intr_reject(ctx, "INCR");
      // ModExprList 1
      if (expr_ret_511) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_511
        ret = SUCC;
        #line 455 "daisho.peg"
        rule=node(INCR, rule);
        #line 10013 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_511) rew(mod_511);
      expr_ret_510 = expr_ret_511;
      // ModExprList end
      if (!expr_ret_510) rew(mod_510);
      expr_ret_509 = expr_ret_510;
    }

    // SlashExpr 1
    if (!expr_ret_509) {
      daisho_astnode_t* expr_ret_512 = NULL;
      rec(mod_512);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_513 = NULL;
      rec(mod_513);
      // ModExprList 0
      intr_enter(ctx, "DECR", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_DECR) {
        // Not capturing DECR.
        expr_ret_513 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_513 = NULL;
      }

      if (expr_ret_513) intr_accept(ctx, "DECR"); else intr_reject(ctx, "DECR");
      // ModExprList 1
      if (expr_ret_513) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_513
        ret = SUCC;
        #line 456 "daisho.peg"
        rule=node(DECR, rule);
        #line 10053 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_513) rew(mod_513);
      expr_ret_512 = expr_ret_513;
      // ModExprList end
      if (!expr_ret_512) rew(mod_512);
      expr_ret_509 = expr_ret_512;
    }

    // SlashExpr end
    expr_ret_508 = expr_ret_509;

    // optional
    if (!expr_ret_508)
      expr_ret_508 = SUCC;
    expr_ret_506 = expr_ret_508;
  }

  // ModExprList end
  if (!expr_ret_506) rew(mod_506);
  expr_ret_505 = expr_ret_506;
  if (!rule) rule = expr_ret_505;
  if (!expr_ret_505) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "increxpr");
  else if (rule) intr_accept(ctx, "increxpr");
  else intr_reject(ctx, "increxpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_514
  daisho_astnode_t* expr_ret_514 = NULL;
  daisho_astnode_t* expr_ret_515 = NULL;
  intr_enter(ctx, "atomexpr", ctx->pos);
  daisho_astnode_t* expr_ret_516 = NULL;

  // SlashExpr 0
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_517 = NULL;
    rec(mod_517);
    // ModExprList Forwarding
    expr_ret_517 = daisho_parse_blockexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_517) rew(mod_517);
    expr_ret_516 = expr_ret_517;
  }

  // SlashExpr 1
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_518 = NULL;
    rec(mod_518);
    // ModExprList Forwarding
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_518 = leaf(VARIDENT);
      expr_ret_518->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_518->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_518 = NULL;
    }

    if (expr_ret_518) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    // ModExprList end
    if (!expr_ret_518) rew(mod_518);
    expr_ret_516 = expr_ret_518;
  }

  // SlashExpr 2
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_519 = NULL;
    rec(mod_519);
    // ModExprList Forwarding
    expr_ret_519 = daisho_parse_vardeclexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_519) rew(mod_519);
    expr_ret_516 = expr_ret_519;
  }

  // SlashExpr 3
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_520 = NULL;
    rec(mod_520);
    // ModExprList Forwarding
    expr_ret_520 = daisho_parse_lambdaexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_520) rew(mod_520);
    expr_ret_516 = expr_ret_520;
  }

  // SlashExpr 4
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_521 = NULL;
    rec(mod_521);
    // ModExprList Forwarding
    expr_ret_521 = daisho_parse_parenexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_521) rew(mod_521);
    expr_ret_516 = expr_ret_521;
  }

  // SlashExpr 5
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_522 = NULL;
    rec(mod_522);
    // ModExprList Forwarding
    expr_ret_522 = daisho_parse_tuplelit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_522) rew(mod_522);
    expr_ret_516 = expr_ret_522;
  }

  // SlashExpr 6
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_523 = NULL;
    rec(mod_523);
    // ModExprList Forwarding
    expr_ret_523 = daisho_parse_listcomp(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_523) rew(mod_523);
    expr_ret_516 = expr_ret_523;
  }

  // SlashExpr 7
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_524 = NULL;
    rec(mod_524);
    // ModExprList Forwarding
    expr_ret_524 = daisho_parse_listlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_524) rew(mod_524);
    expr_ret_516 = expr_ret_524;
  }

  // SlashExpr 8
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_525 = NULL;
    rec(mod_525);
    // ModExprList Forwarding
    intr_enter(ctx, "NUMLIT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_525 = leaf(NUMLIT);
      expr_ret_525->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_525->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_525 = NULL;
    }

    if (expr_ret_525) intr_accept(ctx, "NUMLIT"); else intr_reject(ctx, "NUMLIT");
    // ModExprList end
    if (!expr_ret_525) rew(mod_525);
    expr_ret_516 = expr_ret_525;
  }

  // SlashExpr 9
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_526 = NULL;
    rec(mod_526);
    // ModExprList Forwarding
    intr_enter(ctx, "SELFVAR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFVAR) {
      // Capturing SELFVAR.
      expr_ret_526 = leaf(SELFVAR);
      expr_ret_526->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_526->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_526 = NULL;
    }

    if (expr_ret_526) intr_accept(ctx, "SELFVAR"); else intr_reject(ctx, "SELFVAR");
    // ModExprList end
    if (!expr_ret_526) rew(mod_526);
    expr_ret_516 = expr_ret_526;
  }

  // SlashExpr 10
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_527 = NULL;
    rec(mod_527);
    // ModExprList Forwarding
    intr_enter(ctx, "CHARLIT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CHARLIT) {
      // Capturing CHARLIT.
      expr_ret_527 = leaf(CHARLIT);
      expr_ret_527->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_527->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_527 = NULL;
    }

    if (expr_ret_527) intr_accept(ctx, "CHARLIT"); else intr_reject(ctx, "CHARLIT");
    // ModExprList end
    if (!expr_ret_527) rew(mod_527);
    expr_ret_516 = expr_ret_527;
  }

  // SlashExpr 11
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_528 = NULL;
    rec(mod_528);
    // ModExprList Forwarding
    expr_ret_528 = daisho_parse_strlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_528) rew(mod_528);
    expr_ret_516 = expr_ret_528;
  }

  // SlashExpr 12
  if (!expr_ret_516) {
    daisho_astnode_t* expr_ret_529 = NULL;
    rec(mod_529);
    // ModExprList Forwarding
    expr_ret_529 = daisho_parse_sizeofexpr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_529) rew(mod_529);
    expr_ret_516 = expr_ret_529;
  }

  // SlashExpr end
  expr_ret_515 = expr_ret_516;

  if (!rule) rule = expr_ret_515;
  if (!expr_ret_515) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "atomexpr");
  else if (rule) intr_accept(ctx, "atomexpr");
  else intr_reject(ctx, "atomexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_semiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_530
  daisho_astnode_t* expr_ret_530 = NULL;
  daisho_astnode_t* expr_ret_531 = NULL;
  intr_enter(ctx, "semiornl", ctx->pos);
  daisho_astnode_t* expr_ret_532 = NULL;

  // SlashExpr 0
  if (!expr_ret_532) {
    daisho_astnode_t* expr_ret_533 = NULL;
    rec(mod_533);
    // ModExprList Forwarding
    intr_enter(ctx, "SEMI", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_533 = leaf(SEMI);
      expr_ret_533->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_533->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_533 = NULL;
    }

    if (expr_ret_533) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
    // ModExprList end
    if (!expr_ret_533) rew(mod_533);
    expr_ret_532 = expr_ret_533;
  }

  // SlashExpr 1
  if (!expr_ret_532) {
    daisho_astnode_t* expr_ret_534 = NULL;
    rec(mod_534);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_534
    ret = SUCC;
    #line 577 "daisho.peg"
    ret = (ctx->pos >= ctx->len ||
                      ctx->tokens[ctx->pos - 1].line < ctx->tokens[ctx->pos].line)
                      ? leaf(SEMI)
                      : NULL;
    #line 10346 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_534) rew(mod_534);
    expr_ret_532 = expr_ret_534;
  }

  // SlashExpr end
  expr_ret_531 = expr_ret_532;

  if (!rule) rule = expr_ret_531;
  if (!expr_ret_531) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "semiornl");
  else if (rule) intr_accept(ctx, "semiornl");
  else intr_reject(ctx, "semiornl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  int skip=0;

  daisho_astnode_t* e = NULL;
  #define rule expr_ret_535
  daisho_astnode_t* expr_ret_535 = NULL;
  daisho_astnode_t* expr_ret_536 = NULL;
  intr_enter(ctx, "blockexpr", ctx->pos);
  daisho_astnode_t* expr_ret_537 = NULL;
  rec(mod_537);
  // ModExprList 0
  intr_enter(ctx, "LCBRACK", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
    // Not capturing LCBRACK.
    expr_ret_537 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_537 = NULL;
  }

  if (expr_ret_537) intr_accept(ctx, "LCBRACK"); else intr_reject(ctx, "LCBRACK");
  // ModExprList 1
  if (expr_ret_537) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_537
    ret = SUCC;
    #line 583 "daisho.peg"
    rule=list(BLOCK);
    #line 10396 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_537) {
    daisho_astnode_t* expr_ret_538 = NULL;
    daisho_astnode_t* expr_ret_539 = SUCC;
    while (expr_ret_539)
    {
      rec(kleene_rew_538);
      daisho_astnode_t* expr_ret_540 = NULL;
      rec(mod_540);
      // ModExprList 0
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_540
      ret = SUCC;
      #line 584 "daisho.peg"
      if (skip) ret=NULL;
      #line 10418 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList 1
      if (expr_ret_540) {
        rec(mexpr_state_541)
        daisho_astnode_t* expr_ret_541 = NULL;
        intr_enter(ctx, "RCBRACK", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
          // Not capturing RCBRACK.
          expr_ret_541 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_541 = NULL;
        }

        if (expr_ret_541) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
        // invert
        expr_ret_541 = expr_ret_541 ? NULL : SUCC;
        // rewind
        rew(mexpr_state_541);
        expr_ret_540 = expr_ret_541;
      }

      // ModExprList 2
      if (expr_ret_540) {
        daisho_astnode_t* expr_ret_542 = NULL;
        expr_ret_542 = daisho_parse_expr(ctx);
        if (ctx->exit) return NULL;
        // optional
        if (!expr_ret_542)
          expr_ret_542 = SUCC;
        expr_ret_540 = expr_ret_542;
        e = expr_ret_542;
      }

      // ModExprList 3
      if (expr_ret_540) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_540
        ret = SUCC;
        #line 585 "daisho.peg"
        if(has(e)) add(rule, e);
        #line 10463 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 4
      if (expr_ret_540) {
        daisho_astnode_t* expr_ret_543 = NULL;

        // SlashExpr 0
        if (!expr_ret_543) {
          daisho_astnode_t* expr_ret_544 = NULL;
          rec(mod_544);
          // ModExprList Forwarding
          expr_ret_544 = daisho_parse_semiornl(ctx);
          if (ctx->exit) return NULL;
          // ModExprList end
          if (!expr_ret_544) rew(mod_544);
          expr_ret_543 = expr_ret_544;
        }

        // SlashExpr 1
        if (!expr_ret_543) {
          daisho_astnode_t* expr_ret_545 = NULL;
          rec(mod_545);
          // ModExprList Forwarding
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_545
          ret = SUCC;
          #line 586 "daisho.peg"
          skip=1;
          #line 10496 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
          // ModExprList end
          if (!expr_ret_545) rew(mod_545);
          expr_ret_543 = expr_ret_545;
        }

        // SlashExpr end
        expr_ret_540 = expr_ret_543;

      }

      // ModExprList end
      if (!expr_ret_540) rew(mod_540);
      expr_ret_539 = expr_ret_540;
    }

    expr_ret_538 = SUCC;
    expr_ret_537 = expr_ret_538;
  }

  // ModExprList 3
  if (expr_ret_537) {
    intr_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Capturing RCBRACK.
      expr_ret_537 = leaf(RCBRACK);
      expr_ret_537->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_537->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_537 = NULL;
    }

    if (expr_ret_537) intr_accept(ctx, "RCBRACK"); else intr_reject(ctx, "RCBRACK");
  }

  // ModExprList end
  if (!expr_ret_537) rew(mod_537);
  expr_ret_536 = expr_ret_537;
  if (!rule) rule = expr_ret_536;
  if (!expr_ret_536) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "blockexpr");
  else if (rule) intr_accept(ctx, "blockexpr");
  else intr_reject(ctx, "blockexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* al = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_546
  daisho_astnode_t* expr_ret_546 = NULL;
  daisho_astnode_t* expr_ret_547 = NULL;
  intr_enter(ctx, "lambdaexpr", ctx->pos);
  daisho_astnode_t* expr_ret_548 = NULL;
  rec(mod_548);
  // ModExprList 0
  daisho_astnode_t* expr_ret_549 = NULL;
  rec(mod_549);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_549 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_549 = NULL;
  }

  if (expr_ret_549) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_549) {
    daisho_astnode_t* expr_ret_550 = NULL;
    daisho_astnode_t* expr_ret_551 = NULL;

    // SlashExpr 0
    if (!expr_ret_551) {
      daisho_astnode_t* expr_ret_552 = NULL;
      rec(mod_552);
      // ModExprList 0
      rec(mexpr_state_553)
      daisho_astnode_t* expr_ret_553 = NULL;
      intr_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_553 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_553 = NULL;
      }

      if (expr_ret_553) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
      // invert
      expr_ret_553 = expr_ret_553 ? NULL : SUCC;
      // rewind
      rew(mexpr_state_553);
      expr_ret_552 = expr_ret_553;
      // ModExprList 1
      if (expr_ret_552) {
        daisho_astnode_t* expr_ret_554 = NULL;
        expr_ret_554 = daisho_parse_arglist(ctx);
        if (ctx->exit) return NULL;
        expr_ret_552 = expr_ret_554;
        al = expr_ret_554;
      }

      // ModExprList end
      if (!expr_ret_552) rew(mod_552);
      expr_ret_551 = expr_ret_552;
    }

    // SlashExpr 1
    if (!expr_ret_551) {
      daisho_astnode_t* expr_ret_555 = NULL;
      rec(mod_555);
      // ModExprList Forwarding
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_555
      ret = SUCC;
      #line 590 "daisho.peg"
      al=leaf(ARGLIST);
      #line 10622 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
      // ModExprList end
      if (!expr_ret_555) rew(mod_555);
      expr_ret_551 = expr_ret_555;
    }

    // SlashExpr end
    expr_ret_550 = expr_ret_551;

    // optional
    if (!expr_ret_550)
      expr_ret_550 = SUCC;
    expr_ret_549 = expr_ret_550;
  }

  // ModExprList 2
  if (expr_ret_549) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_549 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_549 = NULL;
    }

    if (expr_ret_549) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_549) rew(mod_549);
  expr_ret_548 = expr_ret_549;
  // ModExprList 1
  if (expr_ret_548) {
    intr_enter(ctx, "ARROW", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_548 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_548 = NULL;
    }

    if (expr_ret_548) intr_accept(ctx, "ARROW"); else intr_reject(ctx, "ARROW");
  }

  // ModExprList 2
  if (expr_ret_548) {
    daisho_astnode_t* expr_ret_556 = NULL;
    expr_ret_556 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_548 = expr_ret_556;
    e = expr_ret_556;
  }

  // ModExprList 3
  if (expr_ret_548) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_548
    ret = SUCC;
    #line 592 "daisho.peg"
    rule=node(LAMBDA, al, e);
    #line 10688 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_548) rew(mod_548);
  expr_ret_547 = expr_ret_548;
  if (!rule) rule = expr_ret_547;
  if (!expr_ret_547) rule = NULL;
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
  #define rule expr_ret_557
  daisho_astnode_t* expr_ret_557 = NULL;
  daisho_astnode_t* expr_ret_558 = NULL;
  intr_enter(ctx, "listcomp", ctx->pos);
  daisho_astnode_t* expr_ret_559 = NULL;
  rec(mod_559);
  // ModExprList 0
  intr_enter(ctx, "LSBRACK", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
    // Not capturing LSBRACK.
    expr_ret_559 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_559 = NULL;
  }

  if (expr_ret_559) intr_accept(ctx, "LSBRACK"); else intr_reject(ctx, "LSBRACK");
  // ModExprList 1
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_560 = NULL;
    daisho_astnode_t* expr_ret_561 = NULL;
    rec(mod_561);
    // ModExprList 0
    daisho_astnode_t* expr_ret_562 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_562 = leaf(VARIDENT);
      expr_ret_562->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_562->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_562 = NULL;
    }

    if (expr_ret_562) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_561 = expr_ret_562;
    en = expr_ret_562;
    // ModExprList 1
    if (expr_ret_561) {
      intr_enter(ctx, "COMMA", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_561 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_561 = NULL;
      }

      if (expr_ret_561) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    }

    // ModExprList end
    if (!expr_ret_561) rew(mod_561);
    expr_ret_560 = expr_ret_561;
    // optional
    if (!expr_ret_560)
      expr_ret_560 = SUCC;
    expr_ret_559 = expr_ret_560;
  }

  // ModExprList 2
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_563 = NULL;
    expr_ret_563 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_559 = expr_ret_563;
    e = expr_ret_563;
  }

  // ModExprList 3
  if (expr_ret_559) {
    intr_enter(ctx, "FOR", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_559 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_559 = NULL;
    }

    if (expr_ret_559) intr_accept(ctx, "FOR"); else intr_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_564 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_564 = leaf(VARIDENT);
      expr_ret_564->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_564->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_564 = NULL;
    }

    if (expr_ret_564) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_559 = expr_ret_564;
    item = expr_ret_564;
  }

  // ModExprList 5
  if (expr_ret_559) {
    intr_enter(ctx, "IN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_559 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_559 = NULL;
    }

    if (expr_ret_559) intr_accept(ctx, "IN"); else intr_reject(ctx, "IN");
  }

  // ModExprList 6
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_565 = NULL;
    expr_ret_565 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_559 = expr_ret_565;
    in = expr_ret_565;
  }

  // ModExprList 7
  if (expr_ret_559) {
    daisho_astnode_t* expr_ret_566 = NULL;
    daisho_astnode_t* expr_ret_567 = NULL;
    rec(mod_567);
    // ModExprList 0
    intr_enter(ctx, "WHERE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
      // Not capturing WHERE.
      expr_ret_567 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_567 = NULL;
    }

    if (expr_ret_567) intr_accept(ctx, "WHERE"); else intr_reject(ctx, "WHERE");
    // ModExprList 1
    if (expr_ret_567) {
      daisho_astnode_t* expr_ret_568 = NULL;
      expr_ret_568 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_567 = expr_ret_568;
      cond = expr_ret_568;
    }

    // ModExprList end
    if (!expr_ret_567) rew(mod_567);
    expr_ret_566 = expr_ret_567;
    // optional
    if (!expr_ret_566)
      expr_ret_566 = SUCC;
    expr_ret_559 = expr_ret_566;
  }

  // ModExprList 8
  if (expr_ret_559) {
    intr_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_559 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_559 = NULL;
    }

    if (expr_ret_559) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
  }

  // ModExprList 9
  if (expr_ret_559) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_559
    ret = SUCC;
    #line 601 "daisho.peg"
    rule = list(LISTCOMP);
              if (en) add(rule, node(COMPENUMERATE, en));
              add(rule, e);add(rule, item);add(rule, in);
              if (cond) add(rule, node(COMPCOND, cond));;
    #line 10897 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_559) rew(mod_559);
  expr_ret_558 = expr_ret_559;
  if (!rule) rule = expr_ret_558;
  if (!expr_ret_558) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "listcomp");
  else if (rule) intr_accept(ctx, "listcomp");
  else intr_reject(ctx, "listcomp");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_569
  daisho_astnode_t* expr_ret_569 = NULL;
  daisho_astnode_t* expr_ret_570 = NULL;
  intr_enter(ctx, "parenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_571 = NULL;
  rec(mod_571);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_571 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_571 = NULL;
  }

  if (expr_ret_571) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_571) {
    daisho_astnode_t* expr_ret_572 = NULL;
    expr_ret_572 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    expr_ret_571 = expr_ret_572;
    rule = expr_ret_572;
  }

  // ModExprList 2
  if (expr_ret_571) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_571 = leaf(CLOSE);
      expr_ret_571->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_571->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_571 = NULL;
    }

    if (expr_ret_571) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_571) rew(mod_571);
  expr_ret_570 = expr_ret_571;
  if (!rule) rule = expr_ret_570;
  if (!expr_ret_570) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "parenexpr");
  else if (rule) intr_accept(ctx, "parenexpr");
  else intr_reject(ctx, "parenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_573
  daisho_astnode_t* expr_ret_573 = NULL;
  daisho_astnode_t* expr_ret_574 = NULL;
  intr_enter(ctx, "listlit", ctx->pos);
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
    expr_ret_576 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_575 = expr_ret_576;
    rule = expr_ret_576;
  }

  // ModExprList 2
  if (expr_ret_575) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_575
    ret = SUCC;
    #line 609 "daisho.peg"
    rule->kind = kind(LISTLIT);
    #line 11007 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_575) {
    intr_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Capturing RSBRACK.
      expr_ret_575 = leaf(RSBRACK);
      expr_ret_575->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_575->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_575 = NULL;
    }

    if (expr_ret_575) intr_accept(ctx, "RSBRACK"); else intr_reject(ctx, "RSBRACK");
  }

  // ModExprList end
  if (!expr_ret_575) rew(mod_575);
  expr_ret_574 = expr_ret_575;
  if (!rule) rule = expr_ret_574;
  if (!expr_ret_574) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "listlit");
  else if (rule) intr_accept(ctx, "listlit");
  else intr_reject(ctx, "listlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tuplelit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rule = NULL;
  #define rule expr_ret_577
  daisho_astnode_t* expr_ret_577 = NULL;
  daisho_astnode_t* expr_ret_578 = NULL;
  intr_enter(ctx, "tuplelit", ctx->pos);
  daisho_astnode_t* expr_ret_579 = NULL;
  rec(mod_579);
  // ModExprList 0
  intr_enter(ctx, "OPEN", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
    // Not capturing OPEN.
    expr_ret_579 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_579 = NULL;
  }

  if (expr_ret_579) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  // ModExprList 1
  if (expr_ret_579) {
    daisho_astnode_t* expr_ret_580 = NULL;
    expr_ret_580 = daisho_parse_exprlist(ctx);
    if (ctx->exit) return NULL;
    expr_ret_579 = expr_ret_580;
    rule = expr_ret_580;
  }

  // ModExprList 2
  if (expr_ret_579) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_579
    ret = SUCC;
    #line 613 "daisho.peg"
    rule->kind = kind(TUPLELIT);
    #line 11077 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 3
  if (expr_ret_579) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Capturing CLOSE.
      expr_ret_579 = leaf(CLOSE);
      expr_ret_579->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_579->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_579 = NULL;
    }

    if (expr_ret_579) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_579) rew(mod_579);
  expr_ret_578 = expr_ret_579;
  if (!rule) rule = expr_ret_578;
  if (!expr_ret_578) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "tuplelit");
  else if (rule) intr_accept(ctx, "tuplelit");
  else intr_reject(ctx, "tuplelit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_vardeclexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* i = NULL;
  #define rule expr_ret_581
  daisho_astnode_t* expr_ret_581 = NULL;
  daisho_astnode_t* expr_ret_582 = NULL;
  intr_enter(ctx, "vardeclexpr", ctx->pos);
  daisho_astnode_t* expr_ret_583 = NULL;
  rec(mod_583);
  // ModExprList 0
  daisho_astnode_t* expr_ret_584 = NULL;
  expr_ret_584 = daisho_parse_type(ctx);
  if (ctx->exit) return NULL;
  expr_ret_583 = expr_ret_584;
  t = expr_ret_584;
  // ModExprList 1
  if (expr_ret_583) {
    daisho_astnode_t* expr_ret_585 = NULL;
    intr_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_585 = leaf(VARIDENT);
      expr_ret_585->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_585->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_585 = NULL;
    }

    if (expr_ret_585) intr_accept(ctx, "VARIDENT"); else intr_reject(ctx, "VARIDENT");
    expr_ret_583 = expr_ret_585;
    i = expr_ret_585;
  }

  // ModExprList 2
  if (expr_ret_583) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_583
    ret = SUCC;
    #line 621 "daisho.peg"
    rule=node(VARDECL, t, i);
    #line 11153 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_583) rew(mod_583);
  expr_ret_582 = expr_ret_583;
  if (!rule) rule = expr_ret_582;
  if (!expr_ret_582) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "vardeclexpr");
  else if (rule) intr_accept(ctx, "vardeclexpr");
  else intr_reject(ctx, "vardeclexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_586
  daisho_astnode_t* expr_ret_586 = NULL;
  daisho_astnode_t* expr_ret_587 = NULL;
  intr_enter(ctx, "strlit", ctx->pos);
  daisho_astnode_t* expr_ret_588 = NULL;

  // SlashExpr 0
  if (!expr_ret_588) {
    daisho_astnode_t* expr_ret_589 = NULL;
    rec(mod_589);
    // ModExprList Forwarding
    expr_ret_589 = daisho_parse_sstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_589) rew(mod_589);
    expr_ret_588 = expr_ret_589;
  }

  // SlashExpr 1
  if (!expr_ret_588) {
    daisho_astnode_t* expr_ret_590 = NULL;
    rec(mod_590);
    // ModExprList Forwarding
    expr_ret_590 = daisho_parse_fstrlit(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_590) rew(mod_590);
    expr_ret_588 = expr_ret_590;
  }

  // SlashExpr end
  expr_ret_587 = expr_ret_588;

  if (!rule) rule = expr_ret_587;
  if (!expr_ret_587) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "strlit");
  else if (rule) intr_accept(ctx, "strlit");
  else intr_reject(ctx, "strlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_591
  daisho_astnode_t* expr_ret_591 = NULL;
  daisho_astnode_t* expr_ret_592 = NULL;
  intr_enter(ctx, "sstrlit", ctx->pos);
  daisho_astnode_t* expr_ret_593 = NULL;
  rec(mod_593);
  // ModExprList 0
  daisho_astnode_t* expr_ret_594 = NULL;
  intr_enter(ctx, "STRLIT", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
    // Capturing STRLIT.
    expr_ret_594 = leaf(STRLIT);
    expr_ret_594->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_594->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_594 = NULL;
  }

  if (expr_ret_594) intr_accept(ctx, "STRLIT"); else intr_reject(ctx, "STRLIT");
  expr_ret_593 = expr_ret_594;
  s = expr_ret_594;
  // ModExprList 1
  if (expr_ret_593) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_593
    ret = SUCC;
    #line 626 "daisho.peg"
    rule=list(SSTR); add(rule, s);
    #line 11246 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_593) {
    daisho_astnode_t* expr_ret_595 = NULL;
    daisho_astnode_t* expr_ret_596 = SUCC;
    while (expr_ret_596)
    {
      rec(kleene_rew_595);
      daisho_astnode_t* expr_ret_597 = NULL;
      rec(mod_597);
      // ModExprList 0
      daisho_astnode_t* expr_ret_598 = NULL;
      intr_enter(ctx, "STRLIT", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
        // Capturing STRLIT.
        expr_ret_598 = leaf(STRLIT);
        expr_ret_598->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_598->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_598 = NULL;
      }

      if (expr_ret_598) intr_accept(ctx, "STRLIT"); else intr_reject(ctx, "STRLIT");
      expr_ret_597 = expr_ret_598;
      s = expr_ret_598;
      // ModExprList 1
      if (expr_ret_597) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_597
        ret = SUCC;
        #line 627 "daisho.peg"
        add(rule, s);
        #line 11285 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_597) rew(mod_597);
      expr_ret_596 = expr_ret_597;
    }

    expr_ret_595 = SUCC;
    expr_ret_593 = expr_ret_595;
  }

  // ModExprList end
  if (!expr_ret_593) rew(mod_593);
  expr_ret_592 = expr_ret_593;
  if (!rule) rule = expr_ret_592;
  if (!expr_ret_592) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sstrlit");
  else if (rule) intr_accept(ctx, "sstrlit");
  else intr_reject(ctx, "sstrlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fstrlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_599
  daisho_astnode_t* expr_ret_599 = NULL;
  daisho_astnode_t* expr_ret_600 = NULL;
  intr_enter(ctx, "fstrlit", ctx->pos);
  daisho_astnode_t* expr_ret_601 = NULL;
  rec(mod_601);
  // ModExprList 0
  daisho_astnode_t* expr_ret_602 = NULL;
  expr_ret_602 = daisho_parse_fstrfrag(ctx);
  if (ctx->exit) return NULL;
  expr_ret_601 = expr_ret_602;
  f = expr_ret_602;
  // ModExprList 1
  if (expr_ret_601) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_601
    ret = SUCC;
    #line 629 "daisho.peg"
    rule=list(FSTR); add(rule, f);
    #line 11334 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_601) {
    daisho_astnode_t* expr_ret_603 = NULL;
    daisho_astnode_t* expr_ret_604 = SUCC;
    while (expr_ret_604)
    {
      rec(kleene_rew_603);
      daisho_astnode_t* expr_ret_605 = NULL;
      rec(mod_605);
      // ModExprList 0
      daisho_astnode_t* expr_ret_606 = NULL;
      expr_ret_606 = daisho_parse_fstrfrag(ctx);
      if (ctx->exit) return NULL;
      expr_ret_605 = expr_ret_606;
      f = expr_ret_606;
      // ModExprList 1
      if (expr_ret_605) {
        // CodeExpr
        intr_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_605
        ret = SUCC;
        #line 630 "daisho.peg"
        add(rule, f);
        #line 11363 "daisho_tokenizer_parser.h"

        if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_605) rew(mod_605);
      expr_ret_604 = expr_ret_605;
    }

    expr_ret_603 = SUCC;
    expr_ret_601 = expr_ret_603;
  }

  // ModExprList end
  if (!expr_ret_601) rew(mod_601);
  expr_ret_600 = expr_ret_601;
  if (!rule) rule = expr_ret_600;
  if (!expr_ret_600) rule = NULL;
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
  #define rule expr_ret_607
  daisho_astnode_t* expr_ret_607 = NULL;
  daisho_astnode_t* expr_ret_608 = NULL;
  intr_enter(ctx, "fstrfrag", ctx->pos);
  daisho_astnode_t* expr_ret_609 = NULL;

  // SlashExpr 0
  if (!expr_ret_609) {
    daisho_astnode_t* expr_ret_610 = NULL;
    rec(mod_610);
    // ModExprList Forwarding
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
    // ModExprList end
    if (!expr_ret_610) rew(mod_610);
    expr_ret_609 = expr_ret_610;
  }

  // SlashExpr 1
  if (!expr_ret_609) {
    daisho_astnode_t* expr_ret_611 = NULL;
    rec(mod_611);
    // ModExprList 0
    daisho_astnode_t* expr_ret_612 = NULL;
    intr_enter(ctx, "FSTRLITSTART", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITSTART) {
      // Capturing FSTRLITSTART.
      expr_ret_612 = leaf(FSTRLITSTART);
      expr_ret_612->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_612->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_612 = NULL;
    }

    if (expr_ret_612) intr_accept(ctx, "FSTRLITSTART"); else intr_reject(ctx, "FSTRLITSTART");
    expr_ret_611 = expr_ret_612;
    s = expr_ret_612;
    // ModExprList 1
    if (expr_ret_611) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_611
      ret = SUCC;
      #line 633 "daisho.peg"
      rule=list(FSTRFRAG); add(rule, s);
      #line 11451 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 2
    if (expr_ret_611) {
      daisho_astnode_t* expr_ret_613 = NULL;
      expr_ret_613 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      expr_ret_611 = expr_ret_613;
      x = expr_ret_613;
    }

    // ModExprList 3
    if (expr_ret_611) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_611
      ret = SUCC;
      #line 634 "daisho.peg"
      add(rule, x);
      #line 11474 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 4
    if (expr_ret_611) {
      daisho_astnode_t* expr_ret_614 = NULL;
      daisho_astnode_t* expr_ret_615 = SUCC;
      while (expr_ret_615)
      {
        rec(kleene_rew_614);
        daisho_astnode_t* expr_ret_616 = NULL;
        rec(mod_616);
        // ModExprList 0
        daisho_astnode_t* expr_ret_617 = NULL;
        intr_enter(ctx, "FSTRLITMID", ctx->pos);
        if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITMID) {
          // Capturing FSTRLITMID.
          expr_ret_617 = leaf(FSTRLITMID);
          expr_ret_617->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_617->repr_len = ctx->tokens[ctx->pos].len;
          ctx->pos++;
        } else {
          expr_ret_617 = NULL;
        }

        if (expr_ret_617) intr_accept(ctx, "FSTRLITMID"); else intr_reject(ctx, "FSTRLITMID");
        expr_ret_616 = expr_ret_617;
        m = expr_ret_617;
        // ModExprList 1
        if (expr_ret_616) {
          daisho_astnode_t* expr_ret_618 = NULL;
          expr_ret_618 = daisho_parse_expr(ctx);
          if (ctx->exit) return NULL;
          expr_ret_616 = expr_ret_618;
          x = expr_ret_618;
        }

        // ModExprList 2
        if (expr_ret_616) {
          // CodeExpr
          intr_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_616
          ret = SUCC;
          #line 635 "daisho.peg"
          add(rule, m); add(rule, x);
          #line 11522 "daisho_tokenizer_parser.h"

          if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_616) rew(mod_616);
        expr_ret_615 = expr_ret_616;
      }

      expr_ret_614 = SUCC;
      expr_ret_611 = expr_ret_614;
    }

    // ModExprList 5
    if (expr_ret_611) {
      daisho_astnode_t* expr_ret_619 = NULL;
      intr_enter(ctx, "FSTRLITEND", ctx->pos);
      if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLITEND) {
        // Capturing FSTRLITEND.
        expr_ret_619 = leaf(FSTRLITEND);
        expr_ret_619->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_619->repr_len = ctx->tokens[ctx->pos].len;
        ctx->pos++;
      } else {
        expr_ret_619 = NULL;
      }

      if (expr_ret_619) intr_accept(ctx, "FSTRLITEND"); else intr_reject(ctx, "FSTRLITEND");
      expr_ret_611 = expr_ret_619;
      e = expr_ret_619;
    }

    // ModExprList 6
    if (expr_ret_611) {
      // CodeExpr
      intr_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_611
      ret = SUCC;
      #line 636 "daisho.peg"
      add(rule, e);
      #line 11564 "daisho_tokenizer_parser.h"

      if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_611) rew(mod_611);
    expr_ret_609 = expr_ret_611;
  }

  // SlashExpr end
  expr_ret_608 = expr_ret_609;

  if (!rule) rule = expr_ret_608;
  if (!expr_ret_608) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "fstrfrag");
  else if (rule) intr_accept(ctx, "fstrfrag");
  else intr_reject(ctx, "fstrfrag");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sizeofexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* te = NULL;
  #define rule expr_ret_620
  daisho_astnode_t* expr_ret_620 = NULL;
  daisho_astnode_t* expr_ret_621 = NULL;
  intr_enter(ctx, "sizeofexpr", ctx->pos);
  daisho_astnode_t* expr_ret_622 = NULL;
  rec(mod_622);
  // ModExprList 0
  intr_enter(ctx, "SIZEOF", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SIZEOF) {
    // Not capturing SIZEOF.
    expr_ret_622 = SUCC;
    ctx->pos++;
  } else {
    expr_ret_622 = NULL;
  }

  if (expr_ret_622) intr_accept(ctx, "SIZEOF"); else intr_reject(ctx, "SIZEOF");
  // ModExprList 1
  if (expr_ret_622) {
    intr_enter(ctx, "OPEN", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_622 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_622 = NULL;
    }

    if (expr_ret_622) intr_accept(ctx, "OPEN"); else intr_reject(ctx, "OPEN");
  }

  // ModExprList 2
  if (expr_ret_622) {
    daisho_astnode_t* expr_ret_623 = NULL;
    daisho_astnode_t* expr_ret_624 = NULL;

    // SlashExpr 0
    if (!expr_ret_624) {
      daisho_astnode_t* expr_ret_625 = NULL;
      rec(mod_625);
      // ModExprList Forwarding
      expr_ret_625 = daisho_parse_type(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_625) rew(mod_625);
      expr_ret_624 = expr_ret_625;
    }

    // SlashExpr 1
    if (!expr_ret_624) {
      daisho_astnode_t* expr_ret_626 = NULL;
      rec(mod_626);
      // ModExprList Forwarding
      expr_ret_626 = daisho_parse_expr(ctx);
      if (ctx->exit) return NULL;
      // ModExprList end
      if (!expr_ret_626) rew(mod_626);
      expr_ret_624 = expr_ret_626;
    }

    // SlashExpr end
    expr_ret_623 = expr_ret_624;

    expr_ret_622 = expr_ret_623;
    te = expr_ret_623;
  }

  // ModExprList 3
  if (expr_ret_622) {
    intr_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_622 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_622 = NULL;
    }

    if (expr_ret_622) intr_accept(ctx, "CLOSE"); else intr_reject(ctx, "CLOSE");
  }

  // ModExprList 4
  if (expr_ret_622) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_622
    ret = SUCC;
    #line 638 "daisho.peg"
    rule=node(SIZEOF, te);
    #line 11678 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_622) rew(mod_622);
  expr_ret_621 = expr_ret_622;
  if (!rule) rule = expr_ret_621;
  if (!expr_ret_621) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "sizeofexpr");
  else if (rule) intr_accept(ctx, "sizeofexpr");
  else intr_reject(ctx, "sizeofexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_627
  daisho_astnode_t* expr_ret_627 = NULL;
  daisho_astnode_t* expr_ret_628 = NULL;
  intr_enter(ctx, "wexpr", ctx->pos);
  daisho_astnode_t* expr_ret_629 = NULL;
  rec(mod_629);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_630 = NULL;

  // SlashExpr 0
  if (!expr_ret_630) {
    daisho_astnode_t* expr_ret_631 = NULL;
    rec(mod_631);
    // ModExprList Forwarding
    expr_ret_631 = daisho_parse_expr(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_631) rew(mod_631);
    expr_ret_630 = expr_ret_631;
  }

  // SlashExpr 1
  if (!expr_ret_630) {
    daisho_astnode_t* expr_ret_632 = NULL;
    rec(mod_632);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_632
    ret = SUCC;
    #line 733 "daisho.peg"
    WARNING("Missing expression."); ret=leaf(RECOVERY);
    #line 11729 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_632) rew(mod_632);
    expr_ret_630 = expr_ret_632;
  }

  // SlashExpr end
  expr_ret_629 = expr_ret_630;

  // ModExprList end
  if (!expr_ret_629) rew(mod_629);
  expr_ret_628 = expr_ret_629;
  if (!rule) rule = expr_ret_628;
  if (!expr_ret_628) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wexpr");
  else if (rule) intr_accept(ctx, "wexpr");
  else intr_reject(ctx, "wexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_noexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_633
  daisho_astnode_t* expr_ret_633 = NULL;
  daisho_astnode_t* expr_ret_634 = NULL;
  intr_enter(ctx, "noexpr", ctx->pos);
  daisho_astnode_t* expr_ret_635 = NULL;
  rec(mod_635);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_636 = NULL;
  rec(mod_636);
  // ModExprList 0
  daisho_astnode_t* expr_ret_637 = NULL;
  expr_ret_637 = daisho_parse_expr(ctx);
  if (ctx->exit) return NULL;
  expr_ret_636 = expr_ret_637;
  e = expr_ret_637;
  // ModExprList 1
  if (expr_ret_636) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_636
    ret = SUCC;
    #line 734 "daisho.peg"
    WARNING("Extra expression."); ret=e;
    #line 11778 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_636) rew(mod_636);
  expr_ret_635 = expr_ret_636;
  // ModExprList end
  if (!expr_ret_635) rew(mod_635);
  expr_ret_634 = expr_ret_635;
  if (!rule) rule = expr_ret_634;
  if (!expr_ret_634) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "noexpr");
  else if (rule) intr_accept(ctx, "noexpr");
  else intr_reject(ctx, "noexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wcomma(daisho_parser_ctx* ctx) {
  #define rule expr_ret_638
  daisho_astnode_t* expr_ret_638 = NULL;
  daisho_astnode_t* expr_ret_639 = NULL;
  intr_enter(ctx, "wcomma", ctx->pos);
  daisho_astnode_t* expr_ret_640 = NULL;
  rec(mod_640);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_641 = NULL;

  // SlashExpr 0
  if (!expr_ret_641) {
    daisho_astnode_t* expr_ret_642 = NULL;
    rec(mod_642);
    // ModExprList Forwarding
    intr_enter(ctx, "COMMA", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Capturing COMMA.
      expr_ret_642 = leaf(COMMA);
      expr_ret_642->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_642->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_642 = NULL;
    }

    if (expr_ret_642) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
    // ModExprList end
    if (!expr_ret_642) rew(mod_642);
    expr_ret_641 = expr_ret_642;
  }

  // SlashExpr 1
  if (!expr_ret_641) {
    daisho_astnode_t* expr_ret_643 = NULL;
    rec(mod_643);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_643
    ret = SUCC;
    #line 735 "daisho.peg"
    WARNING("Missing comma."); ret=leaf(COMMA);
    #line 11842 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_643) rew(mod_643);
    expr_ret_641 = expr_ret_643;
  }

  // SlashExpr end
  expr_ret_640 = expr_ret_641;

  // ModExprList end
  if (!expr_ret_640) rew(mod_640);
  expr_ret_639 = expr_ret_640;
  if (!rule) rule = expr_ret_639;
  if (!expr_ret_639) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wcomma");
  else if (rule) intr_accept(ctx, "wcomma");
  else intr_reject(ctx, "wcomma");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nocomma(daisho_parser_ctx* ctx) {
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_644
  daisho_astnode_t* expr_ret_644 = NULL;
  daisho_astnode_t* expr_ret_645 = NULL;
  intr_enter(ctx, "nocomma", ctx->pos);
  daisho_astnode_t* expr_ret_646 = NULL;
  rec(mod_646);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_647 = NULL;
  rec(mod_647);
  // ModExprList 0
  daisho_astnode_t* expr_ret_648 = NULL;
  intr_enter(ctx, "COMMA", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
    // Capturing COMMA.
    expr_ret_648 = leaf(COMMA);
    expr_ret_648->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_648->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_648 = NULL;
  }

  if (expr_ret_648) intr_accept(ctx, "COMMA"); else intr_reject(ctx, "COMMA");
  expr_ret_647 = expr_ret_648;
  c = expr_ret_648;
  // ModExprList 1
  if (expr_ret_647) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_647
    ret = SUCC;
    #line 736 "daisho.peg"
    WARNING("Extra comma."); ret=c;
    #line 11901 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_647) rew(mod_647);
  expr_ret_646 = expr_ret_647;
  // ModExprList end
  if (!expr_ret_646) rew(mod_646);
  expr_ret_645 = expr_ret_646;
  if (!rule) rule = expr_ret_645;
  if (!expr_ret_645) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nocomma");
  else if (rule) intr_accept(ctx, "nocomma");
  else intr_reject(ctx, "nocomma");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemi(daisho_parser_ctx* ctx) {
  #define rule expr_ret_649
  daisho_astnode_t* expr_ret_649 = NULL;
  daisho_astnode_t* expr_ret_650 = NULL;
  intr_enter(ctx, "wsemi", ctx->pos);
  daisho_astnode_t* expr_ret_651 = NULL;
  rec(mod_651);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_652 = NULL;

  // SlashExpr 0
  if (!expr_ret_652) {
    daisho_astnode_t* expr_ret_653 = NULL;
    rec(mod_653);
    // ModExprList Forwarding
    intr_enter(ctx, "SEMI", ctx->pos);
    if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Capturing SEMI.
      expr_ret_653 = leaf(SEMI);
      expr_ret_653->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_653->repr_len = ctx->tokens[ctx->pos].len;
      ctx->pos++;
    } else {
      expr_ret_653 = NULL;
    }

    if (expr_ret_653) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
    // ModExprList end
    if (!expr_ret_653) rew(mod_653);
    expr_ret_652 = expr_ret_653;
  }

  // SlashExpr 1
  if (!expr_ret_652) {
    daisho_astnode_t* expr_ret_654 = NULL;
    rec(mod_654);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_654
    ret = SUCC;
    #line 737 "daisho.peg"
    WARNING("Missing semicolon."); ret=leaf(SEMI);
    #line 11965 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_654) rew(mod_654);
    expr_ret_652 = expr_ret_654;
  }

  // SlashExpr end
  expr_ret_651 = expr_ret_652;

  // ModExprList end
  if (!expr_ret_651) rew(mod_651);
  expr_ret_650 = expr_ret_651;
  if (!rule) rule = expr_ret_650;
  if (!expr_ret_650) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "wsemi");
  else if (rule) intr_accept(ctx, "wsemi");
  else intr_reject(ctx, "wsemi");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nosemi(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_655
  daisho_astnode_t* expr_ret_655 = NULL;
  daisho_astnode_t* expr_ret_656 = NULL;
  intr_enter(ctx, "nosemi", ctx->pos);
  daisho_astnode_t* expr_ret_657 = NULL;
  rec(mod_657);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_658 = NULL;
  rec(mod_658);
  // ModExprList 0
  daisho_astnode_t* expr_ret_659 = NULL;
  intr_enter(ctx, "SEMI", ctx->pos);
  if (ctx->pos < ctx->len && ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
    // Capturing SEMI.
    expr_ret_659 = leaf(SEMI);
    expr_ret_659->tok_repr = ctx->tokens[ctx->pos].content;
    expr_ret_659->repr_len = ctx->tokens[ctx->pos].len;
    ctx->pos++;
  } else {
    expr_ret_659 = NULL;
  }

  if (expr_ret_659) intr_accept(ctx, "SEMI"); else intr_reject(ctx, "SEMI");
  expr_ret_658 = expr_ret_659;
  s = expr_ret_659;
  // ModExprList 1
  if (expr_ret_658) {
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_658
    ret = SUCC;
    #line 738 "daisho.peg"
    WARNING("Extra semicolon."); ret=s;
    #line 12024 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_658) rew(mod_658);
  expr_ret_657 = expr_ret_658;
  // ModExprList end
  if (!expr_ret_657) rew(mod_657);
  expr_ret_656 = expr_ret_657;
  if (!rule) rule = expr_ret_656;
  if (!expr_ret_656) rule = NULL;
  if (rule==SUCC) intr_succ(ctx, "nosemi");
  else if (rule) intr_accept(ctx, "nosemi");
  else intr_reject(ctx, "nosemi");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_wsemiornl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_660
  daisho_astnode_t* expr_ret_660 = NULL;
  daisho_astnode_t* expr_ret_661 = NULL;
  intr_enter(ctx, "wsemiornl", ctx->pos);
  daisho_astnode_t* expr_ret_662 = NULL;
  rec(mod_662);
  // ModExprList Forwarding
  daisho_astnode_t* expr_ret_663 = NULL;

  // SlashExpr 0
  if (!expr_ret_663) {
    daisho_astnode_t* expr_ret_664 = NULL;
    rec(mod_664);
    // ModExprList Forwarding
    expr_ret_664 = daisho_parse_semiornl(ctx);
    if (ctx->exit) return NULL;
    // ModExprList end
    if (!expr_ret_664) rew(mod_664);
    expr_ret_663 = expr_ret_664;
  }

  // SlashExpr 1
  if (!expr_ret_663) {
    daisho_astnode_t* expr_ret_665 = NULL;
    rec(mod_665);
    // ModExprList Forwarding
    // CodeExpr
    intr_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_665
    ret = SUCC;
    #line 739 "daisho.peg"
    WARNING("Missing semicolon or newline."); ret=leaf(SEMI);
    #line 12078 "daisho_tokenizer_parser.h"

    if (ret) intr_accept(ctx, "CodeExpr"); else intr_reject(ctx, "CodeExpr");
    #undef ret
    // ModExprList end
    if (!expr_ret_665) rew(mod_665);
    expr_ret_663 = expr_ret_665;
  }

  // SlashExpr end
  expr_ret_662 = expr_ret_663;

  // ModExprList end
  if (!expr_ret_662) rew(mod_662);
  expr_ret_661 = expr_ret_662;
  if (!rule) rule = expr_ret_661;
  if (!expr_ret_661) rule = NULL;
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

