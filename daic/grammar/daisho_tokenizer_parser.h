
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
#include <assert.h>


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
  DAISHO_TOK_DIV,
  DAISHO_TOK_POW,
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
  DAISHO_TOK_CFN,
  DAISHO_TOK_FNTYPE,
  DAISHO_TOK_CTYPE,
  DAISHO_TOK_NAMESPACE,
  DAISHO_TOK_SELFTYPE,
  DAISHO_TOK_SELFVAR,
  DAISHO_TOK_VOIDTYPE,
  DAISHO_TOK_VOIDPTR,
  DAISHO_TOK_ALIAS,
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
  DAISHO_TOK_SQUOTE,
  DAISHO_TOK_DQUOTE,
  DAISHO_TOK_ARROW,
  DAISHO_TOK_DARROW,
  DAISHO_TOK_RET,
  DAISHO_TOK_OP,
  DAISHO_TOK_REDEF,
  DAISHO_TOK_TYPEIDENT,
  DAISHO_TOK_TRAITIDENT,
  DAISHO_TOK_VARIDENT,
  DAISHO_TOK_CIDENT,
  DAISHO_TOK_NUMLIT,
  DAISHO_TOK_STRLIT,
  DAISHO_TOK_FSTRLIT,
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
  "DAISHO_TOK_STREAMBEGIN",
  "DAISHO_TOK_STREAMEND",
  "DAISHO_TOK_PLUS",
  "DAISHO_TOK_MINUS",
  "DAISHO_TOK_STAR",
  "DAISHO_TOK_DIV",
  "DAISHO_TOK_POW",
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
  "DAISHO_TOK_IF",
  "DAISHO_TOK_ELSE",
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
  "DAISHO_TOK_CFN",
  "DAISHO_TOK_FNTYPE",
  "DAISHO_TOK_CTYPE",
  "DAISHO_TOK_NAMESPACE",
  "DAISHO_TOK_SELFTYPE",
  "DAISHO_TOK_SELFVAR",
  "DAISHO_TOK_VOIDTYPE",
  "DAISHO_TOK_VOIDPTR",
  "DAISHO_TOK_ALIAS",
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
  "DAISHO_TOK_SQUOTE",
  "DAISHO_TOK_DQUOTE",
  "DAISHO_TOK_ARROW",
  "DAISHO_TOK_DARROW",
  "DAISHO_TOK_RET",
  "DAISHO_TOK_OP",
  "DAISHO_TOK_REDEF",
  "DAISHO_TOK_TYPEIDENT",
  "DAISHO_TOK_TRAITIDENT",
  "DAISHO_TOK_VARIDENT",
  "DAISHO_TOK_CIDENT",
  "DAISHO_TOK_NUMLIT",
  "DAISHO_TOK_STRLIT",
  "DAISHO_TOK_FSTRLIT",
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
        else if (c == 34 /*'"'*/) trie_state = 123;
        else if (c == 35 /*'#'*/) trie_state = 118;
        else if (c == 36 /*'$'*/) trie_state = 120;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 39 /*'''*/) trie_state = 122;
        else if (c == 40 /*'('*/) trie_state = 112;
        else if (c == 41 /*')'*/) trie_state = 113;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 111;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 110;
        else if (c == 47 /*'/'*/) trie_state = 4;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 109;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 119;
        else if (c == 70 /*'F'*/) trie_state = 75;
        else if (c == 83 /*'S'*/) trie_state = 91;
        else if (c == 86 /*'V'*/) trie_state = 99;
        else if (c == 91 /*'['*/) trie_state = 116;
        else if (c == 93 /*']'*/) trie_state = 117;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 121;
        else if (c == 97 /*'a'*/) trie_state = 58;
        else if (c == 99 /*'c'*/) trie_state = 77;
        else if (c == 101 /*'e'*/) trie_state = 41;
        else if (c == 102 /*'f'*/) trie_state = 45;
        else if (c == 105 /*'i'*/) trie_state = 39;
        else if (c == 110 /*'n'*/) trie_state = 82;
        else if (c == 115 /*'s'*/) trie_state = 95;
        else if (c == 116 /*'t'*/) trie_state = 54;
        else if (c == 117 /*'u'*/) trie_state = 65;
        else if (c == 119 /*'w'*/) trie_state = 49;
        else if (c == 123 /*'{'*/) trie_state = 114;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 115;
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
        else if (c == 62 /*'>'*/) trie_state = 124;
        else trie_state = -1;
      }
      else if (trie_state == 3) {
        if (c == 42 /*'*'*/) trie_state = 5;
        else if (c == 61 /*'='*/) trie_state = 23;
        else trie_state = -1;
      }
      else if (trie_state == 4) {
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
        else if (c == 62 /*'>'*/) trie_state = 125;
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
        if (c == 105 /*'i'*/) trie_state = 106;
        else if (c == 115 /*'s'*/) trie_state = 60;
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
        if (c == 116 /*'t'*/) trie_state = 78;
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
        if (c == 97 /*'a'*/) trie_state = 83;
        else trie_state = -1;
      }
      else if (trie_state == 83) {
        if (c == 109 /*'m'*/) trie_state = 84;
        else trie_state = -1;
      }
      else if (trie_state == 84) {
        if (c == 101 /*'e'*/) trie_state = 85;
        else trie_state = -1;
      }
      else if (trie_state == 85) {
        if (c == 115 /*'s'*/) trie_state = 86;
        else trie_state = -1;
      }
      else if (trie_state == 86) {
        if (c == 112 /*'p'*/) trie_state = 87;
        else trie_state = -1;
      }
      else if (trie_state == 87) {
        if (c == 97 /*'a'*/) trie_state = 88;
        else trie_state = -1;
      }
      else if (trie_state == 88) {
        if (c == 99 /*'c'*/) trie_state = 89;
        else trie_state = -1;
      }
      else if (trie_state == 89) {
        if (c == 101 /*'e'*/) trie_state = 90;
        else trie_state = -1;
      }
      else if (trie_state == 91) {
        if (c == 101 /*'e'*/) trie_state = 92;
        else trie_state = -1;
      }
      else if (trie_state == 92) {
        if (c == 108 /*'l'*/) trie_state = 93;
        else trie_state = -1;
      }
      else if (trie_state == 93) {
        if (c == 102 /*'f'*/) trie_state = 94;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 101 /*'e'*/) trie_state = 96;
        else trie_state = -1;
      }
      else if (trie_state == 96) {
        if (c == 108 /*'l'*/) trie_state = 97;
        else trie_state = -1;
      }
      else if (trie_state == 97) {
        if (c == 102 /*'f'*/) trie_state = 98;
        else trie_state = -1;
      }
      else if (trie_state == 99) {
        if (c == 111 /*'o'*/) trie_state = 100;
        else trie_state = -1;
      }
      else if (trie_state == 100) {
        if (c == 105 /*'i'*/) trie_state = 101;
        else trie_state = -1;
      }
      else if (trie_state == 101) {
        if (c == 100 /*'d'*/) trie_state = 102;
        else trie_state = -1;
      }
      else if (trie_state == 102) {
        if (c == 80 /*'P'*/) trie_state = 103;
        else trie_state = -1;
      }
      else if (trie_state == 103) {
        if (c == 116 /*'t'*/) trie_state = 104;
        else trie_state = -1;
      }
      else if (trie_state == 104) {
        if (c == 114 /*'r'*/) trie_state = 105;
        else trie_state = -1;
      }
      else if (trie_state == 106) {
        if (c == 97 /*'a'*/) trie_state = 107;
        else trie_state = -1;
      }
      else if (trie_state == 107) {
        if (c == 115 /*'s'*/) trie_state = 108;
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
        trie_tokenkind =  DAISHO_TOK_POW;
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
      else if (trie_state == 90) {
        trie_tokenkind =  DAISHO_TOK_NAMESPACE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 94) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 102) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_VOIDPTR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_ALIAS;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 114) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 115) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 116) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 117) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 118) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 119) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 120) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 121) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 122) {
        trie_tokenkind =  DAISHO_TOK_SQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 123) {
        trie_tokenkind =  DAISHO_TOK_DQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 124) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 125) {
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

    // Transition CFN State Machine
    if (smaut_state_2 != -1) {
      all_dead = 0;

      if ((smaut_state_2 == 0) &
         (c == 99)) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 102)) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 117)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 110)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 99)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 2) &
         (c == 110)) {
          smaut_state_2 = 6;
      }
      else {
        smaut_state_2 = -1;
      }

      // Check accept
      if ((smaut_state_2 == 4) | (smaut_state_2 == 5) | (smaut_state_2 == 6)) {
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

    // Transition TRAITIDENT State Machine
    if (smaut_state_7 != -1) {
      all_dead = 0;

      if ((smaut_state_7 == 0) &
         (((c >= 65) & (c <= 90)))) {
          smaut_state_7 = 1;
      }
      else if (((smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_7 = 2;
      }
      else if (((smaut_state_7 == 1) | (smaut_state_7 == 2)) &
         (c == 39)) {
          smaut_state_7 = 3;
      }
      else {
        smaut_state_7 = -1;
      }

      // Check accept
      if (smaut_state_7 == 3) {
        smaut_munch_size_7 = iidx + 1;
      }
    }

    // Transition VARIDENT State Machine
    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
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

    // Transition CIDENT State Machine
    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)))) {
          smaut_state_9 = 1;
      }
      else if (((smaut_state_9 == 1) | (smaut_state_9 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_9 = 2;
      }
      else {
        smaut_state_9 = -1;
      }

      // Check accept
      if ((smaut_state_9 == 1) | (smaut_state_9 == 2)) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition NUMLIT State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if (((smaut_state_10 == 0) | (smaut_state_10 == 1)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_10 = 1;
      }
      else if ((smaut_state_10 == 0) &
         (c == 46)) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 1) &
         (c == 46)) {
          smaut_state_10 = 3;
      }
      else if (((smaut_state_10 == 2) | (smaut_state_10 == 3)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_10 = 3;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if ((smaut_state_10 == 1) | (smaut_state_10 == 3)) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         (c == 34)) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 1) &
         (c == 34)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 1) &
         (c == 92)) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 1) &
         (!(c == 10))) {
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
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if (smaut_state_11 == 2) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition FSTRLIT State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 102)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 34)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 2) &
         (c == 34)) {
          smaut_state_12 = 4;
      }
      else if ((smaut_state_12 == 1) &
         (c == 92)) {
          smaut_state_12 = 3;
      }
      else if ((smaut_state_12 == 1) &
         (!(c == 10))) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 110)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 102)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 98)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 114)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 116)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 101)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 92)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 39)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 3) &
         (c == 34)) {
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
    kind = DAISHO_TOK_FSTRLIT;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_CIDENT;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_TRAITIDENT;
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
    kind = DAISHO_TOK_CFN;
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
  DAISHO_NODE_CIDENT,
  DAISHO_NODE_CFNDECL,
  DAISHO_NODE_TMPLDECL,
  DAISHO_NODE_IF,
  DAISHO_NODE_IFELSE,
  DAISHO_NODE_STRLITS,
  DAISHO_NODE_PROG,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_GLOBALSCOPE,
  DAISHO_NODE_NAMESPACEDECL,
  DAISHO_NODE_STRUCTDECL,
  DAISHO_NODE_UNIONDECL,
  DAISHO_NODE_TRAITDECL,
  DAISHO_NODE_CTYPEDECL,
  DAISHO_NODE_ALIASDECL,
  DAISHO_NODE_FNDECL,
  DAISHO_NODE_TMPLBEGIN,
  DAISHO_NODE_TMPLEXPAND,
  DAISHO_NODE_TMPLEXPANDLIST,
  DAISHO_NODE_TMPLSTRUCT,
  DAISHO_NODE_TMPLUNION,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_TMPLTYPE,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_STRUCT,
  DAISHO_NODE_UNION,
  DAISHO_NODE_TRAIT,
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
  DAISHO_NODE_ELVIS,
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
  DAISHO_NODE_CALL,
  DAISHO_NODE_TMPLCALL,
  DAISHO_NODE_FNARGLIST,
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
  DAISHO_NODE_TRAITIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 97
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_CIDENT",
  "DAISHO_NODE_CFNDECL",
  "DAISHO_NODE_TMPLDECL",
  "DAISHO_NODE_IF",
  "DAISHO_NODE_IFELSE",
  "DAISHO_NODE_STRLITS",
  "DAISHO_NODE_PROG",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_NAMESPACE",
  "DAISHO_NODE_GLOBALSCOPE",
  "DAISHO_NODE_NAMESPACEDECL",
  "DAISHO_NODE_STRUCTDECL",
  "DAISHO_NODE_UNIONDECL",
  "DAISHO_NODE_TRAITDECL",
  "DAISHO_NODE_CTYPEDECL",
  "DAISHO_NODE_ALIASDECL",
  "DAISHO_NODE_FNDECL",
  "DAISHO_NODE_TMPLBEGIN",
  "DAISHO_NODE_TMPLEXPAND",
  "DAISHO_NODE_TMPLEXPANDLIST",
  "DAISHO_NODE_TMPLSTRUCT",
  "DAISHO_NODE_TMPLUNION",
  "DAISHO_NODE_TMPLTRAIT",
  "DAISHO_NODE_TMPLTYPE",
  "DAISHO_NODE_MEMBERLIST",
  "DAISHO_NODE_STRUCT",
  "DAISHO_NODE_UNION",
  "DAISHO_NODE_TRAIT",
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
  "DAISHO_NODE_ELVIS",
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
  "DAISHO_NODE_CALL",
  "DAISHO_NODE_TMPLCALL",
  "DAISHO_NODE_FNARGLIST",
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
  "DAISHO_NODE_TRAITIDENT",
  "DAISHO_NODE_VARIDENT",
};

struct daisho_astnode_t;
typedef struct daisho_astnode_t daisho_astnode_t;
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
  void* symtab;
  void* type;
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
#define node(kind, ...)          PGEN_CAT(daisho_astnode_fixed_, PGEN_NARG(__VA_ARGS__))(ctx->alloc, DAISHO_NODE_##kind, __VA_ARGS__)
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

#include "../asthelpers.h"


static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_edecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_decl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_aliasdecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmpldeclmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplex(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ttexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ifeexpr(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fncallargs(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_strlits(daisho_parser_ctx* ctx);


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
    expr_ret_2 = daisho_parse_edecl(ctx);
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
        expr_ret_5 = daisho_parse_edecl(ctx);
      }

      // ModExprList end
      if (!expr_ret_5) rew(mod_5);
      expr_ret_4 = expr_ret_5 ? SUCC : NULL;
    }

    expr_ret_4 = SUCC;
    expr_ret_2 = expr_ret_4;
  }

  // ModExprList 3
  if (expr_ret_2)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_2 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_2 = NULL;
    }

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

static inline daisho_astnode_t* daisho_parse_edecl(daisho_parser_ctx* ctx) {
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
    expr_ret_9 = daisho_parse_decl(ctx);
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
    expr_ret_10 = daisho_parse_expr(ctx);
    // ModExprList end
    if (!expr_ret_10) rew(mod_10);
    expr_ret_8 = expr_ret_10;
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

static inline daisho_astnode_t* daisho_parse_decl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_11

  daisho_astnode_t* expr_ret_12 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  daisho_astnode_t* expr_ret_13 = NULL;

  rec(slash_13);

  // SlashExpr 0
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    rec(mod_14);
    // ModExprList Forwarding
    expr_ret_14 = daisho_parse_nsdecl(ctx);
    // ModExprList end
    if (!expr_ret_14) rew(mod_14);
    expr_ret_13 = expr_ret_14;
  }

  // SlashExpr 1
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_15 = NULL;
    rec(mod_15);
    // ModExprList Forwarding
    expr_ret_15 = daisho_parse_structdecl(ctx);
    // ModExprList end
    if (!expr_ret_15) rew(mod_15);
    expr_ret_13 = expr_ret_15;
  }

  // SlashExpr 2
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_16 = NULL;
    rec(mod_16);
    // ModExprList Forwarding
    expr_ret_16 = daisho_parse_uniondecl(ctx);
    // ModExprList end
    if (!expr_ret_16) rew(mod_16);
    expr_ret_13 = expr_ret_16;
  }

  // SlashExpr 3
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_17 = NULL;
    rec(mod_17);
    // ModExprList Forwarding
    expr_ret_17 = daisho_parse_traitdecl(ctx);
    // ModExprList end
    if (!expr_ret_17) rew(mod_17);
    expr_ret_13 = expr_ret_17;
  }

  // SlashExpr 4
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_18 = NULL;
    rec(mod_18);
    // ModExprList Forwarding
    expr_ret_18 = daisho_parse_impldecl(ctx);
    // ModExprList end
    if (!expr_ret_18) rew(mod_18);
    expr_ret_13 = expr_ret_18;
  }

  // SlashExpr 5
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_19 = NULL;
    rec(mod_19);
    // ModExprList Forwarding
    expr_ret_19 = daisho_parse_ctypedecl(ctx);
    // ModExprList end
    if (!expr_ret_19) rew(mod_19);
    expr_ret_13 = expr_ret_19;
  }

  // SlashExpr 6
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_20 = NULL;
    rec(mod_20);
    // ModExprList Forwarding
    expr_ret_20 = daisho_parse_aliasdecl(ctx);
    // ModExprList end
    if (!expr_ret_20) rew(mod_20);
    expr_ret_13 = expr_ret_20;
  }

  // SlashExpr 7
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_21 = NULL;
    rec(mod_21);
    // ModExprList Forwarding
    expr_ret_21 = daisho_parse_fndecl(ctx);
    // ModExprList end
    if (!expr_ret_21) rew(mod_21);
    expr_ret_13 = expr_ret_21;
  }

  // SlashExpr end
  if (!expr_ret_13) rew(slash_13);
  expr_ret_12 = expr_ret_13;

  if (!rule) rule = expr_ret_12;
  if (!expr_ret_12) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_22

  daisho_astnode_t* expr_ret_23 = NULL;
  daisho_astnode_t* expr_ret_22 = NULL;
  daisho_astnode_t* expr_ret_24 = NULL;
  rec(mod_24);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_24 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_24 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_24)
  {
    daisho_astnode_t* expr_ret_25 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_25 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_25->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_25->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_25 = NULL;
    }

    expr_ret_24 = expr_ret_25;
    t = expr_ret_25;
  }

  // ModExprList 2
  if (expr_ret_24)
  {
    // CodeExpr
    #define ret expr_ret_24
    ret = SUCC;

    rule=node(NAMESPACEDECL, t);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_24) rew(mod_24);
  expr_ret_23 = expr_ret_24 ? SUCC : NULL;
  if (!rule) rule = expr_ret_23;
  if (!expr_ret_23) rule = NULL;
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
  #define rule expr_ret_26

  daisho_astnode_t* expr_ret_27 = NULL;
  daisho_astnode_t* expr_ret_26 = NULL;
  daisho_astnode_t* expr_ret_28 = NULL;
  rec(mod_28);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      // Not capturing STRUCT.
      expr_ret_28 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_28 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_29 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_29 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_29->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_29->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

    expr_ret_28 = expr_ret_29;
    id = expr_ret_29;
  }

  // ModExprList 2
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_30 = NULL;
    expr_ret_30 = daisho_parse_tmpldecl(ctx);
    // optional
    if (!expr_ret_30)
      expr_ret_30 = SUCC;
    expr_ret_28 = expr_ret_30;
    tmpl = expr_ret_30;
  }

  // ModExprList 3
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_31 = NULL;
    daisho_astnode_t* expr_ret_32 = NULL;
    rec(mod_32);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_32 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_32 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_32)
    {
      expr_ret_32 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_32)
    {
      daisho_astnode_t* expr_ret_33 = NULL;
      expr_ret_33 = SUCC;
      while (expr_ret_33)
      {
        daisho_astnode_t* expr_ret_34 = NULL;
        rec(mod_34);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
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

        // ModExprList end
        if (!expr_ret_34) rew(mod_34);
        expr_ret_33 = expr_ret_34 ? SUCC : NULL;
      }

      expr_ret_33 = SUCC;
      expr_ret_32 = expr_ret_33;
    }

    // ModExprList end
    if (!expr_ret_32) rew(mod_32);
    expr_ret_31 = expr_ret_32 ? SUCC : NULL;
    // optional
    if (!expr_ret_31)
      expr_ret_31 = SUCC;
    expr_ret_28 = expr_ret_31;
    impl = expr_ret_31;
  }

  // ModExprList 4
  if (expr_ret_28)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_28 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_28 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_35 = NULL;
    // CodeExpr
    #define ret expr_ret_35
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_28 = expr_ret_35;
    members = expr_ret_35;
  }

  // ModExprList 6
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_36 = NULL;
    expr_ret_36 = SUCC;
    while (expr_ret_36)
    {
      daisho_astnode_t* expr_ret_37 = NULL;
      rec(mod_37);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_38 = NULL;
        expr_ret_38 = daisho_parse_typemember(ctx);
        expr_ret_37 = expr_ret_38;
        m = expr_ret_38;
      }

      // ModExprList 1
      if (expr_ret_37)
      {
        // CodeExpr
        #define ret expr_ret_37
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_37) rew(mod_37);
      expr_ret_36 = expr_ret_37 ? SUCC : NULL;
    }

    expr_ret_36 = SUCC;
    expr_ret_28 = expr_ret_36;
  }

  // ModExprList 7
  if (expr_ret_28)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_28 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_28 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_28)
  {
    daisho_astnode_t* expr_ret_39 = NULL;
    // CodeExpr
    #define ret expr_ret_39
    ret = SUCC;

    n = node(STRUCTDECL, id, members);
              rule = has(tmpl) ? node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_28 = expr_ret_39;
    n = expr_ret_39;
  }

  // ModExprList end
  if (!expr_ret_28) rew(mod_28);
  expr_ret_27 = expr_ret_28 ? SUCC : NULL;
  if (!rule) rule = expr_ret_27;
  if (!expr_ret_27) rule = NULL;
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
  #define rule expr_ret_40

  daisho_astnode_t* expr_ret_41 = NULL;
  daisho_astnode_t* expr_ret_40 = NULL;
  daisho_astnode_t* expr_ret_42 = NULL;
  rec(mod_42);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      // Not capturing UNION.
      expr_ret_42 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_42 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_43 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_43 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_43->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_43->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    expr_ret_42 = expr_ret_43;
    id = expr_ret_43;
  }

  // ModExprList 2
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_44 = NULL;
    expr_ret_44 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_44)
      expr_ret_44 = SUCC;
    expr_ret_42 = expr_ret_44;
    tmpl = expr_ret_44;
  }

  // ModExprList 3
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_45 = NULL;
    daisho_astnode_t* expr_ret_46 = NULL;
    rec(mod_46);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_46 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_46 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_46)
    {
      expr_ret_46 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_46)
    {
      daisho_astnode_t* expr_ret_47 = NULL;
      expr_ret_47 = SUCC;
      while (expr_ret_47)
      {
        daisho_astnode_t* expr_ret_48 = NULL;
        rec(mod_48);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_48 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_48 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_48)
        {
          expr_ret_48 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_48) rew(mod_48);
        expr_ret_47 = expr_ret_48 ? SUCC : NULL;
      }

      expr_ret_47 = SUCC;
      expr_ret_46 = expr_ret_47;
    }

    // ModExprList end
    if (!expr_ret_46) rew(mod_46);
    expr_ret_45 = expr_ret_46 ? SUCC : NULL;
    // optional
    if (!expr_ret_45)
      expr_ret_45 = SUCC;
    expr_ret_42 = expr_ret_45;
    impl = expr_ret_45;
  }

  // ModExprList 4
  if (expr_ret_42)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_42 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_42 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_49 = NULL;
    // CodeExpr
    #define ret expr_ret_49
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_42 = expr_ret_49;
    members = expr_ret_49;
  }

  // ModExprList 6
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_50 = NULL;
    expr_ret_50 = SUCC;
    while (expr_ret_50)
    {
      daisho_astnode_t* expr_ret_51 = NULL;
      rec(mod_51);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_52 = NULL;
        expr_ret_52 = daisho_parse_typemember(ctx);
        expr_ret_51 = expr_ret_52;
        m = expr_ret_52;
      }

      // ModExprList 1
      if (expr_ret_51)
      {
        // CodeExpr
        #define ret expr_ret_51
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_51) rew(mod_51);
      expr_ret_50 = expr_ret_51 ? SUCC : NULL;
    }

    expr_ret_50 = SUCC;
    expr_ret_42 = expr_ret_50;
  }

  // ModExprList 7
  if (expr_ret_42)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_42 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_42 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_42)
  {
    daisho_astnode_t* expr_ret_53 = NULL;
    // CodeExpr
    #define ret expr_ret_53
    ret = SUCC;

    n = node(UNIONDECL, id, members);
              rule = has(tmpl) ? node(TMPLUNION, tmpl, n) : n;

    #undef ret
    expr_ret_42 = expr_ret_53;
    n = expr_ret_53;
  }

  // ModExprList end
  if (!expr_ret_42) rew(mod_42);
  expr_ret_41 = expr_ret_42 ? SUCC : NULL;
  if (!rule) rule = expr_ret_41;
  if (!expr_ret_41) rule = NULL;
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
  #define rule expr_ret_54

  daisho_astnode_t* expr_ret_55 = NULL;
  daisho_astnode_t* expr_ret_54 = NULL;
  daisho_astnode_t* expr_ret_56 = NULL;
  rec(mod_56);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      // Not capturing TRAIT.
      expr_ret_56 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_56 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_57 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_57 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_57->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_57->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_57 = NULL;
    }

    expr_ret_56 = expr_ret_57;
    id = expr_ret_57;
  }

  // ModExprList 2
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_58 = NULL;
    expr_ret_58 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_58)
      expr_ret_58 = SUCC;
    expr_ret_56 = expr_ret_58;
    tmpl = expr_ret_58;
  }

  // ModExprList 3
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_59 = NULL;
    daisho_astnode_t* expr_ret_60 = NULL;
    rec(mod_60);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_60 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_60 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_60)
    {
      expr_ret_60 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_60)
    {
      daisho_astnode_t* expr_ret_61 = NULL;
      expr_ret_61 = SUCC;
      while (expr_ret_61)
      {
        daisho_astnode_t* expr_ret_62 = NULL;
        rec(mod_62);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_62 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_62 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_62)
        {
          expr_ret_62 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_62) rew(mod_62);
        expr_ret_61 = expr_ret_62 ? SUCC : NULL;
      }

      expr_ret_61 = SUCC;
      expr_ret_60 = expr_ret_61;
    }

    // ModExprList end
    if (!expr_ret_60) rew(mod_60);
    expr_ret_59 = expr_ret_60 ? SUCC : NULL;
    // optional
    if (!expr_ret_59)
      expr_ret_59 = SUCC;
    expr_ret_56 = expr_ret_59;
    impl = expr_ret_59;
  }

  // ModExprList 4
  if (expr_ret_56)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_56 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_56 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_63 = NULL;
    // CodeExpr
    #define ret expr_ret_63
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_56 = expr_ret_63;
    members = expr_ret_63;
  }

  // ModExprList 6
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_64 = NULL;
    expr_ret_64 = SUCC;
    while (expr_ret_64)
    {
      daisho_astnode_t* expr_ret_65 = NULL;
      rec(mod_65);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_66 = NULL;
        expr_ret_66 = daisho_parse_fnmember(ctx);
        expr_ret_65 = expr_ret_66;
        m = expr_ret_66;
      }

      // ModExprList 1
      if (expr_ret_65)
      {
        // CodeExpr
        #define ret expr_ret_65
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_65) rew(mod_65);
      expr_ret_64 = expr_ret_65 ? SUCC : NULL;
    }

    expr_ret_64 = SUCC;
    expr_ret_56 = expr_ret_64;
  }

  // ModExprList 7
  if (expr_ret_56)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_56 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_56 = NULL;
    }

  }

  // ModExprList 8
  if (expr_ret_56)
  {
    daisho_astnode_t* expr_ret_67 = NULL;
    // CodeExpr
    #define ret expr_ret_67
    ret = SUCC;

    n = node(TRAITDECL, id, members);
              rule = has(tmpl) ? node(TMPLTRAIT, tmpl, n) : n;

    #undef ret
    expr_ret_56 = expr_ret_67;
    n = expr_ret_67;
  }

  // ModExprList end
  if (!expr_ret_56) rew(mod_56);
  expr_ret_55 = expr_ret_56 ? SUCC : NULL;
  if (!rule) rule = expr_ret_55;
  if (!expr_ret_55) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_68

  daisho_astnode_t* expr_ret_69 = NULL;
  daisho_astnode_t* expr_ret_68 = NULL;
  daisho_astnode_t* expr_ret_70 = NULL;
  rec(mod_70);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_71 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_71 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_71->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_71->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_71 = NULL;
    }

    expr_ret_70 = expr_ret_71;
    tt = expr_ret_71;
  }

  // ModExprList 2
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_72 = NULL;
    expr_ret_72 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_72)
      expr_ret_72 = SUCC;
    expr_ret_70 = expr_ret_72;
  }

  // ModExprList 3
  if (expr_ret_70)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_73 = NULL;
    expr_ret_73 = daisho_parse_type(ctx);
    expr_ret_70 = expr_ret_73;
    ft = expr_ret_73;
  }

  // ModExprList 5
  if (expr_ret_70)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_74 = NULL;
    // CodeExpr
    #define ret expr_ret_74
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_70 = expr_ret_74;
    members = expr_ret_74;
  }

  // ModExprList 7
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_75 = NULL;
    expr_ret_75 = SUCC;
    while (expr_ret_75)
    {
      daisho_astnode_t* expr_ret_76 = NULL;
      rec(mod_76);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_77 = NULL;
        expr_ret_77 = daisho_parse_fnmember(ctx);
        expr_ret_76 = expr_ret_77;
        m = expr_ret_77;
      }

      // ModExprList 1
      if (expr_ret_76)
      {
        // CodeExpr
        #define ret expr_ret_76
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_76) rew(mod_76);
      expr_ret_75 = expr_ret_76 ? SUCC : NULL;
    }

    expr_ret_75 = SUCC;
    expr_ret_70 = expr_ret_75;
  }

  // ModExprList 8
  if (expr_ret_70)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_70) rew(mod_70);
  expr_ret_69 = expr_ret_70 ? SUCC : NULL;
  if (!rule) rule = expr_ret_69;
  if (!expr_ret_69) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_78

  daisho_astnode_t* expr_ret_79 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  daisho_astnode_t* expr_ret_80 = NULL;
  rec(mod_80);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_81 = NULL;
    expr_ret_81 = daisho_parse_type(ctx);
    expr_ret_80 = expr_ret_81;
    t = expr_ret_81;
  }

  // ModExprList 1
  if (expr_ret_80)
  {
    daisho_astnode_t* expr_ret_82 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_82 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_82->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_82->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

    expr_ret_80 = expr_ret_82;
    v = expr_ret_82;
  }

  // ModExprList 2
  if (expr_ret_80)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_80 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_80 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_80)
  {
    // CodeExpr
    #define ret expr_ret_80
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_80) rew(mod_80);
  expr_ret_79 = expr_ret_80 ? SUCC : NULL;
  if (!rule) rule = expr_ret_79;
  if (!expr_ret_79) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_83

  daisho_astnode_t* expr_ret_84 = NULL;
  daisho_astnode_t* expr_ret_83 = NULL;
  daisho_astnode_t* expr_ret_85 = NULL;
  rec(mod_85);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_86 = NULL;
    daisho_astnode_t* expr_ret_87 = NULL;

    rec(slash_87);

    // SlashExpr 0
    if (!expr_ret_87)
    {
      daisho_astnode_t* expr_ret_88 = NULL;
      rec(mod_88);
      // ModExprList Forwarding
      expr_ret_88 = daisho_parse_fndecl(ctx);
      // ModExprList end
      if (!expr_ret_88) rew(mod_88);
      expr_ret_87 = expr_ret_88;
    }

    // SlashExpr 1
    if (!expr_ret_87)
    {
      daisho_astnode_t* expr_ret_89 = NULL;
      rec(mod_89);
      // ModExprList Forwarding
      expr_ret_89 = daisho_parse_cfndecl(ctx);
      // ModExprList end
      if (!expr_ret_89) rew(mod_89);
      expr_ret_87 = expr_ret_89;
    }

    // SlashExpr 2
    if (!expr_ret_87)
    {
      daisho_astnode_t* expr_ret_90 = NULL;
      rec(mod_90);
      // ModExprList Forwarding
      expr_ret_90 = daisho_parse_fnproto(ctx);
      // ModExprList end
      if (!expr_ret_90) rew(mod_90);
      expr_ret_87 = expr_ret_90;
    }

    // SlashExpr end
    if (!expr_ret_87) rew(slash_87);
    expr_ret_86 = expr_ret_87;

    expr_ret_85 = expr_ret_86;
    r = expr_ret_86;
  }

  // ModExprList 1
  if (expr_ret_85)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_85)
  {
    // CodeExpr
    #define ret expr_ret_85
    ret = SUCC;

    rule=r;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_85) rew(mod_85);
  expr_ret_84 = expr_ret_85 ? SUCC : NULL;
  if (!rule) rule = expr_ret_84;
  if (!expr_ret_84) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_91

  daisho_astnode_t* expr_ret_92 = NULL;
  daisho_astnode_t* expr_ret_91 = NULL;
  daisho_astnode_t* expr_ret_93 = NULL;
  rec(mod_93);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      // Not capturing CTYPE.
      expr_ret_93 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_93 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_93)
  {
    daisho_astnode_t* expr_ret_94 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_94 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_94->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_94->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_94 = NULL;
    }

    expr_ret_93 = expr_ret_94;
    t = expr_ret_94;
  }

  // ModExprList 2
  if (expr_ret_93)
  {
    daisho_astnode_t* expr_ret_95 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Capturing CIDENT.
      expr_ret_95 = leaf(CIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_95->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_95->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

    expr_ret_93 = expr_ret_95;
    c = expr_ret_95;
  }

  // ModExprList 3
  if (expr_ret_93)
  {
    // CodeExpr
    #define ret expr_ret_93
    ret = SUCC;

    rule=srepr(node(CTYPEDECL, t, c), "ctypedecl");

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_93) rew(mod_93);
  expr_ret_92 = expr_ret_93 ? SUCC : NULL;
  if (!rule) rule = expr_ret_92;
  if (!expr_ret_92) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_aliasdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_96

  daisho_astnode_t* expr_ret_97 = NULL;
  daisho_astnode_t* expr_ret_96 = NULL;
  daisho_astnode_t* expr_ret_98 = NULL;
  rec(mod_98);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALIAS) {
      // Not capturing ALIAS.
      expr_ret_98 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_98 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_98)
  {
    daisho_astnode_t* expr_ret_99 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_99 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_99->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_99->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_99 = NULL;
    }

    expr_ret_98 = expr_ret_99;
    t = expr_ret_99;
  }

  // ModExprList 2
  if (expr_ret_98)
  {
    daisho_astnode_t* expr_ret_100 = NULL;
    expr_ret_100 = daisho_parse_type(ctx);
    expr_ret_98 = expr_ret_100;
    f = expr_ret_100;
  }

  // ModExprList 3
  if (expr_ret_98)
  {
    // CodeExpr
    #define ret expr_ret_98
    ret = SUCC;

    rule=srepr(node(ALIASDECL, t, f), "aliasdecl");

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_98) rew(mod_98);
  expr_ret_97 = expr_ret_98 ? SUCC : NULL;
  if (!rule) rule = expr_ret_97;
  if (!expr_ret_97) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rt = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_101

  daisho_astnode_t* expr_ret_102 = NULL;
  daisho_astnode_t* expr_ret_101 = NULL;
  daisho_astnode_t* expr_ret_103 = NULL;
  rec(mod_103);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Not capturing FN.
      expr_ret_103 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_103 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_103)
  {
    daisho_astnode_t* expr_ret_104 = NULL;
    expr_ret_104 = daisho_parse_type(ctx);
    expr_ret_103 = expr_ret_104;
    rt = expr_ret_104;
  }

  // ModExprList 2
  if (expr_ret_103)
  {
    daisho_astnode_t* expr_ret_105 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_105 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_105->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_105->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_105 = NULL;
    }

    expr_ret_103 = expr_ret_105;
    t = expr_ret_105;
  }

  // ModExprList 3
  if (expr_ret_103)
  {
    daisho_astnode_t* expr_ret_106 = NULL;
    expr_ret_106 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_106)
      expr_ret_106 = SUCC;
    expr_ret_103 = expr_ret_106;
    t = expr_ret_106;
  }

  // ModExprList 4
  if (expr_ret_103)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_103 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_103 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_103)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_103 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_103 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_103)
  {
    daisho_astnode_t* expr_ret_107 = NULL;
    expr_ret_107 = daisho_parse_expr(ctx);
    expr_ret_103 = expr_ret_107;
    e = expr_ret_107;
  }

  // ModExprList 7
  if (expr_ret_103)
  {
    // CodeExpr
    #define ret expr_ret_103
    ret = SUCC;

    rule=srepr(node(FNDECL, rt, t, e), "fndecl");

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_103) rew(mod_103);
  expr_ret_102 = expr_ret_103 ? SUCC : NULL;
  if (!rule) rule = expr_ret_102;
  if (!expr_ret_102) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rt = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_108

  daisho_astnode_t* expr_ret_109 = NULL;
  daisho_astnode_t* expr_ret_108 = NULL;
  daisho_astnode_t* expr_ret_110 = NULL;
  rec(mod_110);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
      // Not capturing CFN.
      expr_ret_110 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_110 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_110)
  {
    daisho_astnode_t* expr_ret_111 = NULL;
    expr_ret_111 = daisho_parse_type(ctx);
    expr_ret_110 = expr_ret_111;
    rt = expr_ret_111;
  }

  // ModExprList 2
  if (expr_ret_110)
  {
    daisho_astnode_t* expr_ret_112 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_112 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_112->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_112->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_112 = NULL;
    }

    expr_ret_110 = expr_ret_112;
    t = expr_ret_112;
  }

  // ModExprList 3
  if (expr_ret_110)
  {
    daisho_astnode_t* expr_ret_113 = NULL;
    expr_ret_113 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_113)
      expr_ret_113 = SUCC;
    expr_ret_110 = expr_ret_113;
    t = expr_ret_113;
  }

  // ModExprList 4
  if (expr_ret_110)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_110 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_110 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_110)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_110 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_110 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_110)
  {
    daisho_astnode_t* expr_ret_114 = NULL;
    expr_ret_114 = daisho_parse_expr(ctx);
    expr_ret_110 = expr_ret_114;
    e = expr_ret_114;
  }

  // ModExprList 7
  if (expr_ret_110)
  {
    // CodeExpr
    #define ret expr_ret_110
    ret = SUCC;

    rule=srepr(node(CFNDECL, rt, t, e), "cfndecl");

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_110) rew(mod_110);
  expr_ret_109 = expr_ret_110 ? SUCC : NULL;
  if (!rule) rule = expr_ret_109;
  if (!expr_ret_109) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_115

  daisho_astnode_t* expr_ret_116 = NULL;
  daisho_astnode_t* expr_ret_115 = NULL;
  daisho_astnode_t* expr_ret_117 = NULL;
  rec(mod_117);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_117 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_117 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_117)
  {
    daisho_astnode_t* expr_ret_118 = NULL;
    // CodeExpr
    #define ret expr_ret_118
    ret = SUCC;

    rule=ret=list(TMPLDECL);

    #undef ret
    expr_ret_117 = expr_ret_118;
    l = expr_ret_118;
  }

  // ModExprList 2
  if (expr_ret_117)
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    expr_ret_119 = daisho_parse_tmpldeclmember(ctx);
    // optional
    if (!expr_ret_119)
      expr_ret_119 = SUCC;
    expr_ret_117 = expr_ret_119;
    m = expr_ret_119;
  }

  // ModExprList 3
  if (expr_ret_117)
  {
    // CodeExpr
    #define ret expr_ret_117
    ret = SUCC;

    if (has(m)) add(l, m);

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_117)
  {
    daisho_astnode_t* expr_ret_120 = NULL;
    expr_ret_120 = SUCC;
    while (expr_ret_120)
    {
      daisho_astnode_t* expr_ret_121 = NULL;
      rec(mod_121);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_121 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_121 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_121)
      {
        daisho_astnode_t* expr_ret_122 = NULL;
        expr_ret_122 = daisho_parse_tmpldeclmember(ctx);
        expr_ret_121 = expr_ret_122;
        m = expr_ret_122;
      }

      // ModExprList 2
      if (expr_ret_121)
      {
        // CodeExpr
        #define ret expr_ret_121
        ret = SUCC;

        add(l, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_121) rew(mod_121);
      expr_ret_120 = expr_ret_121 ? SUCC : NULL;
    }

    expr_ret_120 = SUCC;
    expr_ret_117 = expr_ret_120;
  }

  // ModExprList 5
  if (expr_ret_117)
  {
    daisho_astnode_t* expr_ret_123 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_123 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_123 = NULL;
    }

    // optional
    if (!expr_ret_123)
      expr_ret_123 = SUCC;
    expr_ret_117 = expr_ret_123;
  }

  // ModExprList 6
  if (expr_ret_117)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_117 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_117 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_117) rew(mod_117);
  expr_ret_116 = expr_ret_117 ? SUCC : NULL;
  if (!rule) rule = expr_ret_116;
  if (!expr_ret_116) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldeclmember(daisho_parser_ctx* ctx) {
  #define rule expr_ret_124

  daisho_astnode_t* expr_ret_125 = NULL;
  daisho_astnode_t* expr_ret_124 = NULL;
  daisho_astnode_t* expr_ret_126 = NULL;
  rec(mod_126);
  // ModExprList 0
  {
    expr_ret_126 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_126)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_126 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_126 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_126)
  {
    daisho_astnode_t* expr_ret_127 = NULL;
    daisho_astnode_t* expr_ret_128 = NULL;
    rec(mod_128);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
        // Not capturing EQ.
        expr_ret_128 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_128 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_128)
    {
      expr_ret_128 = daisho_parse_type(ctx);
    }

    // ModExprList end
    if (!expr_ret_128) rew(mod_128);
    expr_ret_127 = expr_ret_128 ? SUCC : NULL;
    // optional
    if (!expr_ret_127)
      expr_ret_127 = SUCC;
    expr_ret_126 = expr_ret_127;
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

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_129

  daisho_astnode_t* expr_ret_130 = NULL;
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_131 = NULL;
  rec(mod_131);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_131 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_131 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_131)
  {
    daisho_astnode_t* expr_ret_132 = NULL;
    // CodeExpr
    #define ret expr_ret_132
    ret = SUCC;

    rule=ret=list(TMPLEXPANDLIST);

    #undef ret
    expr_ret_131 = expr_ret_132;
    l = expr_ret_132;
  }

  // ModExprList 2
  if (expr_ret_131)
  {
    daisho_astnode_t* expr_ret_133 = NULL;
    expr_ret_133 = daisho_parse_tmplex(ctx);
    // optional
    if (!expr_ret_133)
      expr_ret_133 = SUCC;
    expr_ret_131 = expr_ret_133;
    m = expr_ret_133;
  }

  // ModExprList 3
  if (expr_ret_131)
  {
    // CodeExpr
    #define ret expr_ret_131
    ret = SUCC;

    if (has(m)) add(l, m);

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_131)
  {
    daisho_astnode_t* expr_ret_134 = NULL;
    expr_ret_134 = SUCC;
    while (expr_ret_134)
    {
      daisho_astnode_t* expr_ret_135 = NULL;
      rec(mod_135);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_135 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_135 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_135)
      {
        daisho_astnode_t* expr_ret_136 = NULL;
        expr_ret_136 = daisho_parse_tmplex(ctx);
        expr_ret_135 = expr_ret_136;
        m = expr_ret_136;
      }

      // ModExprList 2
      if (expr_ret_135)
      {
        // CodeExpr
        #define ret expr_ret_135
        ret = SUCC;

        add(l, m);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_135) rew(mod_135);
      expr_ret_134 = expr_ret_135 ? SUCC : NULL;
    }

    expr_ret_134 = SUCC;
    expr_ret_131 = expr_ret_134;
  }

  // ModExprList 5
  if (expr_ret_131)
  {
    daisho_astnode_t* expr_ret_137 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_137 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_137 = NULL;
    }

    // optional
    if (!expr_ret_137)
      expr_ret_137 = SUCC;
    expr_ret_131 = expr_ret_137;
  }

  // ModExprList 6
  if (expr_ret_131)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_131 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_131 = NULL;
    }

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

static inline daisho_astnode_t* daisho_parse_tmplex(daisho_parser_ctx* ctx) {
  #define rule expr_ret_138

  daisho_astnode_t* expr_ret_139 = NULL;
  daisho_astnode_t* expr_ret_138 = NULL;
  daisho_astnode_t* expr_ret_140 = NULL;

  rec(slash_140);

  // SlashExpr 0
  if (!expr_ret_140)
  {
    daisho_astnode_t* expr_ret_141 = NULL;
    rec(mod_141);
    // ModExprList Forwarding
    expr_ret_141 = daisho_parse_type(ctx);
    // ModExprList end
    if (!expr_ret_141) rew(mod_141);
    expr_ret_140 = expr_ret_141;
  }

  // SlashExpr 1
  if (!expr_ret_140)
  {
    daisho_astnode_t* expr_ret_142 = NULL;
    rec(mod_142);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_142 = leaf(NUMLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_142->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_142->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_142 = NULL;
    }

    // ModExprList end
    if (!expr_ret_142) rew(mod_142);
    expr_ret_140 = expr_ret_142;
  }

  // SlashExpr end
  if (!expr_ret_140) rew(slash_140);
  expr_ret_139 = expr_ret_140;

  if (!rule) rule = expr_ret_139;
  if (!expr_ret_139) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  uint8_t depth = 0;

  daisho_astnode_t* v = NULL;
  daisho_astnode_t* p = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_143

  daisho_astnode_t* expr_ret_144 = NULL;
  daisho_astnode_t* expr_ret_143 = NULL;
  daisho_astnode_t* expr_ret_145 = NULL;

  rec(slash_145);

  // SlashExpr 0
  if (!expr_ret_145)
  {
    daisho_astnode_t* expr_ret_146 = NULL;
    rec(mod_146);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_147 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_147 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_147->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_147->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_147 = NULL;
      }

      expr_ret_146 = expr_ret_147;
      v = expr_ret_147;
    }

    // ModExprList 1
    if (expr_ret_146)
    {
      daisho_astnode_t* expr_ret_148 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_148 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_148 = NULL;
      }

      // invert
      expr_ret_148 = expr_ret_148 ? NULL : SUCC;
      expr_ret_146 = expr_ret_148;
    }

    // ModExprList 2
    if (expr_ret_146)
    {
      // CodeExpr
      #define ret expr_ret_146
      ret = SUCC;

      rule=set_depth(v, 0);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_146) rew(mod_146);
    expr_ret_145 = expr_ret_146 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_145)
  {
    daisho_astnode_t* expr_ret_149 = NULL;
    rec(mod_149);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_150 = NULL;
      expr_ret_150 = daisho_parse_voidptr(ctx);
      expr_ret_149 = expr_ret_150;
      p = expr_ret_150;
    }

    // ModExprList 1
    if (expr_ret_149)
    {
      daisho_astnode_t* expr_ret_151 = NULL;
      expr_ret_151 = SUCC;
      while (expr_ret_151)
      {
        daisho_astnode_t* expr_ret_152 = NULL;
        rec(mod_152);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_152 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_152 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_152)
        {
          // CodeExpr
          #define ret expr_ret_152
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_152) rew(mod_152);
        expr_ret_151 = expr_ret_152 ? SUCC : NULL;
      }

      expr_ret_151 = SUCC;
      expr_ret_149 = expr_ret_151;
    }

    // ModExprList 2
    if (expr_ret_149)
    {
      // CodeExpr
      #define ret expr_ret_149
      ret = SUCC;

      rule=set_depth(p, depth);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_149) rew(mod_149);
    expr_ret_145 = expr_ret_149 ? SUCC : NULL;
  }

  // SlashExpr 2
  if (!expr_ret_145)
  {
    daisho_astnode_t* expr_ret_153 = NULL;
    rec(mod_153);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_154 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
        // Capturing SELFTYPE.
        expr_ret_154 = leaf(SELFTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_154->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_154->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_154 = NULL;
      }

      expr_ret_153 = expr_ret_154;
      s = expr_ret_154;
    }

    // ModExprList 1
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
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_156 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_156 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_156)
        {
          // CodeExpr
          #define ret expr_ret_156
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_156) rew(mod_156);
        expr_ret_155 = expr_ret_156 ? SUCC : NULL;
      }

      expr_ret_155 = SUCC;
      expr_ret_153 = expr_ret_155;
    }

    // ModExprList 2
    if (expr_ret_153)
    {
      // CodeExpr
      #define ret expr_ret_153
      ret = SUCC;

      rule=set_depth(s, depth);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_153) rew(mod_153);
    expr_ret_145 = expr_ret_153 ? SUCC : NULL;
  }

  // SlashExpr 3
  if (!expr_ret_145)
  {
    daisho_astnode_t* expr_ret_157 = NULL;
    rec(mod_157);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_158 = NULL;
      expr_ret_158 = daisho_parse_fntype(ctx);
      expr_ret_157 = expr_ret_158;
      f = expr_ret_158;
    }

    // ModExprList 1
    if (expr_ret_157)
    {
      daisho_astnode_t* expr_ret_159 = NULL;
      expr_ret_159 = SUCC;
      while (expr_ret_159)
      {
        daisho_astnode_t* expr_ret_160 = NULL;
        rec(mod_160);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_160 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_160 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_160)
        {
          // CodeExpr
          #define ret expr_ret_160
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_160) rew(mod_160);
        expr_ret_159 = expr_ret_160 ? SUCC : NULL;
      }

      expr_ret_159 = SUCC;
      expr_ret_157 = expr_ret_159;
    }

    // ModExprList 2
    if (expr_ret_157)
    {
      // CodeExpr
      #define ret expr_ret_157
      ret = SUCC;

      rule=set_depth(f, depth);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_157) rew(mod_157);
    expr_ret_145 = expr_ret_157 ? SUCC : NULL;
  }

  // SlashExpr 4
  if (!expr_ret_145)
  {
    daisho_astnode_t* expr_ret_161 = NULL;
    rec(mod_161);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_162 = NULL;
      expr_ret_162 = daisho_parse_ttexpand(ctx);
      expr_ret_161 = expr_ret_162;
      t = expr_ret_162;
    }

    // ModExprList 1
    if (expr_ret_161)
    {
      daisho_astnode_t* expr_ret_163 = NULL;
      expr_ret_163 = SUCC;
      while (expr_ret_163)
      {
        daisho_astnode_t* expr_ret_164 = NULL;
        rec(mod_164);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_164 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_164 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_164)
        {
          // CodeExpr
          #define ret expr_ret_164
          ret = SUCC;

          depth++;

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_164) rew(mod_164);
        expr_ret_163 = expr_ret_164 ? SUCC : NULL;
      }

      expr_ret_163 = SUCC;
      expr_ret_161 = expr_ret_163;
    }

    // ModExprList 2
    if (expr_ret_161)
    {
      // CodeExpr
      #define ret expr_ret_161
      ret = SUCC;

      rule=set_depth(t, depth);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_161) rew(mod_161);
    expr_ret_145 = expr_ret_161 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_145) rew(slash_145);
  expr_ret_144 = expr_ret_145;

  if (!rule) rule = expr_ret_144;
  if (!expr_ret_144) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_165

  daisho_astnode_t* expr_ret_166 = NULL;
  daisho_astnode_t* expr_ret_165 = NULL;
  daisho_astnode_t* expr_ret_167 = NULL;

  rec(slash_167);

  // SlashExpr 0
  if (!expr_ret_167)
  {
    daisho_astnode_t* expr_ret_168 = NULL;
    rec(mod_168);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_169 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
        // Capturing VOIDPTR.
        expr_ret_169 = leaf(VOIDPTR);
        #if DAISHO_SOURCEINFO
        expr_ret_169->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_169->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_169 = NULL;
      }

      expr_ret_168 = expr_ret_169;
      v = expr_ret_169;
    }

    // ModExprList 1
    if (expr_ret_168)
    {
      // CodeExpr
      #define ret expr_ret_168
      ret = SUCC;

      rule=v;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_168) rew(mod_168);
    expr_ret_167 = expr_ret_168 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_167)
  {
    daisho_astnode_t* expr_ret_170 = NULL;
    rec(mod_170);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_171 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_171 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_171->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_171->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_171 = NULL;
      }

      expr_ret_170 = expr_ret_171;
      v = expr_ret_171;
    }

    // ModExprList 1
    if (expr_ret_170)
    {
      daisho_astnode_t* expr_ret_172 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_172 = leaf(STAR);
        #if DAISHO_SOURCEINFO
        expr_ret_172->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_172->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_172 = NULL;
      }

      expr_ret_170 = expr_ret_172;
      s = expr_ret_172;
    }

    // ModExprList 2
    if (expr_ret_170)
    {
      // CodeExpr
      #define ret expr_ret_170
      ret = SUCC;

      rule=srepr(leaf(VOIDPTR), "VoidPtr");

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_170) rew(mod_170);
    expr_ret_167 = expr_ret_170 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_167) rew(slash_167);
  expr_ret_166 = expr_ret_167;

  if (!rule) rule = expr_ret_166;
  if (!expr_ret_166) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ttexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_173

  daisho_astnode_t* expr_ret_174 = NULL;
  daisho_astnode_t* expr_ret_173 = NULL;
  daisho_astnode_t* expr_ret_175 = NULL;
  rec(mod_175);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_176 = NULL;
    daisho_astnode_t* expr_ret_177 = NULL;

    rec(slash_177);

    // SlashExpr 0
    if (!expr_ret_177)
    {
      daisho_astnode_t* expr_ret_178 = NULL;
      rec(mod_178);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_178 = leaf(TYPEIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_178->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_178->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_178 = NULL;
      }

      // ModExprList end
      if (!expr_ret_178) rew(mod_178);
      expr_ret_177 = expr_ret_178;
    }

    // SlashExpr 1
    if (!expr_ret_177)
    {
      daisho_astnode_t* expr_ret_179 = NULL;
      rec(mod_179);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAITIDENT) {
        // Capturing TRAITIDENT.
        expr_ret_179 = leaf(TRAITIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_179->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_179->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_179 = NULL;
      }

      // ModExprList end
      if (!expr_ret_179) rew(mod_179);
      expr_ret_177 = expr_ret_179;
    }

    // SlashExpr end
    if (!expr_ret_177) rew(slash_177);
    expr_ret_176 = expr_ret_177;

    expr_ret_175 = expr_ret_176;
    i = expr_ret_176;
  }

  // ModExprList 1
  if (expr_ret_175)
  {
    daisho_astnode_t* expr_ret_180 = NULL;
    expr_ret_180 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_180)
      expr_ret_180 = SUCC;
    expr_ret_175 = expr_ret_180;
    t = expr_ret_180;
  }

  // ModExprList 2
  if (expr_ret_175)
  {
    // CodeExpr
    #define ret expr_ret_175
    ret = SUCC;

    rule = has(t) ? node(TMPLTYPE, t, i) : i;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_175) rew(mod_175);
  expr_ret_174 = expr_ret_175 ? SUCC : NULL;
  if (!rule) rule = expr_ret_174;
  if (!expr_ret_174) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* l = NULL;
  #define rule expr_ret_181

  daisho_astnode_t* expr_ret_182 = NULL;
  daisho_astnode_t* expr_ret_181 = NULL;
  daisho_astnode_t* expr_ret_183 = NULL;

  rec(slash_183);

  // SlashExpr 0
  if (!expr_ret_183)
  {
    daisho_astnode_t* expr_ret_184 = NULL;
    rec(mod_184);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_184 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_184 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_184)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        // Not capturing LT.
        expr_ret_184 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_184 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_184)
    {
      daisho_astnode_t* expr_ret_185 = NULL;
      // CodeExpr
      #define ret expr_ret_185
      ret = SUCC;

      ret=list(ARGLIST);

      #undef ret
      expr_ret_184 = expr_ret_185;
      argtypes = expr_ret_185;
    }

    // ModExprList 3
    if (expr_ret_184)
    {
      daisho_astnode_t* expr_ret_186 = NULL;
      daisho_astnode_t* expr_ret_187 = NULL;
      rec(mod_187);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_188 = NULL;
        expr_ret_188 = daisho_parse_type(ctx);
        expr_ret_187 = expr_ret_188;
        t = expr_ret_188;
      }

      // ModExprList 1
      if (expr_ret_187)
      {
        // CodeExpr
        #define ret expr_ret_187
        ret = SUCC;

        add(argtypes, t);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_187) rew(mod_187);
      expr_ret_186 = expr_ret_187 ? SUCC : NULL;
      // optional
      if (!expr_ret_186)
        expr_ret_186 = SUCC;
      expr_ret_184 = expr_ret_186;
    }

    // ModExprList 4
    if (expr_ret_184)
    {
      daisho_astnode_t* expr_ret_189 = NULL;
      expr_ret_189 = SUCC;
      while (expr_ret_189)
      {
        daisho_astnode_t* expr_ret_190 = NULL;
        rec(mod_190);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_190 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_190 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_190)
        {
          daisho_astnode_t* expr_ret_191 = NULL;
          expr_ret_191 = daisho_parse_type(ctx);
          expr_ret_190 = expr_ret_191;
          t = expr_ret_191;
        }

        // ModExprList 2
        if (expr_ret_190)
        {
          // CodeExpr
          #define ret expr_ret_190
          ret = SUCC;

          add(argtypes, t);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_190) rew(mod_190);
        expr_ret_189 = expr_ret_190 ? SUCC : NULL;
      }

      expr_ret_189 = SUCC;
      expr_ret_184 = expr_ret_189;
    }

    // ModExprList 5
    if (expr_ret_184)
    {
      // CodeExpr
      #define ret expr_ret_184
      ret = SUCC;

      if (!argtypes->num_children) add(argtypes, leaf(VOIDTYPE));

      #undef ret
    }

    // ModExprList 6
    if (expr_ret_184)
    {
      daisho_astnode_t* expr_ret_192 = NULL;
      daisho_astnode_t* expr_ret_193 = NULL;
      rec(mod_193);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_194 = NULL;

        rec(slash_194);

        // SlashExpr 0
        if (!expr_ret_194)
        {
          daisho_astnode_t* expr_ret_195 = NULL;
          rec(mod_195);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DARROW) {
            // Not capturing DARROW.
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
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_196 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_196 = NULL;
          }

          // ModExprList end
          if (!expr_ret_196) rew(mod_196);
          expr_ret_194 = expr_ret_196;
        }

        // SlashExpr 2
        if (!expr_ret_194)
        {
          daisho_astnode_t* expr_ret_197 = NULL;
          rec(mod_197);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
              // Not capturing EQ.
              expr_ret_197 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_197 = NULL;
            }

          }

          // ModExprList 1
          if (expr_ret_197)
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
              // Not capturing GT.
              expr_ret_197 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_197 = NULL;
            }

          }

          // ModExprList end
          if (!expr_ret_197) rew(mod_197);
          expr_ret_194 = expr_ret_197 ? SUCC : NULL;
        }

        // SlashExpr end
        if (!expr_ret_194) rew(slash_194);
        expr_ret_193 = expr_ret_194;

      }

      // ModExprList 1
      if (expr_ret_193)
      {
        daisho_astnode_t* expr_ret_198 = NULL;
        expr_ret_198 = daisho_parse_type(ctx);
        expr_ret_193 = expr_ret_198;
        rettype = expr_ret_198;
      }

      // ModExprList end
      if (!expr_ret_193) rew(mod_193);
      expr_ret_192 = expr_ret_193 ? SUCC : NULL;
      // optional
      if (!expr_ret_192)
        expr_ret_192 = SUCC;
      expr_ret_184 = expr_ret_192;
    }

    // ModExprList 7
    if (expr_ret_184)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Not capturing GT.
        expr_ret_184 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_184 = NULL;
      }

    }

    // ModExprList 8
    if (expr_ret_184)
    {
      // CodeExpr
      #define ret expr_ret_184
      ret = SUCC;

      rule=node(FNTYPE, argtypes, !has(rettype) ? leaf(VOIDTYPE) : rettype);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_184) rew(mod_184);
    expr_ret_183 = expr_ret_184 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_183)
  {
    daisho_astnode_t* expr_ret_199 = NULL;
    rec(mod_199);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_199 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_199 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_199)
    {
      daisho_astnode_t* expr_ret_200 = NULL;
      // CodeExpr
      #define ret expr_ret_200
      ret = SUCC;

      ret=list(ARGLIST);add(ret, leaf(VOIDTYPE));;

      #undef ret
      expr_ret_199 = expr_ret_200;
      l = expr_ret_200;
    }

    // ModExprList 2
    if (expr_ret_199)
    {
      // CodeExpr
      #define ret expr_ret_199
      ret = SUCC;

      rule=node(FNTYPE, l, leaf(VOIDTYPE));

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_199) rew(mod_199);
    expr_ret_183 = expr_ret_199 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_183) rew(slash_183);
  expr_ret_182 = expr_ret_183;

  if (!rule) rule = expr_ret_182;
  if (!expr_ret_182) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  #define rule expr_ret_201

  daisho_astnode_t* expr_ret_202 = NULL;
  daisho_astnode_t* expr_ret_201 = NULL;
  daisho_astnode_t* expr_ret_203 = NULL;
  rec(mod_203);
  // ModExprList 0
  {
    expr_ret_203 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_203)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_203 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_203 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_203)
  {
    daisho_astnode_t* expr_ret_204 = NULL;
    expr_ret_204 = daisho_parse_fnarg(ctx);
    // optional
    if (!expr_ret_204)
      expr_ret_204 = SUCC;
    expr_ret_203 = expr_ret_204;
  }

  // ModExprList 3
  if (expr_ret_203)
  {
    daisho_astnode_t* expr_ret_205 = NULL;
    expr_ret_205 = SUCC;
    while (expr_ret_205)
    {
      daisho_astnode_t* expr_ret_206 = NULL;
      rec(mod_206);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_206 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_206 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_206)
      {
        expr_ret_206 = daisho_parse_fnarg(ctx);
      }

      // ModExprList end
      if (!expr_ret_206) rew(mod_206);
      expr_ret_205 = expr_ret_206 ? SUCC : NULL;
    }

    expr_ret_205 = SUCC;
    expr_ret_203 = expr_ret_205;
  }

  // ModExprList 4
  if (expr_ret_203)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_203 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_203 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_203) rew(mod_203);
  expr_ret_202 = expr_ret_203 ? SUCC : NULL;
  if (!rule) rule = expr_ret_202;
  if (!expr_ret_202) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  #define rule expr_ret_207

  daisho_astnode_t* expr_ret_208 = NULL;
  daisho_astnode_t* expr_ret_207 = NULL;
  daisho_astnode_t* expr_ret_209 = NULL;
  rec(mod_209);
  // ModExprList 0
  {
    expr_ret_209 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_209)
  {
    daisho_astnode_t* expr_ret_210 = NULL;
    daisho_astnode_t* expr_ret_211 = NULL;
    rec(mod_211);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_211 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_211 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_211)
    {
      daisho_astnode_t* expr_ret_212 = NULL;
      expr_ret_212 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_212)
        expr_ret_212 = SUCC;
      expr_ret_211 = expr_ret_212;
    }

    // ModExprList end
    if (!expr_ret_211) rew(mod_211);
    expr_ret_210 = expr_ret_211 ? SUCC : NULL;
    // optional
    if (!expr_ret_210)
      expr_ret_210 = SUCC;
    expr_ret_209 = expr_ret_210;
  }

  // ModExprList end
  if (!expr_ret_209) rew(mod_209);
  expr_ret_208 = expr_ret_209 ? SUCC : NULL;
  if (!rule) rule = expr_ret_208;
  if (!expr_ret_208) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_213

  daisho_astnode_t* expr_ret_214 = NULL;
  daisho_astnode_t* expr_ret_213 = NULL;
  daisho_astnode_t* expr_ret_215 = NULL;
  rec(mod_215);
  // ModExprList Forwarding
  expr_ret_215 = daisho_parse_ifeexpr(ctx);
  // ModExprList end
  if (!expr_ret_215) rew(mod_215);
  expr_ret_214 = expr_ret_215;
  if (!rule) rule = expr_ret_214;
  if (!expr_ret_214) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ifeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cond = NULL;
  daisho_astnode_t* ex = NULL;
  daisho_astnode_t* eex = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_216

  daisho_astnode_t* expr_ret_217 = NULL;
  daisho_astnode_t* expr_ret_216 = NULL;
  daisho_astnode_t* expr_ret_218 = NULL;

  rec(slash_218);

  // SlashExpr 0
  if (!expr_ret_218)
  {
    daisho_astnode_t* expr_ret_219 = NULL;
    rec(mod_219);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
        // Not capturing IF.
        expr_ret_219 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_219 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_219)
    {
      daisho_astnode_t* expr_ret_220 = NULL;
      expr_ret_220 = daisho_parse_ternexpr(ctx);
      expr_ret_219 = expr_ret_220;
      cond = expr_ret_220;
    }

    // ModExprList 2
    if (expr_ret_219)
    {
      daisho_astnode_t* expr_ret_221 = NULL;
      expr_ret_221 = daisho_parse_expr(ctx);
      expr_ret_219 = expr_ret_221;
      ex = expr_ret_221;
    }

    // ModExprList 3
    if (expr_ret_219)
    {
      daisho_astnode_t* expr_ret_222 = NULL;
      daisho_astnode_t* expr_ret_223 = NULL;
      rec(mod_223);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
          // Not capturing ELSE.
          expr_ret_223 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_223 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_223)
      {
        daisho_astnode_t* expr_ret_224 = NULL;
        expr_ret_224 = daisho_parse_expr(ctx);
        expr_ret_223 = expr_ret_224;
        eex = expr_ret_224;
      }

      // ModExprList end
      if (!expr_ret_223) rew(mod_223);
      expr_ret_222 = expr_ret_223 ? SUCC : NULL;
      // optional
      if (!expr_ret_222)
        expr_ret_222 = SUCC;
      expr_ret_219 = expr_ret_222;
    }

    // ModExprList 4
    if (expr_ret_219)
    {
      // CodeExpr
      #define ret expr_ret_219
      ret = SUCC;

      rule= !has(eex) ? srepr(node(IF, cond, ex), "if") : srepr(node(IFELSE, cond, ex, eex), "if-else");

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_219) rew(mod_219);
    expr_ret_218 = expr_ret_219 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_218)
  {
    daisho_astnode_t* expr_ret_225 = NULL;
    rec(mod_225);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_226 = NULL;
      expr_ret_226 = daisho_parse_forexpr(ctx);
      expr_ret_225 = expr_ret_226;
      n = expr_ret_226;
    }

    // ModExprList 1
    if (expr_ret_225)
    {
      // CodeExpr
      #define ret expr_ret_225
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_225) rew(mod_225);
    expr_ret_218 = expr_ret_225 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_218) rew(slash_218);
  expr_ret_217 = expr_ret_218;

  if (!rule) rule = expr_ret_217;
  if (!expr_ret_217) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* sn = NULL;
  #define rule expr_ret_227

  daisho_astnode_t* expr_ret_228 = NULL;
  daisho_astnode_t* expr_ret_227 = NULL;
  daisho_astnode_t* expr_ret_229 = NULL;

  rec(slash_229);

  // SlashExpr 0
  if (!expr_ret_229)
  {
    daisho_astnode_t* expr_ret_230 = NULL;
    rec(mod_230);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_230 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_230 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_231 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_231 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_231 = NULL;
      }

      // optional
      if (!expr_ret_231)
        expr_ret_231 = SUCC;
      expr_ret_230 = expr_ret_231;
    }

    // ModExprList 2
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_232 = NULL;
      expr_ret_232 = daisho_parse_whileexpr(ctx);
      expr_ret_230 = expr_ret_232;
      n = expr_ret_232;
    }

    // ModExprList 3
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_233 = NULL;

      rec(slash_233);

      // SlashExpr 0
      if (!expr_ret_233)
      {
        daisho_astnode_t* expr_ret_234 = NULL;
        rec(mod_234);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_235 = NULL;

        rec(slash_235);

        // SlashExpr 0
        if (!expr_ret_235)
        {
          daisho_astnode_t* expr_ret_236 = NULL;
          rec(mod_236);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_236 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_236 = NULL;
          }

          // ModExprList end
          if (!expr_ret_236) rew(mod_236);
          expr_ret_235 = expr_ret_236;
        }

        // SlashExpr 1
        if (!expr_ret_235)
        {
          daisho_astnode_t* expr_ret_237 = NULL;
          rec(mod_237);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_237 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_237 = NULL;
          }

          // ModExprList end
          if (!expr_ret_237) rew(mod_237);
          expr_ret_235 = expr_ret_237;
        }

        // SlashExpr end
        if (!expr_ret_235) rew(slash_235);
        expr_ret_234 = expr_ret_235;

        // ModExprList end
        if (!expr_ret_234) rew(mod_234);
        expr_ret_233 = expr_ret_234;
      }

      // SlashExpr 1
      if (!expr_ret_233)
      {
        daisho_astnode_t* expr_ret_238 = NULL;
        rec(mod_238);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_239 = NULL;
        rec(mod_239);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_239 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_239 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_239)
        {
          daisho_astnode_t* expr_ret_240 = NULL;
          expr_ret_240 = daisho_parse_whileexpr(ctx);
          expr_ret_239 = expr_ret_240;
          sn = expr_ret_240;
        }

        // ModExprList 2
        if (expr_ret_239)
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_239 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_239 = NULL;
          }

        }

        // ModExprList end
        if (!expr_ret_239) rew(mod_239);
        expr_ret_238 = expr_ret_239 ? SUCC : NULL;
        // ModExprList end
        if (!expr_ret_238) rew(mod_238);
        expr_ret_233 = expr_ret_238;
      }

      // SlashExpr end
      if (!expr_ret_233) rew(slash_233);
      expr_ret_230 = expr_ret_233;

    }

    // ModExprList 4
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_241 = NULL;
      expr_ret_241 = daisho_parse_whileexpr(ctx);
      expr_ret_230 = expr_ret_241;
      n = expr_ret_241;
    }

    // ModExprList 5
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_242 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_242 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_242 = NULL;
      }

      // optional
      if (!expr_ret_242)
        expr_ret_242 = SUCC;
      expr_ret_230 = expr_ret_242;
    }

    // ModExprList 6
    if (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_243 = NULL;
      expr_ret_243 = daisho_parse_whileexpr(ctx);
      expr_ret_230 = expr_ret_243;
      n = expr_ret_243;
    }

    // ModExprList end
    if (!expr_ret_230) rew(mod_230);
    expr_ret_229 = expr_ret_230 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_229)
  {
    daisho_astnode_t* expr_ret_244 = NULL;
    rec(mod_244);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_245 = NULL;
      expr_ret_245 = daisho_parse_whileexpr(ctx);
      expr_ret_244 = expr_ret_245;
      n = expr_ret_245;
    }

    // ModExprList 1
    if (expr_ret_244)
    {
      // CodeExpr
      #define ret expr_ret_244
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_244) rew(mod_244);
    expr_ret_229 = expr_ret_244 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_229) rew(slash_229);
  expr_ret_228 = expr_ret_229;

  if (!rule) rule = expr_ret_228;
  if (!expr_ret_228) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_246

  daisho_astnode_t* expr_ret_247 = NULL;
  daisho_astnode_t* expr_ret_246 = NULL;
  daisho_astnode_t* expr_ret_248 = NULL;

  rec(slash_248);

  // SlashExpr 0
  if (!expr_ret_248)
  {
    daisho_astnode_t* expr_ret_249 = NULL;
    rec(mod_249);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
        // Not capturing WHILE.
        expr_ret_249 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_249 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_249)
    {
      daisho_astnode_t* expr_ret_250 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_250 = leaf(OPEN);
        #if DAISHO_SOURCEINFO
        expr_ret_250->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_250->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_250 = NULL;
      }

      // optional
      if (!expr_ret_250)
        expr_ret_250 = SUCC;
      expr_ret_249 = expr_ret_250;
      o = expr_ret_250;
    }

    // ModExprList 2
    if (expr_ret_249)
    {
      daisho_astnode_t* expr_ret_251 = NULL;
      expr_ret_251 = daisho_parse_ternexpr(ctx);
      expr_ret_249 = expr_ret_251;
      n = expr_ret_251;
    }

    // ModExprList 3
    if (expr_ret_249)
    {
      daisho_astnode_t* expr_ret_252 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_252 = leaf(CLOSE);
        #if DAISHO_SOURCEINFO
        expr_ret_252->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_252->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_252 = NULL;
      }

      // optional
      if (!expr_ret_252)
        expr_ret_252 = SUCC;
      expr_ret_249 = expr_ret_252;
      c = expr_ret_252;
    }

    // ModExprList 4
    if (expr_ret_249)
    {
      // CodeExpr
      #define ret expr_ret_249
      ret = SUCC;

      ret=o==c?SUCC:NULL;

      #undef ret
    }

    // ModExprList 5
    if (expr_ret_249)
    {
      expr_ret_249 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_249) rew(mod_249);
    expr_ret_248 = expr_ret_249 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_248)
  {
    daisho_astnode_t* expr_ret_253 = NULL;
    rec(mod_253);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_254 = NULL;
      expr_ret_254 = daisho_parse_ternexpr(ctx);
      expr_ret_253 = expr_ret_254;
      n = expr_ret_254;
    }

    // ModExprList 1
    if (expr_ret_253)
    {
      // CodeExpr
      #define ret expr_ret_253
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_253) rew(mod_253);
    expr_ret_248 = expr_ret_253 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_248) rew(slash_248);
  expr_ret_247 = expr_ret_248;

  if (!rule) rule = expr_ret_247;
  if (!expr_ret_247) rule = NULL;
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
  #define rule expr_ret_255

  daisho_astnode_t* expr_ret_256 = NULL;
  daisho_astnode_t* expr_ret_255 = NULL;
  daisho_astnode_t* expr_ret_257 = NULL;
  rec(mod_257);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_258 = NULL;
    expr_ret_258 = daisho_parse_thenexpr(ctx);
    expr_ret_257 = expr_ret_258;
    n = expr_ret_258;
  }

  // ModExprList 1
  if (expr_ret_257)
  {
    daisho_astnode_t* expr_ret_259 = NULL;
    daisho_astnode_t* expr_ret_260 = NULL;
    rec(mod_260);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_261 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
        // Capturing QUEST.
        expr_ret_261 = leaf(QUEST);
        #if DAISHO_SOURCEINFO
        expr_ret_261->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_261->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_261 = NULL;
      }

      expr_ret_260 = expr_ret_261;
      q = expr_ret_261;
    }

    // ModExprList 1
    if (expr_ret_260)
    {
      daisho_astnode_t* expr_ret_262 = NULL;
      expr_ret_262 = daisho_parse_expr(ctx);
      expr_ret_260 = expr_ret_262;
      qe = expr_ret_262;
    }

    // ModExprList 2
    if (expr_ret_260)
    {
      daisho_astnode_t* expr_ret_263 = NULL;
      daisho_astnode_t* expr_ret_264 = NULL;
      rec(mod_264);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_265 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          // Capturing COLON.
          expr_ret_265 = leaf(COLON);
          #if DAISHO_SOURCEINFO
          expr_ret_265->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_265->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_265 = NULL;
        }

        expr_ret_264 = expr_ret_265;
        c = expr_ret_265;
      }

      // ModExprList 1
      if (expr_ret_264)
      {
        daisho_astnode_t* expr_ret_266 = NULL;
        expr_ret_266 = daisho_parse_expr(ctx);
        expr_ret_264 = expr_ret_266;
        ce = expr_ret_266;
      }

      // ModExprList end
      if (!expr_ret_264) rew(mod_264);
      expr_ret_263 = expr_ret_264 ? SUCC : NULL;
      // optional
      if (!expr_ret_263)
        expr_ret_263 = SUCC;
      expr_ret_260 = expr_ret_263;
    }

    // ModExprList end
    if (!expr_ret_260) rew(mod_260);
    expr_ret_259 = expr_ret_260 ? SUCC : NULL;
    // optional
    if (!expr_ret_259)
      expr_ret_259 = SUCC;
    expr_ret_257 = expr_ret_259;
  }

  // ModExprList 2
  if (expr_ret_257)
  {
    // CodeExpr
    #define ret expr_ret_257
    ret = SUCC;

    rule = !has(qe) ? n
                    : !has(ce) ? node(ELVIS, q, n, qe)
                    :            node(TERN, q, c, n, qe, ce);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_257) rew(mod_257);
  expr_ret_256 = expr_ret_257 ? SUCC : NULL;
  if (!rule) rule = expr_ret_256;
  if (!expr_ret_256) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_267

  daisho_astnode_t* expr_ret_268 = NULL;
  daisho_astnode_t* expr_ret_267 = NULL;
  daisho_astnode_t* expr_ret_269 = NULL;
  rec(mod_269);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_270 = NULL;
    expr_ret_270 = daisho_parse_alsoexpr(ctx);
    expr_ret_269 = expr_ret_270;
    n = expr_ret_270;
  }

  // ModExprList 1
  if (expr_ret_269)
  {
    // CodeExpr
    #define ret expr_ret_269
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_269)
  {
    daisho_astnode_t* expr_ret_271 = NULL;
    expr_ret_271 = SUCC;
    while (expr_ret_271)
    {
      daisho_astnode_t* expr_ret_272 = NULL;
      rec(mod_272);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_273 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
          // Capturing THEN.
          expr_ret_273 = leaf(THEN);
          #if DAISHO_SOURCEINFO
          expr_ret_273->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_273->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_273 = NULL;
        }

        expr_ret_272 = expr_ret_273;
        o = expr_ret_273;
      }

      // ModExprList 1
      if (expr_ret_272)
      {
        daisho_astnode_t* expr_ret_274 = NULL;
        expr_ret_274 = daisho_parse_alsoexpr(ctx);
        expr_ret_272 = expr_ret_274;
        nn = expr_ret_274;
      }

      // ModExprList 2
      if (expr_ret_272)
      {
        // CodeExpr
        #define ret expr_ret_272
        ret = SUCC;

        rule=srepr(node(THEN, rule, nn), "then");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_272) rew(mod_272);
      expr_ret_271 = expr_ret_272 ? SUCC : NULL;
    }

    expr_ret_271 = SUCC;
    expr_ret_269 = expr_ret_271;
  }

  // ModExprList end
  if (!expr_ret_269) rew(mod_269);
  expr_ret_268 = expr_ret_269 ? SUCC : NULL;
  if (!rule) rule = expr_ret_268;
  if (!expr_ret_268) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_275

  daisho_astnode_t* expr_ret_276 = NULL;
  daisho_astnode_t* expr_ret_275 = NULL;
  daisho_astnode_t* expr_ret_277 = NULL;
  rec(mod_277);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_278 = NULL;
    expr_ret_278 = daisho_parse_binop(ctx);
    expr_ret_277 = expr_ret_278;
    n = expr_ret_278;
  }

  // ModExprList 1
  if (expr_ret_277)
  {
    // CodeExpr
    #define ret expr_ret_277
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_277)
  {
    daisho_astnode_t* expr_ret_279 = NULL;
    expr_ret_279 = SUCC;
    while (expr_ret_279)
    {
      daisho_astnode_t* expr_ret_280 = NULL;
      rec(mod_280);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_281 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
          // Capturing ALSO.
          expr_ret_281 = leaf(ALSO);
          #if DAISHO_SOURCEINFO
          expr_ret_281->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_281->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_281 = NULL;
        }

        expr_ret_280 = expr_ret_281;
        o = expr_ret_281;
      }

      // ModExprList 1
      if (expr_ret_280)
      {
        daisho_astnode_t* expr_ret_282 = NULL;
        expr_ret_282 = daisho_parse_binop(ctx);
        expr_ret_280 = expr_ret_282;
        nn = expr_ret_282;
      }

      // ModExprList 2
      if (expr_ret_280)
      {
        // CodeExpr
        #define ret expr_ret_280
        ret = SUCC;

        rule=srepr(node(ALSO, rule, nn), "also");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_280) rew(mod_280);
      expr_ret_279 = expr_ret_280 ? SUCC : NULL;
    }

    expr_ret_279 = SUCC;
    expr_ret_277 = expr_ret_279;
  }

  // ModExprList end
  if (!expr_ret_277) rew(mod_277);
  expr_ret_276 = expr_ret_277 ? SUCC : NULL;
  if (!rule) rule = expr_ret_276;
  if (!expr_ret_276) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  #define rule expr_ret_283

  daisho_astnode_t* expr_ret_284 = NULL;
  daisho_astnode_t* expr_ret_283 = NULL;
  daisho_astnode_t* expr_ret_285 = NULL;
  rec(mod_285);
  // ModExprList Forwarding
  expr_ret_285 = daisho_parse_eqexpr(ctx);
  // ModExprList end
  if (!expr_ret_285) rew(mod_285);
  expr_ret_284 = expr_ret_285;
  if (!rule) rule = expr_ret_284;
  if (!expr_ret_284) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_286

  daisho_astnode_t* expr_ret_287 = NULL;
  daisho_astnode_t* expr_ret_286 = NULL;
  daisho_astnode_t* expr_ret_288 = NULL;
  rec(mod_288);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_289 = NULL;
    expr_ret_289 = daisho_parse_logorexpr(ctx);
    expr_ret_288 = expr_ret_289;
    n = expr_ret_289;
  }

  // ModExprList 1
  if (expr_ret_288)
  {
    // CodeExpr
    #define ret expr_ret_288
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_288)
  {
    daisho_astnode_t* expr_ret_290 = NULL;
    expr_ret_290 = SUCC;
    while (expr_ret_290)
    {
      daisho_astnode_t* expr_ret_291 = NULL;
      rec(mod_291);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_292 = NULL;
        daisho_astnode_t* expr_ret_293 = NULL;

        rec(slash_293);

        // SlashExpr 0
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_294 = NULL;
          rec(mod_294);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            // Capturing EQ.
            expr_ret_294 = leaf(EQ);
            #if DAISHO_SOURCEINFO
            expr_ret_294->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_294->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_294 = NULL;
          }

          // ModExprList end
          if (!expr_ret_294) rew(mod_294);
          expr_ret_293 = expr_ret_294;
        }

        // SlashExpr 1
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_295 = NULL;
          rec(mod_295);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            // Capturing PLEQ.
            expr_ret_295 = leaf(PLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_295->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_295->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_295 = NULL;
          }

          // ModExprList end
          if (!expr_ret_295) rew(mod_295);
          expr_ret_293 = expr_ret_295;
        }

        // SlashExpr 2
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_296 = NULL;
          rec(mod_296);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            // Capturing MINEQ.
            expr_ret_296 = leaf(MINEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_296->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_296->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_296 = NULL;
          }

          // ModExprList end
          if (!expr_ret_296) rew(mod_296);
          expr_ret_293 = expr_ret_296;
        }

        // SlashExpr 3
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_297 = NULL;
          rec(mod_297);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            // Capturing MULEQ.
            expr_ret_297 = leaf(MULEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_297->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_297->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_297 = NULL;
          }

          // ModExprList end
          if (!expr_ret_297) rew(mod_297);
          expr_ret_293 = expr_ret_297;
        }

        // SlashExpr 4
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_298 = NULL;
          rec(mod_298);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            // Capturing DIVEQ.
            expr_ret_298 = leaf(DIVEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_298->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_298->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_298 = NULL;
          }

          // ModExprList end
          if (!expr_ret_298) rew(mod_298);
          expr_ret_293 = expr_ret_298;
        }

        // SlashExpr 5
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_299 = NULL;
          rec(mod_299);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            // Capturing MODEQ.
            expr_ret_299 = leaf(MODEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_299->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_299->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_299 = NULL;
          }

          // ModExprList end
          if (!expr_ret_299) rew(mod_299);
          expr_ret_293 = expr_ret_299;
        }

        // SlashExpr 6
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_300 = NULL;
          rec(mod_300);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            // Capturing ANDEQ.
            expr_ret_300 = leaf(ANDEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_300->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_300->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_300 = NULL;
          }

          // ModExprList end
          if (!expr_ret_300) rew(mod_300);
          expr_ret_293 = expr_ret_300;
        }

        // SlashExpr 7
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_301 = NULL;
          rec(mod_301);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            // Capturing OREQ.
            expr_ret_301 = leaf(OREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_301->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_301->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_301 = NULL;
          }

          // ModExprList end
          if (!expr_ret_301) rew(mod_301);
          expr_ret_293 = expr_ret_301;
        }

        // SlashExpr 8
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_302 = NULL;
          rec(mod_302);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            // Capturing XOREQ.
            expr_ret_302 = leaf(XOREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_302->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_302->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_302 = NULL;
          }

          // ModExprList end
          if (!expr_ret_302) rew(mod_302);
          expr_ret_293 = expr_ret_302;
        }

        // SlashExpr 9
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_303 = NULL;
          rec(mod_303);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            // Capturing BNEQ.
            expr_ret_303 = leaf(BNEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_303->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_303->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_303 = NULL;
          }

          // ModExprList end
          if (!expr_ret_303) rew(mod_303);
          expr_ret_293 = expr_ret_303;
        }

        // SlashExpr 10
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_304 = NULL;
          rec(mod_304);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            // Capturing BSREQ.
            expr_ret_304 = leaf(BSREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_304->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_304->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_304 = NULL;
          }

          // ModExprList end
          if (!expr_ret_304) rew(mod_304);
          expr_ret_293 = expr_ret_304;
        }

        // SlashExpr 11
        if (!expr_ret_293)
        {
          daisho_astnode_t* expr_ret_305 = NULL;
          rec(mod_305);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            // Capturing BSLEQ.
            expr_ret_305 = leaf(BSLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_305->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_305->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_305 = NULL;
          }

          // ModExprList end
          if (!expr_ret_305) rew(mod_305);
          expr_ret_293 = expr_ret_305;
        }

        // SlashExpr end
        if (!expr_ret_293) rew(slash_293);
        expr_ret_292 = expr_ret_293;

        expr_ret_291 = expr_ret_292;
        op = expr_ret_292;
      }

      // ModExprList 1
      if (expr_ret_291)
      {
        daisho_astnode_t* expr_ret_306 = NULL;
        expr_ret_306 = daisho_parse_logorexpr(ctx);
        expr_ret_291 = expr_ret_306;
        t = expr_ret_306;
      }

      // ModExprList 2
      if (expr_ret_291)
      {
        // CodeExpr
        #define ret expr_ret_291
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
                  #if defined(__DAI_UNREACHABLE)
                    __DAI_UNREACHABLE()
                  #else
                    assert(!"Unexpected node type.")
                  #endif
              ;

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_291) rew(mod_291);
      expr_ret_290 = expr_ret_291 ? SUCC : NULL;
    }

    expr_ret_290 = SUCC;
    expr_ret_288 = expr_ret_290;
  }

  // ModExprList end
  if (!expr_ret_288) rew(mod_288);
  expr_ret_287 = expr_ret_288 ? SUCC : NULL;
  if (!rule) rule = expr_ret_287;
  if (!expr_ret_287) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_307

  daisho_astnode_t* expr_ret_308 = NULL;
  daisho_astnode_t* expr_ret_307 = NULL;
  daisho_astnode_t* expr_ret_309 = NULL;
  rec(mod_309);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_310 = NULL;
    expr_ret_310 = daisho_parse_logandexpr(ctx);
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
    expr_ret_311 = SUCC;
    while (expr_ret_311)
    {
      daisho_astnode_t* expr_ret_312 = NULL;
      rec(mod_312);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Not capturing LOGOR.
          expr_ret_312 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_312 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_312)
      {
        daisho_astnode_t* expr_ret_313 = NULL;
        expr_ret_313 = daisho_parse_logandexpr(ctx);
        expr_ret_312 = expr_ret_313;
        n = expr_ret_313;
      }

      // ModExprList 2
      if (expr_ret_312)
      {
        // CodeExpr
        #define ret expr_ret_312
        ret = SUCC;

        rule=srepr(node(LOGOR,  rule, n), "||");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_312) rew(mod_312);
      expr_ret_311 = expr_ret_312 ? SUCC : NULL;
    }

    expr_ret_311 = SUCC;
    expr_ret_309 = expr_ret_311;
  }

  // ModExprList end
  if (!expr_ret_309) rew(mod_309);
  expr_ret_308 = expr_ret_309 ? SUCC : NULL;
  if (!rule) rule = expr_ret_308;
  if (!expr_ret_308) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_314

  daisho_astnode_t* expr_ret_315 = NULL;
  daisho_astnode_t* expr_ret_314 = NULL;
  daisho_astnode_t* expr_ret_316 = NULL;
  rec(mod_316);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_317 = NULL;
    expr_ret_317 = daisho_parse_binorexpr(ctx);
    expr_ret_316 = expr_ret_317;
    n = expr_ret_317;
  }

  // ModExprList 1
  if (expr_ret_316)
  {
    // CodeExpr
    #define ret expr_ret_316
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_316)
  {
    daisho_astnode_t* expr_ret_318 = NULL;
    expr_ret_318 = SUCC;
    while (expr_ret_318)
    {
      daisho_astnode_t* expr_ret_319 = NULL;
      rec(mod_319);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Not capturing LOGAND.
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
        expr_ret_320 = daisho_parse_binorexpr(ctx);
        expr_ret_319 = expr_ret_320;
        n = expr_ret_320;
      }

      // ModExprList 2
      if (expr_ret_319)
      {
        // CodeExpr
        #define ret expr_ret_319
        ret = SUCC;

        rule=srepr(node(LOGAND, rule, n), "&&");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_319) rew(mod_319);
      expr_ret_318 = expr_ret_319 ? SUCC : NULL;
    }

    expr_ret_318 = SUCC;
    expr_ret_316 = expr_ret_318;
  }

  // ModExprList end
  if (!expr_ret_316) rew(mod_316);
  expr_ret_315 = expr_ret_316 ? SUCC : NULL;
  if (!rule) rule = expr_ret_315;
  if (!expr_ret_315) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_321

  daisho_astnode_t* expr_ret_322 = NULL;
  daisho_astnode_t* expr_ret_321 = NULL;
  daisho_astnode_t* expr_ret_323 = NULL;
  rec(mod_323);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_324 = NULL;
    expr_ret_324 = daisho_parse_binxorexpr(ctx);
    expr_ret_323 = expr_ret_324;
    n = expr_ret_324;
  }

  // ModExprList 1
  if (expr_ret_323)
  {
    // CodeExpr
    #define ret expr_ret_323
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_323)
  {
    daisho_astnode_t* expr_ret_325 = NULL;
    expr_ret_325 = SUCC;
    while (expr_ret_325)
    {
      daisho_astnode_t* expr_ret_326 = NULL;
      rec(mod_326);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Not capturing OR.
          expr_ret_326 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_326 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_326)
      {
        daisho_astnode_t* expr_ret_327 = NULL;
        expr_ret_327 = daisho_parse_binxorexpr(ctx);
        expr_ret_326 = expr_ret_327;
        n = expr_ret_327;
      }

      // ModExprList 2
      if (expr_ret_326)
      {
        // CodeExpr
        #define ret expr_ret_326
        ret = SUCC;

        rule=srepr(node(OR,     rule, n), "|");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_326) rew(mod_326);
      expr_ret_325 = expr_ret_326 ? SUCC : NULL;
    }

    expr_ret_325 = SUCC;
    expr_ret_323 = expr_ret_325;
  }

  // ModExprList end
  if (!expr_ret_323) rew(mod_323);
  expr_ret_322 = expr_ret_323 ? SUCC : NULL;
  if (!rule) rule = expr_ret_322;
  if (!expr_ret_322) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_328

  daisho_astnode_t* expr_ret_329 = NULL;
  daisho_astnode_t* expr_ret_328 = NULL;
  daisho_astnode_t* expr_ret_330 = NULL;
  rec(mod_330);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_331 = NULL;
    expr_ret_331 = daisho_parse_binandexpr(ctx);
    expr_ret_330 = expr_ret_331;
    n = expr_ret_331;
  }

  // ModExprList 1
  if (expr_ret_330)
  {
    // CodeExpr
    #define ret expr_ret_330
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_330)
  {
    daisho_astnode_t* expr_ret_332 = NULL;
    expr_ret_332 = SUCC;
    while (expr_ret_332)
    {
      daisho_astnode_t* expr_ret_333 = NULL;
      rec(mod_333);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Not capturing XOR.
          expr_ret_333 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_333 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_333)
      {
        daisho_astnode_t* expr_ret_334 = NULL;
        expr_ret_334 = daisho_parse_binandexpr(ctx);
        expr_ret_333 = expr_ret_334;
        n = expr_ret_334;
      }

      // ModExprList 2
      if (expr_ret_333)
      {
        // CodeExpr
        #define ret expr_ret_333
        ret = SUCC;

        rule=srepr(node(XOR,    rule, n), "^");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_333) rew(mod_333);
      expr_ret_332 = expr_ret_333 ? SUCC : NULL;
    }

    expr_ret_332 = SUCC;
    expr_ret_330 = expr_ret_332;
  }

  // ModExprList end
  if (!expr_ret_330) rew(mod_330);
  expr_ret_329 = expr_ret_330 ? SUCC : NULL;
  if (!rule) rule = expr_ret_329;
  if (!expr_ret_329) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_335

  daisho_astnode_t* expr_ret_336 = NULL;
  daisho_astnode_t* expr_ret_335 = NULL;
  daisho_astnode_t* expr_ret_337 = NULL;
  rec(mod_337);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_338 = NULL;
    expr_ret_338 = daisho_parse_deneqexpr(ctx);
    expr_ret_337 = expr_ret_338;
    n = expr_ret_338;
  }

  // ModExprList 1
  if (expr_ret_337)
  {
    // CodeExpr
    #define ret expr_ret_337
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_337)
  {
    daisho_astnode_t* expr_ret_339 = NULL;
    expr_ret_339 = SUCC;
    while (expr_ret_339)
    {
      daisho_astnode_t* expr_ret_340 = NULL;
      rec(mod_340);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Not capturing AND.
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
        expr_ret_341 = daisho_parse_deneqexpr(ctx);
        expr_ret_340 = expr_ret_341;
        n = expr_ret_341;
      }

      // ModExprList 2
      if (expr_ret_340)
      {
        // CodeExpr
        #define ret expr_ret_340
        ret = SUCC;

        rule=srepr(node(AND,    rule, n), "&");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_340) rew(mod_340);
      expr_ret_339 = expr_ret_340 ? SUCC : NULL;
    }

    expr_ret_339 = SUCC;
    expr_ret_337 = expr_ret_339;
  }

  // ModExprList end
  if (!expr_ret_337) rew(mod_337);
  expr_ret_336 = expr_ret_337 ? SUCC : NULL;
  if (!rule) rule = expr_ret_336;
  if (!expr_ret_336) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_342

  daisho_astnode_t* expr_ret_343 = NULL;
  daisho_astnode_t* expr_ret_342 = NULL;
  daisho_astnode_t* expr_ret_344 = NULL;
  rec(mod_344);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_345 = NULL;
    expr_ret_345 = daisho_parse_cmpexpr(ctx);
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
    expr_ret_346 = SUCC;
    while (expr_ret_346)
    {
      daisho_astnode_t* expr_ret_347 = NULL;

      rec(slash_347);

      // SlashExpr 0
      if (!expr_ret_347)
      {
        daisho_astnode_t* expr_ret_348 = NULL;
        rec(mod_348);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Not capturing DEQ.
            expr_ret_348 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_348 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_348)
        {
          daisho_astnode_t* expr_ret_349 = NULL;
          expr_ret_349 = daisho_parse_cmpexpr(ctx);
          expr_ret_348 = expr_ret_349;
          n = expr_ret_349;
        }

        // ModExprList 2
        if (expr_ret_348)
        {
          // CodeExpr
          #define ret expr_ret_348
          ret = SUCC;

          rule=srepr(node(DEQ, rule, n), "==");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_348) rew(mod_348);
        expr_ret_347 = expr_ret_348 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_347)
      {
        daisho_astnode_t* expr_ret_350 = NULL;
        rec(mod_350);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Not capturing NEQ.
            expr_ret_350 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_350 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_350)
        {
          daisho_astnode_t* expr_ret_351 = NULL;
          expr_ret_351 = daisho_parse_cmpexpr(ctx);
          expr_ret_350 = expr_ret_351;
          n = expr_ret_351;
        }

        // ModExprList 2
        if (expr_ret_350)
        {
          // CodeExpr
          #define ret expr_ret_350
          ret = SUCC;

          rule=srepr(node(NEQ, rule, n), "!=");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_350) rew(mod_350);
        expr_ret_347 = expr_ret_350 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_347) rew(slash_347);
      expr_ret_346 = expr_ret_347;

    }

    expr_ret_346 = SUCC;
    expr_ret_344 = expr_ret_346;
  }

  // ModExprList end
  if (!expr_ret_344) rew(mod_344);
  expr_ret_343 = expr_ret_344 ? SUCC : NULL;
  if (!rule) rule = expr_ret_343;
  if (!expr_ret_343) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_352

  daisho_astnode_t* expr_ret_353 = NULL;
  daisho_astnode_t* expr_ret_352 = NULL;
  daisho_astnode_t* expr_ret_354 = NULL;
  rec(mod_354);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_355 = NULL;
    expr_ret_355 = daisho_parse_sumexpr(ctx);
    expr_ret_354 = expr_ret_355;
    n = expr_ret_355;
  }

  // ModExprList 1
  if (expr_ret_354)
  {
    // CodeExpr
    #define ret expr_ret_354
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_354)
  {
    daisho_astnode_t* expr_ret_356 = NULL;
    expr_ret_356 = SUCC;
    while (expr_ret_356)
    {
      daisho_astnode_t* expr_ret_357 = NULL;

      rec(slash_357);

      // SlashExpr 0
      if (!expr_ret_357)
      {
        daisho_astnode_t* expr_ret_358 = NULL;
        rec(mod_358);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_358 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_358 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_358)
        {
          daisho_astnode_t* expr_ret_359 = NULL;
          expr_ret_359 = daisho_parse_sumexpr(ctx);
          expr_ret_358 = expr_ret_359;
          n = expr_ret_359;
        }

        // ModExprList 2
        if (expr_ret_358)
        {
          // CodeExpr
          #define ret expr_ret_358
          ret = SUCC;

          rule=srepr(node(LT,  rule, n), "<");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_358) rew(mod_358);
        expr_ret_357 = expr_ret_358 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_357)
      {
        daisho_astnode_t* expr_ret_360 = NULL;
        rec(mod_360);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_360 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_360 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_360)
        {
          daisho_astnode_t* expr_ret_361 = NULL;
          expr_ret_361 = daisho_parse_sumexpr(ctx);
          expr_ret_360 = expr_ret_361;
          n = expr_ret_361;
        }

        // ModExprList 2
        if (expr_ret_360)
        {
          // CodeExpr
          #define ret expr_ret_360
          ret = SUCC;

          rule=srepr(node(GT,  rule, n), ">");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_360) rew(mod_360);
        expr_ret_357 = expr_ret_360 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_357)
      {
        daisho_astnode_t* expr_ret_362 = NULL;
        rec(mod_362);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Not capturing LEQ.
            expr_ret_362 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_362 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_362)
        {
          daisho_astnode_t* expr_ret_363 = NULL;
          expr_ret_363 = daisho_parse_sumexpr(ctx);
          expr_ret_362 = expr_ret_363;
          n = expr_ret_363;
        }

        // ModExprList 2
        if (expr_ret_362)
        {
          // CodeExpr
          #define ret expr_ret_362
          ret = SUCC;

          rule=srepr(node(LEQ, rule, n), "<=");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_362) rew(mod_362);
        expr_ret_357 = expr_ret_362 ? SUCC : NULL;
      }

      // SlashExpr 3
      if (!expr_ret_357)
      {
        daisho_astnode_t* expr_ret_364 = NULL;
        rec(mod_364);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Not capturing GEQ.
            expr_ret_364 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_364 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_364)
        {
          daisho_astnode_t* expr_ret_365 = NULL;
          expr_ret_365 = daisho_parse_sumexpr(ctx);
          expr_ret_364 = expr_ret_365;
          n = expr_ret_365;
        }

        // ModExprList 2
        if (expr_ret_364)
        {
          // CodeExpr
          #define ret expr_ret_364
          ret = SUCC;

          rule=srepr(node(GEQ, rule, n), ">=");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_364) rew(mod_364);
        expr_ret_357 = expr_ret_364 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_357) rew(slash_357);
      expr_ret_356 = expr_ret_357;

    }

    expr_ret_356 = SUCC;
    expr_ret_354 = expr_ret_356;
  }

  // ModExprList end
  if (!expr_ret_354) rew(mod_354);
  expr_ret_353 = expr_ret_354 ? SUCC : NULL;
  if (!rule) rule = expr_ret_353;
  if (!expr_ret_353) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_366

  daisho_astnode_t* expr_ret_367 = NULL;
  daisho_astnode_t* expr_ret_366 = NULL;
  daisho_astnode_t* expr_ret_368 = NULL;
  rec(mod_368);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_369 = NULL;
    expr_ret_369 = daisho_parse_multexpr(ctx);
    expr_ret_368 = expr_ret_369;
    n = expr_ret_369;
  }

  // ModExprList 1
  if (expr_ret_368)
  {
    // CodeExpr
    #define ret expr_ret_368
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_368)
  {
    daisho_astnode_t* expr_ret_370 = NULL;
    expr_ret_370 = SUCC;
    while (expr_ret_370)
    {
      daisho_astnode_t* expr_ret_371 = NULL;

      rec(slash_371);

      // SlashExpr 0
      if (!expr_ret_371)
      {
        daisho_astnode_t* expr_ret_372 = NULL;
        rec(mod_372);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Not capturing PLUS.
            expr_ret_372 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_372 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_372)
        {
          daisho_astnode_t* expr_ret_373 = NULL;
          expr_ret_373 = daisho_parse_multexpr(ctx);
          expr_ret_372 = expr_ret_373;
          n = expr_ret_373;
        }

        // ModExprList 2
        if (expr_ret_372)
        {
          // CodeExpr
          #define ret expr_ret_372
          ret = SUCC;

          rule=srepr(node(PLUS,  rule, n), "+");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_372) rew(mod_372);
        expr_ret_371 = expr_ret_372 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_371)
      {
        daisho_astnode_t* expr_ret_374 = NULL;
        rec(mod_374);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Not capturing MINUS.
            expr_ret_374 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_374 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_374)
        {
          daisho_astnode_t* expr_ret_375 = NULL;
          expr_ret_375 = daisho_parse_multexpr(ctx);
          expr_ret_374 = expr_ret_375;
          n = expr_ret_375;
        }

        // ModExprList 2
        if (expr_ret_374)
        {
          // CodeExpr
          #define ret expr_ret_374
          ret = SUCC;

          rule=srepr(node(MINUS, rule, n), "-");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_374) rew(mod_374);
        expr_ret_371 = expr_ret_374 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_371) rew(slash_371);
      expr_ret_370 = expr_ret_371;

    }

    expr_ret_370 = SUCC;
    expr_ret_368 = expr_ret_370;
  }

  // ModExprList end
  if (!expr_ret_368) rew(mod_368);
  expr_ret_367 = expr_ret_368 ? SUCC : NULL;
  if (!rule) rule = expr_ret_367;
  if (!expr_ret_367) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_376

  daisho_astnode_t* expr_ret_377 = NULL;
  daisho_astnode_t* expr_ret_376 = NULL;
  daisho_astnode_t* expr_ret_378 = NULL;
  rec(mod_378);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_379 = NULL;
    expr_ret_379 = daisho_parse_powexpr(ctx);
    expr_ret_378 = expr_ret_379;
    n = expr_ret_379;
  }

  // ModExprList 1
  if (expr_ret_378)
  {
    // CodeExpr
    #define ret expr_ret_378
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_378)
  {
    daisho_astnode_t* expr_ret_380 = NULL;
    expr_ret_380 = SUCC;
    while (expr_ret_380)
    {
      daisho_astnode_t* expr_ret_381 = NULL;

      rec(slash_381);

      // SlashExpr 0
      if (!expr_ret_381)
      {
        daisho_astnode_t* expr_ret_382 = NULL;
        rec(mod_382);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_382 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_382 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_382)
        {
          daisho_astnode_t* expr_ret_383 = NULL;
          expr_ret_383 = daisho_parse_powexpr(ctx);
          expr_ret_382 = expr_ret_383;
          n = expr_ret_383;
        }

        // ModExprList 2
        if (expr_ret_382)
        {
          // CodeExpr
          #define ret expr_ret_382
          ret = SUCC;

          rule=srepr(node(STAR, rule, n), "*");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_382) rew(mod_382);
        expr_ret_381 = expr_ret_382 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_381)
      {
        daisho_astnode_t* expr_ret_384 = NULL;
        rec(mod_384);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Not capturing DIV.
            expr_ret_384 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_384 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_384)
        {
          daisho_astnode_t* expr_ret_385 = NULL;
          expr_ret_385 = daisho_parse_powexpr(ctx);
          expr_ret_384 = expr_ret_385;
          n = expr_ret_385;
        }

        // ModExprList 2
        if (expr_ret_384)
        {
          // CodeExpr
          #define ret expr_ret_384
          ret = SUCC;

          rule=srepr(node(DIV,  rule, n), "/");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_384) rew(mod_384);
        expr_ret_381 = expr_ret_384 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_381)
      {
        daisho_astnode_t* expr_ret_386 = NULL;
        rec(mod_386);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Not capturing MOD.
            expr_ret_386 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_386 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_386)
        {
          daisho_astnode_t* expr_ret_387 = NULL;
          expr_ret_387 = daisho_parse_powexpr(ctx);
          expr_ret_386 = expr_ret_387;
          n = expr_ret_387;
        }

        // ModExprList 2
        if (expr_ret_386)
        {
          // CodeExpr
          #define ret expr_ret_386
          ret = SUCC;

          rule=srepr(node(MOD,  rule, n), "%");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_386) rew(mod_386);
        expr_ret_381 = expr_ret_386 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_381) rew(slash_381);
      expr_ret_380 = expr_ret_381;

    }

    expr_ret_380 = SUCC;
    expr_ret_378 = expr_ret_380;
  }

  // ModExprList end
  if (!expr_ret_378) rew(mod_378);
  expr_ret_377 = expr_ret_378 ? SUCC : NULL;
  if (!rule) rule = expr_ret_377;
  if (!expr_ret_377) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_388

  daisho_astnode_t* expr_ret_389 = NULL;
  daisho_astnode_t* expr_ret_388 = NULL;
  daisho_astnode_t* expr_ret_390 = NULL;
  rec(mod_390);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_391 = NULL;
    expr_ret_391 = daisho_parse_shfexpr(ctx);
    expr_ret_390 = expr_ret_391;
    n = expr_ret_391;
  }

  // ModExprList 1
  if (expr_ret_390)
  {
    // CodeExpr
    #define ret expr_ret_390
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_390)
  {
    daisho_astnode_t* expr_ret_392 = NULL;
    expr_ret_392 = SUCC;
    while (expr_ret_392)
    {
      daisho_astnode_t* expr_ret_393 = NULL;
      rec(mod_393);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_393 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_393 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_393)
      {
        // CodeExpr
        #define ret expr_ret_393
        ret = SUCC;

        rule=srepr(node(POW, rule, n), "**");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_393) rew(mod_393);
      expr_ret_392 = expr_ret_393 ? SUCC : NULL;
    }

    expr_ret_392 = SUCC;
    expr_ret_390 = expr_ret_392;
  }

  // ModExprList end
  if (!expr_ret_390) rew(mod_390);
  expr_ret_389 = expr_ret_390 ? SUCC : NULL;
  if (!rule) rule = expr_ret_389;
  if (!expr_ret_389) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_394

  daisho_astnode_t* expr_ret_395 = NULL;
  daisho_astnode_t* expr_ret_394 = NULL;
  daisho_astnode_t* expr_ret_396 = NULL;
  rec(mod_396);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_397 = NULL;
    expr_ret_397 = daisho_parse_callexpr(ctx);
    expr_ret_396 = expr_ret_397;
    n = expr_ret_397;
  }

  // ModExprList 1
  if (expr_ret_396)
  {
    // CodeExpr
    #define ret expr_ret_396
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_396)
  {
    daisho_astnode_t* expr_ret_398 = NULL;
    expr_ret_398 = SUCC;
    while (expr_ret_398)
    {
      daisho_astnode_t* expr_ret_399 = NULL;

      rec(slash_399);

      // SlashExpr 0
      if (!expr_ret_399)
      {
        daisho_astnode_t* expr_ret_400 = NULL;
        rec(mod_400);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_400 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_400 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_400)
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_400 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_400 = NULL;
          }

        }

        // ModExprList 2
        if (expr_ret_400)
        {
          daisho_astnode_t* expr_ret_401 = NULL;
          expr_ret_401 = daisho_parse_callexpr(ctx);
          expr_ret_400 = expr_ret_401;
          n = expr_ret_401;
        }

        // ModExprList 3
        if (expr_ret_400)
        {
          // CodeExpr
          #define ret expr_ret_400
          ret = SUCC;

          rule=srepr(node(BSL, rule, n), "<<");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_400) rew(mod_400);
        expr_ret_399 = expr_ret_400 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_399)
      {
        daisho_astnode_t* expr_ret_402 = NULL;
        rec(mod_402);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_402 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_402 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_402)
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_402 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_402 = NULL;
          }

        }

        // ModExprList 2
        if (expr_ret_402)
        {
          daisho_astnode_t* expr_ret_403 = NULL;
          expr_ret_403 = daisho_parse_callexpr(ctx);
          expr_ret_402 = expr_ret_403;
          n = expr_ret_403;
        }

        // ModExprList 3
        if (expr_ret_402)
        {
          // CodeExpr
          #define ret expr_ret_402
          ret = SUCC;

          rule=srepr(node(BSR, rule, n), ">>");

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_402) rew(mod_402);
        expr_ret_399 = expr_ret_402 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_399) rew(slash_399);
      expr_ret_398 = expr_ret_399;

    }

    expr_ret_398 = SUCC;
    expr_ret_396 = expr_ret_398;
  }

  // ModExprList end
  if (!expr_ret_396) rew(mod_396);
  expr_ret_395 = expr_ret_396 ? SUCC : NULL;
  if (!rule) rule = expr_ret_395;
  if (!expr_ret_395) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* vi = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* args = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_404

  daisho_astnode_t* expr_ret_405 = NULL;
  daisho_astnode_t* expr_ret_404 = NULL;
  daisho_astnode_t* expr_ret_406 = NULL;

  rec(slash_406);

  // SlashExpr 0
  if (!expr_ret_406)
  {
    daisho_astnode_t* expr_ret_407 = NULL;
    rec(mod_407);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_408 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_408 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_408->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_408->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_408 = NULL;
      }

      expr_ret_407 = expr_ret_408;
      vi = expr_ret_408;
    }

    // ModExprList 1
    if (expr_ret_407)
    {
      daisho_astnode_t* expr_ret_409 = NULL;
      expr_ret_409 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_409)
        expr_ret_409 = SUCC;
      expr_ret_407 = expr_ret_409;
      t = expr_ret_409;
    }

    // ModExprList 2
    if (expr_ret_407)
    {
      daisho_astnode_t* expr_ret_410 = NULL;
      expr_ret_410 = SUCC;
      while (expr_ret_410)
      {
        daisho_astnode_t* expr_ret_411 = NULL;
        rec(mod_411);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_412 = NULL;
          expr_ret_412 = daisho_parse_fncallargs(ctx);
          expr_ret_411 = expr_ret_412;
          args = expr_ret_412;
        }

        // ModExprList 1
        if (expr_ret_411)
        {
          // CodeExpr
          #define ret expr_ret_411
          ret = SUCC;

          rule=node(CALL, vi, args); if (has(t)) {rule=node(TMPLCALL, rule, t);t=NULL;};

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_411) rew(mod_411);
        expr_ret_410 = expr_ret_411 ? SUCC : NULL;
      }

      expr_ret_410 = SUCC;
      expr_ret_407 = expr_ret_410;
    }

    // ModExprList 3
    if (expr_ret_407)
    {
      // CodeExpr
      #define ret expr_ret_407
      ret = SUCC;

      ret=!has(rule)?NULL:SUCC;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_407) rew(mod_407);
    expr_ret_406 = expr_ret_407 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_406)
  {
    daisho_astnode_t* expr_ret_413 = NULL;
    rec(mod_413);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_414 = NULL;
      expr_ret_414 = daisho_parse_castexpr(ctx);
      expr_ret_413 = expr_ret_414;
      n = expr_ret_414;
    }

    // ModExprList 1
    if (expr_ret_413)
    {
      // CodeExpr
      #define ret expr_ret_413
      ret = SUCC;

      rule=n;

      #undef ret
    }

    // ModExprList 2
    if (expr_ret_413)
    {
      daisho_astnode_t* expr_ret_415 = NULL;
      expr_ret_415 = SUCC;
      while (expr_ret_415)
      {
        daisho_astnode_t* expr_ret_416 = NULL;
        rec(mod_416);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_417 = NULL;
          expr_ret_417 = daisho_parse_fncallargs(ctx);
          expr_ret_416 = expr_ret_417;
          args = expr_ret_417;
        }

        // ModExprList 1
        if (expr_ret_416)
        {
          // CodeExpr
          #define ret expr_ret_416
          ret = SUCC;

          rule=node(CALL, rule, args);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_416) rew(mod_416);
        expr_ret_415 = expr_ret_416 ? SUCC : NULL;
      }

      expr_ret_415 = SUCC;
      expr_ret_413 = expr_ret_415;
    }

    // ModExprList end
    if (!expr_ret_413) rew(mod_413);
    expr_ret_406 = expr_ret_413 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_406) rew(slash_406);
  expr_ret_405 = expr_ret_406;

  if (!rule) rule = expr_ret_405;
  if (!expr_ret_405) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fncallargs(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_418

  daisho_astnode_t* expr_ret_419 = NULL;
  daisho_astnode_t* expr_ret_418 = NULL;
  daisho_astnode_t* expr_ret_420 = NULL;
  rec(mod_420);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
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
    // CodeExpr
    #define ret expr_ret_421
    ret = SUCC;

    ret=rule=list(FNARGLIST);

    #undef ret
    expr_ret_420 = expr_ret_421;
    l = expr_ret_421;
  }

  // ModExprList 2
  if (expr_ret_420)
  {
    daisho_astnode_t* expr_ret_422 = NULL;
    expr_ret_422 = daisho_parse_expr(ctx);
    // optional
    if (!expr_ret_422)
      expr_ret_422 = SUCC;
    expr_ret_420 = expr_ret_422;
    e = expr_ret_422;
  }

  // ModExprList 3
  if (expr_ret_420)
  {
    // CodeExpr
    #define ret expr_ret_420
    ret = SUCC;

    if (has(e)) add(l, e);

    #undef ret
  }

  // ModExprList 4
  if (expr_ret_420)
  {
    daisho_astnode_t* expr_ret_423 = NULL;
    expr_ret_423 = SUCC;
    while (expr_ret_423)
    {
      daisho_astnode_t* expr_ret_424 = NULL;
      rec(mod_424);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_424 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_424 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_424)
      {
        daisho_astnode_t* expr_ret_425 = NULL;
        expr_ret_425 = daisho_parse_expr(ctx);
        expr_ret_424 = expr_ret_425;
        e = expr_ret_425;
      }

      // ModExprList 2
      if (expr_ret_424)
      {
        // CodeExpr
        #define ret expr_ret_424
        ret = SUCC;

        add(l, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_424) rew(mod_424);
      expr_ret_423 = expr_ret_424 ? SUCC : NULL;
    }

    expr_ret_423 = SUCC;
    expr_ret_420 = expr_ret_423;
  }

  // ModExprList 5
  if (expr_ret_420)
  {
    daisho_astnode_t* expr_ret_426 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_426 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_426 = NULL;
    }

    // optional
    if (!expr_ret_426)
      expr_ret_426 = SUCC;
    expr_ret_420 = expr_ret_426;
  }

  // ModExprList 6
  if (expr_ret_420)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_420 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_420 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_420) rew(mod_420);
  expr_ret_419 = expr_ret_420 ? SUCC : NULL;
  if (!rule) rule = expr_ret_419;
  if (!expr_ret_419) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_427

  daisho_astnode_t* expr_ret_428 = NULL;
  daisho_astnode_t* expr_ret_427 = NULL;
  daisho_astnode_t* expr_ret_429 = NULL;
  rec(mod_429);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_430 = NULL;
    expr_ret_430 = daisho_parse_refexpr(ctx);
    expr_ret_429 = expr_ret_430;
    n = expr_ret_430;
  }

  // ModExprList 1
  if (expr_ret_429)
  {
    // CodeExpr
    #define ret expr_ret_429
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_429)
  {
    daisho_astnode_t* expr_ret_431 = NULL;
    expr_ret_431 = SUCC;
    while (expr_ret_431)
    {
      daisho_astnode_t* expr_ret_432 = NULL;
      rec(mod_432);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_432 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_432 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_432)
      {
        daisho_astnode_t* expr_ret_433 = NULL;
        expr_ret_433 = daisho_parse_type(ctx);
        expr_ret_432 = expr_ret_433;
        t = expr_ret_433;
      }

      // ModExprList 2
      if (expr_ret_432)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_432 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_432 = NULL;
        }

      }

      // ModExprList 3
      if (expr_ret_432)
      {
        // CodeExpr
        #define ret expr_ret_432
        ret = SUCC;

        rule = srepr(node(CAST, rule, t), "cast");

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_432) rew(mod_432);
      expr_ret_431 = expr_ret_432 ? SUCC : NULL;
    }

    expr_ret_431 = SUCC;
    expr_ret_429 = expr_ret_431;
  }

  // ModExprList end
  if (!expr_ret_429) rew(mod_429);
  expr_ret_428 = expr_ret_429 ? SUCC : NULL;
  if (!rule) rule = expr_ret_428;
  if (!expr_ret_428) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_434

  daisho_astnode_t* expr_ret_435 = NULL;
  daisho_astnode_t* expr_ret_434 = NULL;
  daisho_astnode_t* expr_ret_436 = NULL;
  rec(mod_436);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_437 = NULL;
    expr_ret_437 = daisho_parse_derefexpr(ctx);
    expr_ret_436 = expr_ret_437;
    n = expr_ret_437;
  }

  // ModExprList 1
  if (expr_ret_436)
  {
    daisho_astnode_t* expr_ret_438 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_438 = leaf(REF);
      #if DAISHO_SOURCEINFO
      expr_ret_438->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_438->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_438 = NULL;
    }

    // optional
    if (!expr_ret_438)
      expr_ret_438 = SUCC;
    expr_ret_436 = expr_ret_438;
    r = expr_ret_438;
  }

  // ModExprList 2
  if (expr_ret_436)
  {
    // CodeExpr
    #define ret expr_ret_436
    ret = SUCC;

    rule=has(r) ? srepr(node(REF, n), "@") : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_436) rew(mod_436);
  expr_ret_435 = expr_ret_436 ? SUCC : NULL;
  if (!rule) rule = expr_ret_435;
  if (!expr_ret_435) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_439

  daisho_astnode_t* expr_ret_440 = NULL;
  daisho_astnode_t* expr_ret_439 = NULL;
  daisho_astnode_t* expr_ret_441 = NULL;
  rec(mod_441);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_442 = NULL;
    expr_ret_442 = daisho_parse_postretexpr(ctx);
    expr_ret_441 = expr_ret_442;
    n = expr_ret_442;
  }

  // ModExprList 1
  if (expr_ret_441)
  {
    daisho_astnode_t* expr_ret_443 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
      // Capturing DEREF.
      expr_ret_443 = leaf(DEREF);
      #if DAISHO_SOURCEINFO
      expr_ret_443->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_443->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_443 = NULL;
    }

    // optional
    if (!expr_ret_443)
      expr_ret_443 = SUCC;
    expr_ret_441 = expr_ret_443;
    d = expr_ret_443;
  }

  // ModExprList 2
  if (expr_ret_441)
  {
    // CodeExpr
    #define ret expr_ret_441
    ret = SUCC;

    rule=has(d) ? srepr(node(DEREF, n), "$") : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_441) rew(mod_441);
  expr_ret_440 = expr_ret_441 ? SUCC : NULL;
  if (!rule) rule = expr_ret_440;
  if (!expr_ret_440) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  #define rule expr_ret_444

  daisho_astnode_t* expr_ret_445 = NULL;
  daisho_astnode_t* expr_ret_444 = NULL;
  daisho_astnode_t* expr_ret_446 = NULL;
  rec(mod_446);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_447 = NULL;
    expr_ret_447 = daisho_parse_atomexpr(ctx);
    expr_ret_446 = expr_ret_447;
    n = expr_ret_447;
  }

  // ModExprList 1
  if (expr_ret_446)
  {
    daisho_astnode_t* expr_ret_448 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      // Capturing GRAVE.
      expr_ret_448 = leaf(GRAVE);
      #if DAISHO_SOURCEINFO
      expr_ret_448->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_448->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_448 = NULL;
    }

    // optional
    if (!expr_ret_448)
      expr_ret_448 = SUCC;
    expr_ret_446 = expr_ret_448;
    g = expr_ret_448;
  }

  // ModExprList 2
  if (expr_ret_446)
  {
    // CodeExpr
    #define ret expr_ret_446
    ret = SUCC;

    rule=has(g) ? srepr(node(RET, n), "return") : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_446) rew(mod_446);
  expr_ret_445 = expr_ret_446 ? SUCC : NULL;
  if (!rule) rule = expr_ret_445;
  if (!expr_ret_445) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_449

  daisho_astnode_t* expr_ret_450 = NULL;
  daisho_astnode_t* expr_ret_449 = NULL;
  daisho_astnode_t* expr_ret_451 = NULL;

  rec(slash_451);

  // SlashExpr 0
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_452 = NULL;
    rec(mod_452);
    // ModExprList Forwarding
    expr_ret_452 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_452) rew(mod_452);
    expr_ret_451 = expr_ret_452;
  }

  // SlashExpr 1
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_453 = NULL;
    rec(mod_453);
    // ModExprList Forwarding
    expr_ret_453 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_453) rew(mod_453);
    expr_ret_451 = expr_ret_453;
  }

  // SlashExpr 2
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_454 = NULL;
    rec(mod_454);
    // ModExprList Forwarding
    expr_ret_454 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_454) rew(mod_454);
    expr_ret_451 = expr_ret_454;
  }

  // SlashExpr 3
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_455 = NULL;
    rec(mod_455);
    // ModExprList Forwarding
    expr_ret_455 = daisho_parse_listlit(ctx);
    // ModExprList end
    if (!expr_ret_455) rew(mod_455);
    expr_ret_451 = expr_ret_455;
  }

  // SlashExpr 4
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_456 = NULL;
    rec(mod_456);
    // ModExprList Forwarding
    expr_ret_456 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_456) rew(mod_456);
    expr_ret_451 = expr_ret_456;
  }

  // SlashExpr 5
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_457 = NULL;
    rec(mod_457);
    // ModExprList Forwarding
    expr_ret_457 = daisho_parse_preretexpr(ctx);
    // ModExprList end
    if (!expr_ret_457) rew(mod_457);
    expr_ret_451 = expr_ret_457;
  }

  // SlashExpr 6
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_458 = NULL;
    rec(mod_458);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_458 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_458->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_458->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_458 = NULL;
    }

    // ModExprList end
    if (!expr_ret_458) rew(mod_458);
    expr_ret_451 = expr_ret_458;
  }

  // SlashExpr 7
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_459 = NULL;
    rec(mod_459);
    // ModExprList Forwarding
    expr_ret_459 = daisho_parse_numlit(ctx);
    // ModExprList end
    if (!expr_ret_459) rew(mod_459);
    expr_ret_451 = expr_ret_459;
  }

  // SlashExpr 8
  if (!expr_ret_451)
  {
    daisho_astnode_t* expr_ret_460 = NULL;
    rec(mod_460);
    // ModExprList Forwarding
    expr_ret_460 = daisho_parse_strlits(ctx);
    // ModExprList end
    if (!expr_ret_460) rew(mod_460);
    expr_ret_451 = expr_ret_460;
  }

  // SlashExpr end
  if (!expr_ret_451) rew(slash_451);
  expr_ret_450 = expr_ret_451;

  if (!rule) rule = expr_ret_450;
  if (!expr_ret_450) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_461

  daisho_astnode_t* expr_ret_462 = NULL;
  daisho_astnode_t* expr_ret_461 = NULL;
  daisho_astnode_t* expr_ret_463 = NULL;
  rec(mod_463);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_463 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_463 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_463)
  {
    // CodeExpr
    #define ret expr_ret_463
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_463)
  {
    daisho_astnode_t* expr_ret_464 = NULL;
    expr_ret_464 = SUCC;
    while (expr_ret_464)
    {
      daisho_astnode_t* expr_ret_465 = NULL;
      rec(mod_465);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_466 = NULL;
        expr_ret_466 = daisho_parse_expr(ctx);
        expr_ret_465 = expr_ret_466;
        e = expr_ret_466;
      }

      // ModExprList 1
      if (expr_ret_465)
      {
        // CodeExpr
        #define ret expr_ret_465
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_465) rew(mod_465);
      expr_ret_464 = expr_ret_465 ? SUCC : NULL;
    }

    expr_ret_464 = SUCC;
    expr_ret_463 = expr_ret_464;
  }

  // ModExprList 3
  if (expr_ret_463)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_463 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_463 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_463) rew(mod_463);
  expr_ret_462 = expr_ret_463 ? SUCC : NULL;
  if (!rule) rule = expr_ret_462;
  if (!expr_ret_462) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* caps = NULL;
  daisho_astnode_t* args = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_467

  daisho_astnode_t* expr_ret_468 = NULL;
  daisho_astnode_t* expr_ret_467 = NULL;
  daisho_astnode_t* expr_ret_469 = NULL;
  rec(mod_469);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_470 = NULL;
    daisho_astnode_t* expr_ret_471 = NULL;
    rec(mod_471);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_471 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_471 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_471)
    {
      daisho_astnode_t* expr_ret_472 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_472 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_472->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_472->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_472 = NULL;
      }

      // optional
      if (!expr_ret_472)
        expr_ret_472 = SUCC;
      expr_ret_471 = expr_ret_472;
      v = expr_ret_472;
    }

    // ModExprList 2
    if (expr_ret_471)
    {
      daisho_astnode_t* expr_ret_473 = NULL;
      // CodeExpr
      #define ret expr_ret_473
      ret = SUCC;

      ret=list(ARGLIST);if (has(v)) add(ret, v);

      #undef ret
      expr_ret_471 = expr_ret_473;
      caps = expr_ret_473;
    }

    // ModExprList 3
    if (expr_ret_471)
    {
      daisho_astnode_t* expr_ret_474 = NULL;
      expr_ret_474 = SUCC;
      while (expr_ret_474)
      {
        daisho_astnode_t* expr_ret_475 = NULL;
        rec(mod_475);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_475 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_475 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_475)
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

          expr_ret_475 = expr_ret_476;
          v = expr_ret_476;
        }

        // ModExprList 2
        if (expr_ret_475)
        {
          // CodeExpr
          #define ret expr_ret_475
          ret = SUCC;

          add(caps, v);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_475) rew(mod_475);
        expr_ret_474 = expr_ret_475 ? SUCC : NULL;
      }

      expr_ret_474 = SUCC;
      expr_ret_471 = expr_ret_474;
    }

    // ModExprList 4
    if (expr_ret_471)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_471 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_471 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_471) rew(mod_471);
    expr_ret_470 = expr_ret_471 ? SUCC : NULL;
    // optional
    if (!expr_ret_470)
      expr_ret_470 = SUCC;
    expr_ret_469 = expr_ret_470;
  }

  // ModExprList 1
  if (expr_ret_469)
  {
    daisho_astnode_t* expr_ret_477 = NULL;

    rec(slash_477);

    // SlashExpr 0
    if (!expr_ret_477)
    {
      daisho_astnode_t* expr_ret_478 = NULL;
      rec(mod_478);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_479 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_479 = leaf(VARIDENT);
          #if DAISHO_SOURCEINFO
          expr_ret_479->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_479->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_479 = NULL;
        }

        expr_ret_478 = expr_ret_479;
        v = expr_ret_479;
      }

      // ModExprList 1
      if (expr_ret_478)
      {
        daisho_astnode_t* expr_ret_480 = NULL;
        // CodeExpr
        #define ret expr_ret_480
        ret = SUCC;

        ret=list(ARGLIST);add(ret, v);

        #undef ret
        expr_ret_478 = expr_ret_480;
        args = expr_ret_480;
      }

      // ModExprList end
      if (!expr_ret_478) rew(mod_478);
      expr_ret_477 = expr_ret_478 ? SUCC : NULL;
    }

    // SlashExpr 1
    if (!expr_ret_477)
    {
      daisho_astnode_t* expr_ret_481 = NULL;
      rec(mod_481);
      // ModExprList Forwarding
      daisho_astnode_t* expr_ret_482 = NULL;
      rec(mod_482);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_482 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_482 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_482)
      {
        daisho_astnode_t* expr_ret_483 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_483 = leaf(VARIDENT);
          #if DAISHO_SOURCEINFO
          expr_ret_483->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_483->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_483 = NULL;
        }

        // optional
        if (!expr_ret_483)
          expr_ret_483 = SUCC;
        expr_ret_482 = expr_ret_483;
        v = expr_ret_483;
      }

      // ModExprList 2
      if (expr_ret_482)
      {
        // CodeExpr
        #define ret expr_ret_482
        ret = SUCC;

        if (has(v)) {args=list(ARGLIST); add(args, v);};

        #undef ret
      }

      // ModExprList 3
      if (expr_ret_482)
      {
        daisho_astnode_t* expr_ret_484 = NULL;
        expr_ret_484 = SUCC;
        while (expr_ret_484)
        {
          daisho_astnode_t* expr_ret_485 = NULL;
          rec(mod_485);
          // ModExprList 0
          {
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
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
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
              // Capturing VARIDENT.
              expr_ret_486 = leaf(VARIDENT);
              #if DAISHO_SOURCEINFO
              expr_ret_486->tok_repr = ctx->tokens[ctx->pos].content;
              expr_ret_486->len_or_toknum = ctx->tokens[ctx->pos].len;
              #endif
              ctx->pos++;
            } else {
              expr_ret_486 = NULL;
            }

            expr_ret_485 = expr_ret_486;
            v = expr_ret_486;
          }

          // ModExprList 2
          if (expr_ret_485)
          {
            // CodeExpr
            #define ret expr_ret_485
            ret = SUCC;

            if (!args)  {args=list(ARGLIST);}add(args, v) ;

            #undef ret
          }

          // ModExprList end
          if (!expr_ret_485) rew(mod_485);
          expr_ret_484 = expr_ret_485 ? SUCC : NULL;
        }

        expr_ret_484 = SUCC;
        expr_ret_482 = expr_ret_484;
      }

      // ModExprList 4
      if (expr_ret_482)
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_482 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_482 = NULL;
        }

      }

      // ModExprList end
      if (!expr_ret_482) rew(mod_482);
      expr_ret_481 = expr_ret_482 ? SUCC : NULL;
      // ModExprList end
      if (!expr_ret_481) rew(mod_481);
      expr_ret_477 = expr_ret_481;
    }

    // SlashExpr end
    if (!expr_ret_477) rew(slash_477);
    expr_ret_469 = expr_ret_477;

  }

  // ModExprList 2
  if (expr_ret_469)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_469 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_469 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_469)
  {
    daisho_astnode_t* expr_ret_487 = NULL;
    expr_ret_487 = daisho_parse_expr(ctx);
    expr_ret_469 = expr_ret_487;
    e = expr_ret_487;
  }

  // ModExprList 4
  if (expr_ret_469)
  {
    // CodeExpr
    #define ret expr_ret_469
    ret = SUCC;

    rule=node(LAMBDA, caps ? caps : leaf(ARGLIST), args ? args : leaf(ARGLIST), e);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_469) rew(mod_469);
  expr_ret_468 = expr_ret_469 ? SUCC : NULL;
  if (!rule) rule = expr_ret_468;
  if (!expr_ret_468) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* in = NULL;
  daisho_astnode_t* where = NULL;
  #define rule expr_ret_488

  daisho_astnode_t* expr_ret_489 = NULL;
  daisho_astnode_t* expr_ret_488 = NULL;
  daisho_astnode_t* expr_ret_490 = NULL;
  rec(mod_490);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_490 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_490 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_490)
  {
    daisho_astnode_t* expr_ret_491 = NULL;
    daisho_astnode_t* expr_ret_492 = NULL;
    rec(mod_492);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_493 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_493 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_493->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_493->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_493 = NULL;
      }

      expr_ret_492 = expr_ret_493;
      cnt = expr_ret_493;
    }

    // ModExprList 1
    if (expr_ret_492)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_492 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_492 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_492) rew(mod_492);
    expr_ret_491 = expr_ret_492 ? SUCC : NULL;
    // optional
    if (!expr_ret_491)
      expr_ret_491 = SUCC;
    expr_ret_490 = expr_ret_491;
  }

  // ModExprList 2
  if (expr_ret_490)
  {
    expr_ret_490 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_490)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_490 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_490 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_490)
  {
    daisho_astnode_t* expr_ret_494 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_494 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_494->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_494->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_494 = NULL;
    }

    expr_ret_490 = expr_ret_494;
    item = expr_ret_494;
  }

  // ModExprList 5
  if (expr_ret_490)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_490 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_490 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_490)
  {
    daisho_astnode_t* expr_ret_495 = NULL;
    expr_ret_495 = daisho_parse_expr(ctx);
    expr_ret_490 = expr_ret_495;
    in = expr_ret_495;
  }

  // ModExprList 7
  if (expr_ret_490)
  {
    daisho_astnode_t* expr_ret_496 = NULL;
    daisho_astnode_t* expr_ret_497 = NULL;
    rec(mod_497);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        // Not capturing WHERE.
        expr_ret_497 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_497 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_497)
    {
      daisho_astnode_t* expr_ret_498 = NULL;
      expr_ret_498 = daisho_parse_expr(ctx);
      expr_ret_497 = expr_ret_498;
      where = expr_ret_498;
    }

    // ModExprList end
    if (!expr_ret_497) rew(mod_497);
    expr_ret_496 = expr_ret_497 ? SUCC : NULL;
    // optional
    if (!expr_ret_496)
      expr_ret_496 = SUCC;
    expr_ret_490 = expr_ret_496;
  }

  // ModExprList 8
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
  expr_ret_489 = expr_ret_490 ? SUCC : NULL;
  if (!rule) rule = expr_ret_489;
  if (!expr_ret_489) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_499

  daisho_astnode_t* expr_ret_500 = NULL;
  daisho_astnode_t* expr_ret_499 = NULL;
  daisho_astnode_t* expr_ret_501 = NULL;
  rec(mod_501);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_501 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_501 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_501)
  {
    daisho_astnode_t* expr_ret_502 = NULL;
    expr_ret_502 = daisho_parse_expr(ctx);
    // optional
    if (!expr_ret_502)
      expr_ret_502 = SUCC;
    expr_ret_501 = expr_ret_502;
  }

  // ModExprList 2
  if (expr_ret_501)
  {
    daisho_astnode_t* expr_ret_503 = NULL;
    expr_ret_503 = SUCC;
    while (expr_ret_503)
    {
      daisho_astnode_t* expr_ret_504 = NULL;
      rec(mod_504);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_504 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_504 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_504)
      {
        expr_ret_504 = daisho_parse_expr(ctx);
      }

      // ModExprList end
      if (!expr_ret_504) rew(mod_504);
      expr_ret_503 = expr_ret_504 ? SUCC : NULL;
    }

    expr_ret_503 = SUCC;
    expr_ret_501 = expr_ret_503;
  }

  // ModExprList 3
  if (expr_ret_501)
  {
    daisho_astnode_t* expr_ret_505 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_505 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_505 = NULL;
    }

    // optional
    if (!expr_ret_505)
      expr_ret_505 = SUCC;
    expr_ret_501 = expr_ret_505;
  }

  // ModExprList 4
  if (expr_ret_501)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_501 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_501 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_501) rew(mod_501);
  expr_ret_500 = expr_ret_501 ? SUCC : NULL;
  if (!rule) rule = expr_ret_500;
  if (!expr_ret_500) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_506

  daisho_astnode_t* expr_ret_507 = NULL;
  daisho_astnode_t* expr_ret_506 = NULL;
  daisho_astnode_t* expr_ret_508 = NULL;
  rec(mod_508);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_508 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_508 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_508)
  {
    daisho_astnode_t* expr_ret_509 = NULL;
    expr_ret_509 = daisho_parse_expr(ctx);
    expr_ret_508 = expr_ret_509;
    e = expr_ret_509;
  }

  // ModExprList 2
  if (expr_ret_508)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_508 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_508 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_508)
  {
    // CodeExpr
    #define ret expr_ret_508
    ret = SUCC;

    rule=e;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_508) rew(mod_508);
  expr_ret_507 = expr_ret_508 ? SUCC : NULL;
  if (!rule) rule = expr_ret_507;
  if (!expr_ret_507) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_510

  daisho_astnode_t* expr_ret_511 = NULL;
  daisho_astnode_t* expr_ret_510 = NULL;
  daisho_astnode_t* expr_ret_512 = NULL;
  rec(mod_512);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_513 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_513 = leaf(RET);
      #if DAISHO_SOURCEINFO
      expr_ret_513->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_513->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_513 = NULL;
    }

    expr_ret_512 = expr_ret_513;
    r = expr_ret_513;
  }

  // ModExprList 1
  if (expr_ret_512)
  {
    daisho_astnode_t* expr_ret_514 = NULL;
    expr_ret_514 = daisho_parse_expr(ctx);
    expr_ret_512 = expr_ret_514;
    e = expr_ret_514;
  }

  // ModExprList 2
  if (expr_ret_512)
  {
    // CodeExpr
    #define ret expr_ret_512
    ret = SUCC;

    rule=node(RET, r, e);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_512) rew(mod_512);
  expr_ret_511 = expr_ret_512 ? SUCC : NULL;
  if (!rule) rule = expr_ret_511;
  if (!expr_ret_511) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* pm = NULL;
  daisho_astnode_t* nl = NULL;
  #define rule expr_ret_515

  daisho_astnode_t* expr_ret_516 = NULL;
  daisho_astnode_t* expr_ret_515 = NULL;
  daisho_astnode_t* expr_ret_517 = NULL;
  rec(mod_517);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_518 = NULL;
    daisho_astnode_t* expr_ret_519 = NULL;

    rec(slash_519);

    // SlashExpr 0
    if (!expr_ret_519)
    {
      daisho_astnode_t* expr_ret_520 = NULL;
      rec(mod_520);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
        // Capturing PLUS.
        expr_ret_520 = leaf(PLUS);
        #if DAISHO_SOURCEINFO
        expr_ret_520->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_520->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_520 = NULL;
      }

      // ModExprList end
      if (!expr_ret_520) rew(mod_520);
      expr_ret_519 = expr_ret_520;
    }

    // SlashExpr 1
    if (!expr_ret_519)
    {
      daisho_astnode_t* expr_ret_521 = NULL;
      rec(mod_521);
      // ModExprList Forwarding
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
        // Capturing MINUS.
        expr_ret_521 = leaf(MINUS);
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
      expr_ret_519 = expr_ret_521;
    }

    // SlashExpr end
    if (!expr_ret_519) rew(slash_519);
    expr_ret_518 = expr_ret_519;

    // optional
    if (!expr_ret_518)
      expr_ret_518 = SUCC;
    expr_ret_517 = expr_ret_518;
    pm = expr_ret_518;
  }

  // ModExprList 1
  if (expr_ret_517)
  {
    daisho_astnode_t* expr_ret_522 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_522 = leaf(NUMLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_522->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_522->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_522 = NULL;
    }

    expr_ret_517 = expr_ret_522;
    nl = expr_ret_522;
  }

  // ModExprList 2
  if (expr_ret_517)
  {
    // CodeExpr
    #define ret expr_ret_517
    ret = SUCC;

    rule = nl;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_517) rew(mod_517);
  expr_ret_516 = expr_ret_517 ? SUCC : NULL;
  if (!rule) rule = expr_ret_516;
  if (!expr_ret_516) rule = NULL;
  rule_end:;
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlits(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* l = NULL;
  #define rule expr_ret_523

  daisho_astnode_t* expr_ret_524 = NULL;
  daisho_astnode_t* expr_ret_523 = NULL;
  daisho_astnode_t* expr_ret_525 = NULL;
  rec(mod_525);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_526 = NULL;
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

    expr_ret_525 = expr_ret_526;
    s = expr_ret_526;
  }

  // ModExprList 1
  if (expr_ret_525)
  {
    daisho_astnode_t* expr_ret_527 = NULL;
    // CodeExpr
    #define ret expr_ret_527
    ret = SUCC;

    ret=list(STRLITS);add(ret, s);

    #undef ret
    expr_ret_525 = expr_ret_527;
    l = expr_ret_527;
  }

  // ModExprList 2
  if (expr_ret_525)
  {
    daisho_astnode_t* expr_ret_528 = NULL;
    expr_ret_528 = SUCC;
    while (expr_ret_528)
    {
      daisho_astnode_t* expr_ret_529 = NULL;
      rec(mod_529);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_530 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
          // Capturing STRLIT.
          expr_ret_530 = leaf(STRLIT);
          #if DAISHO_SOURCEINFO
          expr_ret_530->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_530->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_530 = NULL;
        }

        expr_ret_529 = expr_ret_530;
        s = expr_ret_530;
      }

      // ModExprList 1
      if (expr_ret_529)
      {
        // CodeExpr
        #define ret expr_ret_529
        ret = SUCC;

        add(l, s);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_529) rew(mod_529);
      expr_ret_528 = expr_ret_529 ? SUCC : NULL;
    }

    expr_ret_528 = SUCC;
    expr_ret_525 = expr_ret_528;
  }

  // ModExprList 3
  if (expr_ret_525)
  {
    // CodeExpr
    #define ret expr_ret_525
    ret = SUCC;

    rule=l;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_525) rew(mod_525);
  expr_ret_524 = expr_ret_525 ? SUCC : NULL;
  if (!rule) rule = expr_ret_524;
  if (!expr_ret_524) rule = NULL;
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

