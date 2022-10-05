
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
#define PGEN_DEBUG 1

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
  DAISHO_TOK_FNIDENT,
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
// Tokens 1 through 90 are the ones you defined.
// This totals 92 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 92
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
  "DAISHO_TOK_FNIDENT",
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

    // Transition FNIDENT State Machine
    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_10 = 1;
      }
      else if (((smaut_state_10 == 1) | (smaut_state_10 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_10 = 2;
      }
      else if ((smaut_state_10 == 0) &
         (c == 43)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 0) &
         (c == 45)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 0) &
         (c == 47)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 0) &
         (c == 37)) {
          smaut_state_10 = 3;
      }
      else if ((smaut_state_10 == 0) &
         (c == 42)) {
          smaut_state_10 = 4;
      }
      else if ((smaut_state_10 == 4) &
         (c == 42)) {
          smaut_state_10 = 5;
      }
      else if ((smaut_state_10 == 0) &
         (c == 60)) {
          smaut_state_10 = 6;
      }
      else if ((smaut_state_10 == 6) &
         (c == 60)) {
          smaut_state_10 = 7;
      }
      else if ((smaut_state_10 == 0) &
         (c == 62)) {
          smaut_state_10 = 8;
      }
      else if ((smaut_state_10 == 8) &
         (c == 62)) {
          smaut_state_10 = 9;
      }
      else if ((smaut_state_10 == 0) &
         (c == 91)) {
          smaut_state_10 = 10;
      }
      else if ((smaut_state_10 == 10) &
         (c == 93)) {
          smaut_state_10 = 11;
      }
      else if ((smaut_state_10 == 0) &
         (c == 40)) {
          smaut_state_10 = 12;
      }
      else if ((smaut_state_10 == 12) &
         (c == 41)) {
          smaut_state_10 = 13;
      }
      else if ((smaut_state_10 == 0) &
         (c == 35)) {
          smaut_state_10 = 14;
      }
      else if ((smaut_state_10 == 0) &
         (c == 126)) {
          smaut_state_10 = 15;
      }
      else if ((smaut_state_10 == 0) &
         (c == 33)) {
          smaut_state_10 = 16;
      }
      else if ((smaut_state_10 == 0) &
         (c == 61)) {
          smaut_state_10 = 17;
      }
      else if (((smaut_state_10 == 16) | (smaut_state_10 == 17)) &
         (c == 61)) {
          smaut_state_10 = 18;
      }
      else {
        smaut_state_10 = -1;
      }

      // Check accept
      if ((smaut_state_10 == 1) | (smaut_state_10 == 2) | (smaut_state_10 == 3) | (smaut_state_10 == 4) | (smaut_state_10 == 5) | (smaut_state_10 == 6) | (smaut_state_10 == 7) | (smaut_state_10 == 8) | (smaut_state_10 == 9) | (smaut_state_10 == 11)) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition NUMLIT State Machine
    if (smaut_state_11 != -1) {
      all_dead = 0;

      if (((smaut_state_11 == 0) | (smaut_state_11 == 1)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_11 = 1;
      }
      else if ((smaut_state_11 == 0) &
         (c == 46)) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 1) &
         (c == 46)) {
          smaut_state_11 = 3;
      }
      else if (((smaut_state_11 == 2) | (smaut_state_11 == 3)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_11 = 3;
      }
      else {
        smaut_state_11 = -1;
      }

      // Check accept
      if ((smaut_state_11 == 1) | (smaut_state_11 == 3)) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

    // Transition STRLIT State Machine
    if (smaut_state_12 != -1) {
      all_dead = 0;

      if ((smaut_state_12 == 0) &
         (c == 34)) {
          smaut_state_12 = 1;
      }
      else if ((smaut_state_12 == 1) &
         (c == 34)) {
          smaut_state_12 = 2;
      }
      else if ((smaut_state_12 == 1) &
         (c == 10)) {
          smaut_state_12 = 9;
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
      else {
        smaut_state_12 = -1;
      }

      // Check accept
      if (smaut_state_12 == 2) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    // Transition FSTRLIT State Machine
    if (smaut_state_13 != -1) {
      all_dead = 0;

      if ((smaut_state_13 == 0) &
         (c == 102)) {
          smaut_state_13 = 1;
      }
      else if ((smaut_state_13 == 1) &
         (c == 34)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 2) &
         (c == 34)) {
          smaut_state_13 = 4;
      }
      else if ((smaut_state_13 == 1) &
         (c == 10)) {
          smaut_state_13 = 9;
      }
      else if ((smaut_state_13 == 1) &
         (c == 92)) {
          smaut_state_13 = 3;
      }
      else if ((smaut_state_13 == 1) &
         (1)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 110)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 102)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 98)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 114)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 116)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 101)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 92)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 39)) {
          smaut_state_13 = 2;
      }
      else if ((smaut_state_13 == 3) &
         (c == 34)) {
          smaut_state_13 = 2;
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
    kind = DAISHO_TOK_FSTRLIT;
    max_munch = smaut_munch_size_13;
  }
  if (smaut_munch_size_12 >= max_munch) {
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_FNIDENT;
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
  DAISHO_NODE_CAPLIST,
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
  DAISHO_NODE_FSTRLIT,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_TYPEIDENT,
  DAISHO_NODE_TRAITIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 98
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_CIDENT",
  "DAISHO_NODE_CFNDECL",
  "DAISHO_NODE_TMPLDECL",
  "DAISHO_NODE_IF",
  "DAISHO_NODE_IFELSE",
  "DAISHO_NODE_CAPLIST",
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
  "DAISHO_NODE_FSTRLIT",
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (n0 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p)\n", daisho_nodekind_name[kind], (void*)n0);
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (n0 == SUCC) | (n1 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1);
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2);
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (!n3) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC) | (n3 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2, (void*)n3);
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
daisho_astnode_t const * const SUCC = ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t));
  if ((!n0) | (!n1) | (!n2) | (!n3) | (!n4) | (n0 == SUCC) | (n1 == SUCC) | (n2 == SUCC) | (n3 == SUCC) | (n4 == SUCC))
    fprintf(stderr, "Invalid arguments: node(%s, %p, %p, %p, %p, %p)\n", daisho_nodekind_name[kind], (void*)n0, (void*)n1, (void*)n2, (void*)n3, (void*)n4);
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

#include "../asthelpers.h"


#if PGEN_DEBUG
#define PGEN_DEBUG_WIDTH 14
typedef struct {
  const char* rule_name;
  size_t pos;
} dbg_entry;

static struct {
  dbg_entry rules[500];
  size_t size;
  int status;
  int first;
} dbg_stack;

#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
static inline void dbg_display(daisho_parser_ctx* ctx, const char* last) {
  if (!dbg_stack.first) dbg_stack.first = 1;
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
  if (dbg_stack.status == -1) {
    printf("\x1b[31m"); // Red
    printf("Failed: %s\n", last);
  } else if (dbg_stack.status == 0) {
    printf("\x1b[34m"); // Blue
    printf("Entering: %s\n", last);
  } else if (dbg_stack.status == 1) {
    printf("\x1b[32m"); // Green
    printf("Accepted: %s\n", last);
  } else {
    printf("\x1b[33m"); // Green
    printf("SUCCED: %s\n", last), exit(1);
  }
  printf("\x1b[0m"); // Clear Formatting

  // Write labels and line.
  for (size_t i = 0; i < width; i++) putchar('-');  // Write following lines
  for (size_t i = height; i --> 0;) {
    putchar(' ');

    // Print rule stack
    if (i < dbg_stack.size) {
      printf("%-14s", dbg_stack.rules[i].rule_name);
    } else {
      for (size_t sp = 0; sp < 14; sp++) putchar(' ');
    }

    printf(" | "); // 3 Separator chars

    // Print tokens
    size_t remaining_tokens = ctx->len - ctx->pos;
    if (i < remaining_tokens) {
      const char* name = daisho_tokenkind_name[ctx->tokens[ctx->pos + i].kind];
      size_t ns = strlen(name);
      size_t remaining = rightwidth - ns;
      printf("%s", name);
      for (size_t sp = 0; sp < remaining; sp++) putchar(' ');
    }

    putchar(' ');
    putchar('\n');
  }
}

static inline void dbg_enter(daisho_parser_ctx* ctx, const char* name, size_t pos) {
  dbg_stack.rules[dbg_stack.size++] = (dbg_entry){name, pos};
  dbg_stack.status = 0;
  dbg_display(ctx, name);
}

static inline void dbg_accept(daisho_parser_ctx* ctx, const char* accpeting) {
  dbg_stack.size--;
  dbg_stack.status = 1;
  dbg_display(ctx, accpeting);
}

static inline void dbg_reject(daisho_parser_ctx* ctx, const char* rejecting) {
  dbg_stack.size--;
  dbg_stack.status = -1;
  dbg_display(ctx, rejecting);
}
static inline void dbg_succ(daisho_parser_ctx* ctx, const char* succing) {
  dbg_stack.size--;
  dbg_stack.status = 2;
  dbg_display(ctx, succing);
}
#endif /* PGEN_DEBUG */

static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  #define rule expr_ret_0

  daisho_astnode_t* expr_ret_1 = NULL;
  daisho_astnode_t* expr_ret_0 = NULL;
  dbg_enter(ctx, "file", ctx->pos);
  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_3 = NULL;
    dbg_enter(ctx, "SHEBANG", ctx->pos);
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

    if (expr_ret_3) dbg_accept(ctx, "SHEBANG"); else dbg_reject(ctx, "SHEBANG");
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

    rec(slash_4);

    // SlashExpr 0
    if (!expr_ret_4)
    {
      daisho_astnode_t* expr_ret_5 = NULL;
      rec(mod_5);
      // ModExprList Forwarding
      expr_ret_5 = daisho_parse_expr(ctx);
      // ModExprList end
      if (!expr_ret_5) rew(mod_5);
      expr_ret_4 = expr_ret_5;
    }

    // SlashExpr 1
    if (!expr_ret_4)
    {
      daisho_astnode_t* expr_ret_6 = NULL;
      rec(mod_6);
      // ModExprList Forwarding
      expr_ret_6 = daisho_parse_decl(ctx);
      // ModExprList end
      if (!expr_ret_6) rew(mod_6);
      expr_ret_4 = expr_ret_6;
    }

    // SlashExpr end
    if (!expr_ret_4) rew(slash_4);
    expr_ret_2 = expr_ret_4;

  }

  // ModExprList 2
  if (expr_ret_2)
  {
    daisho_astnode_t* expr_ret_7 = NULL;
    expr_ret_7 = SUCC;
    while (expr_ret_7)
    {
      daisho_astnode_t* expr_ret_8 = NULL;
      rec(mod_8);
      // ModExprList 0
      {
        dbg_enter(ctx, "SEMI", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
          // Not capturing SEMI.
          expr_ret_8 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_8 = NULL;
        }

        if (expr_ret_8) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
      }

      // ModExprList 1
      if (expr_ret_8)
      {
        daisho_astnode_t* expr_ret_9 = NULL;

        rec(slash_9);

        // SlashExpr 0
        if (!expr_ret_9)
        {
          daisho_astnode_t* expr_ret_10 = NULL;
          rec(mod_10);
          // ModExprList Forwarding
          expr_ret_10 = daisho_parse_expr(ctx);
          // ModExprList end
          if (!expr_ret_10) rew(mod_10);
          expr_ret_9 = expr_ret_10;
        }

        // SlashExpr 1
        if (!expr_ret_9)
        {
          daisho_astnode_t* expr_ret_11 = NULL;
          rec(mod_11);
          // ModExprList Forwarding
          expr_ret_11 = daisho_parse_decl(ctx);
          // ModExprList end
          if (!expr_ret_11) rew(mod_11);
          expr_ret_9 = expr_ret_11;
        }

        // SlashExpr end
        if (!expr_ret_9) rew(slash_9);
        expr_ret_8 = expr_ret_9;

      }

      // ModExprList end
      if (!expr_ret_8) rew(mod_8);
      expr_ret_7 = expr_ret_8 ? SUCC : NULL;
    }

    expr_ret_7 = SUCC;
    expr_ret_2 = expr_ret_7;
  }

  // ModExprList end
  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2 ? SUCC : NULL;
  if (!rule) rule = expr_ret_1;
  if (!expr_ret_1) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "file");
  else if (rule) dbg_accept(ctx, "file");
  else dbg_reject(ctx, "file");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_decl(daisho_parser_ctx* ctx) {
  #define rule expr_ret_12

  daisho_astnode_t* expr_ret_13 = NULL;
  daisho_astnode_t* expr_ret_12 = NULL;
  dbg_enter(ctx, "decl", ctx->pos);
  daisho_astnode_t* expr_ret_14 = NULL;

  rec(slash_14);

  // SlashExpr 0
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_15 = NULL;
    rec(mod_15);
    // ModExprList Forwarding
    expr_ret_15 = daisho_parse_nsdecl(ctx);
    // ModExprList end
    if (!expr_ret_15) rew(mod_15);
    expr_ret_14 = expr_ret_15;
  }

  // SlashExpr 1
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_16 = NULL;
    rec(mod_16);
    // ModExprList Forwarding
    expr_ret_16 = daisho_parse_structdecl(ctx);
    // ModExprList end
    if (!expr_ret_16) rew(mod_16);
    expr_ret_14 = expr_ret_16;
  }

  // SlashExpr 2
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_17 = NULL;
    rec(mod_17);
    // ModExprList Forwarding
    expr_ret_17 = daisho_parse_uniondecl(ctx);
    // ModExprList end
    if (!expr_ret_17) rew(mod_17);
    expr_ret_14 = expr_ret_17;
  }

  // SlashExpr 3
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_18 = NULL;
    rec(mod_18);
    // ModExprList Forwarding
    expr_ret_18 = daisho_parse_traitdecl(ctx);
    // ModExprList end
    if (!expr_ret_18) rew(mod_18);
    expr_ret_14 = expr_ret_18;
  }

  // SlashExpr 4
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_19 = NULL;
    rec(mod_19);
    // ModExprList Forwarding
    expr_ret_19 = daisho_parse_impldecl(ctx);
    // ModExprList end
    if (!expr_ret_19) rew(mod_19);
    expr_ret_14 = expr_ret_19;
  }

  // SlashExpr 5
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_20 = NULL;
    rec(mod_20);
    // ModExprList Forwarding
    expr_ret_20 = daisho_parse_ctypedecl(ctx);
    // ModExprList end
    if (!expr_ret_20) rew(mod_20);
    expr_ret_14 = expr_ret_20;
  }

  // SlashExpr 6
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_21 = NULL;
    rec(mod_21);
    // ModExprList Forwarding
    expr_ret_21 = daisho_parse_aliasdecl(ctx);
    // ModExprList end
    if (!expr_ret_21) rew(mod_21);
    expr_ret_14 = expr_ret_21;
  }

  // SlashExpr 7
  if (!expr_ret_14)
  {
    daisho_astnode_t* expr_ret_22 = NULL;
    rec(mod_22);
    // ModExprList Forwarding
    expr_ret_22 = daisho_parse_fndecl(ctx);
    // ModExprList end
    if (!expr_ret_22) rew(mod_22);
    expr_ret_14 = expr_ret_22;
  }

  // SlashExpr end
  if (!expr_ret_14) rew(slash_14);
  expr_ret_13 = expr_ret_14;

  if (!rule) rule = expr_ret_13;
  if (!expr_ret_13) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "decl");
  else if (rule) dbg_accept(ctx, "decl");
  else dbg_reject(ctx, "decl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_23

  daisho_astnode_t* expr_ret_24 = NULL;
  daisho_astnode_t* expr_ret_23 = NULL;
  dbg_enter(ctx, "nsdecl", ctx->pos);
  daisho_astnode_t* expr_ret_25 = NULL;
  rec(mod_25);
  // ModExprList 0
  {
    dbg_enter(ctx, "NAMESPACE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_25 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_25 = NULL;
    }

    if (expr_ret_25) dbg_accept(ctx, "NAMESPACE"); else dbg_reject(ctx, "NAMESPACE");
  }

  // ModExprList 1
  if (expr_ret_25)
  {
    daisho_astnode_t* expr_ret_26 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_26 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_26->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_26->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_26 = NULL;
    }

    if (expr_ret_26) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_25 = expr_ret_26;
    t = expr_ret_26;
  }

  // ModExprList 2
  if (expr_ret_25)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_25
    ret = SUCC;

    rule=node(NAMESPACEDECL, t);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_25) rew(mod_25);
  expr_ret_24 = expr_ret_25 ? SUCC : NULL;
  if (!rule) rule = expr_ret_24;
  if (!expr_ret_24) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "nsdecl");
  else if (rule) dbg_accept(ctx, "nsdecl");
  else dbg_reject(ctx, "nsdecl");
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
  #define rule expr_ret_27

  daisho_astnode_t* expr_ret_28 = NULL;
  daisho_astnode_t* expr_ret_27 = NULL;
  dbg_enter(ctx, "structdecl", ctx->pos);
  daisho_astnode_t* expr_ret_29 = NULL;
  rec(mod_29);
  // ModExprList 0
  {
    dbg_enter(ctx, "STRUCT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      // Not capturing STRUCT.
      expr_ret_29 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

    if (expr_ret_29) dbg_accept(ctx, "STRUCT"); else dbg_reject(ctx, "STRUCT");
  }

  // ModExprList 1
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_30 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_30 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_30->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_30->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_30 = NULL;
    }

    if (expr_ret_30) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_29 = expr_ret_30;
    id = expr_ret_30;
  }

  // ModExprList 2
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_31 = NULL;
    expr_ret_31 = daisho_parse_tmpldecl(ctx);
    // optional
    if (!expr_ret_31)
      expr_ret_31 = SUCC;
    expr_ret_29 = expr_ret_31;
    tmpl = expr_ret_31;
  }

  // ModExprList 3
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_32 = NULL;
    daisho_astnode_t* expr_ret_33 = NULL;
    rec(mod_33);
    // ModExprList 0
    {
      dbg_enter(ctx, "IMPL", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_33 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_33 = NULL;
      }

      if (expr_ret_33) dbg_accept(ctx, "IMPL"); else dbg_reject(ctx, "IMPL");
    }

    // ModExprList 1
    if (expr_ret_33)
    {
      expr_ret_33 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_33)
    {
      daisho_astnode_t* expr_ret_34 = NULL;
      expr_ret_34 = SUCC;
      while (expr_ret_34)
      {
        daisho_astnode_t* expr_ret_35 = NULL;
        rec(mod_35);
        // ModExprList 0
        {
          dbg_enter(ctx, "COMMA", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_35 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_35 = NULL;
          }

          if (expr_ret_35) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
        }

        // ModExprList 1
        if (expr_ret_35)
        {
          expr_ret_35 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_35) rew(mod_35);
        expr_ret_34 = expr_ret_35 ? SUCC : NULL;
      }

      expr_ret_34 = SUCC;
      expr_ret_33 = expr_ret_34;
    }

    // ModExprList end
    if (!expr_ret_33) rew(mod_33);
    expr_ret_32 = expr_ret_33 ? SUCC : NULL;
    // optional
    if (!expr_ret_32)
      expr_ret_32 = SUCC;
    expr_ret_29 = expr_ret_32;
    impl = expr_ret_32;
  }

  // ModExprList 4
  if (expr_ret_29)
  {
    dbg_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_29 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

    if (expr_ret_29) dbg_accept(ctx, "LCBRACK"); else dbg_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_36 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_36
    ret = SUCC;

    ret=list(MEMBERLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_29 = expr_ret_36;
    members = expr_ret_36;
  }

  // ModExprList 6
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_37 = NULL;
    expr_ret_37 = SUCC;
    while (expr_ret_37)
    {
      daisho_astnode_t* expr_ret_38 = NULL;
      rec(mod_38);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_39 = NULL;
        expr_ret_39 = daisho_parse_typemember(ctx);
        expr_ret_38 = expr_ret_39;
        m = expr_ret_39;
      }

      // ModExprList 1
      if (expr_ret_38)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_38
        ret = SUCC;

        add(members, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_38) rew(mod_38);
      expr_ret_37 = expr_ret_38 ? SUCC : NULL;
    }

    expr_ret_37 = SUCC;
    expr_ret_29 = expr_ret_37;
  }

  // ModExprList 7
  if (expr_ret_29)
  {
    dbg_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_29 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_29 = NULL;
    }

    if (expr_ret_29) dbg_accept(ctx, "RCBRACK"); else dbg_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_29)
  {
    daisho_astnode_t* expr_ret_40 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_40
    ret = SUCC;

    n = node(STRUCTDECL, id, members);
              rule = has(tmpl) ? node(TMPLSTRUCT, tmpl, n) : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_29 = expr_ret_40;
    n = expr_ret_40;
  }

  // ModExprList end
  if (!expr_ret_29) rew(mod_29);
  expr_ret_28 = expr_ret_29 ? SUCC : NULL;
  if (!rule) rule = expr_ret_28;
  if (!expr_ret_28) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "structdecl");
  else if (rule) dbg_accept(ctx, "structdecl");
  else dbg_reject(ctx, "structdecl");
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
  #define rule expr_ret_41

  daisho_astnode_t* expr_ret_42 = NULL;
  daisho_astnode_t* expr_ret_41 = NULL;
  dbg_enter(ctx, "uniondecl", ctx->pos);
  daisho_astnode_t* expr_ret_43 = NULL;
  rec(mod_43);
  // ModExprList 0
  {
    dbg_enter(ctx, "UNION", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      // Not capturing UNION.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) dbg_accept(ctx, "UNION"); else dbg_reject(ctx, "UNION");
  }

  // ModExprList 1
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_44 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_44 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_44->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_44->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_44 = NULL;
    }

    if (expr_ret_44) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_43 = expr_ret_44;
    id = expr_ret_44;
  }

  // ModExprList 2
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_45 = NULL;
    expr_ret_45 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_45)
      expr_ret_45 = SUCC;
    expr_ret_43 = expr_ret_45;
    tmpl = expr_ret_45;
  }

  // ModExprList 3
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_46 = NULL;
    daisho_astnode_t* expr_ret_47 = NULL;
    rec(mod_47);
    // ModExprList 0
    {
      dbg_enter(ctx, "IMPL", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_47 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_47 = NULL;
      }

      if (expr_ret_47) dbg_accept(ctx, "IMPL"); else dbg_reject(ctx, "IMPL");
    }

    // ModExprList 1
    if (expr_ret_47)
    {
      expr_ret_47 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_47)
    {
      daisho_astnode_t* expr_ret_48 = NULL;
      expr_ret_48 = SUCC;
      while (expr_ret_48)
      {
        daisho_astnode_t* expr_ret_49 = NULL;
        rec(mod_49);
        // ModExprList 0
        {
          dbg_enter(ctx, "COMMA", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_49 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_49 = NULL;
          }

          if (expr_ret_49) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
        }

        // ModExprList 1
        if (expr_ret_49)
        {
          expr_ret_49 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_49) rew(mod_49);
        expr_ret_48 = expr_ret_49 ? SUCC : NULL;
      }

      expr_ret_48 = SUCC;
      expr_ret_47 = expr_ret_48;
    }

    // ModExprList end
    if (!expr_ret_47) rew(mod_47);
    expr_ret_46 = expr_ret_47 ? SUCC : NULL;
    // optional
    if (!expr_ret_46)
      expr_ret_46 = SUCC;
    expr_ret_43 = expr_ret_46;
    impl = expr_ret_46;
  }

  // ModExprList 4
  if (expr_ret_43)
  {
    dbg_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) dbg_accept(ctx, "LCBRACK"); else dbg_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_50 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_50
    ret = SUCC;

    ret=list(MEMBERLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_43 = expr_ret_50;
    members = expr_ret_50;
  }

  // ModExprList 6
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_51 = NULL;
    expr_ret_51 = SUCC;
    while (expr_ret_51)
    {
      daisho_astnode_t* expr_ret_52 = NULL;
      rec(mod_52);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_53 = NULL;
        expr_ret_53 = daisho_parse_typemember(ctx);
        expr_ret_52 = expr_ret_53;
        m = expr_ret_53;
      }

      // ModExprList 1
      if (expr_ret_52)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_52
        ret = SUCC;

        add(members, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_52) rew(mod_52);
      expr_ret_51 = expr_ret_52 ? SUCC : NULL;
    }

    expr_ret_51 = SUCC;
    expr_ret_43 = expr_ret_51;
  }

  // ModExprList 7
  if (expr_ret_43)
  {
    dbg_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

    if (expr_ret_43) dbg_accept(ctx, "RCBRACK"); else dbg_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_54 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_54
    ret = SUCC;

    n = node(UNIONDECL, id, members);
              rule = has(tmpl) ? node(TMPLUNION, tmpl, n) : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_43 = expr_ret_54;
    n = expr_ret_54;
  }

  // ModExprList end
  if (!expr_ret_43) rew(mod_43);
  expr_ret_42 = expr_ret_43 ? SUCC : NULL;
  if (!rule) rule = expr_ret_42;
  if (!expr_ret_42) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "uniondecl");
  else if (rule) dbg_accept(ctx, "uniondecl");
  else dbg_reject(ctx, "uniondecl");
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
  #define rule expr_ret_55

  daisho_astnode_t* expr_ret_56 = NULL;
  daisho_astnode_t* expr_ret_55 = NULL;
  dbg_enter(ctx, "traitdecl", ctx->pos);
  daisho_astnode_t* expr_ret_57 = NULL;
  rec(mod_57);
  // ModExprList 0
  {
    dbg_enter(ctx, "TRAIT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      // Not capturing TRAIT.
      expr_ret_57 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_57 = NULL;
    }

    if (expr_ret_57) dbg_accept(ctx, "TRAIT"); else dbg_reject(ctx, "TRAIT");
  }

  // ModExprList 1
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_58 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_58 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_58->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_58->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

    if (expr_ret_58) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_57 = expr_ret_58;
    id = expr_ret_58;
  }

  // ModExprList 2
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_59 = NULL;
    expr_ret_59 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_59)
      expr_ret_59 = SUCC;
    expr_ret_57 = expr_ret_59;
    tmpl = expr_ret_59;
  }

  // ModExprList 3
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_60 = NULL;
    daisho_astnode_t* expr_ret_61 = NULL;
    rec(mod_61);
    // ModExprList 0
    {
      dbg_enter(ctx, "IMPL", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_61 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_61 = NULL;
      }

      if (expr_ret_61) dbg_accept(ctx, "IMPL"); else dbg_reject(ctx, "IMPL");
    }

    // ModExprList 1
    if (expr_ret_61)
    {
      expr_ret_61 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_61)
    {
      daisho_astnode_t* expr_ret_62 = NULL;
      expr_ret_62 = SUCC;
      while (expr_ret_62)
      {
        daisho_astnode_t* expr_ret_63 = NULL;
        rec(mod_63);
        // ModExprList 0
        {
          dbg_enter(ctx, "COMMA", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_63 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_63 = NULL;
          }

          if (expr_ret_63) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
        }

        // ModExprList 1
        if (expr_ret_63)
        {
          expr_ret_63 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_63) rew(mod_63);
        expr_ret_62 = expr_ret_63 ? SUCC : NULL;
      }

      expr_ret_62 = SUCC;
      expr_ret_61 = expr_ret_62;
    }

    // ModExprList end
    if (!expr_ret_61) rew(mod_61);
    expr_ret_60 = expr_ret_61 ? SUCC : NULL;
    // optional
    if (!expr_ret_60)
      expr_ret_60 = SUCC;
    expr_ret_57 = expr_ret_60;
    impl = expr_ret_60;
  }

  // ModExprList 4
  if (expr_ret_57)
  {
    dbg_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_57 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_57 = NULL;
    }

    if (expr_ret_57) dbg_accept(ctx, "LCBRACK"); else dbg_reject(ctx, "LCBRACK");
  }

  // ModExprList 5
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_64 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_64
    ret = SUCC;

    ret=list(MEMBERLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_57 = expr_ret_64;
    members = expr_ret_64;
  }

  // ModExprList 6
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_65 = NULL;
    expr_ret_65 = SUCC;
    while (expr_ret_65)
    {
      daisho_astnode_t* expr_ret_66 = NULL;
      rec(mod_66);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_67 = NULL;
        expr_ret_67 = daisho_parse_fnmember(ctx);
        expr_ret_66 = expr_ret_67;
        m = expr_ret_67;
      }

      // ModExprList 1
      if (expr_ret_66)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_66
        ret = SUCC;

        add(members, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_66) rew(mod_66);
      expr_ret_65 = expr_ret_66 ? SUCC : NULL;
    }

    expr_ret_65 = SUCC;
    expr_ret_57 = expr_ret_65;
  }

  // ModExprList 7
  if (expr_ret_57)
  {
    dbg_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_57 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_57 = NULL;
    }

    if (expr_ret_57) dbg_accept(ctx, "RCBRACK"); else dbg_reject(ctx, "RCBRACK");
  }

  // ModExprList 8
  if (expr_ret_57)
  {
    daisho_astnode_t* expr_ret_68 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_68
    ret = SUCC;

    n = node(TRAITDECL, id, members);
              rule = has(tmpl) ? node(TMPLTRAIT, tmpl, n) : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_57 = expr_ret_68;
    n = expr_ret_68;
  }

  // ModExprList end
  if (!expr_ret_57) rew(mod_57);
  expr_ret_56 = expr_ret_57 ? SUCC : NULL;
  if (!rule) rule = expr_ret_56;
  if (!expr_ret_56) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "traitdecl");
  else if (rule) dbg_accept(ctx, "traitdecl");
  else dbg_reject(ctx, "traitdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_69

  daisho_astnode_t* expr_ret_70 = NULL;
  daisho_astnode_t* expr_ret_69 = NULL;
  dbg_enter(ctx, "impldecl", ctx->pos);
  daisho_astnode_t* expr_ret_71 = NULL;
  rec(mod_71);
  // ModExprList 0
  {
    dbg_enter(ctx, "IMPL", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_71 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_71 = NULL;
    }

    if (expr_ret_71) dbg_accept(ctx, "IMPL"); else dbg_reject(ctx, "IMPL");
  }

  // ModExprList 1
  if (expr_ret_71)
  {
    daisho_astnode_t* expr_ret_72 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_72 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_72->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_72->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_72 = NULL;
    }

    if (expr_ret_72) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_71 = expr_ret_72;
    tt = expr_ret_72;
  }

  // ModExprList 2
  if (expr_ret_71)
  {
    daisho_astnode_t* expr_ret_73 = NULL;
    expr_ret_73 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_73)
      expr_ret_73 = SUCC;
    expr_ret_71 = expr_ret_73;
  }

  // ModExprList 3
  if (expr_ret_71)
  {
    dbg_enter(ctx, "FOR", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_71 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_71 = NULL;
    }

    if (expr_ret_71) dbg_accept(ctx, "FOR"); else dbg_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_71)
  {
    daisho_astnode_t* expr_ret_74 = NULL;
    expr_ret_74 = daisho_parse_type(ctx);
    expr_ret_71 = expr_ret_74;
    ft = expr_ret_74;
  }

  // ModExprList 5
  if (expr_ret_71)
  {
    dbg_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_71 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_71 = NULL;
    }

    if (expr_ret_71) dbg_accept(ctx, "LCBRACK"); else dbg_reject(ctx, "LCBRACK");
  }

  // ModExprList 6
  if (expr_ret_71)
  {
    daisho_astnode_t* expr_ret_75 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_75
    ret = SUCC;

    ret=list(MEMBERLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_71 = expr_ret_75;
    members = expr_ret_75;
  }

  // ModExprList 7
  if (expr_ret_71)
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
        expr_ret_78 = daisho_parse_fnmember(ctx);
        expr_ret_77 = expr_ret_78;
        m = expr_ret_78;
      }

      // ModExprList 1
      if (expr_ret_77)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_77
        ret = SUCC;

        add(members, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_77) rew(mod_77);
      expr_ret_76 = expr_ret_77 ? SUCC : NULL;
    }

    expr_ret_76 = SUCC;
    expr_ret_71 = expr_ret_76;
  }

  // ModExprList 8
  if (expr_ret_71)
  {
    dbg_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_71 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_71 = NULL;
    }

    if (expr_ret_71) dbg_accept(ctx, "RCBRACK"); else dbg_reject(ctx, "RCBRACK");
  }

  // ModExprList end
  if (!expr_ret_71) rew(mod_71);
  expr_ret_70 = expr_ret_71 ? SUCC : NULL;
  if (!rule) rule = expr_ret_70;
  if (!expr_ret_70) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "impldecl");
  else if (rule) dbg_accept(ctx, "impldecl");
  else dbg_reject(ctx, "impldecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  #define rule expr_ret_79

  daisho_astnode_t* expr_ret_80 = NULL;
  daisho_astnode_t* expr_ret_79 = NULL;
  dbg_enter(ctx, "typemember", ctx->pos);
  daisho_astnode_t* expr_ret_81 = NULL;
  rec(mod_81);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_82 = NULL;
    expr_ret_82 = daisho_parse_type(ctx);
    expr_ret_81 = expr_ret_82;
    t = expr_ret_82;
  }

  // ModExprList 1
  if (expr_ret_81)
  {
    daisho_astnode_t* expr_ret_83 = NULL;
    dbg_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_83 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_83->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_83->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_83 = NULL;
    }

    if (expr_ret_83) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    expr_ret_81 = expr_ret_83;
    v = expr_ret_83;
  }

  // ModExprList 2
  if (expr_ret_81)
  {
    dbg_enter(ctx, "SEMI", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_81 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_81 = NULL;
    }

    if (expr_ret_81) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
  }

  // ModExprList 3
  if (expr_ret_81)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_81
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_81) rew(mod_81);
  expr_ret_80 = expr_ret_81 ? SUCC : NULL;
  if (!rule) rule = expr_ret_80;
  if (!expr_ret_80) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "typemember");
  else if (rule) dbg_accept(ctx, "typemember");
  else dbg_reject(ctx, "typemember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_84

  daisho_astnode_t* expr_ret_85 = NULL;
  daisho_astnode_t* expr_ret_84 = NULL;
  dbg_enter(ctx, "fnmember", ctx->pos);
  daisho_astnode_t* expr_ret_86 = NULL;
  rec(mod_86);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_87 = NULL;
    daisho_astnode_t* expr_ret_88 = NULL;

    rec(slash_88);

    // SlashExpr 0
    if (!expr_ret_88)
    {
      daisho_astnode_t* expr_ret_89 = NULL;
      rec(mod_89);
      // ModExprList Forwarding
      expr_ret_89 = daisho_parse_fndecl(ctx);
      // ModExprList end
      if (!expr_ret_89) rew(mod_89);
      expr_ret_88 = expr_ret_89;
    }

    // SlashExpr 1
    if (!expr_ret_88)
    {
      daisho_astnode_t* expr_ret_90 = NULL;
      rec(mod_90);
      // ModExprList Forwarding
      expr_ret_90 = daisho_parse_cfndecl(ctx);
      // ModExprList end
      if (!expr_ret_90) rew(mod_90);
      expr_ret_88 = expr_ret_90;
    }

    // SlashExpr 2
    if (!expr_ret_88)
    {
      daisho_astnode_t* expr_ret_91 = NULL;
      rec(mod_91);
      // ModExprList Forwarding
      expr_ret_91 = daisho_parse_fnproto(ctx);
      // ModExprList end
      if (!expr_ret_91) rew(mod_91);
      expr_ret_88 = expr_ret_91;
    }

    // SlashExpr end
    if (!expr_ret_88) rew(slash_88);
    expr_ret_87 = expr_ret_88;

    expr_ret_86 = expr_ret_87;
    r = expr_ret_87;
  }

  // ModExprList 1
  if (expr_ret_86)
  {
    dbg_enter(ctx, "SEMI", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_86 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_86 = NULL;
    }

    if (expr_ret_86) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
  }

  // ModExprList 2
  if (expr_ret_86)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_86
    ret = SUCC;

    rule=r;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_86) rew(mod_86);
  expr_ret_85 = expr_ret_86 ? SUCC : NULL;
  if (!rule) rule = expr_ret_85;
  if (!expr_ret_85) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fnmember");
  else if (rule) dbg_accept(ctx, "fnmember");
  else dbg_reject(ctx, "fnmember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypedecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_92

  daisho_astnode_t* expr_ret_93 = NULL;
  daisho_astnode_t* expr_ret_92 = NULL;
  dbg_enter(ctx, "ctypedecl", ctx->pos);
  daisho_astnode_t* expr_ret_94 = NULL;
  rec(mod_94);
  // ModExprList 0
  {
    dbg_enter(ctx, "CTYPE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      // Not capturing CTYPE.
      expr_ret_94 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_94 = NULL;
    }

    if (expr_ret_94) dbg_accept(ctx, "CTYPE"); else dbg_reject(ctx, "CTYPE");
  }

  // ModExprList 1
  if (expr_ret_94)
  {
    daisho_astnode_t* expr_ret_95 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_95 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_95->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_95->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_95 = NULL;
    }

    if (expr_ret_95) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_94 = expr_ret_95;
    t = expr_ret_95;
  }

  // ModExprList 2
  if (expr_ret_94)
  {
    daisho_astnode_t* expr_ret_96 = NULL;
    dbg_enter(ctx, "CIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Capturing CIDENT.
      expr_ret_96 = leaf(CIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_96->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_96->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_96 = NULL;
    }

    if (expr_ret_96) dbg_accept(ctx, "CIDENT"); else dbg_reject(ctx, "CIDENT");
    expr_ret_94 = expr_ret_96;
    c = expr_ret_96;
  }

  // ModExprList 3
  if (expr_ret_94)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_94
    ret = SUCC;

    rule=srepr(node(CTYPEDECL, t, c), "ctypedecl");

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_94) rew(mod_94);
  expr_ret_93 = expr_ret_94 ? SUCC : NULL;
  if (!rule) rule = expr_ret_93;
  if (!expr_ret_93) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "ctypedecl");
  else if (rule) dbg_accept(ctx, "ctypedecl");
  else dbg_reject(ctx, "ctypedecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_aliasdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* f = NULL;
  #define rule expr_ret_97

  daisho_astnode_t* expr_ret_98 = NULL;
  daisho_astnode_t* expr_ret_97 = NULL;
  dbg_enter(ctx, "aliasdecl", ctx->pos);
  daisho_astnode_t* expr_ret_99 = NULL;
  rec(mod_99);
  // ModExprList 0
  {
    dbg_enter(ctx, "ALIAS", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALIAS) {
      // Not capturing ALIAS.
      expr_ret_99 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_99 = NULL;
    }

    if (expr_ret_99) dbg_accept(ctx, "ALIAS"); else dbg_reject(ctx, "ALIAS");
  }

  // ModExprList 1
  if (expr_ret_99)
  {
    daisho_astnode_t* expr_ret_100 = NULL;
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Capturing TYPEIDENT.
      expr_ret_100 = leaf(TYPEIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_100->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_100->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_100 = NULL;
    }

    if (expr_ret_100) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
    expr_ret_99 = expr_ret_100;
    t = expr_ret_100;
  }

  // ModExprList 2
  if (expr_ret_99)
  {
    daisho_astnode_t* expr_ret_101 = NULL;
    expr_ret_101 = daisho_parse_type(ctx);
    expr_ret_99 = expr_ret_101;
    f = expr_ret_101;
  }

  // ModExprList 3
  if (expr_ret_99)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_99
    ret = SUCC;

    rule=srepr(node(ALIASDECL, t, f), "aliasdecl");

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_99) rew(mod_99);
  expr_ret_98 = expr_ret_99 ? SUCC : NULL;
  if (!rule) rule = expr_ret_98;
  if (!expr_ret_98) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "aliasdecl");
  else if (rule) dbg_accept(ctx, "aliasdecl");
  else dbg_reject(ctx, "aliasdecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rt = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_102

  daisho_astnode_t* expr_ret_103 = NULL;
  daisho_astnode_t* expr_ret_102 = NULL;
  dbg_enter(ctx, "fndecl", ctx->pos);
  daisho_astnode_t* expr_ret_104 = NULL;
  rec(mod_104);
  // ModExprList 0
  {
    dbg_enter(ctx, "FN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Not capturing FN.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

    if (expr_ret_104) dbg_accept(ctx, "FN"); else dbg_reject(ctx, "FN");
  }

  // ModExprList 1
  if (expr_ret_104)
  {
    daisho_astnode_t* expr_ret_105 = NULL;
    expr_ret_105 = daisho_parse_type(ctx);
    expr_ret_104 = expr_ret_105;
    rt = expr_ret_105;
  }

  // ModExprList 2
  if (expr_ret_104)
  {
    daisho_astnode_t* expr_ret_106 = NULL;
    dbg_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_106 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_106->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_106->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_106 = NULL;
    }

    if (expr_ret_106) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    expr_ret_104 = expr_ret_106;
    t = expr_ret_106;
  }

  // ModExprList 3
  if (expr_ret_104)
  {
    daisho_astnode_t* expr_ret_107 = NULL;
    expr_ret_107 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_107)
      expr_ret_107 = SUCC;
    expr_ret_104 = expr_ret_107;
    t = expr_ret_107;
  }

  // ModExprList 4
  if (expr_ret_104)
  {
    dbg_enter(ctx, "OPEN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

    if (expr_ret_104) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
  }

  // ModExprList 5
  if (expr_ret_104)
  {
    dbg_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

    if (expr_ret_104) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
  }

  // ModExprList 6
  if (expr_ret_104)
  {
    daisho_astnode_t* expr_ret_108 = NULL;
    expr_ret_108 = daisho_parse_expr(ctx);
    expr_ret_104 = expr_ret_108;
    e = expr_ret_108;
  }

  // ModExprList 7
  if (expr_ret_104)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_104
    ret = SUCC;

    rule=srepr(node(FNDECL, rt, t, e), "fndecl");

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_104) rew(mod_104);
  expr_ret_103 = expr_ret_104 ? SUCC : NULL;
  if (!rule) rule = expr_ret_103;
  if (!expr_ret_103) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fndecl");
  else if (rule) dbg_accept(ctx, "fndecl");
  else dbg_reject(ctx, "fndecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* rt = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_109

  daisho_astnode_t* expr_ret_110 = NULL;
  daisho_astnode_t* expr_ret_109 = NULL;
  dbg_enter(ctx, "cfndecl", ctx->pos);
  daisho_astnode_t* expr_ret_111 = NULL;
  rec(mod_111);
  // ModExprList 0
  {
    dbg_enter(ctx, "CFN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFN) {
      // Not capturing CFN.
      expr_ret_111 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_111 = NULL;
    }

    if (expr_ret_111) dbg_accept(ctx, "CFN"); else dbg_reject(ctx, "CFN");
  }

  // ModExprList 1
  if (expr_ret_111)
  {
    daisho_astnode_t* expr_ret_112 = NULL;
    expr_ret_112 = daisho_parse_type(ctx);
    expr_ret_111 = expr_ret_112;
    rt = expr_ret_112;
  }

  // ModExprList 2
  if (expr_ret_111)
  {
    daisho_astnode_t* expr_ret_113 = NULL;
    dbg_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_113 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_113->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_113->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_113 = NULL;
    }

    if (expr_ret_113) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    expr_ret_111 = expr_ret_113;
    t = expr_ret_113;
  }

  // ModExprList 3
  if (expr_ret_111)
  {
    daisho_astnode_t* expr_ret_114 = NULL;
    expr_ret_114 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_114)
      expr_ret_114 = SUCC;
    expr_ret_111 = expr_ret_114;
    t = expr_ret_114;
  }

  // ModExprList 4
  if (expr_ret_111)
  {
    dbg_enter(ctx, "OPEN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_111 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_111 = NULL;
    }

    if (expr_ret_111) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
  }

  // ModExprList 5
  if (expr_ret_111)
  {
    dbg_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_111 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_111 = NULL;
    }

    if (expr_ret_111) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
  }

  // ModExprList 6
  if (expr_ret_111)
  {
    daisho_astnode_t* expr_ret_115 = NULL;
    expr_ret_115 = daisho_parse_expr(ctx);
    expr_ret_111 = expr_ret_115;
    e = expr_ret_115;
  }

  // ModExprList 7
  if (expr_ret_111)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_111
    ret = SUCC;

    rule=srepr(node(CFNDECL, rt, t, e), "cfndecl");

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_111) rew(mod_111);
  expr_ret_110 = expr_ret_111 ? SUCC : NULL;
  if (!rule) rule = expr_ret_110;
  if (!expr_ret_110) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "cfndecl");
  else if (rule) dbg_accept(ctx, "cfndecl");
  else dbg_reject(ctx, "cfndecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_116

  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_116 = NULL;
  dbg_enter(ctx, "tmpldecl", ctx->pos);
  daisho_astnode_t* expr_ret_118 = NULL;
  rec(mod_118);
  // ModExprList 0
  {
    dbg_enter(ctx, "LT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_118 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_118 = NULL;
    }

    if (expr_ret_118) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
  }

  // ModExprList 1
  if (expr_ret_118)
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_119
    ret = SUCC;

    rule=ret=list(TMPLDECL);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_118 = expr_ret_119;
    l = expr_ret_119;
  }

  // ModExprList 2
  if (expr_ret_118)
  {
    daisho_astnode_t* expr_ret_120 = NULL;
    expr_ret_120 = daisho_parse_tmpldeclmember(ctx);
    // optional
    if (!expr_ret_120)
      expr_ret_120 = SUCC;
    expr_ret_118 = expr_ret_120;
    m = expr_ret_120;
  }

  // ModExprList 3
  if (expr_ret_118)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_118
    ret = SUCC;

    if (has(m)) add(l, m);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_118)
  {
    daisho_astnode_t* expr_ret_121 = NULL;
    expr_ret_121 = SUCC;
    while (expr_ret_121)
    {
      daisho_astnode_t* expr_ret_122 = NULL;
      rec(mod_122);
      // ModExprList 0
      {
        dbg_enter(ctx, "COMMA", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_122 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_122 = NULL;
        }

        if (expr_ret_122) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
      }

      // ModExprList 1
      if (expr_ret_122)
      {
        daisho_astnode_t* expr_ret_123 = NULL;
        expr_ret_123 = daisho_parse_tmpldeclmember(ctx);
        expr_ret_122 = expr_ret_123;
        m = expr_ret_123;
      }

      // ModExprList 2
      if (expr_ret_122)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_122
        ret = SUCC;

        add(l, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_122) rew(mod_122);
      expr_ret_121 = expr_ret_122 ? SUCC : NULL;
    }

    expr_ret_121 = SUCC;
    expr_ret_118 = expr_ret_121;
  }

  // ModExprList 5
  if (expr_ret_118)
  {
    daisho_astnode_t* expr_ret_124 = NULL;
    dbg_enter(ctx, "COMMA", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_124 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_124 = NULL;
    }

    if (expr_ret_124) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
    // optional
    if (!expr_ret_124)
      expr_ret_124 = SUCC;
    expr_ret_118 = expr_ret_124;
  }

  // ModExprList 6
  if (expr_ret_118)
  {
    dbg_enter(ctx, "GT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_118 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_118 = NULL;
    }

    if (expr_ret_118) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
  }

  // ModExprList end
  if (!expr_ret_118) rew(mod_118);
  expr_ret_117 = expr_ret_118 ? SUCC : NULL;
  if (!rule) rule = expr_ret_117;
  if (!expr_ret_117) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "tmpldecl");
  else if (rule) dbg_accept(ctx, "tmpldecl");
  else dbg_reject(ctx, "tmpldecl");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldeclmember(daisho_parser_ctx* ctx) {
  #define rule expr_ret_125

  daisho_astnode_t* expr_ret_126 = NULL;
  daisho_astnode_t* expr_ret_125 = NULL;
  dbg_enter(ctx, "tmpldeclmember", ctx->pos);
  daisho_astnode_t* expr_ret_127 = NULL;
  rec(mod_127);
  // ModExprList 0
  {
    expr_ret_127 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_127)
  {
    dbg_enter(ctx, "TYPEIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
      // Not capturing TYPEIDENT.
      expr_ret_127 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_127 = NULL;
    }

    if (expr_ret_127) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
  }

  // ModExprList 2
  if (expr_ret_127)
  {
    daisho_astnode_t* expr_ret_128 = NULL;
    daisho_astnode_t* expr_ret_129 = NULL;
    rec(mod_129);
    // ModExprList 0
    {
      dbg_enter(ctx, "EQ", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
        // Not capturing EQ.
        expr_ret_129 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_129 = NULL;
      }

      if (expr_ret_129) dbg_accept(ctx, "EQ"); else dbg_reject(ctx, "EQ");
    }

    // ModExprList 1
    if (expr_ret_129)
    {
      expr_ret_129 = daisho_parse_type(ctx);
    }

    // ModExprList end
    if (!expr_ret_129) rew(mod_129);
    expr_ret_128 = expr_ret_129 ? SUCC : NULL;
    // optional
    if (!expr_ret_128)
      expr_ret_128 = SUCC;
    expr_ret_127 = expr_ret_128;
  }

  // ModExprList end
  if (!expr_ret_127) rew(mod_127);
  expr_ret_126 = expr_ret_127 ? SUCC : NULL;
  if (!rule) rule = expr_ret_126;
  if (!expr_ret_126) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "tmpldeclmember");
  else if (rule) dbg_accept(ctx, "tmpldeclmember");
  else dbg_reject(ctx, "tmpldeclmember");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* m = NULL;
  #define rule expr_ret_130

  daisho_astnode_t* expr_ret_131 = NULL;
  daisho_astnode_t* expr_ret_130 = NULL;
  dbg_enter(ctx, "tmplexpand", ctx->pos);
  daisho_astnode_t* expr_ret_132 = NULL;
  rec(mod_132);
  // ModExprList 0
  {
    dbg_enter(ctx, "LT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_132 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_132 = NULL;
    }

    if (expr_ret_132) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
  }

  // ModExprList 1
  if (expr_ret_132)
  {
    daisho_astnode_t* expr_ret_133 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_133
    ret = SUCC;

    rule=ret=list(TMPLEXPANDLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_132 = expr_ret_133;
    l = expr_ret_133;
  }

  // ModExprList 2
  if (expr_ret_132)
  {
    daisho_astnode_t* expr_ret_134 = NULL;
    expr_ret_134 = daisho_parse_tmplex(ctx);
    // optional
    if (!expr_ret_134)
      expr_ret_134 = SUCC;
    expr_ret_132 = expr_ret_134;
    m = expr_ret_134;
  }

  // ModExprList 3
  if (expr_ret_132)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_132
    ret = SUCC;

    if (has(m)) add(l, m);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_132)
  {
    daisho_astnode_t* expr_ret_135 = NULL;
    expr_ret_135 = SUCC;
    while (expr_ret_135)
    {
      daisho_astnode_t* expr_ret_136 = NULL;
      rec(mod_136);
      // ModExprList 0
      {
        dbg_enter(ctx, "COMMA", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_136 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_136 = NULL;
        }

        if (expr_ret_136) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
      }

      // ModExprList 1
      if (expr_ret_136)
      {
        daisho_astnode_t* expr_ret_137 = NULL;
        expr_ret_137 = daisho_parse_tmplex(ctx);
        expr_ret_136 = expr_ret_137;
        m = expr_ret_137;
      }

      // ModExprList 2
      if (expr_ret_136)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_136
        ret = SUCC;

        add(l, m);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_136) rew(mod_136);
      expr_ret_135 = expr_ret_136 ? SUCC : NULL;
    }

    expr_ret_135 = SUCC;
    expr_ret_132 = expr_ret_135;
  }

  // ModExprList 5
  if (expr_ret_132)
  {
    daisho_astnode_t* expr_ret_138 = NULL;
    dbg_enter(ctx, "COMMA", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_138 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_138 = NULL;
    }

    if (expr_ret_138) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
    // optional
    if (!expr_ret_138)
      expr_ret_138 = SUCC;
    expr_ret_132 = expr_ret_138;
  }

  // ModExprList 6
  if (expr_ret_132)
  {
    dbg_enter(ctx, "GT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_132 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_132 = NULL;
    }

    if (expr_ret_132) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
  }

  // ModExprList end
  if (!expr_ret_132) rew(mod_132);
  expr_ret_131 = expr_ret_132 ? SUCC : NULL;
  if (!rule) rule = expr_ret_131;
  if (!expr_ret_131) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "tmplexpand");
  else if (rule) dbg_accept(ctx, "tmplexpand");
  else dbg_reject(ctx, "tmplexpand");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplex(daisho_parser_ctx* ctx) {
  #define rule expr_ret_139

  daisho_astnode_t* expr_ret_140 = NULL;
  daisho_astnode_t* expr_ret_139 = NULL;
  dbg_enter(ctx, "tmplex", ctx->pos);
  daisho_astnode_t* expr_ret_141 = NULL;

  rec(slash_141);

  // SlashExpr 0
  if (!expr_ret_141)
  {
    daisho_astnode_t* expr_ret_142 = NULL;
    rec(mod_142);
    // ModExprList Forwarding
    expr_ret_142 = daisho_parse_type(ctx);
    // ModExprList end
    if (!expr_ret_142) rew(mod_142);
    expr_ret_141 = expr_ret_142;
  }

  // SlashExpr 1
  if (!expr_ret_141)
  {
    daisho_astnode_t* expr_ret_143 = NULL;
    rec(mod_143);
    // ModExprList Forwarding
    dbg_enter(ctx, "NUMLIT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_143 = leaf(NUMLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_143->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_143->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_143 = NULL;
    }

    if (expr_ret_143) dbg_accept(ctx, "NUMLIT"); else dbg_reject(ctx, "NUMLIT");
    // ModExprList end
    if (!expr_ret_143) rew(mod_143);
    expr_ret_141 = expr_ret_143;
  }

  // SlashExpr end
  if (!expr_ret_141) rew(slash_141);
  expr_ret_140 = expr_ret_141;

  if (!rule) rule = expr_ret_140;
  if (!expr_ret_140) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "tmplex");
  else if (rule) dbg_accept(ctx, "tmplex");
  else dbg_reject(ctx, "tmplex");
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
  #define rule expr_ret_144

  daisho_astnode_t* expr_ret_145 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
  dbg_enter(ctx, "type", ctx->pos);
  daisho_astnode_t* expr_ret_146 = NULL;

  rec(slash_146);

  // SlashExpr 0
  if (!expr_ret_146)
  {
    daisho_astnode_t* expr_ret_147 = NULL;
    rec(mod_147);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_148 = NULL;
      dbg_enter(ctx, "VOIDTYPE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_148 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_148->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_148->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_148 = NULL;
      }

      if (expr_ret_148) dbg_accept(ctx, "VOIDTYPE"); else dbg_reject(ctx, "VOIDTYPE");
      expr_ret_147 = expr_ret_148;
      v = expr_ret_148;
    }

    // ModExprList 1
    if (expr_ret_147)
    {
      daisho_astnode_t* expr_ret_149 = NULL;
      dbg_enter(ctx, "STAR", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_149 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_149 = NULL;
      }

      if (expr_ret_149) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
      // invert
      expr_ret_149 = expr_ret_149 ? NULL : SUCC;
      expr_ret_147 = expr_ret_149;
    }

    // ModExprList 2
    if (expr_ret_147)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_147
      ret = SUCC;

      rule=set_depth(v, 0);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_147) rew(mod_147);
    expr_ret_146 = expr_ret_147 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_146)
  {
    daisho_astnode_t* expr_ret_150 = NULL;
    rec(mod_150);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_151 = NULL;
      expr_ret_151 = daisho_parse_voidptr(ctx);
      expr_ret_150 = expr_ret_151;
      p = expr_ret_151;
    }

    // ModExprList 1
    if (expr_ret_150)
    {
      daisho_astnode_t* expr_ret_152 = NULL;
      expr_ret_152 = SUCC;
      while (expr_ret_152)
      {
        daisho_astnode_t* expr_ret_153 = NULL;
        rec(mod_153);
        // ModExprList 0
        {
          dbg_enter(ctx, "STAR", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_153 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_153 = NULL;
          }

          if (expr_ret_153) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
        }

        // ModExprList 1
        if (expr_ret_153)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_153
          ret = SUCC;

          depth++;

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_153) rew(mod_153);
        expr_ret_152 = expr_ret_153 ? SUCC : NULL;
      }

      expr_ret_152 = SUCC;
      expr_ret_150 = expr_ret_152;
    }

    // ModExprList 2
    if (expr_ret_150)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_150
      ret = SUCC;

      rule=set_depth(p, depth);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_150) rew(mod_150);
    expr_ret_146 = expr_ret_150 ? SUCC : NULL;
  }

  // SlashExpr 2
  if (!expr_ret_146)
  {
    daisho_astnode_t* expr_ret_154 = NULL;
    rec(mod_154);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_155 = NULL;
      dbg_enter(ctx, "SELFTYPE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
        // Capturing SELFTYPE.
        expr_ret_155 = leaf(SELFTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_155->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_155->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_155 = NULL;
      }

      if (expr_ret_155) dbg_accept(ctx, "SELFTYPE"); else dbg_reject(ctx, "SELFTYPE");
      expr_ret_154 = expr_ret_155;
      s = expr_ret_155;
    }

    // ModExprList 1
    if (expr_ret_154)
    {
      daisho_astnode_t* expr_ret_156 = NULL;
      expr_ret_156 = SUCC;
      while (expr_ret_156)
      {
        daisho_astnode_t* expr_ret_157 = NULL;
        rec(mod_157);
        // ModExprList 0
        {
          dbg_enter(ctx, "STAR", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_157 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_157 = NULL;
          }

          if (expr_ret_157) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
        }

        // ModExprList 1
        if (expr_ret_157)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_157
          ret = SUCC;

          depth++;

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_157) rew(mod_157);
        expr_ret_156 = expr_ret_157 ? SUCC : NULL;
      }

      expr_ret_156 = SUCC;
      expr_ret_154 = expr_ret_156;
    }

    // ModExprList 2
    if (expr_ret_154)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_154
      ret = SUCC;

      rule=set_depth(s, depth);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_154) rew(mod_154);
    expr_ret_146 = expr_ret_154 ? SUCC : NULL;
  }

  // SlashExpr 3
  if (!expr_ret_146)
  {
    daisho_astnode_t* expr_ret_158 = NULL;
    rec(mod_158);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_159 = NULL;
      expr_ret_159 = daisho_parse_fntype(ctx);
      expr_ret_158 = expr_ret_159;
      f = expr_ret_159;
    }

    // ModExprList 1
    if (expr_ret_158)
    {
      daisho_astnode_t* expr_ret_160 = NULL;
      expr_ret_160 = SUCC;
      while (expr_ret_160)
      {
        daisho_astnode_t* expr_ret_161 = NULL;
        rec(mod_161);
        // ModExprList 0
        {
          dbg_enter(ctx, "STAR", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_161 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_161 = NULL;
          }

          if (expr_ret_161) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
        }

        // ModExprList 1
        if (expr_ret_161)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_161
          ret = SUCC;

          depth++;

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_161) rew(mod_161);
        expr_ret_160 = expr_ret_161 ? SUCC : NULL;
      }

      expr_ret_160 = SUCC;
      expr_ret_158 = expr_ret_160;
    }

    // ModExprList 2
    if (expr_ret_158)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_158
      ret = SUCC;

      rule=set_depth(f, depth);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_158) rew(mod_158);
    expr_ret_146 = expr_ret_158 ? SUCC : NULL;
  }

  // SlashExpr 4
  if (!expr_ret_146)
  {
    daisho_astnode_t* expr_ret_162 = NULL;
    rec(mod_162);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_163 = NULL;
      expr_ret_163 = daisho_parse_ttexpand(ctx);
      expr_ret_162 = expr_ret_163;
      t = expr_ret_163;
    }

    // ModExprList 1
    if (expr_ret_162)
    {
      daisho_astnode_t* expr_ret_164 = NULL;
      expr_ret_164 = SUCC;
      while (expr_ret_164)
      {
        daisho_astnode_t* expr_ret_165 = NULL;
        rec(mod_165);
        // ModExprList 0
        {
          dbg_enter(ctx, "STAR", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_165 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_165 = NULL;
          }

          if (expr_ret_165) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
        }

        // ModExprList 1
        if (expr_ret_165)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_165
          ret = SUCC;

          depth++;

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_165) rew(mod_165);
        expr_ret_164 = expr_ret_165 ? SUCC : NULL;
      }

      expr_ret_164 = SUCC;
      expr_ret_162 = expr_ret_164;
    }

    // ModExprList 2
    if (expr_ret_162)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_162
      ret = SUCC;

      rule=set_depth(t, depth);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_162) rew(mod_162);
    expr_ret_146 = expr_ret_162 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_146) rew(slash_146);
  expr_ret_145 = expr_ret_146;

  if (!rule) rule = expr_ret_145;
  if (!expr_ret_145) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "type");
  else if (rule) dbg_accept(ctx, "type");
  else dbg_reject(ctx, "type");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_voidptr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  #define rule expr_ret_166

  daisho_astnode_t* expr_ret_167 = NULL;
  daisho_astnode_t* expr_ret_166 = NULL;
  dbg_enter(ctx, "voidptr", ctx->pos);
  daisho_astnode_t* expr_ret_168 = NULL;

  rec(slash_168);

  // SlashExpr 0
  if (!expr_ret_168)
  {
    daisho_astnode_t* expr_ret_169 = NULL;
    rec(mod_169);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_170 = NULL;
      dbg_enter(ctx, "VOIDPTR", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDPTR) {
        // Capturing VOIDPTR.
        expr_ret_170 = leaf(VOIDPTR);
        #if DAISHO_SOURCEINFO
        expr_ret_170->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_170->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_170 = NULL;
      }

      if (expr_ret_170) dbg_accept(ctx, "VOIDPTR"); else dbg_reject(ctx, "VOIDPTR");
      expr_ret_169 = expr_ret_170;
      v = expr_ret_170;
    }

    // ModExprList 1
    if (expr_ret_169)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_169
      ret = SUCC;

      rule=v;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_169) rew(mod_169);
    expr_ret_168 = expr_ret_169 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_168)
  {
    daisho_astnode_t* expr_ret_171 = NULL;
    rec(mod_171);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_172 = NULL;
      dbg_enter(ctx, "VOIDTYPE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_172 = leaf(VOIDTYPE);
        #if DAISHO_SOURCEINFO
        expr_ret_172->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_172->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_172 = NULL;
      }

      if (expr_ret_172) dbg_accept(ctx, "VOIDTYPE"); else dbg_reject(ctx, "VOIDTYPE");
      expr_ret_171 = expr_ret_172;
      v = expr_ret_172;
    }

    // ModExprList 1
    if (expr_ret_171)
    {
      daisho_astnode_t* expr_ret_173 = NULL;
      dbg_enter(ctx, "STAR", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Capturing STAR.
        expr_ret_173 = leaf(STAR);
        #if DAISHO_SOURCEINFO
        expr_ret_173->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_173->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_173 = NULL;
      }

      if (expr_ret_173) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
      expr_ret_171 = expr_ret_173;
      s = expr_ret_173;
    }

    // ModExprList 2
    if (expr_ret_171)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_171
      ret = SUCC;

      rule=srepr(leaf(VOIDPTR), "VoidPtr");

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_171) rew(mod_171);
    expr_ret_168 = expr_ret_171 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_168) rew(slash_168);
  expr_ret_167 = expr_ret_168;

  if (!rule) rule = expr_ret_167;
  if (!expr_ret_167) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "voidptr");
  else if (rule) dbg_accept(ctx, "voidptr");
  else dbg_reject(ctx, "voidptr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ttexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_174

  daisho_astnode_t* expr_ret_175 = NULL;
  daisho_astnode_t* expr_ret_174 = NULL;
  dbg_enter(ctx, "ttexpand", ctx->pos);
  daisho_astnode_t* expr_ret_176 = NULL;
  rec(mod_176);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_177 = NULL;
    daisho_astnode_t* expr_ret_178 = NULL;

    rec(slash_178);

    // SlashExpr 0
    if (!expr_ret_178)
    {
      daisho_astnode_t* expr_ret_179 = NULL;
      rec(mod_179);
      // ModExprList Forwarding
      dbg_enter(ctx, "TYPEIDENT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TYPEIDENT) {
        // Capturing TYPEIDENT.
        expr_ret_179 = leaf(TYPEIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_179->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_179->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_179 = NULL;
      }

      if (expr_ret_179) dbg_accept(ctx, "TYPEIDENT"); else dbg_reject(ctx, "TYPEIDENT");
      // ModExprList end
      if (!expr_ret_179) rew(mod_179);
      expr_ret_178 = expr_ret_179;
    }

    // SlashExpr 1
    if (!expr_ret_178)
    {
      daisho_astnode_t* expr_ret_180 = NULL;
      rec(mod_180);
      // ModExprList Forwarding
      dbg_enter(ctx, "TRAITIDENT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAITIDENT) {
        // Capturing TRAITIDENT.
        expr_ret_180 = leaf(TRAITIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_180->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_180->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_180 = NULL;
      }

      if (expr_ret_180) dbg_accept(ctx, "TRAITIDENT"); else dbg_reject(ctx, "TRAITIDENT");
      // ModExprList end
      if (!expr_ret_180) rew(mod_180);
      expr_ret_178 = expr_ret_180;
    }

    // SlashExpr end
    if (!expr_ret_178) rew(slash_178);
    expr_ret_177 = expr_ret_178;

    expr_ret_176 = expr_ret_177;
    i = expr_ret_177;
  }

  // ModExprList 1
  if (expr_ret_176)
  {
    daisho_astnode_t* expr_ret_181 = NULL;
    expr_ret_181 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_181)
      expr_ret_181 = SUCC;
    expr_ret_176 = expr_ret_181;
    t = expr_ret_181;
  }

  // ModExprList 2
  if (expr_ret_176)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_176
    ret = SUCC;

    rule = has(t) ? node(TMPLTYPE, t, i) : i;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_176) rew(mod_176);
  expr_ret_175 = expr_ret_176 ? SUCC : NULL;
  if (!rule) rule = expr_ret_175;
  if (!expr_ret_175) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "ttexpand");
  else if (rule) dbg_accept(ctx, "ttexpand");
  else dbg_reject(ctx, "ttexpand");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* l = NULL;
  #define rule expr_ret_182

  daisho_astnode_t* expr_ret_183 = NULL;
  daisho_astnode_t* expr_ret_182 = NULL;
  dbg_enter(ctx, "fntype", ctx->pos);
  daisho_astnode_t* expr_ret_184 = NULL;

  rec(slash_184);

  // SlashExpr 0
  if (!expr_ret_184)
  {
    daisho_astnode_t* expr_ret_185 = NULL;
    rec(mod_185);
    // ModExprList 0
    {
      dbg_enter(ctx, "FNTYPE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_185 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_185 = NULL;
      }

      if (expr_ret_185) dbg_accept(ctx, "FNTYPE"); else dbg_reject(ctx, "FNTYPE");
    }

    // ModExprList 1
    if (expr_ret_185)
    {
      dbg_enter(ctx, "LT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        // Not capturing LT.
        expr_ret_185 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_185 = NULL;
      }

      if (expr_ret_185) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
    }

    // ModExprList 2
    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_186 = NULL;
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_186
      ret = SUCC;

      ret=list(ARGLIST);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
      expr_ret_185 = expr_ret_186;
      argtypes = expr_ret_186;
    }

    // ModExprList 3
    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_187 = NULL;
      daisho_astnode_t* expr_ret_188 = NULL;
      rec(mod_188);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_189 = NULL;
        expr_ret_189 = daisho_parse_type(ctx);
        expr_ret_188 = expr_ret_189;
        t = expr_ret_189;
      }

      // ModExprList 1
      if (expr_ret_188)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_188
        ret = SUCC;

        add(argtypes, t);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_188) rew(mod_188);
      expr_ret_187 = expr_ret_188 ? SUCC : NULL;
      // optional
      if (!expr_ret_187)
        expr_ret_187 = SUCC;
      expr_ret_185 = expr_ret_187;
    }

    // ModExprList 4
    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_190 = NULL;
      expr_ret_190 = SUCC;
      while (expr_ret_190)
      {
        daisho_astnode_t* expr_ret_191 = NULL;
        rec(mod_191);
        // ModExprList 0
        {
          dbg_enter(ctx, "COMMA", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_191 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_191 = NULL;
          }

          if (expr_ret_191) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
        }

        // ModExprList 1
        if (expr_ret_191)
        {
          daisho_astnode_t* expr_ret_192 = NULL;
          expr_ret_192 = daisho_parse_type(ctx);
          expr_ret_191 = expr_ret_192;
          t = expr_ret_192;
        }

        // ModExprList 2
        if (expr_ret_191)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_191
          ret = SUCC;

          add(argtypes, t);

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_191) rew(mod_191);
        expr_ret_190 = expr_ret_191 ? SUCC : NULL;
      }

      expr_ret_190 = SUCC;
      expr_ret_185 = expr_ret_190;
    }

    // ModExprList 5
    if (expr_ret_185)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_185
      ret = SUCC;

      if (!argtypes->num_children) add(argtypes, leaf(VOIDTYPE));

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 6
    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_193 = NULL;
      daisho_astnode_t* expr_ret_194 = NULL;
      rec(mod_194);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_195 = NULL;

        rec(slash_195);

        // SlashExpr 0
        if (!expr_ret_195)
        {
          daisho_astnode_t* expr_ret_196 = NULL;
          rec(mod_196);
          // ModExprList Forwarding
          dbg_enter(ctx, "ARROW", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
            // Not capturing ARROW.
            expr_ret_196 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_196 = NULL;
          }

          if (expr_ret_196) dbg_accept(ctx, "ARROW"); else dbg_reject(ctx, "ARROW");
          // ModExprList end
          if (!expr_ret_196) rew(mod_196);
          expr_ret_195 = expr_ret_196;
        }

        // SlashExpr 1
        if (!expr_ret_195)
        {
          daisho_astnode_t* expr_ret_197 = NULL;
          rec(mod_197);
          // ModExprList Forwarding
          dbg_enter(ctx, "SEMI", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_197 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_197 = NULL;
          }

          if (expr_ret_197) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
          // ModExprList end
          if (!expr_ret_197) rew(mod_197);
          expr_ret_195 = expr_ret_197;
        }

        // SlashExpr 2
        if (!expr_ret_195)
        {
          daisho_astnode_t* expr_ret_198 = NULL;
          rec(mod_198);
          // ModExprList 0
          {
            dbg_enter(ctx, "EQ", ctx->pos);
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
              // Not capturing EQ.
              expr_ret_198 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_198 = NULL;
            }

            if (expr_ret_198) dbg_accept(ctx, "EQ"); else dbg_reject(ctx, "EQ");
          }

          // ModExprList 1
          if (expr_ret_198)
          {
            dbg_enter(ctx, "GT", ctx->pos);
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
              // Not capturing GT.
              expr_ret_198 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_198 = NULL;
            }

            if (expr_ret_198) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
          }

          // ModExprList end
          if (!expr_ret_198) rew(mod_198);
          expr_ret_195 = expr_ret_198 ? SUCC : NULL;
        }

        // SlashExpr end
        if (!expr_ret_195) rew(slash_195);
        expr_ret_194 = expr_ret_195;

      }

      // ModExprList 1
      if (expr_ret_194)
      {
        daisho_astnode_t* expr_ret_199 = NULL;
        expr_ret_199 = daisho_parse_type(ctx);
        expr_ret_194 = expr_ret_199;
        rettype = expr_ret_199;
      }

      // ModExprList end
      if (!expr_ret_194) rew(mod_194);
      expr_ret_193 = expr_ret_194 ? SUCC : NULL;
      // optional
      if (!expr_ret_193)
        expr_ret_193 = SUCC;
      expr_ret_185 = expr_ret_193;
    }

    // ModExprList 7
    if (expr_ret_185)
    {
      dbg_enter(ctx, "GT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Not capturing GT.
        expr_ret_185 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_185 = NULL;
      }

      if (expr_ret_185) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
    }

    // ModExprList 8
    if (expr_ret_185)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_185
      ret = SUCC;

      rule=node(FNTYPE, argtypes, !has(rettype) ? leaf(VOIDTYPE) : rettype);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_185) rew(mod_185);
    expr_ret_184 = expr_ret_185 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_184)
  {
    daisho_astnode_t* expr_ret_200 = NULL;
    rec(mod_200);
    // ModExprList 0
    {
      dbg_enter(ctx, "FNTYPE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Not capturing FNTYPE.
        expr_ret_200 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_200 = NULL;
      }

      if (expr_ret_200) dbg_accept(ctx, "FNTYPE"); else dbg_reject(ctx, "FNTYPE");
    }

    // ModExprList 1
    if (expr_ret_200)
    {
      daisho_astnode_t* expr_ret_201 = NULL;
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_201
      ret = SUCC;

      l=list(ARGLIST);add(l, leaf(VOIDTYPE));

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
      expr_ret_200 = expr_ret_201;
      l = expr_ret_201;
    }

    // ModExprList 2
    if (expr_ret_200)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_200
      ret = SUCC;

      rule=node(FNTYPE, l, leaf(VOIDTYPE));

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_200) rew(mod_200);
    expr_ret_184 = expr_ret_200 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_184) rew(slash_184);
  expr_ret_183 = expr_ret_184;

  if (!rule) rule = expr_ret_183;
  if (!expr_ret_183) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fntype");
  else if (rule) dbg_accept(ctx, "fntype");
  else dbg_reject(ctx, "fntype");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  #define rule expr_ret_202

  daisho_astnode_t* expr_ret_203 = NULL;
  daisho_astnode_t* expr_ret_202 = NULL;
  dbg_enter(ctx, "fnproto", ctx->pos);
  daisho_astnode_t* expr_ret_204 = NULL;
  rec(mod_204);
  // ModExprList 0
  {
    expr_ret_204 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_204)
  {
    dbg_enter(ctx, "OPEN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_204 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_204 = NULL;
    }

    if (expr_ret_204) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
  }

  // ModExprList 2
  if (expr_ret_204)
  {
    daisho_astnode_t* expr_ret_205 = NULL;
    expr_ret_205 = daisho_parse_fnarg(ctx);
    // optional
    if (!expr_ret_205)
      expr_ret_205 = SUCC;
    expr_ret_204 = expr_ret_205;
  }

  // ModExprList 3
  if (expr_ret_204)
  {
    daisho_astnode_t* expr_ret_206 = NULL;
    expr_ret_206 = SUCC;
    while (expr_ret_206)
    {
      daisho_astnode_t* expr_ret_207 = NULL;
      rec(mod_207);
      // ModExprList 0
      {
        dbg_enter(ctx, "COMMA", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_207 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_207 = NULL;
        }

        if (expr_ret_207) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
      }

      // ModExprList 1
      if (expr_ret_207)
      {
        expr_ret_207 = daisho_parse_fnarg(ctx);
      }

      // ModExprList end
      if (!expr_ret_207) rew(mod_207);
      expr_ret_206 = expr_ret_207 ? SUCC : NULL;
    }

    expr_ret_206 = SUCC;
    expr_ret_204 = expr_ret_206;
  }

  // ModExprList 4
  if (expr_ret_204)
  {
    dbg_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_204 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_204 = NULL;
    }

    if (expr_ret_204) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_204) rew(mod_204);
  expr_ret_203 = expr_ret_204 ? SUCC : NULL;
  if (!rule) rule = expr_ret_203;
  if (!expr_ret_203) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fnproto");
  else if (rule) dbg_accept(ctx, "fnproto");
  else dbg_reject(ctx, "fnproto");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  #define rule expr_ret_208

  daisho_astnode_t* expr_ret_209 = NULL;
  daisho_astnode_t* expr_ret_208 = NULL;
  dbg_enter(ctx, "fnarg", ctx->pos);
  daisho_astnode_t* expr_ret_210 = NULL;
  rec(mod_210);
  // ModExprList 0
  {
    expr_ret_210 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_210)
  {
    daisho_astnode_t* expr_ret_211 = NULL;
    daisho_astnode_t* expr_ret_212 = NULL;
    rec(mod_212);
    // ModExprList 0
    {
      dbg_enter(ctx, "VARIDENT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_212 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_212 = NULL;
      }

      if (expr_ret_212) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    }

    // ModExprList 1
    if (expr_ret_212)
    {
      daisho_astnode_t* expr_ret_213 = NULL;
      expr_ret_213 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_213)
        expr_ret_213 = SUCC;
      expr_ret_212 = expr_ret_213;
    }

    // ModExprList end
    if (!expr_ret_212) rew(mod_212);
    expr_ret_211 = expr_ret_212 ? SUCC : NULL;
    // optional
    if (!expr_ret_211)
      expr_ret_211 = SUCC;
    expr_ret_210 = expr_ret_211;
  }

  // ModExprList end
  if (!expr_ret_210) rew(mod_210);
  expr_ret_209 = expr_ret_210 ? SUCC : NULL;
  if (!rule) rule = expr_ret_209;
  if (!expr_ret_209) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fnarg");
  else if (rule) dbg_accept(ctx, "fnarg");
  else dbg_reject(ctx, "fnarg");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx) {
  #define rule expr_ret_214

  daisho_astnode_t* expr_ret_215 = NULL;
  daisho_astnode_t* expr_ret_214 = NULL;
  dbg_enter(ctx, "fnbody", ctx->pos);
  daisho_astnode_t* expr_ret_216 = NULL;
  rec(mod_216);
  // ModExprList Forwarding
  expr_ret_216 = daisho_parse_expr(ctx);
  // ModExprList end
  if (!expr_ret_216) rew(mod_216);
  expr_ret_215 = expr_ret_216;
  if (!rule) rule = expr_ret_215;
  if (!expr_ret_215) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fnbody");
  else if (rule) dbg_accept(ctx, "fnbody");
  else dbg_reject(ctx, "fnbody");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_217

  daisho_astnode_t* expr_ret_218 = NULL;
  daisho_astnode_t* expr_ret_217 = NULL;
  dbg_enter(ctx, "expr", ctx->pos);
  daisho_astnode_t* expr_ret_219 = NULL;
  rec(mod_219);
  // ModExprList Forwarding
  expr_ret_219 = daisho_parse_ifeexpr(ctx);
  // ModExprList end
  if (!expr_ret_219) rew(mod_219);
  expr_ret_218 = expr_ret_219;
  if (!rule) rule = expr_ret_218;
  if (!expr_ret_218) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "expr");
  else if (rule) dbg_accept(ctx, "expr");
  else dbg_reject(ctx, "expr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ifeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cond = NULL;
  daisho_astnode_t* ex = NULL;
  daisho_astnode_t* eex = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_220

  daisho_astnode_t* expr_ret_221 = NULL;
  daisho_astnode_t* expr_ret_220 = NULL;
  dbg_enter(ctx, "ifeexpr", ctx->pos);
  daisho_astnode_t* expr_ret_222 = NULL;

  rec(slash_222);

  // SlashExpr 0
  if (!expr_ret_222)
  {
    daisho_astnode_t* expr_ret_223 = NULL;
    rec(mod_223);
    // ModExprList 0
    {
      dbg_enter(ctx, "IF", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IF) {
        // Not capturing IF.
        expr_ret_223 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_223 = NULL;
      }

      if (expr_ret_223) dbg_accept(ctx, "IF"); else dbg_reject(ctx, "IF");
    }

    // ModExprList 1
    if (expr_ret_223)
    {
      daisho_astnode_t* expr_ret_224 = NULL;
      expr_ret_224 = daisho_parse_ternexpr(ctx);
      expr_ret_223 = expr_ret_224;
      cond = expr_ret_224;
    }

    // ModExprList 2
    if (expr_ret_223)
    {
      daisho_astnode_t* expr_ret_225 = NULL;
      expr_ret_225 = daisho_parse_expr(ctx);
      expr_ret_223 = expr_ret_225;
      ex = expr_ret_225;
    }

    // ModExprList 3
    if (expr_ret_223)
    {
      daisho_astnode_t* expr_ret_226 = NULL;
      daisho_astnode_t* expr_ret_227 = NULL;
      rec(mod_227);
      // ModExprList 0
      {
        dbg_enter(ctx, "ELSE", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ELSE) {
          // Not capturing ELSE.
          expr_ret_227 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_227 = NULL;
        }

        if (expr_ret_227) dbg_accept(ctx, "ELSE"); else dbg_reject(ctx, "ELSE");
      }

      // ModExprList 1
      if (expr_ret_227)
      {
        daisho_astnode_t* expr_ret_228 = NULL;
        expr_ret_228 = daisho_parse_expr(ctx);
        expr_ret_227 = expr_ret_228;
        eex = expr_ret_228;
      }

      // ModExprList end
      if (!expr_ret_227) rew(mod_227);
      expr_ret_226 = expr_ret_227 ? SUCC : NULL;
      // optional
      if (!expr_ret_226)
        expr_ret_226 = SUCC;
      expr_ret_223 = expr_ret_226;
    }

    // ModExprList 4
    if (expr_ret_223)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_223
      ret = SUCC;

      rule= !has(eex) ? srepr(node(IF, cond, ex), "if") : srepr(node(IFELSE, cond, ex, eex), "if-else");

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_223) rew(mod_223);
    expr_ret_222 = expr_ret_223 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_222)
  {
    daisho_astnode_t* expr_ret_229 = NULL;
    rec(mod_229);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_230 = NULL;
      expr_ret_230 = daisho_parse_forexpr(ctx);
      expr_ret_229 = expr_ret_230;
      n = expr_ret_230;
    }

    // ModExprList 1
    if (expr_ret_229)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_229
      ret = SUCC;

      rule=n;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_229) rew(mod_229);
    expr_ret_222 = expr_ret_229 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_222) rew(slash_222);
  expr_ret_221 = expr_ret_222;

  if (!rule) rule = expr_ret_221;
  if (!expr_ret_221) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "ifeexpr");
  else if (rule) dbg_accept(ctx, "ifeexpr");
  else dbg_reject(ctx, "ifeexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* sn = NULL;
  #define rule expr_ret_231

  daisho_astnode_t* expr_ret_232 = NULL;
  daisho_astnode_t* expr_ret_231 = NULL;
  dbg_enter(ctx, "forexpr", ctx->pos);
  daisho_astnode_t* expr_ret_233 = NULL;

  rec(slash_233);

  // SlashExpr 0
  if (!expr_ret_233)
  {
    daisho_astnode_t* expr_ret_234 = NULL;
    rec(mod_234);
    // ModExprList 0
    {
      dbg_enter(ctx, "FOR", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_234 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_234 = NULL;
      }

      if (expr_ret_234) dbg_accept(ctx, "FOR"); else dbg_reject(ctx, "FOR");
    }

    // ModExprList 1
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_235 = NULL;
      dbg_enter(ctx, "OPEN", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_235 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_235 = NULL;
      }

      if (expr_ret_235) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_235)
        expr_ret_235 = SUCC;
      expr_ret_234 = expr_ret_235;
    }

    // ModExprList 2
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_236 = NULL;
      expr_ret_236 = daisho_parse_whileexpr(ctx);
      expr_ret_234 = expr_ret_236;
      n = expr_ret_236;
    }

    // ModExprList 3
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_237 = NULL;

      rec(slash_237);

      // SlashExpr 0
      if (!expr_ret_237)
      {
        daisho_astnode_t* expr_ret_238 = NULL;
        rec(mod_238);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_239 = NULL;

        rec(slash_239);

        // SlashExpr 0
        if (!expr_ret_239)
        {
          daisho_astnode_t* expr_ret_240 = NULL;
          rec(mod_240);
          // ModExprList Forwarding
          dbg_enter(ctx, "COLON", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
            // Not capturing COLON.
            expr_ret_240 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_240 = NULL;
          }

          if (expr_ret_240) dbg_accept(ctx, "COLON"); else dbg_reject(ctx, "COLON");
          // ModExprList end
          if (!expr_ret_240) rew(mod_240);
          expr_ret_239 = expr_ret_240;
        }

        // SlashExpr 1
        if (!expr_ret_239)
        {
          daisho_astnode_t* expr_ret_241 = NULL;
          rec(mod_241);
          // ModExprList Forwarding
          dbg_enter(ctx, "IN", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
            // Not capturing IN.
            expr_ret_241 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_241 = NULL;
          }

          if (expr_ret_241) dbg_accept(ctx, "IN"); else dbg_reject(ctx, "IN");
          // ModExprList end
          if (!expr_ret_241) rew(mod_241);
          expr_ret_239 = expr_ret_241;
        }

        // SlashExpr end
        if (!expr_ret_239) rew(slash_239);
        expr_ret_238 = expr_ret_239;

        // ModExprList end
        if (!expr_ret_238) rew(mod_238);
        expr_ret_237 = expr_ret_238;
      }

      // SlashExpr 1
      if (!expr_ret_237)
      {
        daisho_astnode_t* expr_ret_242 = NULL;
        rec(mod_242);
        // ModExprList Forwarding
        daisho_astnode_t* expr_ret_243 = NULL;
        rec(mod_243);
        // ModExprList 0
        {
          dbg_enter(ctx, "SEMI", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_243 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_243 = NULL;
          }

          if (expr_ret_243) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
        }

        // ModExprList 1
        if (expr_ret_243)
        {
          daisho_astnode_t* expr_ret_244 = NULL;
          expr_ret_244 = daisho_parse_whileexpr(ctx);
          expr_ret_243 = expr_ret_244;
          sn = expr_ret_244;
        }

        // ModExprList 2
        if (expr_ret_243)
        {
          dbg_enter(ctx, "SEMI", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
            // Not capturing SEMI.
            expr_ret_243 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_243 = NULL;
          }

          if (expr_ret_243) dbg_accept(ctx, "SEMI"); else dbg_reject(ctx, "SEMI");
        }

        // ModExprList end
        if (!expr_ret_243) rew(mod_243);
        expr_ret_242 = expr_ret_243 ? SUCC : NULL;
        // ModExprList end
        if (!expr_ret_242) rew(mod_242);
        expr_ret_237 = expr_ret_242;
      }

      // SlashExpr end
      if (!expr_ret_237) rew(slash_237);
      expr_ret_234 = expr_ret_237;

    }

    // ModExprList 4
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_245 = NULL;
      expr_ret_245 = daisho_parse_whileexpr(ctx);
      expr_ret_234 = expr_ret_245;
      n = expr_ret_245;
    }

    // ModExprList 5
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_246 = NULL;
      dbg_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_246 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_246 = NULL;
      }

      if (expr_ret_246) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_246)
        expr_ret_246 = SUCC;
      expr_ret_234 = expr_ret_246;
    }

    // ModExprList 6
    if (expr_ret_234)
    {
      daisho_astnode_t* expr_ret_247 = NULL;
      expr_ret_247 = daisho_parse_whileexpr(ctx);
      expr_ret_234 = expr_ret_247;
      n = expr_ret_247;
    }

    // ModExprList end
    if (!expr_ret_234) rew(mod_234);
    expr_ret_233 = expr_ret_234 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_233)
  {
    daisho_astnode_t* expr_ret_248 = NULL;
    rec(mod_248);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_249 = NULL;
      expr_ret_249 = daisho_parse_whileexpr(ctx);
      expr_ret_248 = expr_ret_249;
      n = expr_ret_249;
    }

    // ModExprList 1
    if (expr_ret_248)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_248
      ret = SUCC;

      rule=n;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_248) rew(mod_248);
    expr_ret_233 = expr_ret_248 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_233) rew(slash_233);
  expr_ret_232 = expr_ret_233;

  if (!rule) rule = expr_ret_232;
  if (!expr_ret_232) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "forexpr");
  else if (rule) dbg_accept(ctx, "forexpr");
  else dbg_reject(ctx, "forexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* c = NULL;
  #define rule expr_ret_250

  daisho_astnode_t* expr_ret_251 = NULL;
  daisho_astnode_t* expr_ret_250 = NULL;
  dbg_enter(ctx, "whileexpr", ctx->pos);
  daisho_astnode_t* expr_ret_252 = NULL;

  rec(slash_252);

  // SlashExpr 0
  if (!expr_ret_252)
  {
    daisho_astnode_t* expr_ret_253 = NULL;
    rec(mod_253);
    // ModExprList 0
    {
      dbg_enter(ctx, "WHILE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
        // Not capturing WHILE.
        expr_ret_253 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_253 = NULL;
      }

      if (expr_ret_253) dbg_accept(ctx, "WHILE"); else dbg_reject(ctx, "WHILE");
    }

    // ModExprList 1
    if (expr_ret_253)
    {
      daisho_astnode_t* expr_ret_254 = NULL;
      dbg_enter(ctx, "OPEN", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_254 = leaf(OPEN);
        #if DAISHO_SOURCEINFO
        expr_ret_254->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_254->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_254 = NULL;
      }

      if (expr_ret_254) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
      // optional
      if (!expr_ret_254)
        expr_ret_254 = SUCC;
      expr_ret_253 = expr_ret_254;
      o = expr_ret_254;
    }

    // ModExprList 2
    if (expr_ret_253)
    {
      daisho_astnode_t* expr_ret_255 = NULL;
      expr_ret_255 = daisho_parse_ternexpr(ctx);
      expr_ret_253 = expr_ret_255;
      n = expr_ret_255;
    }

    // ModExprList 3
    if (expr_ret_253)
    {
      daisho_astnode_t* expr_ret_256 = NULL;
      dbg_enter(ctx, "CLOSE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Capturing CLOSE.
        expr_ret_256 = leaf(CLOSE);
        #if DAISHO_SOURCEINFO
        expr_ret_256->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_256->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_256 = NULL;
      }

      if (expr_ret_256) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
      // optional
      if (!expr_ret_256)
        expr_ret_256 = SUCC;
      expr_ret_253 = expr_ret_256;
      c = expr_ret_256;
    }

    // ModExprList 4
    if (expr_ret_253)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_253
      ret = SUCC;

      ret=o==c?SUCC:NULL;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 5
    if (expr_ret_253)
    {
      expr_ret_253 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_253) rew(mod_253);
    expr_ret_252 = expr_ret_253 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_252)
  {
    daisho_astnode_t* expr_ret_257 = NULL;
    rec(mod_257);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_258 = NULL;
      expr_ret_258 = daisho_parse_ternexpr(ctx);
      expr_ret_257 = expr_ret_258;
      n = expr_ret_258;
    }

    // ModExprList 1
    if (expr_ret_257)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_257
      ret = SUCC;

      rule=n;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_257) rew(mod_257);
    expr_ret_252 = expr_ret_257 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_252) rew(slash_252);
  expr_ret_251 = expr_ret_252;

  if (!rule) rule = expr_ret_251;
  if (!expr_ret_251) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "whileexpr");
  else if (rule) dbg_accept(ctx, "whileexpr");
  else dbg_reject(ctx, "whileexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* q = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* ce = NULL;
  #define rule expr_ret_259

  daisho_astnode_t* expr_ret_260 = NULL;
  daisho_astnode_t* expr_ret_259 = NULL;
  dbg_enter(ctx, "ternexpr", ctx->pos);
  daisho_astnode_t* expr_ret_261 = NULL;
  rec(mod_261);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_262 = NULL;
    expr_ret_262 = daisho_parse_thenexpr(ctx);
    expr_ret_261 = expr_ret_262;
    n = expr_ret_262;
  }

  // ModExprList 1
  if (expr_ret_261)
  {
    daisho_astnode_t* expr_ret_263 = NULL;
    daisho_astnode_t* expr_ret_264 = NULL;
    rec(mod_264);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_265 = NULL;
      dbg_enter(ctx, "QUEST", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
        // Capturing QUEST.
        expr_ret_265 = leaf(QUEST);
        #if DAISHO_SOURCEINFO
        expr_ret_265->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_265->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_265 = NULL;
      }

      if (expr_ret_265) dbg_accept(ctx, "QUEST"); else dbg_reject(ctx, "QUEST");
      expr_ret_264 = expr_ret_265;
      q = expr_ret_265;
    }

    // ModExprList 1
    if (expr_ret_264)
    {
      daisho_astnode_t* expr_ret_266 = NULL;
      expr_ret_266 = daisho_parse_expr(ctx);
      expr_ret_264 = expr_ret_266;
      qe = expr_ret_266;
    }

    // ModExprList 2
    if (expr_ret_264)
    {
      daisho_astnode_t* expr_ret_267 = NULL;
      daisho_astnode_t* expr_ret_268 = NULL;
      rec(mod_268);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_269 = NULL;
        dbg_enter(ctx, "COLON", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          // Capturing COLON.
          expr_ret_269 = leaf(COLON);
          #if DAISHO_SOURCEINFO
          expr_ret_269->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_269->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_269 = NULL;
        }

        if (expr_ret_269) dbg_accept(ctx, "COLON"); else dbg_reject(ctx, "COLON");
        expr_ret_268 = expr_ret_269;
        c = expr_ret_269;
      }

      // ModExprList 1
      if (expr_ret_268)
      {
        daisho_astnode_t* expr_ret_270 = NULL;
        expr_ret_270 = daisho_parse_expr(ctx);
        expr_ret_268 = expr_ret_270;
        ce = expr_ret_270;
      }

      // ModExprList end
      if (!expr_ret_268) rew(mod_268);
      expr_ret_267 = expr_ret_268 ? SUCC : NULL;
      // optional
      if (!expr_ret_267)
        expr_ret_267 = SUCC;
      expr_ret_264 = expr_ret_267;
    }

    // ModExprList end
    if (!expr_ret_264) rew(mod_264);
    expr_ret_263 = expr_ret_264 ? SUCC : NULL;
    // optional
    if (!expr_ret_263)
      expr_ret_263 = SUCC;
    expr_ret_261 = expr_ret_263;
  }

  // ModExprList 2
  if (expr_ret_261)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_261
    ret = SUCC;

    rule = !has(qe) ? n
                    : !has(ce) ? node(ELVIS, q, n, qe)
                    :            node(TERN, q, c, n, qe, ce);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_261) rew(mod_261);
  expr_ret_260 = expr_ret_261 ? SUCC : NULL;
  if (!rule) rule = expr_ret_260;
  if (!expr_ret_260) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "ternexpr");
  else if (rule) dbg_accept(ctx, "ternexpr");
  else dbg_reject(ctx, "ternexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_271

  daisho_astnode_t* expr_ret_272 = NULL;
  daisho_astnode_t* expr_ret_271 = NULL;
  dbg_enter(ctx, "thenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_273 = NULL;
  rec(mod_273);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_274 = NULL;
    expr_ret_274 = daisho_parse_alsoexpr(ctx);
    expr_ret_273 = expr_ret_274;
    n = expr_ret_274;
  }

  // ModExprList 1
  if (expr_ret_273)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_273
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
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
        daisho_astnode_t* expr_ret_277 = NULL;
        dbg_enter(ctx, "THEN", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
          // Capturing THEN.
          expr_ret_277 = leaf(THEN);
          #if DAISHO_SOURCEINFO
          expr_ret_277->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_277->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_277 = NULL;
        }

        if (expr_ret_277) dbg_accept(ctx, "THEN"); else dbg_reject(ctx, "THEN");
        expr_ret_276 = expr_ret_277;
        o = expr_ret_277;
      }

      // ModExprList 1
      if (expr_ret_276)
      {
        daisho_astnode_t* expr_ret_278 = NULL;
        expr_ret_278 = daisho_parse_alsoexpr(ctx);
        expr_ret_276 = expr_ret_278;
        nn = expr_ret_278;
      }

      // ModExprList 2
      if (expr_ret_276)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_276
        ret = SUCC;

        rule=srepr(node(THEN, rule, nn), "then");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
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
  if (rule==SUCC) dbg_succ(ctx, "thenexpr");
  else if (rule) dbg_accept(ctx, "thenexpr");
  else dbg_reject(ctx, "thenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* nn = NULL;
  #define rule expr_ret_279

  daisho_astnode_t* expr_ret_280 = NULL;
  daisho_astnode_t* expr_ret_279 = NULL;
  dbg_enter(ctx, "alsoexpr", ctx->pos);
  daisho_astnode_t* expr_ret_281 = NULL;
  rec(mod_281);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_282 = NULL;
    expr_ret_282 = daisho_parse_binop(ctx);
    expr_ret_281 = expr_ret_282;
    n = expr_ret_282;
  }

  // ModExprList 1
  if (expr_ret_281)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_281
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_281)
  {
    daisho_astnode_t* expr_ret_283 = NULL;
    expr_ret_283 = SUCC;
    while (expr_ret_283)
    {
      daisho_astnode_t* expr_ret_284 = NULL;
      rec(mod_284);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_285 = NULL;
        dbg_enter(ctx, "ALSO", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
          // Capturing ALSO.
          expr_ret_285 = leaf(ALSO);
          #if DAISHO_SOURCEINFO
          expr_ret_285->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_285->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_285 = NULL;
        }

        if (expr_ret_285) dbg_accept(ctx, "ALSO"); else dbg_reject(ctx, "ALSO");
        expr_ret_284 = expr_ret_285;
        o = expr_ret_285;
      }

      // ModExprList 1
      if (expr_ret_284)
      {
        daisho_astnode_t* expr_ret_286 = NULL;
        expr_ret_286 = daisho_parse_binop(ctx);
        expr_ret_284 = expr_ret_286;
        nn = expr_ret_286;
      }

      // ModExprList 2
      if (expr_ret_284)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_284
        ret = SUCC;

        rule=srepr(node(ALSO, rule, nn), "also");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_284) rew(mod_284);
      expr_ret_283 = expr_ret_284 ? SUCC : NULL;
    }

    expr_ret_283 = SUCC;
    expr_ret_281 = expr_ret_283;
  }

  // ModExprList end
  if (!expr_ret_281) rew(mod_281);
  expr_ret_280 = expr_ret_281 ? SUCC : NULL;
  if (!rule) rule = expr_ret_280;
  if (!expr_ret_280) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "alsoexpr");
  else if (rule) dbg_accept(ctx, "alsoexpr");
  else dbg_reject(ctx, "alsoexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  #define rule expr_ret_287

  daisho_astnode_t* expr_ret_288 = NULL;
  daisho_astnode_t* expr_ret_287 = NULL;
  dbg_enter(ctx, "binop", ctx->pos);
  daisho_astnode_t* expr_ret_289 = NULL;
  rec(mod_289);
  // ModExprList Forwarding
  expr_ret_289 = daisho_parse_eqexpr(ctx);
  // ModExprList end
  if (!expr_ret_289) rew(mod_289);
  expr_ret_288 = expr_ret_289;
  if (!rule) rule = expr_ret_288;
  if (!expr_ret_288) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "binop");
  else if (rule) dbg_accept(ctx, "binop");
  else dbg_reject(ctx, "binop");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_290

  daisho_astnode_t* expr_ret_291 = NULL;
  daisho_astnode_t* expr_ret_290 = NULL;
  dbg_enter(ctx, "eqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_292 = NULL;
  rec(mod_292);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_293 = NULL;
    expr_ret_293 = daisho_parse_logorexpr(ctx);
    expr_ret_292 = expr_ret_293;
    n = expr_ret_293;
  }

  // ModExprList 1
  if (expr_ret_292)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_292
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_292)
  {
    daisho_astnode_t* expr_ret_294 = NULL;
    expr_ret_294 = SUCC;
    while (expr_ret_294)
    {
      daisho_astnode_t* expr_ret_295 = NULL;
      rec(mod_295);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_296 = NULL;
        daisho_astnode_t* expr_ret_297 = NULL;

        rec(slash_297);

        // SlashExpr 0
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_298 = NULL;
          rec(mod_298);
          // ModExprList Forwarding
          dbg_enter(ctx, "EQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            // Capturing EQ.
            expr_ret_298 = leaf(EQ);
            #if DAISHO_SOURCEINFO
            expr_ret_298->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_298->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_298 = NULL;
          }

          if (expr_ret_298) dbg_accept(ctx, "EQ"); else dbg_reject(ctx, "EQ");
          // ModExprList end
          if (!expr_ret_298) rew(mod_298);
          expr_ret_297 = expr_ret_298;
        }

        // SlashExpr 1
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_299 = NULL;
          rec(mod_299);
          // ModExprList Forwarding
          dbg_enter(ctx, "PLEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            // Capturing PLEQ.
            expr_ret_299 = leaf(PLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_299->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_299->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_299 = NULL;
          }

          if (expr_ret_299) dbg_accept(ctx, "PLEQ"); else dbg_reject(ctx, "PLEQ");
          // ModExprList end
          if (!expr_ret_299) rew(mod_299);
          expr_ret_297 = expr_ret_299;
        }

        // SlashExpr 2
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_300 = NULL;
          rec(mod_300);
          // ModExprList Forwarding
          dbg_enter(ctx, "MINEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            // Capturing MINEQ.
            expr_ret_300 = leaf(MINEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_300->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_300->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_300 = NULL;
          }

          if (expr_ret_300) dbg_accept(ctx, "MINEQ"); else dbg_reject(ctx, "MINEQ");
          // ModExprList end
          if (!expr_ret_300) rew(mod_300);
          expr_ret_297 = expr_ret_300;
        }

        // SlashExpr 3
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_301 = NULL;
          rec(mod_301);
          // ModExprList Forwarding
          dbg_enter(ctx, "MULEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            // Capturing MULEQ.
            expr_ret_301 = leaf(MULEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_301->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_301->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_301 = NULL;
          }

          if (expr_ret_301) dbg_accept(ctx, "MULEQ"); else dbg_reject(ctx, "MULEQ");
          // ModExprList end
          if (!expr_ret_301) rew(mod_301);
          expr_ret_297 = expr_ret_301;
        }

        // SlashExpr 4
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_302 = NULL;
          rec(mod_302);
          // ModExprList Forwarding
          dbg_enter(ctx, "DIVEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            // Capturing DIVEQ.
            expr_ret_302 = leaf(DIVEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_302->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_302->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_302 = NULL;
          }

          if (expr_ret_302) dbg_accept(ctx, "DIVEQ"); else dbg_reject(ctx, "DIVEQ");
          // ModExprList end
          if (!expr_ret_302) rew(mod_302);
          expr_ret_297 = expr_ret_302;
        }

        // SlashExpr 5
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_303 = NULL;
          rec(mod_303);
          // ModExprList Forwarding
          dbg_enter(ctx, "MODEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            // Capturing MODEQ.
            expr_ret_303 = leaf(MODEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_303->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_303->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_303 = NULL;
          }

          if (expr_ret_303) dbg_accept(ctx, "MODEQ"); else dbg_reject(ctx, "MODEQ");
          // ModExprList end
          if (!expr_ret_303) rew(mod_303);
          expr_ret_297 = expr_ret_303;
        }

        // SlashExpr 6
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_304 = NULL;
          rec(mod_304);
          // ModExprList Forwarding
          dbg_enter(ctx, "ANDEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            // Capturing ANDEQ.
            expr_ret_304 = leaf(ANDEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_304->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_304->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_304 = NULL;
          }

          if (expr_ret_304) dbg_accept(ctx, "ANDEQ"); else dbg_reject(ctx, "ANDEQ");
          // ModExprList end
          if (!expr_ret_304) rew(mod_304);
          expr_ret_297 = expr_ret_304;
        }

        // SlashExpr 7
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_305 = NULL;
          rec(mod_305);
          // ModExprList Forwarding
          dbg_enter(ctx, "OREQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            // Capturing OREQ.
            expr_ret_305 = leaf(OREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_305->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_305->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_305 = NULL;
          }

          if (expr_ret_305) dbg_accept(ctx, "OREQ"); else dbg_reject(ctx, "OREQ");
          // ModExprList end
          if (!expr_ret_305) rew(mod_305);
          expr_ret_297 = expr_ret_305;
        }

        // SlashExpr 8
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_306 = NULL;
          rec(mod_306);
          // ModExprList Forwarding
          dbg_enter(ctx, "XOREQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            // Capturing XOREQ.
            expr_ret_306 = leaf(XOREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_306->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_306->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_306 = NULL;
          }

          if (expr_ret_306) dbg_accept(ctx, "XOREQ"); else dbg_reject(ctx, "XOREQ");
          // ModExprList end
          if (!expr_ret_306) rew(mod_306);
          expr_ret_297 = expr_ret_306;
        }

        // SlashExpr 9
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_307 = NULL;
          rec(mod_307);
          // ModExprList Forwarding
          dbg_enter(ctx, "BNEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            // Capturing BNEQ.
            expr_ret_307 = leaf(BNEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_307->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_307->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_307 = NULL;
          }

          if (expr_ret_307) dbg_accept(ctx, "BNEQ"); else dbg_reject(ctx, "BNEQ");
          // ModExprList end
          if (!expr_ret_307) rew(mod_307);
          expr_ret_297 = expr_ret_307;
        }

        // SlashExpr 10
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_308 = NULL;
          rec(mod_308);
          // ModExprList Forwarding
          dbg_enter(ctx, "BSREQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            // Capturing BSREQ.
            expr_ret_308 = leaf(BSREQ);
            #if DAISHO_SOURCEINFO
            expr_ret_308->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_308->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_308 = NULL;
          }

          if (expr_ret_308) dbg_accept(ctx, "BSREQ"); else dbg_reject(ctx, "BSREQ");
          // ModExprList end
          if (!expr_ret_308) rew(mod_308);
          expr_ret_297 = expr_ret_308;
        }

        // SlashExpr 11
        if (!expr_ret_297)
        {
          daisho_astnode_t* expr_ret_309 = NULL;
          rec(mod_309);
          // ModExprList Forwarding
          dbg_enter(ctx, "BSLEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            // Capturing BSLEQ.
            expr_ret_309 = leaf(BSLEQ);
            #if DAISHO_SOURCEINFO
            expr_ret_309->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_309->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_309 = NULL;
          }

          if (expr_ret_309) dbg_accept(ctx, "BSLEQ"); else dbg_reject(ctx, "BSLEQ");
          // ModExprList end
          if (!expr_ret_309) rew(mod_309);
          expr_ret_297 = expr_ret_309;
        }

        // SlashExpr end
        if (!expr_ret_297) rew(slash_297);
        expr_ret_296 = expr_ret_297;

        expr_ret_295 = expr_ret_296;
        op = expr_ret_296;
      }

      // ModExprList 1
      if (expr_ret_295)
      {
        daisho_astnode_t* expr_ret_310 = NULL;
        expr_ret_310 = daisho_parse_logorexpr(ctx);
        expr_ret_295 = expr_ret_310;
        t = expr_ret_310;
      }

      // ModExprList 2
      if (expr_ret_295)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_295
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

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_295) rew(mod_295);
      expr_ret_294 = expr_ret_295 ? SUCC : NULL;
    }

    expr_ret_294 = SUCC;
    expr_ret_292 = expr_ret_294;
  }

  // ModExprList end
  if (!expr_ret_292) rew(mod_292);
  expr_ret_291 = expr_ret_292 ? SUCC : NULL;
  if (!rule) rule = expr_ret_291;
  if (!expr_ret_291) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "eqexpr");
  else if (rule) dbg_accept(ctx, "eqexpr");
  else dbg_reject(ctx, "eqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_311

  daisho_astnode_t* expr_ret_312 = NULL;
  daisho_astnode_t* expr_ret_311 = NULL;
  dbg_enter(ctx, "logorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_313 = NULL;
  rec(mod_313);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_314 = NULL;
    expr_ret_314 = daisho_parse_logandexpr(ctx);
    expr_ret_313 = expr_ret_314;
    n = expr_ret_314;
  }

  // ModExprList 1
  if (expr_ret_313)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_313
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_313)
  {
    daisho_astnode_t* expr_ret_315 = NULL;
    expr_ret_315 = SUCC;
    while (expr_ret_315)
    {
      daisho_astnode_t* expr_ret_316 = NULL;
      rec(mod_316);
      // ModExprList 0
      {
        dbg_enter(ctx, "LOGOR", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Not capturing LOGOR.
          expr_ret_316 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_316 = NULL;
        }

        if (expr_ret_316) dbg_accept(ctx, "LOGOR"); else dbg_reject(ctx, "LOGOR");
      }

      // ModExprList 1
      if (expr_ret_316)
      {
        daisho_astnode_t* expr_ret_317 = NULL;
        expr_ret_317 = daisho_parse_logandexpr(ctx);
        expr_ret_316 = expr_ret_317;
        n = expr_ret_317;
      }

      // ModExprList 2
      if (expr_ret_316)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_316
        ret = SUCC;

        rule=srepr(node(LOGOR,  rule, n), "||");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_316) rew(mod_316);
      expr_ret_315 = expr_ret_316 ? SUCC : NULL;
    }

    expr_ret_315 = SUCC;
    expr_ret_313 = expr_ret_315;
  }

  // ModExprList end
  if (!expr_ret_313) rew(mod_313);
  expr_ret_312 = expr_ret_313 ? SUCC : NULL;
  if (!rule) rule = expr_ret_312;
  if (!expr_ret_312) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "logorexpr");
  else if (rule) dbg_accept(ctx, "logorexpr");
  else dbg_reject(ctx, "logorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_318

  daisho_astnode_t* expr_ret_319 = NULL;
  daisho_astnode_t* expr_ret_318 = NULL;
  dbg_enter(ctx, "logandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_320 = NULL;
  rec(mod_320);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_321 = NULL;
    expr_ret_321 = daisho_parse_binorexpr(ctx);
    expr_ret_320 = expr_ret_321;
    n = expr_ret_321;
  }

  // ModExprList 1
  if (expr_ret_320)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_320
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_320)
  {
    daisho_astnode_t* expr_ret_322 = NULL;
    expr_ret_322 = SUCC;
    while (expr_ret_322)
    {
      daisho_astnode_t* expr_ret_323 = NULL;
      rec(mod_323);
      // ModExprList 0
      {
        dbg_enter(ctx, "LOGAND", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Not capturing LOGAND.
          expr_ret_323 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_323 = NULL;
        }

        if (expr_ret_323) dbg_accept(ctx, "LOGAND"); else dbg_reject(ctx, "LOGAND");
      }

      // ModExprList 1
      if (expr_ret_323)
      {
        daisho_astnode_t* expr_ret_324 = NULL;
        expr_ret_324 = daisho_parse_binorexpr(ctx);
        expr_ret_323 = expr_ret_324;
        n = expr_ret_324;
      }

      // ModExprList 2
      if (expr_ret_323)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_323
        ret = SUCC;

        rule=srepr(node(LOGAND, rule, n), "&&");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_323) rew(mod_323);
      expr_ret_322 = expr_ret_323 ? SUCC : NULL;
    }

    expr_ret_322 = SUCC;
    expr_ret_320 = expr_ret_322;
  }

  // ModExprList end
  if (!expr_ret_320) rew(mod_320);
  expr_ret_319 = expr_ret_320 ? SUCC : NULL;
  if (!rule) rule = expr_ret_319;
  if (!expr_ret_319) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "logandexpr");
  else if (rule) dbg_accept(ctx, "logandexpr");
  else dbg_reject(ctx, "logandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_325

  daisho_astnode_t* expr_ret_326 = NULL;
  daisho_astnode_t* expr_ret_325 = NULL;
  dbg_enter(ctx, "binorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_327 = NULL;
  rec(mod_327);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_328 = NULL;
    expr_ret_328 = daisho_parse_binxorexpr(ctx);
    expr_ret_327 = expr_ret_328;
    n = expr_ret_328;
  }

  // ModExprList 1
  if (expr_ret_327)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_327
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_327)
  {
    daisho_astnode_t* expr_ret_329 = NULL;
    expr_ret_329 = SUCC;
    while (expr_ret_329)
    {
      daisho_astnode_t* expr_ret_330 = NULL;
      rec(mod_330);
      // ModExprList 0
      {
        dbg_enter(ctx, "OR", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Not capturing OR.
          expr_ret_330 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_330 = NULL;
        }

        if (expr_ret_330) dbg_accept(ctx, "OR"); else dbg_reject(ctx, "OR");
      }

      // ModExprList 1
      if (expr_ret_330)
      {
        daisho_astnode_t* expr_ret_331 = NULL;
        expr_ret_331 = daisho_parse_binxorexpr(ctx);
        expr_ret_330 = expr_ret_331;
        n = expr_ret_331;
      }

      // ModExprList 2
      if (expr_ret_330)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_330
        ret = SUCC;

        rule=srepr(node(OR,     rule, n), "|");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_330) rew(mod_330);
      expr_ret_329 = expr_ret_330 ? SUCC : NULL;
    }

    expr_ret_329 = SUCC;
    expr_ret_327 = expr_ret_329;
  }

  // ModExprList end
  if (!expr_ret_327) rew(mod_327);
  expr_ret_326 = expr_ret_327 ? SUCC : NULL;
  if (!rule) rule = expr_ret_326;
  if (!expr_ret_326) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "binorexpr");
  else if (rule) dbg_accept(ctx, "binorexpr");
  else dbg_reject(ctx, "binorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_332

  daisho_astnode_t* expr_ret_333 = NULL;
  daisho_astnode_t* expr_ret_332 = NULL;
  dbg_enter(ctx, "binxorexpr", ctx->pos);
  daisho_astnode_t* expr_ret_334 = NULL;
  rec(mod_334);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_335 = NULL;
    expr_ret_335 = daisho_parse_binandexpr(ctx);
    expr_ret_334 = expr_ret_335;
    n = expr_ret_335;
  }

  // ModExprList 1
  if (expr_ret_334)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_334
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_334)
  {
    daisho_astnode_t* expr_ret_336 = NULL;
    expr_ret_336 = SUCC;
    while (expr_ret_336)
    {
      daisho_astnode_t* expr_ret_337 = NULL;
      rec(mod_337);
      // ModExprList 0
      {
        dbg_enter(ctx, "XOR", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Not capturing XOR.
          expr_ret_337 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_337 = NULL;
        }

        if (expr_ret_337) dbg_accept(ctx, "XOR"); else dbg_reject(ctx, "XOR");
      }

      // ModExprList 1
      if (expr_ret_337)
      {
        daisho_astnode_t* expr_ret_338 = NULL;
        expr_ret_338 = daisho_parse_binandexpr(ctx);
        expr_ret_337 = expr_ret_338;
        n = expr_ret_338;
      }

      // ModExprList 2
      if (expr_ret_337)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_337
        ret = SUCC;

        rule=srepr(node(XOR,    rule, n), "^");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_337) rew(mod_337);
      expr_ret_336 = expr_ret_337 ? SUCC : NULL;
    }

    expr_ret_336 = SUCC;
    expr_ret_334 = expr_ret_336;
  }

  // ModExprList end
  if (!expr_ret_334) rew(mod_334);
  expr_ret_333 = expr_ret_334 ? SUCC : NULL;
  if (!rule) rule = expr_ret_333;
  if (!expr_ret_333) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "binxorexpr");
  else if (rule) dbg_accept(ctx, "binxorexpr");
  else dbg_reject(ctx, "binxorexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_339

  daisho_astnode_t* expr_ret_340 = NULL;
  daisho_astnode_t* expr_ret_339 = NULL;
  dbg_enter(ctx, "binandexpr", ctx->pos);
  daisho_astnode_t* expr_ret_341 = NULL;
  rec(mod_341);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_342 = NULL;
    expr_ret_342 = daisho_parse_deneqexpr(ctx);
    expr_ret_341 = expr_ret_342;
    n = expr_ret_342;
  }

  // ModExprList 1
  if (expr_ret_341)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_341
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_341)
  {
    daisho_astnode_t* expr_ret_343 = NULL;
    expr_ret_343 = SUCC;
    while (expr_ret_343)
    {
      daisho_astnode_t* expr_ret_344 = NULL;
      rec(mod_344);
      // ModExprList 0
      {
        dbg_enter(ctx, "AND", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Not capturing AND.
          expr_ret_344 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_344 = NULL;
        }

        if (expr_ret_344) dbg_accept(ctx, "AND"); else dbg_reject(ctx, "AND");
      }

      // ModExprList 1
      if (expr_ret_344)
      {
        daisho_astnode_t* expr_ret_345 = NULL;
        expr_ret_345 = daisho_parse_deneqexpr(ctx);
        expr_ret_344 = expr_ret_345;
        n = expr_ret_345;
      }

      // ModExprList 2
      if (expr_ret_344)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_344
        ret = SUCC;

        rule=srepr(node(AND,    rule, n), "&");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_344) rew(mod_344);
      expr_ret_343 = expr_ret_344 ? SUCC : NULL;
    }

    expr_ret_343 = SUCC;
    expr_ret_341 = expr_ret_343;
  }

  // ModExprList end
  if (!expr_ret_341) rew(mod_341);
  expr_ret_340 = expr_ret_341 ? SUCC : NULL;
  if (!rule) rule = expr_ret_340;
  if (!expr_ret_340) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "binandexpr");
  else if (rule) dbg_accept(ctx, "binandexpr");
  else dbg_reject(ctx, "binandexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_346

  daisho_astnode_t* expr_ret_347 = NULL;
  daisho_astnode_t* expr_ret_346 = NULL;
  dbg_enter(ctx, "deneqexpr", ctx->pos);
  daisho_astnode_t* expr_ret_348 = NULL;
  rec(mod_348);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_349 = NULL;
    expr_ret_349 = daisho_parse_cmpexpr(ctx);
    expr_ret_348 = expr_ret_349;
    n = expr_ret_349;
  }

  // ModExprList 1
  if (expr_ret_348)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_348
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_348)
  {
    daisho_astnode_t* expr_ret_350 = NULL;
    expr_ret_350 = SUCC;
    while (expr_ret_350)
    {
      daisho_astnode_t* expr_ret_351 = NULL;

      rec(slash_351);

      // SlashExpr 0
      if (!expr_ret_351)
      {
        daisho_astnode_t* expr_ret_352 = NULL;
        rec(mod_352);
        // ModExprList 0
        {
          dbg_enter(ctx, "DEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Not capturing DEQ.
            expr_ret_352 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_352 = NULL;
          }

          if (expr_ret_352) dbg_accept(ctx, "DEQ"); else dbg_reject(ctx, "DEQ");
        }

        // ModExprList 1
        if (expr_ret_352)
        {
          daisho_astnode_t* expr_ret_353 = NULL;
          expr_ret_353 = daisho_parse_cmpexpr(ctx);
          expr_ret_352 = expr_ret_353;
          n = expr_ret_353;
        }

        // ModExprList 2
        if (expr_ret_352)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_352
          ret = SUCC;

          rule=srepr(node(DEQ, rule, n), "==");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_352) rew(mod_352);
        expr_ret_351 = expr_ret_352 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_351)
      {
        daisho_astnode_t* expr_ret_354 = NULL;
        rec(mod_354);
        // ModExprList 0
        {
          dbg_enter(ctx, "NEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Not capturing NEQ.
            expr_ret_354 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_354 = NULL;
          }

          if (expr_ret_354) dbg_accept(ctx, "NEQ"); else dbg_reject(ctx, "NEQ");
        }

        // ModExprList 1
        if (expr_ret_354)
        {
          daisho_astnode_t* expr_ret_355 = NULL;
          expr_ret_355 = daisho_parse_cmpexpr(ctx);
          expr_ret_354 = expr_ret_355;
          n = expr_ret_355;
        }

        // ModExprList 2
        if (expr_ret_354)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_354
          ret = SUCC;

          rule=srepr(node(NEQ, rule, n), "!=");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_354) rew(mod_354);
        expr_ret_351 = expr_ret_354 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_351) rew(slash_351);
      expr_ret_350 = expr_ret_351;

    }

    expr_ret_350 = SUCC;
    expr_ret_348 = expr_ret_350;
  }

  // ModExprList end
  if (!expr_ret_348) rew(mod_348);
  expr_ret_347 = expr_ret_348 ? SUCC : NULL;
  if (!rule) rule = expr_ret_347;
  if (!expr_ret_347) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "deneqexpr");
  else if (rule) dbg_accept(ctx, "deneqexpr");
  else dbg_reject(ctx, "deneqexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_356

  daisho_astnode_t* expr_ret_357 = NULL;
  daisho_astnode_t* expr_ret_356 = NULL;
  dbg_enter(ctx, "cmpexpr", ctx->pos);
  daisho_astnode_t* expr_ret_358 = NULL;
  rec(mod_358);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_359 = NULL;
    expr_ret_359 = daisho_parse_sumexpr(ctx);
    expr_ret_358 = expr_ret_359;
    n = expr_ret_359;
  }

  // ModExprList 1
  if (expr_ret_358)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_358
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_358)
  {
    daisho_astnode_t* expr_ret_360 = NULL;
    expr_ret_360 = SUCC;
    while (expr_ret_360)
    {
      daisho_astnode_t* expr_ret_361 = NULL;

      rec(slash_361);

      // SlashExpr 0
      if (!expr_ret_361)
      {
        daisho_astnode_t* expr_ret_362 = NULL;
        rec(mod_362);
        // ModExprList 0
        {
          dbg_enter(ctx, "LT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_362 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_362 = NULL;
          }

          if (expr_ret_362) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
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
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_362
          ret = SUCC;

          rule=srepr(node(LT,  rule, n), "<");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_362) rew(mod_362);
        expr_ret_361 = expr_ret_362 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_361)
      {
        daisho_astnode_t* expr_ret_364 = NULL;
        rec(mod_364);
        // ModExprList 0
        {
          dbg_enter(ctx, "GT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_364 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_364 = NULL;
          }

          if (expr_ret_364) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
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
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_364
          ret = SUCC;

          rule=srepr(node(GT,  rule, n), ">");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_364) rew(mod_364);
        expr_ret_361 = expr_ret_364 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_361)
      {
        daisho_astnode_t* expr_ret_366 = NULL;
        rec(mod_366);
        // ModExprList 0
        {
          dbg_enter(ctx, "LEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Not capturing LEQ.
            expr_ret_366 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_366 = NULL;
          }

          if (expr_ret_366) dbg_accept(ctx, "LEQ"); else dbg_reject(ctx, "LEQ");
        }

        // ModExprList 1
        if (expr_ret_366)
        {
          daisho_astnode_t* expr_ret_367 = NULL;
          expr_ret_367 = daisho_parse_sumexpr(ctx);
          expr_ret_366 = expr_ret_367;
          n = expr_ret_367;
        }

        // ModExprList 2
        if (expr_ret_366)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_366
          ret = SUCC;

          rule=srepr(node(LEQ, rule, n), "<=");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_366) rew(mod_366);
        expr_ret_361 = expr_ret_366 ? SUCC : NULL;
      }

      // SlashExpr 3
      if (!expr_ret_361)
      {
        daisho_astnode_t* expr_ret_368 = NULL;
        rec(mod_368);
        // ModExprList 0
        {
          dbg_enter(ctx, "GEQ", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Not capturing GEQ.
            expr_ret_368 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_368 = NULL;
          }

          if (expr_ret_368) dbg_accept(ctx, "GEQ"); else dbg_reject(ctx, "GEQ");
        }

        // ModExprList 1
        if (expr_ret_368)
        {
          daisho_astnode_t* expr_ret_369 = NULL;
          expr_ret_369 = daisho_parse_sumexpr(ctx);
          expr_ret_368 = expr_ret_369;
          n = expr_ret_369;
        }

        // ModExprList 2
        if (expr_ret_368)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_368
          ret = SUCC;

          rule=srepr(node(GEQ, rule, n), ">=");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_368) rew(mod_368);
        expr_ret_361 = expr_ret_368 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_361) rew(slash_361);
      expr_ret_360 = expr_ret_361;

    }

    expr_ret_360 = SUCC;
    expr_ret_358 = expr_ret_360;
  }

  // ModExprList end
  if (!expr_ret_358) rew(mod_358);
  expr_ret_357 = expr_ret_358 ? SUCC : NULL;
  if (!rule) rule = expr_ret_357;
  if (!expr_ret_357) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "cmpexpr");
  else if (rule) dbg_accept(ctx, "cmpexpr");
  else dbg_reject(ctx, "cmpexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_370

  daisho_astnode_t* expr_ret_371 = NULL;
  daisho_astnode_t* expr_ret_370 = NULL;
  dbg_enter(ctx, "sumexpr", ctx->pos);
  daisho_astnode_t* expr_ret_372 = NULL;
  rec(mod_372);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_373 = NULL;
    expr_ret_373 = daisho_parse_multexpr(ctx);
    expr_ret_372 = expr_ret_373;
    n = expr_ret_373;
  }

  // ModExprList 1
  if (expr_ret_372)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_372
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_372)
  {
    daisho_astnode_t* expr_ret_374 = NULL;
    expr_ret_374 = SUCC;
    while (expr_ret_374)
    {
      daisho_astnode_t* expr_ret_375 = NULL;

      rec(slash_375);

      // SlashExpr 0
      if (!expr_ret_375)
      {
        daisho_astnode_t* expr_ret_376 = NULL;
        rec(mod_376);
        // ModExprList 0
        {
          dbg_enter(ctx, "PLUS", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Not capturing PLUS.
            expr_ret_376 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_376 = NULL;
          }

          if (expr_ret_376) dbg_accept(ctx, "PLUS"); else dbg_reject(ctx, "PLUS");
        }

        // ModExprList 1
        if (expr_ret_376)
        {
          daisho_astnode_t* expr_ret_377 = NULL;
          expr_ret_377 = daisho_parse_multexpr(ctx);
          expr_ret_376 = expr_ret_377;
          n = expr_ret_377;
        }

        // ModExprList 2
        if (expr_ret_376)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_376
          ret = SUCC;

          rule=srepr(node(PLUS,  rule, n), "+");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_376) rew(mod_376);
        expr_ret_375 = expr_ret_376 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_375)
      {
        daisho_astnode_t* expr_ret_378 = NULL;
        rec(mod_378);
        // ModExprList 0
        {
          dbg_enter(ctx, "MINUS", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Not capturing MINUS.
            expr_ret_378 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_378 = NULL;
          }

          if (expr_ret_378) dbg_accept(ctx, "MINUS"); else dbg_reject(ctx, "MINUS");
        }

        // ModExprList 1
        if (expr_ret_378)
        {
          daisho_astnode_t* expr_ret_379 = NULL;
          expr_ret_379 = daisho_parse_multexpr(ctx);
          expr_ret_378 = expr_ret_379;
          n = expr_ret_379;
        }

        // ModExprList 2
        if (expr_ret_378)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_378
          ret = SUCC;

          rule=srepr(node(MINUS, rule, n), "-");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_378) rew(mod_378);
        expr_ret_375 = expr_ret_378 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_375) rew(slash_375);
      expr_ret_374 = expr_ret_375;

    }

    expr_ret_374 = SUCC;
    expr_ret_372 = expr_ret_374;
  }

  // ModExprList end
  if (!expr_ret_372) rew(mod_372);
  expr_ret_371 = expr_ret_372 ? SUCC : NULL;
  if (!rule) rule = expr_ret_371;
  if (!expr_ret_371) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "sumexpr");
  else if (rule) dbg_accept(ctx, "sumexpr");
  else dbg_reject(ctx, "sumexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_380

  daisho_astnode_t* expr_ret_381 = NULL;
  daisho_astnode_t* expr_ret_380 = NULL;
  dbg_enter(ctx, "multexpr", ctx->pos);
  daisho_astnode_t* expr_ret_382 = NULL;
  rec(mod_382);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_383 = NULL;
    expr_ret_383 = daisho_parse_powexpr(ctx);
    expr_ret_382 = expr_ret_383;
    n = expr_ret_383;
  }

  // ModExprList 1
  if (expr_ret_382)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_382
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_382)
  {
    daisho_astnode_t* expr_ret_384 = NULL;
    expr_ret_384 = SUCC;
    while (expr_ret_384)
    {
      daisho_astnode_t* expr_ret_385 = NULL;

      rec(slash_385);

      // SlashExpr 0
      if (!expr_ret_385)
      {
        daisho_astnode_t* expr_ret_386 = NULL;
        rec(mod_386);
        // ModExprList 0
        {
          dbg_enter(ctx, "STAR", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Not capturing STAR.
            expr_ret_386 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_386 = NULL;
          }

          if (expr_ret_386) dbg_accept(ctx, "STAR"); else dbg_reject(ctx, "STAR");
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
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_386
          ret = SUCC;

          rule=srepr(node(STAR, rule, n), "*");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_386) rew(mod_386);
        expr_ret_385 = expr_ret_386 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_385)
      {
        daisho_astnode_t* expr_ret_388 = NULL;
        rec(mod_388);
        // ModExprList 0
        {
          dbg_enter(ctx, "DIV", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Not capturing DIV.
            expr_ret_388 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_388 = NULL;
          }

          if (expr_ret_388) dbg_accept(ctx, "DIV"); else dbg_reject(ctx, "DIV");
        }

        // ModExprList 1
        if (expr_ret_388)
        {
          daisho_astnode_t* expr_ret_389 = NULL;
          expr_ret_389 = daisho_parse_powexpr(ctx);
          expr_ret_388 = expr_ret_389;
          n = expr_ret_389;
        }

        // ModExprList 2
        if (expr_ret_388)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_388
          ret = SUCC;

          rule=srepr(node(DIV,  rule, n), "/");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_388) rew(mod_388);
        expr_ret_385 = expr_ret_388 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_385)
      {
        daisho_astnode_t* expr_ret_390 = NULL;
        rec(mod_390);
        // ModExprList 0
        {
          dbg_enter(ctx, "MOD", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Not capturing MOD.
            expr_ret_390 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_390 = NULL;
          }

          if (expr_ret_390) dbg_accept(ctx, "MOD"); else dbg_reject(ctx, "MOD");
        }

        // ModExprList 1
        if (expr_ret_390)
        {
          daisho_astnode_t* expr_ret_391 = NULL;
          expr_ret_391 = daisho_parse_powexpr(ctx);
          expr_ret_390 = expr_ret_391;
          n = expr_ret_391;
        }

        // ModExprList 2
        if (expr_ret_390)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_390
          ret = SUCC;

          rule=srepr(node(MOD,  rule, n), "%");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_390) rew(mod_390);
        expr_ret_385 = expr_ret_390 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_385) rew(slash_385);
      expr_ret_384 = expr_ret_385;

    }

    expr_ret_384 = SUCC;
    expr_ret_382 = expr_ret_384;
  }

  // ModExprList end
  if (!expr_ret_382) rew(mod_382);
  expr_ret_381 = expr_ret_382 ? SUCC : NULL;
  if (!rule) rule = expr_ret_381;
  if (!expr_ret_381) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "multexpr");
  else if (rule) dbg_accept(ctx, "multexpr");
  else dbg_reject(ctx, "multexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_392

  daisho_astnode_t* expr_ret_393 = NULL;
  daisho_astnode_t* expr_ret_392 = NULL;
  dbg_enter(ctx, "powexpr", ctx->pos);
  daisho_astnode_t* expr_ret_394 = NULL;
  rec(mod_394);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_395 = NULL;
    expr_ret_395 = daisho_parse_shfexpr(ctx);
    expr_ret_394 = expr_ret_395;
    n = expr_ret_395;
  }

  // ModExprList 1
  if (expr_ret_394)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_394
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_394)
  {
    daisho_astnode_t* expr_ret_396 = NULL;
    expr_ret_396 = SUCC;
    while (expr_ret_396)
    {
      daisho_astnode_t* expr_ret_397 = NULL;
      rec(mod_397);
      // ModExprList 0
      {
        dbg_enter(ctx, "POW", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          // Not capturing POW.
          expr_ret_397 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_397 = NULL;
        }

        if (expr_ret_397) dbg_accept(ctx, "POW"); else dbg_reject(ctx, "POW");
      }

      // ModExprList 1
      if (expr_ret_397)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_397
        ret = SUCC;

        rule=srepr(node(POW, rule, n), "**");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_397) rew(mod_397);
      expr_ret_396 = expr_ret_397 ? SUCC : NULL;
    }

    expr_ret_396 = SUCC;
    expr_ret_394 = expr_ret_396;
  }

  // ModExprList end
  if (!expr_ret_394) rew(mod_394);
  expr_ret_393 = expr_ret_394 ? SUCC : NULL;
  if (!rule) rule = expr_ret_393;
  if (!expr_ret_393) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "powexpr");
  else if (rule) dbg_accept(ctx, "powexpr");
  else dbg_reject(ctx, "powexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_398

  daisho_astnode_t* expr_ret_399 = NULL;
  daisho_astnode_t* expr_ret_398 = NULL;
  dbg_enter(ctx, "shfexpr", ctx->pos);
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
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_400
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_400)
  {
    daisho_astnode_t* expr_ret_402 = NULL;
    expr_ret_402 = SUCC;
    while (expr_ret_402)
    {
      daisho_astnode_t* expr_ret_403 = NULL;

      rec(slash_403);

      // SlashExpr 0
      if (!expr_ret_403)
      {
        daisho_astnode_t* expr_ret_404 = NULL;
        rec(mod_404);
        // ModExprList 0
        {
          dbg_enter(ctx, "LT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_404 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_404 = NULL;
          }

          if (expr_ret_404) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
        }

        // ModExprList 1
        if (expr_ret_404)
        {
          dbg_enter(ctx, "LT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Not capturing LT.
            expr_ret_404 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_404 = NULL;
          }

          if (expr_ret_404) dbg_accept(ctx, "LT"); else dbg_reject(ctx, "LT");
        }

        // ModExprList 2
        if (expr_ret_404)
        {
          daisho_astnode_t* expr_ret_405 = NULL;
          expr_ret_405 = daisho_parse_callexpr(ctx);
          expr_ret_404 = expr_ret_405;
          n = expr_ret_405;
        }

        // ModExprList 3
        if (expr_ret_404)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_404
          ret = SUCC;

          rule=srepr(node(BSL, rule, n), "<<");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_404) rew(mod_404);
        expr_ret_403 = expr_ret_404 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_403)
      {
        daisho_astnode_t* expr_ret_406 = NULL;
        rec(mod_406);
        // ModExprList 0
        {
          dbg_enter(ctx, "GT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_406 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_406 = NULL;
          }

          if (expr_ret_406) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
        }

        // ModExprList 1
        if (expr_ret_406)
        {
          dbg_enter(ctx, "GT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Not capturing GT.
            expr_ret_406 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_406 = NULL;
          }

          if (expr_ret_406) dbg_accept(ctx, "GT"); else dbg_reject(ctx, "GT");
        }

        // ModExprList 2
        if (expr_ret_406)
        {
          daisho_astnode_t* expr_ret_407 = NULL;
          expr_ret_407 = daisho_parse_callexpr(ctx);
          expr_ret_406 = expr_ret_407;
          n = expr_ret_407;
        }

        // ModExprList 3
        if (expr_ret_406)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_406
          ret = SUCC;

          rule=srepr(node(BSR, rule, n), ">>");

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_406) rew(mod_406);
        expr_ret_403 = expr_ret_406 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_403) rew(slash_403);
      expr_ret_402 = expr_ret_403;

    }

    expr_ret_402 = SUCC;
    expr_ret_400 = expr_ret_402;
  }

  // ModExprList end
  if (!expr_ret_400) rew(mod_400);
  expr_ret_399 = expr_ret_400 ? SUCC : NULL;
  if (!rule) rule = expr_ret_399;
  if (!expr_ret_399) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "shfexpr");
  else if (rule) dbg_accept(ctx, "shfexpr");
  else dbg_reject(ctx, "shfexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* vi = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* args = NULL;
  daisho_astnode_t* n = NULL;
  #define rule expr_ret_408

  daisho_astnode_t* expr_ret_409 = NULL;
  daisho_astnode_t* expr_ret_408 = NULL;
  dbg_enter(ctx, "callexpr", ctx->pos);
  daisho_astnode_t* expr_ret_410 = NULL;

  rec(slash_410);

  // SlashExpr 0
  if (!expr_ret_410)
  {
    daisho_astnode_t* expr_ret_411 = NULL;
    rec(mod_411);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_412 = NULL;
      dbg_enter(ctx, "VARIDENT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_412 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_412->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_412->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_412 = NULL;
      }

      if (expr_ret_412) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
      expr_ret_411 = expr_ret_412;
      vi = expr_ret_412;
    }

    // ModExprList 1
    if (expr_ret_411)
    {
      daisho_astnode_t* expr_ret_413 = NULL;
      expr_ret_413 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_413)
        expr_ret_413 = SUCC;
      expr_ret_411 = expr_ret_413;
      t = expr_ret_413;
    }

    // ModExprList 2
    if (expr_ret_411)
    {
      daisho_astnode_t* expr_ret_414 = NULL;
      expr_ret_414 = SUCC;
      while (expr_ret_414)
      {
        daisho_astnode_t* expr_ret_415 = NULL;
        rec(mod_415);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_416 = NULL;
          expr_ret_416 = daisho_parse_fncallargs(ctx);
          expr_ret_415 = expr_ret_416;
          args = expr_ret_416;
        }

        // ModExprList 1
        if (expr_ret_415)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_415
          ret = SUCC;

          rule=node(CALL, vi, args); if (has(t)) {rule=node(TMPLCALL, rule, t);t=NULL;};

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_415) rew(mod_415);
        expr_ret_414 = expr_ret_415 ? SUCC : NULL;
      }

      expr_ret_414 = SUCC;
      expr_ret_411 = expr_ret_414;
    }

    // ModExprList 3
    if (expr_ret_411)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_411
      ret = SUCC;

      ret=!has(rule)?NULL:SUCC;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList end
    if (!expr_ret_411) rew(mod_411);
    expr_ret_410 = expr_ret_411 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_410)
  {
    daisho_astnode_t* expr_ret_417 = NULL;
    rec(mod_417);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_418 = NULL;
      expr_ret_418 = daisho_parse_castexpr(ctx);
      expr_ret_417 = expr_ret_418;
      n = expr_ret_418;
    }

    // ModExprList 1
    if (expr_ret_417)
    {
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_417
      ret = SUCC;

      rule=n;

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
    }

    // ModExprList 2
    if (expr_ret_417)
    {
      daisho_astnode_t* expr_ret_419 = NULL;
      expr_ret_419 = SUCC;
      while (expr_ret_419)
      {
        daisho_astnode_t* expr_ret_420 = NULL;
        rec(mod_420);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_421 = NULL;
          expr_ret_421 = daisho_parse_fncallargs(ctx);
          expr_ret_420 = expr_ret_421;
          args = expr_ret_421;
        }

        // ModExprList 1
        if (expr_ret_420)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_420
          ret = SUCC;

          rule=node(CALL, rule, args);

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_420) rew(mod_420);
        expr_ret_419 = expr_ret_420 ? SUCC : NULL;
      }

      expr_ret_419 = SUCC;
      expr_ret_417 = expr_ret_419;
    }

    // ModExprList end
    if (!expr_ret_417) rew(mod_417);
    expr_ret_410 = expr_ret_417 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_410) rew(slash_410);
  expr_ret_409 = expr_ret_410;

  if (!rule) rule = expr_ret_409;
  if (!expr_ret_409) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "callexpr");
  else if (rule) dbg_accept(ctx, "callexpr");
  else dbg_reject(ctx, "callexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fncallargs(daisho_parser_ctx* ctx) {
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_422

  daisho_astnode_t* expr_ret_423 = NULL;
  daisho_astnode_t* expr_ret_422 = NULL;
  dbg_enter(ctx, "fncallargs", ctx->pos);
  daisho_astnode_t* expr_ret_424 = NULL;
  rec(mod_424);
  // ModExprList 0
  {
    dbg_enter(ctx, "OPEN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_424 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_424 = NULL;
    }

    if (expr_ret_424) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
  }

  // ModExprList 1
  if (expr_ret_424)
  {
    daisho_astnode_t* expr_ret_425 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_425
    ret = SUCC;

    ret=rule=list(FNARGLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_424 = expr_ret_425;
    l = expr_ret_425;
  }

  // ModExprList 2
  if (expr_ret_424)
  {
    daisho_astnode_t* expr_ret_426 = NULL;
    expr_ret_426 = daisho_parse_expr(ctx);
    // optional
    if (!expr_ret_426)
      expr_ret_426 = SUCC;
    expr_ret_424 = expr_ret_426;
    e = expr_ret_426;
  }

  // ModExprList 3
  if (expr_ret_424)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_424
    ret = SUCC;

    if (has(e)) add(l, e);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 4
  if (expr_ret_424)
  {
    daisho_astnode_t* expr_ret_427 = NULL;
    expr_ret_427 = SUCC;
    while (expr_ret_427)
    {
      daisho_astnode_t* expr_ret_428 = NULL;
      rec(mod_428);
      // ModExprList 0
      {
        dbg_enter(ctx, "COMMA", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_428 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_428 = NULL;
        }

        if (expr_ret_428) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
      }

      // ModExprList 1
      if (expr_ret_428)
      {
        daisho_astnode_t* expr_ret_429 = NULL;
        expr_ret_429 = daisho_parse_expr(ctx);
        expr_ret_428 = expr_ret_429;
        e = expr_ret_429;
      }

      // ModExprList 2
      if (expr_ret_428)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_428
        ret = SUCC;

        add(l, e);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_428) rew(mod_428);
      expr_ret_427 = expr_ret_428 ? SUCC : NULL;
    }

    expr_ret_427 = SUCC;
    expr_ret_424 = expr_ret_427;
  }

  // ModExprList 5
  if (expr_ret_424)
  {
    daisho_astnode_t* expr_ret_430 = NULL;
    dbg_enter(ctx, "COMMA", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_430 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_430 = NULL;
    }

    if (expr_ret_430) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
    // optional
    if (!expr_ret_430)
      expr_ret_430 = SUCC;
    expr_ret_424 = expr_ret_430;
  }

  // ModExprList 6
  if (expr_ret_424)
  {
    dbg_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_424 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_424 = NULL;
    }

    if (expr_ret_424) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
  }

  // ModExprList end
  if (!expr_ret_424) rew(mod_424);
  expr_ret_423 = expr_ret_424 ? SUCC : NULL;
  if (!rule) rule = expr_ret_423;
  if (!expr_ret_423) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "fncallargs");
  else if (rule) dbg_accept(ctx, "fncallargs");
  else dbg_reject(ctx, "fncallargs");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* t = NULL;
  #define rule expr_ret_431

  daisho_astnode_t* expr_ret_432 = NULL;
  daisho_astnode_t* expr_ret_431 = NULL;
  dbg_enter(ctx, "castexpr", ctx->pos);
  daisho_astnode_t* expr_ret_433 = NULL;
  rec(mod_433);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_434 = NULL;
    expr_ret_434 = daisho_parse_refexpr(ctx);
    expr_ret_433 = expr_ret_434;
    n = expr_ret_434;
  }

  // ModExprList 1
  if (expr_ret_433)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_433
    ret = SUCC;

    rule=n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_433)
  {
    daisho_astnode_t* expr_ret_435 = NULL;
    expr_ret_435 = SUCC;
    while (expr_ret_435)
    {
      daisho_astnode_t* expr_ret_436 = NULL;
      rec(mod_436);
      // ModExprList 0
      {
        dbg_enter(ctx, "OPEN", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_436 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_436 = NULL;
        }

        if (expr_ret_436) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
      }

      // ModExprList 1
      if (expr_ret_436)
      {
        daisho_astnode_t* expr_ret_437 = NULL;
        expr_ret_437 = daisho_parse_type(ctx);
        expr_ret_436 = expr_ret_437;
        t = expr_ret_437;
      }

      // ModExprList 2
      if (expr_ret_436)
      {
        dbg_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_436 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_436 = NULL;
        }

        if (expr_ret_436) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
      }

      // ModExprList 3
      if (expr_ret_436)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_436
        ret = SUCC;

        rule = srepr(node(CAST, rule, t), "cast");

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_436) rew(mod_436);
      expr_ret_435 = expr_ret_436 ? SUCC : NULL;
    }

    expr_ret_435 = SUCC;
    expr_ret_433 = expr_ret_435;
  }

  // ModExprList end
  if (!expr_ret_433) rew(mod_433);
  expr_ret_432 = expr_ret_433 ? SUCC : NULL;
  if (!rule) rule = expr_ret_432;
  if (!expr_ret_432) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "castexpr");
  else if (rule) dbg_accept(ctx, "castexpr");
  else dbg_reject(ctx, "castexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  #define rule expr_ret_438

  daisho_astnode_t* expr_ret_439 = NULL;
  daisho_astnode_t* expr_ret_438 = NULL;
  dbg_enter(ctx, "refexpr", ctx->pos);
  daisho_astnode_t* expr_ret_440 = NULL;
  rec(mod_440);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_441 = NULL;
    expr_ret_441 = daisho_parse_derefexpr(ctx);
    expr_ret_440 = expr_ret_441;
    n = expr_ret_441;
  }

  // ModExprList 1
  if (expr_ret_440)
  {
    daisho_astnode_t* expr_ret_442 = NULL;
    dbg_enter(ctx, "REF", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_442 = leaf(REF);
      #if DAISHO_SOURCEINFO
      expr_ret_442->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_442->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_442 = NULL;
    }

    if (expr_ret_442) dbg_accept(ctx, "REF"); else dbg_reject(ctx, "REF");
    // optional
    if (!expr_ret_442)
      expr_ret_442 = SUCC;
    expr_ret_440 = expr_ret_442;
    r = expr_ret_442;
  }

  // ModExprList 2
  if (expr_ret_440)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_440
    ret = SUCC;

    rule=has(r) ? srepr(node(REF, n), "@") : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_440) rew(mod_440);
  expr_ret_439 = expr_ret_440 ? SUCC : NULL;
  if (!rule) rule = expr_ret_439;
  if (!expr_ret_439) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "refexpr");
  else if (rule) dbg_accept(ctx, "refexpr");
  else dbg_reject(ctx, "refexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  #define rule expr_ret_443

  daisho_astnode_t* expr_ret_444 = NULL;
  daisho_astnode_t* expr_ret_443 = NULL;
  dbg_enter(ctx, "derefexpr", ctx->pos);
  daisho_astnode_t* expr_ret_445 = NULL;
  rec(mod_445);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_446 = NULL;
    expr_ret_446 = daisho_parse_postretexpr(ctx);
    expr_ret_445 = expr_ret_446;
    n = expr_ret_446;
  }

  // ModExprList 1
  if (expr_ret_445)
  {
    daisho_astnode_t* expr_ret_447 = NULL;
    dbg_enter(ctx, "DEREF", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
      // Capturing DEREF.
      expr_ret_447 = leaf(DEREF);
      #if DAISHO_SOURCEINFO
      expr_ret_447->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_447->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_447 = NULL;
    }

    if (expr_ret_447) dbg_accept(ctx, "DEREF"); else dbg_reject(ctx, "DEREF");
    // optional
    if (!expr_ret_447)
      expr_ret_447 = SUCC;
    expr_ret_445 = expr_ret_447;
    d = expr_ret_447;
  }

  // ModExprList 2
  if (expr_ret_445)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_445
    ret = SUCC;

    rule=has(d) ? srepr(node(REF, n), "$") : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_445) rew(mod_445);
  expr_ret_444 = expr_ret_445 ? SUCC : NULL;
  if (!rule) rule = expr_ret_444;
  if (!expr_ret_444) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "derefexpr");
  else if (rule) dbg_accept(ctx, "derefexpr");
  else dbg_reject(ctx, "derefexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  #define rule expr_ret_448

  daisho_astnode_t* expr_ret_449 = NULL;
  daisho_astnode_t* expr_ret_448 = NULL;
  dbg_enter(ctx, "postretexpr", ctx->pos);
  daisho_astnode_t* expr_ret_450 = NULL;
  rec(mod_450);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_451 = NULL;
    expr_ret_451 = daisho_parse_atomexpr(ctx);
    expr_ret_450 = expr_ret_451;
    n = expr_ret_451;
  }

  // ModExprList 1
  if (expr_ret_450)
  {
    daisho_astnode_t* expr_ret_452 = NULL;
    dbg_enter(ctx, "GRAVE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      // Capturing GRAVE.
      expr_ret_452 = leaf(GRAVE);
      #if DAISHO_SOURCEINFO
      expr_ret_452->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_452->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_452 = NULL;
    }

    if (expr_ret_452) dbg_accept(ctx, "GRAVE"); else dbg_reject(ctx, "GRAVE");
    // optional
    if (!expr_ret_452)
      expr_ret_452 = SUCC;
    expr_ret_450 = expr_ret_452;
    g = expr_ret_452;
  }

  // ModExprList 2
  if (expr_ret_450)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_450
    ret = SUCC;

    rule=has(g) ? srepr(node(RET, n), "return") : n;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_450) rew(mod_450);
  expr_ret_449 = expr_ret_450 ? SUCC : NULL;
  if (!rule) rule = expr_ret_449;
  if (!expr_ret_449) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "postretexpr");
  else if (rule) dbg_accept(ctx, "postretexpr");
  else dbg_reject(ctx, "postretexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  #define rule expr_ret_453

  daisho_astnode_t* expr_ret_454 = NULL;
  daisho_astnode_t* expr_ret_453 = NULL;
  dbg_enter(ctx, "atomexpr", ctx->pos);
  daisho_astnode_t* expr_ret_455 = NULL;

  rec(slash_455);

  // SlashExpr 0
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_456 = NULL;
    rec(mod_456);
    // ModExprList Forwarding
    expr_ret_456 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_456) rew(mod_456);
    expr_ret_455 = expr_ret_456;
  }

  // SlashExpr 1
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_457 = NULL;
    rec(mod_457);
    // ModExprList Forwarding
    expr_ret_457 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_457) rew(mod_457);
    expr_ret_455 = expr_ret_457;
  }

  // SlashExpr 2
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_458 = NULL;
    rec(mod_458);
    // ModExprList Forwarding
    expr_ret_458 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_458) rew(mod_458);
    expr_ret_455 = expr_ret_458;
  }

  // SlashExpr 3
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_459 = NULL;
    rec(mod_459);
    // ModExprList Forwarding
    expr_ret_459 = daisho_parse_listlit(ctx);
    // ModExprList end
    if (!expr_ret_459) rew(mod_459);
    expr_ret_455 = expr_ret_459;
  }

  // SlashExpr 4
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_460 = NULL;
    rec(mod_460);
    // ModExprList Forwarding
    expr_ret_460 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_460) rew(mod_460);
    expr_ret_455 = expr_ret_460;
  }

  // SlashExpr 5
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_461 = NULL;
    rec(mod_461);
    // ModExprList Forwarding
    expr_ret_461 = daisho_parse_preretexpr(ctx);
    // ModExprList end
    if (!expr_ret_461) rew(mod_461);
    expr_ret_455 = expr_ret_461;
  }

  // SlashExpr 6
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_462 = NULL;
    rec(mod_462);
    // ModExprList Forwarding
    dbg_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_462 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_462->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_462->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_462 = NULL;
    }

    if (expr_ret_462) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    // ModExprList end
    if (!expr_ret_462) rew(mod_462);
    expr_ret_455 = expr_ret_462;
  }

  // SlashExpr 7
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_463 = NULL;
    rec(mod_463);
    // ModExprList Forwarding
    expr_ret_463 = daisho_parse_numlit(ctx);
    // ModExprList end
    if (!expr_ret_463) rew(mod_463);
    expr_ret_455 = expr_ret_463;
  }

  // SlashExpr 8
  if (!expr_ret_455)
  {
    daisho_astnode_t* expr_ret_464 = NULL;
    rec(mod_464);
    // ModExprList Forwarding
    expr_ret_464 = daisho_parse_strlit(ctx);
    // ModExprList end
    if (!expr_ret_464) rew(mod_464);
    expr_ret_455 = expr_ret_464;
  }

  // SlashExpr end
  if (!expr_ret_455) rew(slash_455);
  expr_ret_454 = expr_ret_455;

  if (!rule) rule = expr_ret_454;
  if (!expr_ret_454) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "atomexpr");
  else if (rule) dbg_accept(ctx, "atomexpr");
  else dbg_reject(ctx, "atomexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_465

  daisho_astnode_t* expr_ret_466 = NULL;
  daisho_astnode_t* expr_ret_465 = NULL;
  dbg_enter(ctx, "blockexpr", ctx->pos);
  daisho_astnode_t* expr_ret_467 = NULL;
  rec(mod_467);
  // ModExprList 0
  {
    dbg_enter(ctx, "LCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_467 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_467 = NULL;
    }

    if (expr_ret_467) dbg_accept(ctx, "LCBRACK"); else dbg_reject(ctx, "LCBRACK");
  }

  // ModExprList 1
  if (expr_ret_467)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_467
    ret = SUCC;

    rule=list(BLK);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList 2
  if (expr_ret_467)
  {
    daisho_astnode_t* expr_ret_468 = NULL;
    expr_ret_468 = SUCC;
    while (expr_ret_468)
    {
      daisho_astnode_t* expr_ret_469 = NULL;
      rec(mod_469);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_470 = NULL;
        expr_ret_470 = daisho_parse_expr(ctx);
        expr_ret_469 = expr_ret_470;
        e = expr_ret_470;
      }

      // ModExprList 1
      if (expr_ret_469)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_469
        ret = SUCC;

        add(rule, e);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_469) rew(mod_469);
      expr_ret_468 = expr_ret_469 ? SUCC : NULL;
    }

    expr_ret_468 = SUCC;
    expr_ret_467 = expr_ret_468;
  }

  // ModExprList 3
  if (expr_ret_467)
  {
    dbg_enter(ctx, "RCBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_467 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_467 = NULL;
    }

    if (expr_ret_467) dbg_accept(ctx, "RCBRACK"); else dbg_reject(ctx, "RCBRACK");
  }

  // ModExprList end
  if (!expr_ret_467) rew(mod_467);
  expr_ret_466 = expr_ret_467 ? SUCC : NULL;
  if (!rule) rule = expr_ret_466;
  if (!expr_ret_466) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "blockexpr");
  else if (rule) dbg_accept(ctx, "blockexpr");
  else dbg_reject(ctx, "blockexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* caps = NULL;
  daisho_astnode_t* args = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_471

  daisho_astnode_t* expr_ret_472 = NULL;
  daisho_astnode_t* expr_ret_471 = NULL;
  dbg_enter(ctx, "lambdaexpr", ctx->pos);
  daisho_astnode_t* expr_ret_473 = NULL;
  rec(mod_473);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_474 = NULL;
    daisho_astnode_t* expr_ret_475 = NULL;
    rec(mod_475);
    // ModExprList 0
    {
      dbg_enter(ctx, "LSBRACK", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
        // Not capturing LSBRACK.
        expr_ret_475 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_475 = NULL;
      }

      if (expr_ret_475) dbg_accept(ctx, "LSBRACK"); else dbg_reject(ctx, "LSBRACK");
    }

    // ModExprList 1
    if (expr_ret_475)
    {
      daisho_astnode_t* expr_ret_476 = NULL;
      dbg_enter(ctx, "VARIDENT", ctx->pos);
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

      if (expr_ret_476) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
      // optional
      if (!expr_ret_476)
        expr_ret_476 = SUCC;
      expr_ret_475 = expr_ret_476;
      v = expr_ret_476;
    }

    // ModExprList 2
    if (expr_ret_475)
    {
      daisho_astnode_t* expr_ret_477 = NULL;
      // CodeExpr
      dbg_enter(ctx, "CodeExpr", ctx->pos);
      #define ret expr_ret_477
      ret = SUCC;

      ret=list(ARGLIST);if (has(v)) add(ret, v);

      if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
      #undef ret
      expr_ret_475 = expr_ret_477;
      caps = expr_ret_477;
    }

    // ModExprList 3
    if (expr_ret_475)
    {
      daisho_astnode_t* expr_ret_478 = NULL;
      expr_ret_478 = SUCC;
      while (expr_ret_478)
      {
        daisho_astnode_t* expr_ret_479 = NULL;
        rec(mod_479);
        // ModExprList 0
        {
          dbg_enter(ctx, "COMMA", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_479 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_479 = NULL;
          }

          if (expr_ret_479) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
        }

        // ModExprList 1
        if (expr_ret_479)
        {
          daisho_astnode_t* expr_ret_480 = NULL;
          dbg_enter(ctx, "VARIDENT", ctx->pos);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
            // Capturing VARIDENT.
            expr_ret_480 = leaf(VARIDENT);
            #if DAISHO_SOURCEINFO
            expr_ret_480->tok_repr = ctx->tokens[ctx->pos].content;
            expr_ret_480->len_or_toknum = ctx->tokens[ctx->pos].len;
            #endif
            ctx->pos++;
          } else {
            expr_ret_480 = NULL;
          }

          if (expr_ret_480) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
          expr_ret_479 = expr_ret_480;
          v = expr_ret_480;
        }

        // ModExprList 2
        if (expr_ret_479)
        {
          // CodeExpr
          dbg_enter(ctx, "CodeExpr", ctx->pos);
          #define ret expr_ret_479
          ret = SUCC;

          add(caps, v);

          if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
          #undef ret
        }

        // ModExprList end
        if (!expr_ret_479) rew(mod_479);
        expr_ret_478 = expr_ret_479 ? SUCC : NULL;
      }

      expr_ret_478 = SUCC;
      expr_ret_475 = expr_ret_478;
    }

    // ModExprList 4
    if (expr_ret_475)
    {
      dbg_enter(ctx, "RSBRACK", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
        // Not capturing RSBRACK.
        expr_ret_475 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_475 = NULL;
      }

      if (expr_ret_475) dbg_accept(ctx, "RSBRACK"); else dbg_reject(ctx, "RSBRACK");
    }

    // ModExprList end
    if (!expr_ret_475) rew(mod_475);
    expr_ret_474 = expr_ret_475 ? SUCC : NULL;
    // optional
    if (!expr_ret_474)
      expr_ret_474 = SUCC;
    expr_ret_473 = expr_ret_474;
  }

  // ModExprList 1
  if (expr_ret_473)
  {
    daisho_astnode_t* expr_ret_481 = NULL;
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_481
    ret = SUCC;

    ret=list(ARGLIST);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
    expr_ret_473 = expr_ret_481;
    args = expr_ret_481;
  }

  // ModExprList 2
  if (expr_ret_473)
  {
    daisho_astnode_t* expr_ret_482 = NULL;

    rec(slash_482);

    // SlashExpr 0
    if (!expr_ret_482)
    {
      daisho_astnode_t* expr_ret_483 = NULL;
      rec(mod_483);
      // ModExprList 0
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_483
        ret = SUCC;

        ret=(!caps || !caps->num_children)?SUCC:NULL;

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 1
      if (expr_ret_483)
      {
        daisho_astnode_t* expr_ret_484 = NULL;
        dbg_enter(ctx, "VARIDENT", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
          // Capturing VARIDENT.
          expr_ret_484 = leaf(VARIDENT);
          #if DAISHO_SOURCEINFO
          expr_ret_484->tok_repr = ctx->tokens[ctx->pos].content;
          expr_ret_484->len_or_toknum = ctx->tokens[ctx->pos].len;
          #endif
          ctx->pos++;
        } else {
          expr_ret_484 = NULL;
        }

        if (expr_ret_484) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
        expr_ret_483 = expr_ret_484;
        v = expr_ret_484;
      }

      // ModExprList 2
      if (expr_ret_483)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_483
        ret = SUCC;

        add(args, v);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList end
      if (!expr_ret_483) rew(mod_483);
      expr_ret_482 = expr_ret_483 ? SUCC : NULL;
    }

    // SlashExpr 1
    if (!expr_ret_482)
    {
      daisho_astnode_t* expr_ret_485 = NULL;
      rec(mod_485);
      // ModExprList 0
      {
        dbg_enter(ctx, "OPEN", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
          // Not capturing OPEN.
          expr_ret_485 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_485 = NULL;
        }

        if (expr_ret_485) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
      }

      // ModExprList 1
      if (expr_ret_485)
      {
        daisho_astnode_t* expr_ret_486 = NULL;
        dbg_enter(ctx, "VARIDENT", ctx->pos);
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

        if (expr_ret_486) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
        // optional
        if (!expr_ret_486)
          expr_ret_486 = SUCC;
        expr_ret_485 = expr_ret_486;
        v = expr_ret_486;
      }

      // ModExprList 2
      if (expr_ret_485)
      {
        // CodeExpr
        dbg_enter(ctx, "CodeExpr", ctx->pos);
        #define ret expr_ret_485
        ret = SUCC;

        add(args, v);

        if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
        #undef ret
      }

      // ModExprList 3
      if (expr_ret_485)
      {
        daisho_astnode_t* expr_ret_487 = NULL;
        expr_ret_487 = SUCC;
        while (expr_ret_487)
        {
          daisho_astnode_t* expr_ret_488 = NULL;
          rec(mod_488);
          // ModExprList 0
          {
            dbg_enter(ctx, "COMMA", ctx->pos);
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
              // Not capturing COMMA.
              expr_ret_488 = SUCC;
              ctx->pos++;
            } else {
              expr_ret_488 = NULL;
            }

            if (expr_ret_488) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
          }

          // ModExprList 1
          if (expr_ret_488)
          {
            daisho_astnode_t* expr_ret_489 = NULL;
            dbg_enter(ctx, "VARIDENT", ctx->pos);
            if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
              // Capturing VARIDENT.
              expr_ret_489 = leaf(VARIDENT);
              #if DAISHO_SOURCEINFO
              expr_ret_489->tok_repr = ctx->tokens[ctx->pos].content;
              expr_ret_489->len_or_toknum = ctx->tokens[ctx->pos].len;
              #endif
              ctx->pos++;
            } else {
              expr_ret_489 = NULL;
            }

            if (expr_ret_489) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
            expr_ret_488 = expr_ret_489;
            v = expr_ret_489;
          }

          // ModExprList 2
          if (expr_ret_488)
          {
            // CodeExpr
            dbg_enter(ctx, "CodeExpr", ctx->pos);
            #define ret expr_ret_488
            ret = SUCC;

            add(args, v);

            if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
            #undef ret
          }

          // ModExprList end
          if (!expr_ret_488) rew(mod_488);
          expr_ret_487 = expr_ret_488 ? SUCC : NULL;
        }

        expr_ret_487 = SUCC;
        expr_ret_485 = expr_ret_487;
      }

      // ModExprList 4
      if (expr_ret_485)
      {
        dbg_enter(ctx, "CLOSE", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
          // Not capturing CLOSE.
          expr_ret_485 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_485 = NULL;
        }

        if (expr_ret_485) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
      }

      // ModExprList end
      if (!expr_ret_485) rew(mod_485);
      expr_ret_482 = expr_ret_485 ? SUCC : NULL;
    }

    // SlashExpr end
    if (!expr_ret_482) rew(slash_482);
    expr_ret_473 = expr_ret_482;

  }

  // ModExprList 3
  if (expr_ret_473)
  {
    dbg_enter(ctx, "ARROW", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
      // Not capturing ARROW.
      expr_ret_473 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_473 = NULL;
    }

    if (expr_ret_473) dbg_accept(ctx, "ARROW"); else dbg_reject(ctx, "ARROW");
  }

  // ModExprList 4
  if (expr_ret_473)
  {
    daisho_astnode_t* expr_ret_490 = NULL;
    expr_ret_490 = daisho_parse_expr(ctx);
    expr_ret_473 = expr_ret_490;
    e = expr_ret_490;
  }

  // ModExprList 5
  if (expr_ret_473)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_473
    ret = SUCC;

    rule=node(LAMBDA, caps, args, e);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_473) rew(mod_473);
  expr_ret_472 = expr_ret_473 ? SUCC : NULL;
  if (!rule) rule = expr_ret_472;
  if (!expr_ret_472) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "lambdaexpr");
  else if (rule) dbg_accept(ctx, "lambdaexpr");
  else dbg_reject(ctx, "lambdaexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  #define rule expr_ret_491

  daisho_astnode_t* expr_ret_492 = NULL;
  daisho_astnode_t* expr_ret_491 = NULL;
  dbg_enter(ctx, "listcomp", ctx->pos);
  daisho_astnode_t* expr_ret_493 = NULL;
  rec(mod_493);
  // ModExprList 0
  {
    dbg_enter(ctx, "LSBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_493 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_493 = NULL;
    }

    if (expr_ret_493) dbg_accept(ctx, "LSBRACK"); else dbg_reject(ctx, "LSBRACK");
  }

  // ModExprList 1
  if (expr_ret_493)
  {
    daisho_astnode_t* expr_ret_494 = NULL;
    daisho_astnode_t* expr_ret_495 = NULL;
    rec(mod_495);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_496 = NULL;
      dbg_enter(ctx, "VARIDENT", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_496 = leaf(VARIDENT);
        #if DAISHO_SOURCEINFO
        expr_ret_496->tok_repr = ctx->tokens[ctx->pos].content;
        expr_ret_496->len_or_toknum = ctx->tokens[ctx->pos].len;
        #endif
        ctx->pos++;
      } else {
        expr_ret_496 = NULL;
      }

      if (expr_ret_496) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
      expr_ret_495 = expr_ret_496;
      cnt = expr_ret_496;
    }

    // ModExprList 1
    if (expr_ret_495)
    {
      dbg_enter(ctx, "COMMA", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_495 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_495 = NULL;
      }

      if (expr_ret_495) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
    }

    // ModExprList end
    if (!expr_ret_495) rew(mod_495);
    expr_ret_494 = expr_ret_495 ? SUCC : NULL;
    // optional
    if (!expr_ret_494)
      expr_ret_494 = SUCC;
    expr_ret_493 = expr_ret_494;
  }

  // ModExprList 2
  if (expr_ret_493)
  {
    expr_ret_493 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_493)
  {
    dbg_enter(ctx, "FOR", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_493 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_493 = NULL;
    }

    if (expr_ret_493) dbg_accept(ctx, "FOR"); else dbg_reject(ctx, "FOR");
  }

  // ModExprList 4
  if (expr_ret_493)
  {
    daisho_astnode_t* expr_ret_497 = NULL;
    dbg_enter(ctx, "VARIDENT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_497 = leaf(VARIDENT);
      #if DAISHO_SOURCEINFO
      expr_ret_497->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_497->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_497 = NULL;
    }

    if (expr_ret_497) dbg_accept(ctx, "VARIDENT"); else dbg_reject(ctx, "VARIDENT");
    expr_ret_493 = expr_ret_497;
    item = expr_ret_497;
  }

  // ModExprList 5
  if (expr_ret_493)
  {
    dbg_enter(ctx, "IN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_493 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_493 = NULL;
    }

    if (expr_ret_493) dbg_accept(ctx, "IN"); else dbg_reject(ctx, "IN");
  }

  // ModExprList 6
  if (expr_ret_493)
  {
    expr_ret_493 = daisho_parse_expr(ctx);
  }

  // ModExprList 7
  if (expr_ret_493)
  {
    daisho_astnode_t* expr_ret_498 = NULL;
    daisho_astnode_t* expr_ret_499 = NULL;
    rec(mod_499);
    // ModExprList 0
    {
      dbg_enter(ctx, "WHERE", ctx->pos);
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        // Not capturing WHERE.
        expr_ret_499 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_499 = NULL;
      }

      if (expr_ret_499) dbg_accept(ctx, "WHERE"); else dbg_reject(ctx, "WHERE");
    }

    // ModExprList 1
    if (expr_ret_499)
    {
      expr_ret_499 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_499) rew(mod_499);
    expr_ret_498 = expr_ret_499 ? SUCC : NULL;
    // optional
    if (!expr_ret_498)
      expr_ret_498 = SUCC;
    expr_ret_493 = expr_ret_498;
  }

  // ModExprList 8
  if (expr_ret_493)
  {
    dbg_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_493 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_493 = NULL;
    }

    if (expr_ret_493) dbg_accept(ctx, "RSBRACK"); else dbg_reject(ctx, "RSBRACK");
  }

  // ModExprList end
  if (!expr_ret_493) rew(mod_493);
  expr_ret_492 = expr_ret_493 ? SUCC : NULL;
  if (!rule) rule = expr_ret_492;
  if (!expr_ret_492) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "listcomp");
  else if (rule) dbg_accept(ctx, "listcomp");
  else dbg_reject(ctx, "listcomp");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_500

  daisho_astnode_t* expr_ret_501 = NULL;
  daisho_astnode_t* expr_ret_500 = NULL;
  dbg_enter(ctx, "listlit", ctx->pos);
  daisho_astnode_t* expr_ret_502 = NULL;
  rec(mod_502);
  // ModExprList 0
  {
    dbg_enter(ctx, "LSBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_502 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_502 = NULL;
    }

    if (expr_ret_502) dbg_accept(ctx, "LSBRACK"); else dbg_reject(ctx, "LSBRACK");
  }

  // ModExprList 1
  if (expr_ret_502)
  {
    daisho_astnode_t* expr_ret_503 = NULL;
    expr_ret_503 = daisho_parse_expr(ctx);
    // optional
    if (!expr_ret_503)
      expr_ret_503 = SUCC;
    expr_ret_502 = expr_ret_503;
  }

  // ModExprList 2
  if (expr_ret_502)
  {
    daisho_astnode_t* expr_ret_504 = NULL;
    expr_ret_504 = SUCC;
    while (expr_ret_504)
    {
      daisho_astnode_t* expr_ret_505 = NULL;
      rec(mod_505);
      // ModExprList 0
      {
        dbg_enter(ctx, "COMMA", ctx->pos);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_505 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_505 = NULL;
        }

        if (expr_ret_505) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
      }

      // ModExprList 1
      if (expr_ret_505)
      {
        expr_ret_505 = daisho_parse_expr(ctx);
      }

      // ModExprList end
      if (!expr_ret_505) rew(mod_505);
      expr_ret_504 = expr_ret_505 ? SUCC : NULL;
    }

    expr_ret_504 = SUCC;
    expr_ret_502 = expr_ret_504;
  }

  // ModExprList 3
  if (expr_ret_502)
  {
    daisho_astnode_t* expr_ret_506 = NULL;
    dbg_enter(ctx, "COMMA", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_506 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_506 = NULL;
    }

    if (expr_ret_506) dbg_accept(ctx, "COMMA"); else dbg_reject(ctx, "COMMA");
    // optional
    if (!expr_ret_506)
      expr_ret_506 = SUCC;
    expr_ret_502 = expr_ret_506;
  }

  // ModExprList 4
  if (expr_ret_502)
  {
    dbg_enter(ctx, "RSBRACK", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_502 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_502 = NULL;
    }

    if (expr_ret_502) dbg_accept(ctx, "RSBRACK"); else dbg_reject(ctx, "RSBRACK");
  }

  // ModExprList end
  if (!expr_ret_502) rew(mod_502);
  expr_ret_501 = expr_ret_502 ? SUCC : NULL;
  if (!rule) rule = expr_ret_501;
  if (!expr_ret_501) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "listlit");
  else if (rule) dbg_accept(ctx, "listlit");
  else dbg_reject(ctx, "listlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_507

  daisho_astnode_t* expr_ret_508 = NULL;
  daisho_astnode_t* expr_ret_507 = NULL;
  dbg_enter(ctx, "parenexpr", ctx->pos);
  daisho_astnode_t* expr_ret_509 = NULL;
  rec(mod_509);
  // ModExprList 0
  {
    dbg_enter(ctx, "OPEN", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_509 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_509 = NULL;
    }

    if (expr_ret_509) dbg_accept(ctx, "OPEN"); else dbg_reject(ctx, "OPEN");
  }

  // ModExprList 1
  if (expr_ret_509)
  {
    daisho_astnode_t* expr_ret_510 = NULL;
    expr_ret_510 = daisho_parse_expr(ctx);
    expr_ret_509 = expr_ret_510;
    e = expr_ret_510;
  }

  // ModExprList 2
  if (expr_ret_509)
  {
    dbg_enter(ctx, "CLOSE", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_509 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_509 = NULL;
    }

    if (expr_ret_509) dbg_accept(ctx, "CLOSE"); else dbg_reject(ctx, "CLOSE");
  }

  // ModExprList 3
  if (expr_ret_509)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_509
    ret = SUCC;

    rule=e;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_509) rew(mod_509);
  expr_ret_508 = expr_ret_509 ? SUCC : NULL;
  if (!rule) rule = expr_ret_508;
  if (!expr_ret_508) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "parenexpr");
  else if (rule) dbg_accept(ctx, "parenexpr");
  else dbg_reject(ctx, "parenexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  #define rule expr_ret_511

  daisho_astnode_t* expr_ret_512 = NULL;
  daisho_astnode_t* expr_ret_511 = NULL;
  dbg_enter(ctx, "preretexpr", ctx->pos);
  daisho_astnode_t* expr_ret_513 = NULL;
  rec(mod_513);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_514 = NULL;
    dbg_enter(ctx, "RET", ctx->pos);
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

    if (expr_ret_514) dbg_accept(ctx, "RET"); else dbg_reject(ctx, "RET");
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
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_513
    ret = SUCC;

    rule=node(RET, r, e);

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_513) rew(mod_513);
  expr_ret_512 = expr_ret_513 ? SUCC : NULL;
  if (!rule) rule = expr_ret_512;
  if (!expr_ret_512) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "preretexpr");
  else if (rule) dbg_accept(ctx, "preretexpr");
  else dbg_reject(ctx, "preretexpr");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_numlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* pm = NULL;
  daisho_astnode_t* nl = NULL;
  #define rule expr_ret_516

  daisho_astnode_t* expr_ret_517 = NULL;
  daisho_astnode_t* expr_ret_516 = NULL;
  dbg_enter(ctx, "numlit", ctx->pos);
  daisho_astnode_t* expr_ret_518 = NULL;
  rec(mod_518);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_519 = NULL;
    daisho_astnode_t* expr_ret_520 = NULL;

    rec(slash_520);

    // SlashExpr 0
    if (!expr_ret_520)
    {
      daisho_astnode_t* expr_ret_521 = NULL;
      rec(mod_521);
      // ModExprList Forwarding
      dbg_enter(ctx, "PLUS", ctx->pos);
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

      if (expr_ret_521) dbg_accept(ctx, "PLUS"); else dbg_reject(ctx, "PLUS");
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
      dbg_enter(ctx, "MINUS", ctx->pos);
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

      if (expr_ret_522) dbg_accept(ctx, "MINUS"); else dbg_reject(ctx, "MINUS");
      // ModExprList end
      if (!expr_ret_522) rew(mod_522);
      expr_ret_520 = expr_ret_522;
    }

    // SlashExpr end
    if (!expr_ret_520) rew(slash_520);
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
    dbg_enter(ctx, "NUMLIT", ctx->pos);
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

    if (expr_ret_523) dbg_accept(ctx, "NUMLIT"); else dbg_reject(ctx, "NUMLIT");
    expr_ret_518 = expr_ret_523;
    nl = expr_ret_523;
  }

  // ModExprList 2
  if (expr_ret_518)
  {
    // CodeExpr
    dbg_enter(ctx, "CodeExpr", ctx->pos);
    #define ret expr_ret_518
    ret = SUCC;

    rule = nl;

    if (ret) dbg_accept(ctx, "CodeExpr"); else dbg_reject(ctx, "CodeExpr");
    #undef ret
  }

  // ModExprList end
  if (!expr_ret_518) rew(mod_518);
  expr_ret_517 = expr_ret_518 ? SUCC : NULL;
  if (!rule) rule = expr_ret_517;
  if (!expr_ret_517) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "numlit");
  else if (rule) dbg_accept(ctx, "numlit");
  else dbg_reject(ctx, "numlit");
  return rule;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_strlit(daisho_parser_ctx* ctx) {
  #define rule expr_ret_524

  daisho_astnode_t* expr_ret_525 = NULL;
  daisho_astnode_t* expr_ret_524 = NULL;
  dbg_enter(ctx, "strlit", ctx->pos);
  daisho_astnode_t* expr_ret_526 = NULL;

  rec(slash_526);

  // SlashExpr 0
  if (!expr_ret_526)
  {
    daisho_astnode_t* expr_ret_527 = NULL;
    rec(mod_527);
    // ModExprList Forwarding
    dbg_enter(ctx, "STRLIT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_527 = leaf(STRLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_527->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_527->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_527 = NULL;
    }

    if (expr_ret_527) dbg_accept(ctx, "STRLIT"); else dbg_reject(ctx, "STRLIT");
    // ModExprList end
    if (!expr_ret_527) rew(mod_527);
    expr_ret_526 = expr_ret_527;
  }

  // SlashExpr 1
  if (!expr_ret_526)
  {
    daisho_astnode_t* expr_ret_528 = NULL;
    rec(mod_528);
    // ModExprList Forwarding
    dbg_enter(ctx, "FSTRLIT", ctx->pos);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FSTRLIT) {
      // Capturing FSTRLIT.
      expr_ret_528 = leaf(FSTRLIT);
      #if DAISHO_SOURCEINFO
      expr_ret_528->tok_repr = ctx->tokens[ctx->pos].content;
      expr_ret_528->len_or_toknum = ctx->tokens[ctx->pos].len;
      #endif
      ctx->pos++;
    } else {
      expr_ret_528 = NULL;
    }

    if (expr_ret_528) dbg_accept(ctx, "FSTRLIT"); else dbg_reject(ctx, "FSTRLIT");
    // ModExprList end
    if (!expr_ret_528) rew(mod_528);
    expr_ret_526 = expr_ret_528;
  }

  // SlashExpr end
  if (!expr_ret_526) rew(slash_526);
  expr_ret_525 = expr_ret_526;

  if (!rule) rule = expr_ret_525;
  if (!expr_ret_525) rule = NULL;
  rule_end:;
  if (rule==SUCC) dbg_succ(ctx, "strlit");
  else if (rule) dbg_accept(ctx, "strlit");
  else dbg_reject(ctx, "strlit");
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

