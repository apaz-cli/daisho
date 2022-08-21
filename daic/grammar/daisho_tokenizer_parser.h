
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
#define PGEN_AlLOCATOR_DEBUG 0
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
  return (n + align - (n % align));
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

#define PGEN_ALLOC_OF(allocator, type)                                         \
  pgen_alloc(allocator, sizeof(type), _Alignof(type))
static inline char *pgen_alloc(pgen_allocator *allocator, size_t n,
                               size_t alignment) {
#if PGEN_AlLOCATOR_DEBUG
  printf("Allocating, from: (%u, %u)\n", allocator->rew.arena_idx,
         allocator->rew.filled);
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
        return ret;

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

#if PGEN_AlLOCATOR_DEBUG
  printf("Allocated, to: (%u, %u)", allocator->rew.arena_idx,
         allocator->rew.filled);
#endif

  return ret;
}

// Does not take a pgen_allocator_rewind_t, so does not rebind the
// lifetime of the reallocated object.
static inline void pgen_allocator_realloced(pgen_allocator *allocator,
                                            void *old_ptr, void *new_ptr,
                                            void (*new_free_fn)(void *)) {

#if PGEN_AlLOCATOR_DEBUG
  printf("realloc(%p -> %p): ", old_ptr, new_ptr);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
#endif

  for (size_t i = 0; i < allocator->freelist.len; i++) {
    void *ptr = allocator->freelist.entries[i].ptr;
    if (ptr == old_ptr) {
      allocator->freelist.entries[i].ptr = new_ptr;
      allocator->freelist.entries[i].freefn = new_free_fn;
      return;
    }
  }

#if PGEN_AlLOCATOR_DEBUG
  printf("Realloced: ");
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

static inline void pgen_defer(pgen_allocator *allocator, void (*freefn)(void *),
                              void *ptr, pgen_allocator_rewind_t rew) {
#if PGEN_AlLOCATOR_DEBUG
  printf("defer(%p, (%u, %u)) (%u): ", ptr, rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
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

#if PGEN_AlLOCATOR_DEBUG
  printf("Deferred: (%u) ", allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, (%u, %u)) ", allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

static inline void pgen_allocator_rewind(pgen_allocator *allocator,
                                         pgen_allocator_rewind_t rew) {

#if PGEN_AlLOCATOR_DEBUG
  printf("rewind((%u, %u) -> (%u, %u)): (%u) ",
         allocator->freelist.entries->rew.arena_idx,
         allocator->freelist.entries->rew.filled, rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
  puts("");
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

#if PGEN_AlLOCATOR_DEBUG
  printf("rewound(%u, %u): (%u) ", rew.arena_idx, rew.filled,
         allocator->freelist.len);
  for (size_t i = 0; i < allocator->freelist.len; i++) {
    printf("(%p, %p, (%u, %u)) ", allocator->freelist.entries->freefn,
           allocator->freelist.entries->ptr,
           allocator->freelist.entries->rew.arena_idx,
           allocator->freelist.entries->rew.filled);
  }
#endif
}

#endif /* PGEN_ARENA_INCLUDED */

#ifndef PGEN_PARSER_MACROS_INCLUDED
#define PGEN_PARSER_MACROS_INCLUDED
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

#ifndef DAISHO_TOKENIZER_SOURCEINFO
#define DAISHO_TOKENIZER_SOURCEINFO 1
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
  DAISHO_TOK_FOR,
  DAISHO_TOK_IN,
  DAISHO_TOK_WHILE,
  DAISHO_TOK_THEN,
  DAISHO_TOK_ALSO,
  DAISHO_TOK_WHERE,
  DAISHO_TOK_TEMPLATE,
  DAISHO_TOK_STRUCT,
  DAISHO_TOK_UNION,
  DAISHO_TOK_TRAIT,
  DAISHO_TOK_IMPL,
  DAISHO_TOK_FN,
  DAISHO_TOK_FNTYPE,
  DAISHO_TOK_CTYPE,
  DAISHO_TOK_CFUNC,
  DAISHO_TOK_SELFTYPE,
  DAISHO_TOK_SELFVAR,
  DAISHO_TOK_VOIDTYPE,
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
  DAISHO_TOK_SQUOTE,
  DAISHO_TOK_DQUOTE,
  DAISHO_TOK_ARROW,
  DAISHO_TOK_DARROW,
  DAISHO_TOK_RET,
  DAISHO_TOK_OP,
  DAISHO_TOK_REDEF,
  DAISHO_TOK_STRUCTIDENT,
  DAISHO_TOK_TRAITIDENT,
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
// Tokens 1 through 85 are the ones you defined.
// This totals 87 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 87
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
  "DAISHO_TOK_FOR",
  "DAISHO_TOK_IN",
  "DAISHO_TOK_WHILE",
  "DAISHO_TOK_THEN",
  "DAISHO_TOK_ALSO",
  "DAISHO_TOK_WHERE",
  "DAISHO_TOK_TEMPLATE",
  "DAISHO_TOK_STRUCT",
  "DAISHO_TOK_UNION",
  "DAISHO_TOK_TRAIT",
  "DAISHO_TOK_IMPL",
  "DAISHO_TOK_FN",
  "DAISHO_TOK_FNTYPE",
  "DAISHO_TOK_CTYPE",
  "DAISHO_TOK_CFUNC",
  "DAISHO_TOK_SELFTYPE",
  "DAISHO_TOK_SELFVAR",
  "DAISHO_TOK_VOIDTYPE",
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
  "DAISHO_TOK_SQUOTE",
  "DAISHO_TOK_DQUOTE",
  "DAISHO_TOK_ARROW",
  "DAISHO_TOK_DARROW",
  "DAISHO_TOK_RET",
  "DAISHO_TOK_OP",
  "DAISHO_TOK_REDEF",
  "DAISHO_TOK_STRUCTIDENT",
  "DAISHO_TOK_TRAITIDENT",
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
  size_t start; // The token begins at tokenizer->start[token->start].
  size_t len;   // It goes until tokenizer->start[token->start + token->len] (non-inclusive).
#if DAISHO_TOKENIZER_SOURCEINFO
  size_t line;
  size_t col;
  char* sourceFile;
#endif
#ifdef DAISHO_TOKEN_EXTRA
  DAISHO_TOKEN_EXTRA
#endif
} daisho_token;

typedef struct {
  codepoint_t* start;
  size_t len;
  size_t pos;
#if DAISHO_TOKENIZER_SOURCEINFO
  size_t pos_line;
  size_t pos_col;
  char* pos_sourceFile;
#endif
} daisho_tokenizer;

static inline void daisho_tokenizer_init(daisho_tokenizer* tokenizer, codepoint_t* start, size_t len, char* sourceFile) {
  tokenizer->start = start;
  tokenizer->len = len;
  tokenizer->pos = 0;
#if DAISHO_TOKENIZER_SOURCEINFO
  tokenizer->pos_line = 0;
  tokenizer->pos_col = 0;
  tokenizer->pos_sourceFile = sourceFile;
#else
  (void)sourceFile;
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

    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 10;
        else if (c == 34 /*'"'*/) trie_state = 112;
        else if (c == 35 /*'#'*/) trie_state = 107;
        else if (c == 36 /*'$'*/) trie_state = 109;
        else if (c == 37 /*'%'*/) trie_state = 6;
        else if (c == 38 /*'&'*/) trie_state = 7;
        else if (c == 39 /*'''*/) trie_state = 111;
        else if (c == 40 /*'('*/) trie_state = 101;
        else if (c == 41 /*')'*/) trie_state = 102;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 100;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 99;
        else if (c == 47 /*'/'*/) trie_state = 4;
        else if (c == 58 /*':'*/) trie_state = 37;
        else if (c == 59 /*';'*/) trie_state = 98;
        else if (c == 60 /*'<'*/) trie_state = 17;
        else if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 19;
        else if (c == 63 /*'?'*/) trie_state = 36;
        else if (c == 64 /*'@'*/) trie_state = 108;
        else if (c == 70 /*'F'*/) trie_state = 70;
        else if (c == 83 /*'S'*/) trie_state = 77;
        else if (c == 86 /*'V'*/) trie_state = 85;
        else if (c == 91 /*'['*/) trie_state = 105;
        else if (c == 93 /*']'*/) trie_state = 106;
        else if (c == 94 /*'^'*/) trie_state = 9;
        else if (c == 96 /*'`'*/) trie_state = 110;
        else if (c == 97 /*'a'*/) trie_state = 53;
        else if (c == 99 /*'c'*/) trie_state = 72;
        else if (c == 102 /*'f'*/) trie_state = 39;
        else if (c == 105 /*'i'*/) trie_state = 42;
        else if (c == 110 /*'n'*/) trie_state = 89;
        else if (c == 115 /*'s'*/) trie_state = 81;
        else if (c == 116 /*'t'*/) trie_state = 49;
        else if (c == 117 /*'u'*/) trie_state = 60;
        else if (c == 119 /*'w'*/) trie_state = 44;
        else if (c == 123 /*'{'*/) trie_state = 103;
        else if (c == 124 /*'|'*/) trie_state = 8;
        else if (c == 125 /*'}'*/) trie_state = 104;
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
        else if (c == 62 /*'>'*/) trie_state = 113;
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
        else if (c == 62 /*'>'*/) trie_state = 114;
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
        if (c == 116 /*'t'*/) trie_state = 73;
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
        if (c == 101 /*'e'*/) trie_state = 78;
        else trie_state = -1;
      }
      else if (trie_state == 78) {
        if (c == 108 /*'l'*/) trie_state = 79;
        else trie_state = -1;
      }
      else if (trie_state == 79) {
        if (c == 102 /*'f'*/) trie_state = 80;
        else trie_state = -1;
      }
      else if (trie_state == 81) {
        if (c == 101 /*'e'*/) trie_state = 82;
        else trie_state = -1;
      }
      else if (trie_state == 82) {
        if (c == 108 /*'l'*/) trie_state = 83;
        else trie_state = -1;
      }
      else if (trie_state == 83) {
        if (c == 102 /*'f'*/) trie_state = 84;
        else trie_state = -1;
      }
      else if (trie_state == 85) {
        if (c == 111 /*'o'*/) trie_state = 86;
        else trie_state = -1;
      }
      else if (trie_state == 86) {
        if (c == 105 /*'i'*/) trie_state = 87;
        else trie_state = -1;
      }
      else if (trie_state == 87) {
        if (c == 100 /*'d'*/) trie_state = 88;
        else trie_state = -1;
      }
      else if (trie_state == 89) {
        if (c == 97 /*'a'*/) trie_state = 90;
        else trie_state = -1;
      }
      else if (trie_state == 90) {
        if (c == 109 /*'m'*/) trie_state = 91;
        else trie_state = -1;
      }
      else if (trie_state == 91) {
        if (c == 101 /*'e'*/) trie_state = 92;
        else trie_state = -1;
      }
      else if (trie_state == 92) {
        if (c == 115 /*'s'*/) trie_state = 93;
        else trie_state = -1;
      }
      else if (trie_state == 93) {
        if (c == 112 /*'p'*/) trie_state = 94;
        else trie_state = -1;
      }
      else if (trie_state == 94) {
        if (c == 97 /*'a'*/) trie_state = 95;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 99 /*'c'*/) trie_state = 96;
        else trie_state = -1;
      }
      else if (trie_state == 96) {
        if (c == 101 /*'e'*/) trie_state = 97;
        else trie_state = -1;
      }
      else {
        trie_state = -1;
      }

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
      else if (trie_state == 80) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 84) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 88) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 97) {
        trie_tokenkind =  DAISHO_TOK_NAMESPACE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 99) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 100) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 101) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 102) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 103) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 104) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 106) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 107) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_SQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_DQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 114) {
        trie_tokenkind =  DAISHO_TOK_DARROW;
        trie_munch_size = iidx + 1;
      }
    }

    if (smaut_state_0 != -1) {
      all_dead = 0;

      if ((smaut_state_0 == 0) &
         (c == 116)) {
          smaut_state_0 = 1;
      }
      else if ((smaut_state_0 == 1) &
         (c == 109)) {
          smaut_state_0 = 2;
      }
      else if ((smaut_state_0 == 2) &
         (c == 112)) {
          smaut_state_0 = 3;
      }
      else if ((smaut_state_0 == 3) &
         (c == 108)) {
          smaut_state_0 = 4;
      }
      else if ((smaut_state_0 == 1) &
         (c == 101)) {
          smaut_state_0 = 5;
      }
      else if ((smaut_state_0 == 5) &
         (c == 109)) {
          smaut_state_0 = 6;
      }
      else if ((smaut_state_0 == 6) &
         (c == 112)) {
          smaut_state_0 = 7;
      }
      else if ((smaut_state_0 == 7) &
         (c == 108)) {
          smaut_state_0 = 8;
      }
      else if ((smaut_state_0 == 8) &
         (c == 97)) {
          smaut_state_0 = 9;
      }
      else if ((smaut_state_0 == 9) &
         (c == 116)) {
          smaut_state_0 = 10;
      }
      else if ((smaut_state_0 == 10) &
         (c == 101)) {
          smaut_state_0 = 11;
      }
      else {
        smaut_state_0 = -1;
      }

      if ((smaut_state_0 == 4) | (smaut_state_0 == 11)) {
        smaut_munch_size_0 = iidx + 1;
      }
    }

    if (smaut_state_1 != -1) {
      all_dead = 0;

      if ((smaut_state_1 == 0) &
         (c == 99)) {
          smaut_state_1 = 1;
      }
      else if ((smaut_state_1 == 1) &
         (c == 108)) {
          smaut_state_1 = 2;
      }
      else if ((smaut_state_1 == 2) &
         (c == 97)) {
          smaut_state_1 = 3;
      }
      else if ((smaut_state_1 == 3) &
         (c == 115)) {
          smaut_state_1 = 4;
      }
      else if ((smaut_state_1 == 4) &
         (c == 115)) {
          smaut_state_1 = 5;
      }
      else if ((smaut_state_1 == 0) &
         (c == 115)) {
          smaut_state_1 = 6;
      }
      else if ((smaut_state_1 == 6) &
         (c == 116)) {
          smaut_state_1 = 7;
      }
      else if ((smaut_state_1 == 7) &
         (c == 114)) {
          smaut_state_1 = 8;
      }
      else if ((smaut_state_1 == 8) &
         (c == 117)) {
          smaut_state_1 = 9;
      }
      else if ((smaut_state_1 == 9) &
         (c == 99)) {
          smaut_state_1 = 10;
      }
      else if ((smaut_state_1 == 10) &
         (c == 116)) {
          smaut_state_1 = 11;
      }
      else if ((smaut_state_1 == 0) &
         (c == 116)) {
          smaut_state_1 = 13;
      }
      else if ((smaut_state_1 == 13) &
         (c == 121)) {
          smaut_state_1 = 14;
      }
      else if ((smaut_state_1 == 14) &
         (c == 112)) {
          smaut_state_1 = 15;
      }
      else if ((smaut_state_1 == 15) &
         (c == 101)) {
          smaut_state_1 = 16;
      }
      else {
        smaut_state_1 = -1;
      }

      if ((smaut_state_1 == 5) | (smaut_state_1 == 11) | (smaut_state_1 == 16)) {
        smaut_munch_size_1 = iidx + 1;
      }
    }

    if (smaut_state_2 != -1) {
      all_dead = 0;

      if ((smaut_state_2 == 0) &
         (c == 105)) {
          smaut_state_2 = 1;
      }
      else if ((smaut_state_2 == 1) &
         (c == 109)) {
          smaut_state_2 = 2;
      }
      else if ((smaut_state_2 == 2) &
         (c == 112)) {
          smaut_state_2 = 3;
      }
      else if ((smaut_state_2 == 3) &
         (c == 108)) {
          smaut_state_2 = 4;
      }
      else if ((smaut_state_2 == 4) &
         (c == 101)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 4) &
         (c == 105)) {
          smaut_state_2 = 5;
      }
      else if ((smaut_state_2 == 5) &
         (c == 109)) {
          smaut_state_2 = 6;
      }
      else if ((smaut_state_2 == 6) &
         (c == 101)) {
          smaut_state_2 = 7;
      }
      else if ((smaut_state_2 == 7) &
         (c == 110)) {
          smaut_state_2 = 8;
      }
      else if ((smaut_state_2 == 8) &
         (c == 116)) {
          smaut_state_2 = 9;
      }
      else if ((smaut_state_2 == 9) &
         (c == 115)) {
          smaut_state_2 = 10;
      }
      else {
        smaut_state_2 = -1;
      }

      if ((smaut_state_2 == 4) | (smaut_state_2 == 10)) {
        smaut_munch_size_2 = iidx + 1;
      }
    }

    if (smaut_state_3 != -1) {
      all_dead = 0;

      if ((smaut_state_3 == 0) &
         (c == 99)) {
          smaut_state_3 = 1;
      }
      else if ((smaut_state_3 == 1) &
         (c == 102)) {
          smaut_state_3 = 2;
      }
      else if ((smaut_state_3 == 2) &
         (c == 117)) {
          smaut_state_3 = 3;
      }
      else if ((smaut_state_3 == 3) &
         (c == 110)) {
          smaut_state_3 = 4;
      }
      else if ((smaut_state_3 == 4) &
         (c == 99)) {
          smaut_state_3 = 5;
      }
      else if ((smaut_state_3 == 2) &
         (c == 110)) {
          smaut_state_3 = 6;
      }
      else {
        smaut_state_3 = -1;
      }

      if ((smaut_state_3 == 4) | (smaut_state_3 == 5) | (smaut_state_3 == 6)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

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
         (c == 116)) {
          smaut_state_4 = 3;
      }
      else if ((smaut_state_4 == 3) &
         (c == 117)) {
          smaut_state_4 = 4;
      }
      else if ((smaut_state_4 == 4) &
         (c == 114)) {
          smaut_state_4 = 5;
      }
      else if ((smaut_state_4 == 5) &
         (c == 110)) {
          smaut_state_4 = 6;
      }
      else {
        smaut_state_4 = -1;
      }

      if ((smaut_state_4 == 3) | (smaut_state_4 == 6)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    if (smaut_state_5 != -1) {
      all_dead = 0;

      if ((smaut_state_5 == 0) &
         (c == 111)) {
          smaut_state_5 = 1;
      }
      else if ((smaut_state_5 == 1) &
         (c == 112)) {
          smaut_state_5 = 2;
      }
      else if ((smaut_state_5 == 2) &
         (c == 101)) {
          smaut_state_5 = 3;
      }
      else if ((smaut_state_5 == 3) &
         (c == 114)) {
          smaut_state_5 = 4;
      }
      else if ((smaut_state_5 == 4) &
         (c == 97)) {
          smaut_state_5 = 5;
      }
      else if ((smaut_state_5 == 5) &
         (c == 116)) {
          smaut_state_5 = 6;
      }
      else if ((smaut_state_5 == 6) &
         (c == 111)) {
          smaut_state_5 = 7;
      }
      else if ((smaut_state_5 == 7) &
         (c == 114)) {
          smaut_state_5 = 8;
      }
      else {
        smaut_state_5 = -1;
      }

      if ((smaut_state_5 == 2) | (smaut_state_5 == 8)) {
        smaut_munch_size_5 = iidx + 1;
      }
    }

    if (smaut_state_6 != -1) {
      all_dead = 0;

      if ((smaut_state_6 == 0) &
         (c == 114)) {
          smaut_state_6 = 1;
      }
      else if ((smaut_state_6 == 1) &
         (c == 101)) {
          smaut_state_6 = 2;
      }
      else if ((smaut_state_6 == 2) &
         (c == 100)) {
          smaut_state_6 = 3;
      }
      else if ((smaut_state_6 == 3) &
         (c == 101)) {
          smaut_state_6 = 4;
      }
      else if ((smaut_state_6 == 4) &
         (c == 102)) {
          smaut_state_6 = 5;
      }
      else if ((smaut_state_6 == 5) &
         (c == 105)) {
          smaut_state_6 = 6;
      }
      else if ((smaut_state_6 == 6) &
         (c == 110)) {
          smaut_state_6 = 7;
      }
      else if ((smaut_state_6 == 7) &
         (c == 101)) {
          smaut_state_6 = 8;
      }
      else {
        smaut_state_6 = -1;
      }

      if ((smaut_state_6 == 5) | (smaut_state_6 == 8)) {
        smaut_munch_size_6 = iidx + 1;
      }
    }

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
      else {
        smaut_state_7 = -1;
      }

      if ((smaut_state_7 == 1) | (smaut_state_7 == 2)) {
        smaut_munch_size_7 = iidx + 1;
      }
    }

    if (smaut_state_8 != -1) {
      all_dead = 0;

      if ((smaut_state_8 == 0) &
         (((c >= 65) & (c <= 90)))) {
          smaut_state_8 = 1;
      }
      else if (((smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_8 = 2;
      }
      else if (((smaut_state_8 == 1) | (smaut_state_8 == 2)) &
         (c == 39)) {
          smaut_state_8 = 3;
      }
      else {
        smaut_state_8 = -1;
      }

      if (smaut_state_8 == 3) {
        smaut_munch_size_8 = iidx + 1;
      }
    }

    if (smaut_state_9 != -1) {
      all_dead = 0;

      if ((smaut_state_9 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)))) {
          smaut_state_9 = 1;
      }
      else if (((smaut_state_9 == 1) | (smaut_state_9 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 945) & (c <= 969)) | ((c >= 913) & (c <= 937)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_9 = 2;
      }
      else {
        smaut_state_9 = -1;
      }

      if ((smaut_state_9 == 1) | (smaut_state_9 == 2)) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    if (smaut_state_10 != -1) {
      all_dead = 0;

      if ((smaut_state_10 == 0) &
         ((c == 95) | ((c >= 97) & (c <= 122)))) {
          smaut_state_10 = 1;
      }
      else if (((smaut_state_10 == 1) | (smaut_state_10 == 2)) &
         ((c == 95) | ((c >= 97) & (c <= 122)) | ((c >= 65) & (c <= 90)) | ((c >= 48) & (c <= 57)))) {
          smaut_state_10 = 2;
      }
      else {
        smaut_state_10 = -1;
      }

      if ((smaut_state_10 == 1) | (smaut_state_10 == 2)) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    if (smaut_state_11 != -1) {
      all_dead = 0;

      if ((smaut_state_11 == 0) &
         ((c == 45) | (c == 43))) {
          smaut_state_11 = 1;
      }
      else if (((smaut_state_11 == 0) | (smaut_state_11 == 1) | (smaut_state_11 == 2)) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_11 = 2;
      }
      else if ((smaut_state_11 == 2) &
         (c == 46)) {
          smaut_state_11 = 3;
      }
      else if ((smaut_state_11 == 3) &
         (((c >= 48) & (c <= 57)))) {
          smaut_state_11 = 3;
      }
      else {
        smaut_state_11 = -1;
      }

      if ((smaut_state_11 == 2) | (smaut_state_11 == 3)) {
        smaut_munch_size_11 = iidx + 1;
      }
    }

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

      if (smaut_state_12 == 2) {
        smaut_munch_size_12 = iidx + 1;
      }
    }

    if (smaut_state_13 != -1) {
      all_dead = 0;

      if (((smaut_state_13 == 0) | (smaut_state_13 == 1)) &
         ((c == 32) | (c == 10) | (c == 13) | (c == 9))) {
          smaut_state_13 = 1;
      }
      else {
        smaut_state_13 = -1;
      }

      if (smaut_state_13 == 1) {
        smaut_munch_size_13 = iidx + 1;
      }
    }

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

      if (smaut_state_14 == 4) {
        smaut_munch_size_14 = iidx + 1;
      }
    }

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

      if ((smaut_state_15 == 2) | (smaut_state_15 == 3)) {
        smaut_munch_size_15 = iidx + 1;
      }
    }

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

      if (smaut_state_16 == 3) {
        smaut_munch_size_16 = iidx + 1;
      }
    }

    if (all_dead)
      break;
  }

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
    kind = DAISHO_TOK_STRLIT;
    max_munch = smaut_munch_size_12;
  }
  if (smaut_munch_size_11 >= max_munch) {
    kind = DAISHO_TOK_NUMLIT;
    max_munch = smaut_munch_size_11;
  }
  if (smaut_munch_size_10 >= max_munch) {
    kind = DAISHO_TOK_CIDENT;
    max_munch = smaut_munch_size_10;
  }
  if (smaut_munch_size_9 >= max_munch) {
    kind = DAISHO_TOK_VARIDENT;
    max_munch = smaut_munch_size_9;
  }
  if (smaut_munch_size_8 >= max_munch) {
    kind = DAISHO_TOK_TRAITIDENT;
    max_munch = smaut_munch_size_8;
  }
  if (smaut_munch_size_7 >= max_munch) {
    kind = DAISHO_TOK_STRUCTIDENT;
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
    kind = DAISHO_TOK_CFUNC;
    max_munch = smaut_munch_size_3;
  }
  if (smaut_munch_size_2 >= max_munch) {
    kind = DAISHO_TOK_IMPL;
    max_munch = smaut_munch_size_2;
  }
  if (smaut_munch_size_1 >= max_munch) {
    kind = DAISHO_TOK_STRUCT;
    max_munch = smaut_munch_size_1;
  }
  if (smaut_munch_size_0 >= max_munch) {
    kind = DAISHO_TOK_TEMPLATE;
    max_munch = smaut_munch_size_0;
  }
  if (trie_munch_size >= max_munch) {
    kind = trie_tokenkind;
    max_munch = trie_munch_size;
  }

  daisho_token ret;
  ret.kind = kind;
  ret.start = tokenizer->pos;
  ret.len = max_munch;

#if DAISHO_TOKENIZER_SOURCEINFO
  ret.line = tokenizer->pos_line;
  ret.col = tokenizer->pos_col;
  ret.sourceFile = tokenizer->pos_sourceFile;

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
  daisho_NODE_EMPTY,
  DAISHO_NODE_TYPE,
  DAISHO_NODE_TMPLTYPE,
  DAISHO_NODE_TRAITTYPE,
  DAISHO_NODE_STRUCTTYPE,
  DAISHO_NODE_ARGTYPES,
  DAISHO_NODE_TERN,
  DAISHO_NODE_IFEXP,
  DAISHO_NODE_PROG,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_TEMPLATE,
  DAISHO_NODE_MEMBERLIST,
  DAISHO_NODE_STRUCT,
  DAISHO_NODE_TMPLSTRUCT,
  DAISHO_NODE_UNION,
  DAISHO_NODE_TMPLUNION,
  DAISHO_NODE_TRAIT,
  DAISHO_NODE_TMPLTRAIT,
  DAISHO_NODE_QUEST,
  DAISHO_NODE_COLON,
  DAISHO_NODE_FOR,
  DAISHO_NODE_WHILE,
  DAISHO_NODE_CAST,
  DAISHO_NODE_REF,
  DAISHO_NODE_DEREF,
  DAISHO_NODE_BLK,
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
  DAISHO_NODE_STRUCTIDENT,
  DAISHO_NODE_TRAITIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 75
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_TYPE",
  "DAISHO_NODE_TMPLTYPE",
  "DAISHO_NODE_TRAITTYPE",
  "DAISHO_NODE_STRUCTTYPE",
  "DAISHO_NODE_ARGTYPES",
  "DAISHO_NODE_TERN",
  "DAISHO_NODE_IFEXP",
  "DAISHO_NODE_PROG",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_NAMESPACE",
  "DAISHO_NODE_TEMPLATE",
  "DAISHO_NODE_MEMBERLIST",
  "DAISHO_NODE_STRUCT",
  "DAISHO_NODE_TMPLSTRUCT",
  "DAISHO_NODE_UNION",
  "DAISHO_NODE_TMPLUNION",
  "DAISHO_NODE_TRAIT",
  "DAISHO_NODE_TMPLTRAIT",
  "DAISHO_NODE_QUEST",
  "DAISHO_NODE_COLON",
  "DAISHO_NODE_FOR",
  "DAISHO_NODE_WHILE",
  "DAISHO_NODE_CAST",
  "DAISHO_NODE_REF",
  "DAISHO_NODE_DEREF",
  "DAISHO_NODE_BLK",
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
  "DAISHO_NODE_STRUCTIDENT",
  "DAISHO_NODE_TRAITIDENT",
  "DAISHO_NODE_VARIDENT",
};

struct daisho_astnode_t;
typedef struct daisho_astnode_t daisho_astnode_t;
struct daisho_astnode_t {
  // Extra data in %extra directives:

  void* extra;
  void* type;

  // End of extra data.

  daisho_astnode_kind kind;
  daisho_astnode_t* parent;
  size_t num_children;
  size_t max_children;
  daisho_astnode_t** children;
};

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
    pgen_defer(alloc, free, children, alloc->rew);
  } else {
    children = NULL;
  }

  node->kind = kind;
  node->parent = NULL;
  node->max_children = initial_size;
  node->num_children = 0;
  node->children = children;
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
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_1(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0) {
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
  children[0] = n0;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_2(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1) {
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
  children[0] = n0;
  children[1] = n1;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_3(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2) {
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
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_4(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2,
                             daisho_astnode_t* n3) {
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
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  children[3] = n3;
  return node;
}

static inline daisho_astnode_t* daisho_astnode_fixed_5(
                             pgen_allocator* alloc,
                             daisho_astnode_kind kind,
                             daisho_astnode_t* n0,
                             daisho_astnode_t* n1,
                             daisho_astnode_t* n2,
                             daisho_astnode_t* n3,
                             daisho_astnode_t* n4) {
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
  children[0] = n0;
  children[1] = n1;
  children[2] = n2;
  children[3] = n3;
  children[4] = n4;
  return node;
}

static inline void daisho_astnode_add(pgen_allocator* alloc, daisho_astnode_t *list, daisho_astnode_t *node) {
  if (list->max_children == list->num_children) {
    size_t new_max = list->max_children * 2;
    void* old_ptr = list->children;
    void* new_ptr = realloc(list->children, new_max);
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

#define rec(label)               pgen_parser_rewind_t _rew_##label = (pgen_parser_rewind_t){ctx->alloc->rew, ctx->pos};
#define rew(label)               daisho_parser_rewind(ctx, _rew_##label)
#define node(kind, ...)          PGEN_CAT(daisho_astnode_fixed_, PGEN_NARG(__VA_ARGS__))(ctx->alloc, DAISHO_NODE_##kind, __VA_ARGS__)
#define kind(name) DAISHO_NODE_##name
#define list(kind)               daisho_astnode_list(ctx->alloc, DAISHO_NODE_##kind, 16)
#define leaf(kind)               daisho_astnode_leaf(ctx->alloc, DAISHO_NODE_##kind)
#define add(list, node)  daisho_astnode_add(ctx->alloc, list, node)
#define defer(node, freefn, ptr) pgen_defer(ctx->alloc, freefn, ptr, ctx->alloc->rew)
#define SUCC                     ((daisho_astnode_t*)(void*)(uintptr_t)_Alignof(daisho_astnode_t))

static inline void daisho_astnode_print_h(daisho_astnode_t *node, size_t depth, int fl) {
  #define indent() for (size_t i = 0; i < depth; i++) printf("  ")
  if (node == SUCC)
    puts("ERROR, CAPTURED SUCC."), exit(1);

  indent(); puts("{");
  depth++;
  indent(); printf("\"kind\": "); printf("\"%s\",\n", daisho_nodekind_name[node->kind] + 12);
  size_t cnum = node->num_children;
  indent(); printf("\"num_children\": %zu,\n", cnum);
  indent(); printf("\"children\": [");  if (cnum) {
    putchar('\n');
    for (size_t i = 0; i < cnum; i++)
      daisho_astnode_print_h(node->children[i], depth + 1, i == cnum - 1);
    indent();
  }
  printf("]\n");
  depth--;
  indent(); putchar('}'); if (fl != 1) putchar(','); putchar('\n');
}

static inline void daisho_astnode_print_json(daisho_astnode_t *node) {
  daisho_astnode_print_h(node, 0, 1);
}

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
static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplspec(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_tmplmember(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfexpr(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_ctypeexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx);


static inline daisho_astnode_t* daisho_parse_file(daisho_parser_ctx* ctx) {
  daisho_astnode_t* sh = NULL;
  daisho_astnode_t* expr_ret_1 = NULL;
  daisho_astnode_t* expr_ret_0 = NULL;
  #define rule expr_ret_0

  daisho_astnode_t* expr_ret_2 = NULL;
  rec(mod_2);
  {
    daisho_astnode_t* expr_ret_3 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
      expr_ret_3 = leaf(SHEBANG);
      ctx->pos++;
    } else {
      expr_ret_3 = NULL;
    }

    if (!expr_ret_3)
      expr_ret_3 = SUCC;
    expr_ret_2 = expr_ret_3;
    sh = expr_ret_3;
  }

  if (expr_ret_2)
  {
    expr_ret_2 = daisho_parse_topdecl(ctx);
  }

  if (expr_ret_2)
  {
    daisho_astnode_t* expr_ret_4 = NULL;
    expr_ret_4 = SUCC;
    while (expr_ret_4)
    {
      daisho_astnode_t* expr_ret_5 = NULL;
      rec(mod_5);
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
          expr_ret_5 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_5 = NULL;
        }

      }

      if (expr_ret_5)
      {
        expr_ret_5 = daisho_parse_topdecl(ctx);
      }

      if (!expr_ret_5) rew(mod_5);
      expr_ret_4 = expr_ret_5 ? SUCC : NULL;
    }

    expr_ret_4 = SUCC;
    expr_ret_2 = expr_ret_4;
  }

  if (!expr_ret_2) rew(mod_2);
  expr_ret_1 = expr_ret_2 ? SUCC : NULL;
  return expr_ret_1 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_7 = NULL;
  daisho_astnode_t* expr_ret_6 = NULL;
  #define rule expr_ret_6

  daisho_astnode_t* expr_ret_8 = NULL;

  rec(slash_8);

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_9 = NULL;
    rec(mod_9);
    expr_ret_9 = daisho_parse_structdecl(ctx);
    if (!expr_ret_9) rew(mod_9);
    expr_ret_8 = expr_ret_9;
  }

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_10 = NULL;
    rec(mod_10);
    expr_ret_10 = daisho_parse_uniondecl(ctx);
    if (!expr_ret_10) rew(mod_10);
    expr_ret_8 = expr_ret_10;
  }

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_11 = NULL;
    rec(mod_11);
    expr_ret_11 = daisho_parse_traitdecl(ctx);
    if (!expr_ret_11) rew(mod_11);
    expr_ret_8 = expr_ret_11;
  }

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_12 = NULL;
    rec(mod_12);
    expr_ret_12 = daisho_parse_fndecl(ctx);
    if (!expr_ret_12) rew(mod_12);
    expr_ret_8 = expr_ret_12;
  }

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_13 = NULL;
    rec(mod_13);
    expr_ret_13 = daisho_parse_impldecl(ctx);
    if (!expr_ret_13) rew(mod_13);
    expr_ret_8 = expr_ret_13;
  }

  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    rec(mod_14);
    expr_ret_14 = daisho_parse_nsdecl(ctx);
    if (!expr_ret_14) rew(mod_14);
    expr_ret_8 = expr_ret_14;
  }

  if (!expr_ret_8) rew(slash_8);
  expr_ret_7 = expr_ret_8;

  return expr_ret_7 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_16 = NULL;
  daisho_astnode_t* expr_ret_15 = NULL;
  #define rule expr_ret_15

  daisho_astnode_t* expr_ret_17 = NULL;
  rec(mod_17);
  {
    daisho_astnode_t* expr_ret_18 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      expr_ret_18 = leaf(STRUCT);
      ctx->pos++;
    } else {
      expr_ret_18 = NULL;
    }

    expr_ret_17 = expr_ret_18;
    s = expr_ret_18;
  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_19 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_19 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_19 = NULL;
    }

    expr_ret_17 = expr_ret_19;
    id = expr_ret_19;
  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_20 = NULL;
    expr_ret_20 = daisho_parse_tmpldecl(ctx);
    if (!expr_ret_20)
      expr_ret_20 = SUCC;
    expr_ret_17 = expr_ret_20;
    tmpl = expr_ret_20;
  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_21 = NULL;
    daisho_astnode_t* expr_ret_22 = NULL;
    rec(mod_22);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        expr_ret_22 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_22 = NULL;
      }

    }

    if (expr_ret_22)
    {
      expr_ret_22 = daisho_parse_type(ctx);
    }

    if (expr_ret_22)
    {
      daisho_astnode_t* expr_ret_23 = NULL;
      expr_ret_23 = SUCC;
      while (expr_ret_23)
      {
        daisho_astnode_t* expr_ret_24 = NULL;
        rec(mod_24);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_24 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_24 = NULL;
          }

        }

        if (expr_ret_24)
        {
          expr_ret_24 = daisho_parse_type(ctx);
        }

        if (!expr_ret_24) rew(mod_24);
        expr_ret_23 = expr_ret_24 ? SUCC : NULL;
      }

      expr_ret_23 = SUCC;
      expr_ret_22 = expr_ret_23;
    }

    if (!expr_ret_22) rew(mod_22);
    expr_ret_21 = expr_ret_22 ? SUCC : NULL;
    if (!expr_ret_21)
      expr_ret_21 = SUCC;
    expr_ret_17 = expr_ret_21;
    impl = expr_ret_21;
  }

  if (expr_ret_17)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_25 = NULL;
    #define ret expr_ret_25
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_17 = expr_ret_25;
    members = expr_ret_25;
  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_26 = NULL;
    expr_ret_26 = SUCC;
    while (expr_ret_26)
    {
      daisho_astnode_t* expr_ret_27 = NULL;
      rec(mod_27);
      {
        daisho_astnode_t* expr_ret_28 = NULL;
        expr_ret_28 = daisho_parse_typemember(ctx);
        expr_ret_27 = expr_ret_28;
        m = expr_ret_28;
      }

      if (expr_ret_27)
      {
        #define ret expr_ret_27
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      if (!expr_ret_27) rew(mod_27);
      expr_ret_26 = expr_ret_27 ? SUCC : NULL;
    }

    expr_ret_26 = SUCC;
    expr_ret_17 = expr_ret_26;
  }

  if (expr_ret_17)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_17 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_17 = NULL;
    }

  }

  if (expr_ret_17)
  {
    daisho_astnode_t* expr_ret_29 = NULL;
    #define ret expr_ret_29
    ret = SUCC;

    n = node(STRUCT, s, id, members);
              rule = tmpl != SUCC ? rule=node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_17 = expr_ret_29;
    n = expr_ret_29;
  }

  if (!expr_ret_17) rew(mod_17);
  expr_ret_16 = expr_ret_17 ? SUCC : NULL;
  return expr_ret_16 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* u = NULL;
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;
  #define rule expr_ret_30

  daisho_astnode_t* expr_ret_32 = NULL;
  rec(mod_32);
  {
    daisho_astnode_t* expr_ret_33 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      expr_ret_33 = leaf(UNION);
      ctx->pos++;
    } else {
      expr_ret_33 = NULL;
    }

    expr_ret_32 = expr_ret_33;
    u = expr_ret_33;
  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_34 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_34 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_34 = NULL;
    }

    expr_ret_32 = expr_ret_34;
    id = expr_ret_34;
  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_35 = NULL;
    expr_ret_35 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_35)
      expr_ret_35 = SUCC;
    expr_ret_32 = expr_ret_35;
    tmpl = expr_ret_35;
  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_36 = NULL;
    daisho_astnode_t* expr_ret_37 = NULL;
    rec(mod_37);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        expr_ret_37 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_37 = NULL;
      }

    }

    if (expr_ret_37)
    {
      expr_ret_37 = daisho_parse_type(ctx);
    }

    if (expr_ret_37)
    {
      daisho_astnode_t* expr_ret_38 = NULL;
      expr_ret_38 = SUCC;
      while (expr_ret_38)
      {
        daisho_astnode_t* expr_ret_39 = NULL;
        rec(mod_39);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_39 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_39 = NULL;
          }

        }

        if (expr_ret_39)
        {
          expr_ret_39 = daisho_parse_type(ctx);
        }

        if (!expr_ret_39) rew(mod_39);
        expr_ret_38 = expr_ret_39 ? SUCC : NULL;
      }

      expr_ret_38 = SUCC;
      expr_ret_37 = expr_ret_38;
    }

    if (!expr_ret_37) rew(mod_37);
    expr_ret_36 = expr_ret_37 ? SUCC : NULL;
    if (!expr_ret_36)
      expr_ret_36 = SUCC;
    expr_ret_32 = expr_ret_36;
    impl = expr_ret_36;
  }

  if (expr_ret_32)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_32 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_40 = NULL;
    #define ret expr_ret_40
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_32 = expr_ret_40;
    members = expr_ret_40;
  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_41 = NULL;
    expr_ret_41 = SUCC;
    while (expr_ret_41)
    {
      daisho_astnode_t* expr_ret_42 = NULL;
      rec(mod_42);
      {
        daisho_astnode_t* expr_ret_43 = NULL;
        expr_ret_43 = daisho_parse_typemember(ctx);
        expr_ret_42 = expr_ret_43;
        m = expr_ret_43;
      }

      if (expr_ret_42)
      {
        #define ret expr_ret_42
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      if (!expr_ret_42) rew(mod_42);
      expr_ret_41 = expr_ret_42 ? SUCC : NULL;
    }

    expr_ret_41 = SUCC;
    expr_ret_32 = expr_ret_41;
  }

  if (expr_ret_32)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_32 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

  }

  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_44 = NULL;
    #define ret expr_ret_44
    ret = SUCC;

    n = node(STRUCT, u, id, members);
              rule = tmpl != SUCC ? rule=node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_32 = expr_ret_44;
    n = expr_ret_44;
  }

  if (!expr_ret_32) rew(mod_32);
  expr_ret_31 = expr_ret_32 ? SUCC : NULL;
  return expr_ret_31 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* tmpl = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_46 = NULL;
  daisho_astnode_t* expr_ret_45 = NULL;
  #define rule expr_ret_45

  daisho_astnode_t* expr_ret_47 = NULL;
  rec(mod_47);
  {
    daisho_astnode_t* expr_ret_48 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      expr_ret_48 = leaf(TRAIT);
      ctx->pos++;
    } else {
      expr_ret_48 = NULL;
    }

    expr_ret_47 = expr_ret_48;
    t = expr_ret_48;
  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_49 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_49 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_49 = NULL;
    }

    expr_ret_47 = expr_ret_49;
    id = expr_ret_49;
  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_50 = NULL;
    expr_ret_50 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_50)
      expr_ret_50 = SUCC;
    expr_ret_47 = expr_ret_50;
    tmpl = expr_ret_50;
  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_51 = NULL;
    daisho_astnode_t* expr_ret_52 = NULL;
    rec(mod_52);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        expr_ret_52 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_52 = NULL;
      }

    }

    if (expr_ret_52)
    {
      expr_ret_52 = daisho_parse_type(ctx);
    }

    if (expr_ret_52)
    {
      daisho_astnode_t* expr_ret_53 = NULL;
      expr_ret_53 = SUCC;
      while (expr_ret_53)
      {
        daisho_astnode_t* expr_ret_54 = NULL;
        rec(mod_54);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_54 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_54 = NULL;
          }

        }

        if (expr_ret_54)
        {
          expr_ret_54 = daisho_parse_type(ctx);
        }

        if (!expr_ret_54) rew(mod_54);
        expr_ret_53 = expr_ret_54 ? SUCC : NULL;
      }

      expr_ret_53 = SUCC;
      expr_ret_52 = expr_ret_53;
    }

    if (!expr_ret_52) rew(mod_52);
    expr_ret_51 = expr_ret_52 ? SUCC : NULL;
    if (!expr_ret_51)
      expr_ret_51 = SUCC;
    expr_ret_47 = expr_ret_51;
    impl = expr_ret_51;
  }

  if (expr_ret_47)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_47 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_47 = NULL;
    }

  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_55 = NULL;
    #define ret expr_ret_55
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_47 = expr_ret_55;
    members = expr_ret_55;
  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_56 = NULL;
    expr_ret_56 = SUCC;
    while (expr_ret_56)
    {
      daisho_astnode_t* expr_ret_57 = NULL;
      rec(mod_57);
      {
        daisho_astnode_t* expr_ret_58 = NULL;
        expr_ret_58 = daisho_parse_fnmember(ctx);
        expr_ret_57 = expr_ret_58;
        m = expr_ret_58;
      }

      if (expr_ret_57)
      {
        #define ret expr_ret_57
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      if (!expr_ret_57) rew(mod_57);
      expr_ret_56 = expr_ret_57 ? SUCC : NULL;
    }

    expr_ret_56 = SUCC;
    expr_ret_47 = expr_ret_56;
  }

  if (expr_ret_47)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_47 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_47 = NULL;
    }

  }

  if (expr_ret_47)
  {
    daisho_astnode_t* expr_ret_59 = NULL;
    #define ret expr_ret_59
    ret = SUCC;

    n = node(STRUCT, t, id, members);
              rule = tmpl != SUCC ? rule=node(TMPLSTRUCT, tmpl, n) : n;

    #undef ret
    expr_ret_47 = expr_ret_59;
    n = expr_ret_59;
  }

  if (!expr_ret_47) rew(mod_47);
  expr_ret_46 = expr_ret_47 ? SUCC : NULL;
  return expr_ret_46 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_61 = NULL;
  daisho_astnode_t* expr_ret_60 = NULL;
  #define rule expr_ret_60

  daisho_astnode_t* expr_ret_62 = NULL;
  rec(mod_62);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      expr_ret_62 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_62 = NULL;
    }

  }

  if (expr_ret_62)
  {
    expr_ret_62 = daisho_parse_fnproto(ctx);
  }

  if (expr_ret_62)
  {
    daisho_astnode_t* expr_ret_63 = NULL;
    expr_ret_63 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_63)
      expr_ret_63 = SUCC;
    expr_ret_62 = expr_ret_63;
  }

  if (expr_ret_62)
  {
    expr_ret_62 = daisho_parse_expr(ctx);
  }

  if (!expr_ret_62) rew(mod_62);
  expr_ret_61 = expr_ret_62 ? SUCC : NULL;
  return expr_ret_61 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* members = NULL;
  daisho_astnode_t* m = NULL;
  daisho_astnode_t* expr_ret_65 = NULL;
  daisho_astnode_t* expr_ret_64 = NULL;
  #define rule expr_ret_64

  daisho_astnode_t* expr_ret_66 = NULL;
  rec(mod_66);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

  }

  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_67 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_67 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_67 = NULL;
    }

    expr_ret_66 = expr_ret_67;
    tt = expr_ret_67;
  }

  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_68 = NULL;
    expr_ret_68 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_68)
      expr_ret_68 = SUCC;
    expr_ret_66 = expr_ret_68;
  }

  if (expr_ret_66)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

  }

  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_69 = NULL;
    expr_ret_69 = daisho_parse_type(ctx);
    expr_ret_66 = expr_ret_69;
    ft = expr_ret_69;
  }

  if (expr_ret_66)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

  }

  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_70 = NULL;
    #define ret expr_ret_70
    ret = SUCC;

    ret=list(MEMBERLIST);

    #undef ret
    expr_ret_66 = expr_ret_70;
    members = expr_ret_70;
  }

  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_71 = NULL;
    expr_ret_71 = SUCC;
    while (expr_ret_71)
    {
      daisho_astnode_t* expr_ret_72 = NULL;
      rec(mod_72);
      {
        daisho_astnode_t* expr_ret_73 = NULL;
        expr_ret_73 = daisho_parse_fnmember(ctx);
        expr_ret_72 = expr_ret_73;
        m = expr_ret_73;
      }

      if (expr_ret_72)
      {
        #define ret expr_ret_72
        ret = SUCC;

        add(members, m);

        #undef ret
      }

      if (!expr_ret_72) rew(mod_72);
      expr_ret_71 = expr_ret_72 ? SUCC : NULL;
    }

    expr_ret_71 = SUCC;
    expr_ret_66 = expr_ret_71;
  }

  if (expr_ret_66)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

  }

  if (!expr_ret_66) rew(mod_66);
  expr_ret_65 = expr_ret_66 ? SUCC : NULL;
  return expr_ret_65 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_75 = NULL;
  daisho_astnode_t* expr_ret_74 = NULL;
  #define rule expr_ret_74

  daisho_astnode_t* expr_ret_76 = NULL;
  rec(mod_76);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      expr_ret_76 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_76 = NULL;
    }

  }

  if (expr_ret_76)
  {
    daisho_astnode_t* expr_ret_77 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_77 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_77 = NULL;
    }

    expr_ret_76 = expr_ret_77;
    t = expr_ret_77;
  }

  if (expr_ret_76)
  {
    #define ret expr_ret_76
    ret = SUCC;

    rule=node(NAMESPACE, t);

    #undef ret
  }

  if (!expr_ret_76) rew(mod_76);
  expr_ret_75 = expr_ret_76 ? SUCC : NULL;
  return expr_ret_75 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* expr_ret_79 = NULL;
  daisho_astnode_t* expr_ret_78 = NULL;
  #define rule expr_ret_78

  daisho_astnode_t* expr_ret_80 = NULL;
  rec(mod_80);
  {
    daisho_astnode_t* expr_ret_81 = NULL;
    expr_ret_81 = daisho_parse_type(ctx);
    expr_ret_80 = expr_ret_81;
    t = expr_ret_81;
  }

  if (expr_ret_80)
  {
    daisho_astnode_t* expr_ret_82 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      expr_ret_82 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_82 = NULL;
    }

    expr_ret_80 = expr_ret_82;
    v = expr_ret_82;
  }

  if (expr_ret_80)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      expr_ret_80 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_80 = NULL;
    }

  }

  if (expr_ret_80)
  {
    #define ret expr_ret_80
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    #undef ret
  }

  if (!expr_ret_80) rew(mod_80);
  expr_ret_79 = expr_ret_80 ? SUCC : NULL;
  return expr_ret_79 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* expr_ret_84 = NULL;
  daisho_astnode_t* expr_ret_83 = NULL;
  #define rule expr_ret_83

  daisho_astnode_t* expr_ret_85 = NULL;
  rec(mod_85);
  {
    daisho_astnode_t* expr_ret_86 = NULL;
    daisho_astnode_t* expr_ret_87 = NULL;

    rec(slash_87);

    if (!expr_ret_87)
    {
      daisho_astnode_t* expr_ret_88 = NULL;
      rec(mod_88);
      expr_ret_88 = daisho_parse_fndecl(ctx);
      if (!expr_ret_88) rew(mod_88);
      expr_ret_87 = expr_ret_88;
    }

    if (!expr_ret_87)
    {
      daisho_astnode_t* expr_ret_89 = NULL;
      rec(mod_89);
      expr_ret_89 = daisho_parse_fnproto(ctx);
      if (!expr_ret_89) rew(mod_89);
      expr_ret_87 = expr_ret_89;
    }

    if (!expr_ret_87) rew(slash_87);
    expr_ret_86 = expr_ret_87;

    expr_ret_85 = expr_ret_86;
    r = expr_ret_86;
  }

  if (expr_ret_85)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      expr_ret_85 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_85 = NULL;
    }

  }

  if (expr_ret_85)
  {
    #define ret expr_ret_85
    ret = SUCC;

    rule=r;

    #undef ret
  }

  if (!expr_ret_85) rew(mod_85);
  expr_ret_84 = expr_ret_85 ? SUCC : NULL;
  return expr_ret_84 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  size_t depth = 0;

  daisho_astnode_t* v = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* expr_ret_91 = NULL;
  daisho_astnode_t* expr_ret_90 = NULL;
  #define rule expr_ret_90

  daisho_astnode_t* expr_ret_92 = NULL;

  rec(slash_92);

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_93 = NULL;
    rec(mod_93);
    {
      daisho_astnode_t* expr_ret_94 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        expr_ret_94 = leaf(VOIDTYPE);
        ctx->pos++;
      } else {
        expr_ret_94 = NULL;
      }

      expr_ret_93 = expr_ret_94;
      v = expr_ret_94;
    }

    if (expr_ret_93)
    {
      daisho_astnode_t* expr_ret_95 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        expr_ret_95 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_95 = NULL;
      }

      expr_ret_95 = expr_ret_95 ? NULL : SUCC;
      expr_ret_93 = expr_ret_95;
    }

    if (expr_ret_93)
    {
      #define ret expr_ret_93
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    if (!expr_ret_93) rew(mod_93);
    expr_ret_92 = expr_ret_93 ? SUCC : NULL;
  }

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_96 = NULL;
    rec(mod_96);
    {
      daisho_astnode_t* expr_ret_97 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        expr_ret_97 = leaf(VOIDTYPE);
        ctx->pos++;
      } else {
        expr_ret_97 = NULL;
      }

      expr_ret_96 = expr_ret_97;
      v = expr_ret_97;
    }

    if (expr_ret_96)
    {
      daisho_astnode_t* expr_ret_98 = NULL;
      expr_ret_98 = SUCC;
      while (expr_ret_98)
      {
        daisho_astnode_t* expr_ret_99 = NULL;
        rec(mod_99);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_99 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_99 = NULL;
          }

        }

        if (expr_ret_99)
        {
          #define ret expr_ret_99
          ret = SUCC;

          depth++;

          #undef ret
        }

        if (!expr_ret_99) rew(mod_99);
        expr_ret_98 = expr_ret_99 ? SUCC : NULL;
      }

      expr_ret_98 = SUCC;
      expr_ret_96 = expr_ret_98;
    }

    if (expr_ret_96)
    {
      #define ret expr_ret_96
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    if (!expr_ret_96) rew(mod_96);
    expr_ret_92 = expr_ret_96 ? SUCC : NULL;
  }

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_100 = NULL;
    rec(mod_100);
    {
      daisho_astnode_t* expr_ret_101 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SELFTYPE) {
        expr_ret_101 = leaf(SELFTYPE);
        ctx->pos++;
      } else {
        expr_ret_101 = NULL;
      }

      expr_ret_100 = expr_ret_101;
      s = expr_ret_101;
    }

    if (expr_ret_100)
    {
      daisho_astnode_t* expr_ret_102 = NULL;
      expr_ret_102 = SUCC;
      while (expr_ret_102)
      {
        daisho_astnode_t* expr_ret_103 = NULL;
        rec(mod_103);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_103 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_103 = NULL;
          }

        }

        if (expr_ret_103)
        {
          #define ret expr_ret_103
          ret = SUCC;

          depth++;

          #undef ret
        }

        if (!expr_ret_103) rew(mod_103);
        expr_ret_102 = expr_ret_103 ? SUCC : NULL;
      }

      expr_ret_102 = SUCC;
      expr_ret_100 = expr_ret_102;
    }

    if (expr_ret_100)
    {
      #define ret expr_ret_100
      ret = SUCC;

      rule=node(TYPE, s);

      #undef ret
    }

    if (!expr_ret_100) rew(mod_100);
    expr_ret_92 = expr_ret_100 ? SUCC : NULL;
  }

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_104 = NULL;
    rec(mod_104);
    {
      daisho_astnode_t* expr_ret_105 = NULL;
      expr_ret_105 = daisho_parse_traittype(ctx);
      expr_ret_104 = expr_ret_105;
      t = expr_ret_105;
    }

    if (expr_ret_104)
    {
      daisho_astnode_t* expr_ret_106 = NULL;
      expr_ret_106 = SUCC;
      while (expr_ret_106)
      {
        daisho_astnode_t* expr_ret_107 = NULL;
        rec(mod_107);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_107 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_107 = NULL;
          }

        }

        if (expr_ret_107)
        {
          #define ret expr_ret_107
          ret = SUCC;

          depth++;

          #undef ret
        }

        if (!expr_ret_107) rew(mod_107);
        expr_ret_106 = expr_ret_107 ? SUCC : NULL;
      }

      expr_ret_106 = SUCC;
      expr_ret_104 = expr_ret_106;
    }

    if (expr_ret_104)
    {
      #define ret expr_ret_104
      ret = SUCC;

      rule=node(TYPE, t);

      #undef ret
    }

    if (!expr_ret_104) rew(mod_104);
    expr_ret_92 = expr_ret_104 ? SUCC : NULL;
  }

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_108 = NULL;
    rec(mod_108);
    {
      daisho_astnode_t* expr_ret_109 = NULL;
      expr_ret_109 = daisho_parse_structtype(ctx);
      expr_ret_108 = expr_ret_109;
      s = expr_ret_109;
    }

    if (expr_ret_108)
    {
      daisho_astnode_t* expr_ret_110 = NULL;
      expr_ret_110 = SUCC;
      while (expr_ret_110)
      {
        daisho_astnode_t* expr_ret_111 = NULL;
        rec(mod_111);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_111 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_111 = NULL;
          }

        }

        if (expr_ret_111)
        {
          #define ret expr_ret_111
          ret = SUCC;

          depth++;

          #undef ret
        }

        if (!expr_ret_111) rew(mod_111);
        expr_ret_110 = expr_ret_111 ? SUCC : NULL;
      }

      expr_ret_110 = SUCC;
      expr_ret_108 = expr_ret_110;
    }

    if (expr_ret_108)
    {
      #define ret expr_ret_108
      ret = SUCC;

      rule=node(TYPE, t);

      #undef ret
    }

    if (!expr_ret_108) rew(mod_108);
    expr_ret_92 = expr_ret_108 ? SUCC : NULL;
  }

  if (!expr_ret_92)
  {
    daisho_astnode_t* expr_ret_112 = NULL;
    rec(mod_112);
    {
      daisho_astnode_t* expr_ret_113 = NULL;
      expr_ret_113 = daisho_parse_fntype(ctx);
      expr_ret_112 = expr_ret_113;
      f = expr_ret_113;
    }

    if (expr_ret_112)
    {
      daisho_astnode_t* expr_ret_114 = NULL;
      expr_ret_114 = SUCC;
      while (expr_ret_114)
      {
        daisho_astnode_t* expr_ret_115 = NULL;
        rec(mod_115);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_115 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_115 = NULL;
          }

        }

        if (expr_ret_115)
        {
          #define ret expr_ret_115
          ret = SUCC;

          depth++;

          #undef ret
        }

        if (!expr_ret_115) rew(mod_115);
        expr_ret_114 = expr_ret_115 ? SUCC : NULL;
      }

      expr_ret_114 = SUCC;
      expr_ret_112 = expr_ret_114;
    }

    if (expr_ret_112)
    {
      #define ret expr_ret_112
      ret = SUCC;

      rule=node(TYPE, f);

      #undef ret
    }

    if (!expr_ret_112) rew(mod_112);
    expr_ret_92 = expr_ret_112 ? SUCC : NULL;
  }

  if (!expr_ret_92) rew(slash_92);
  expr_ret_91 = expr_ret_92;

  return expr_ret_91 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* i = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_117 = NULL;
  daisho_astnode_t* expr_ret_116 = NULL;
  #define rule expr_ret_116

  daisho_astnode_t* expr_ret_118 = NULL;
  rec(mod_118);
  {
    daisho_astnode_t* expr_ret_119 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAITIDENT) {
      expr_ret_119 = leaf(TRAITIDENT);
      ctx->pos++;
    } else {
      expr_ret_119 = NULL;
    }

    expr_ret_118 = expr_ret_119;
    i = expr_ret_119;
  }

  if (expr_ret_118)
  {
    daisho_astnode_t* expr_ret_120 = NULL;
    expr_ret_120 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_120)
      expr_ret_120 = SUCC;
    expr_ret_118 = expr_ret_120;
    t = expr_ret_120;
  }

  if (expr_ret_118)
  {
    #define ret expr_ret_118
    ret = SUCC;

    ret = t ? node(TMPLTYPE, t, i) : node(TYPE, i);

    #undef ret
  }

  if (!expr_ret_118) rew(mod_118);
  expr_ret_117 = expr_ret_118 ? SUCC : NULL;
  return expr_ret_117 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_122 = NULL;
  daisho_astnode_t* expr_ret_121 = NULL;
  #define rule expr_ret_121

  daisho_astnode_t* expr_ret_123 = NULL;
  rec(mod_123);
  {
    daisho_astnode_t* expr_ret_124 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      expr_ret_124 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_124 = NULL;
    }

    expr_ret_123 = expr_ret_124;
    s = expr_ret_124;
  }

  if (expr_ret_123)
  {
    daisho_astnode_t* expr_ret_125 = NULL;
    expr_ret_125 = daisho_parse_tmplexpand(ctx);
    if (!expr_ret_125)
      expr_ret_125 = SUCC;
    expr_ret_123 = expr_ret_125;
    t = expr_ret_125;
  }

  if (expr_ret_123)
  {
    #define ret expr_ret_123
    ret = SUCC;

    ret = t ? node(TMPLTYPE, t, s) : node(TYPE, s);

    #undef ret
  }

  if (!expr_ret_123) rew(mod_123);
  expr_ret_122 = expr_ret_123 ? SUCC : NULL;
  return expr_ret_122 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* fn = NULL;
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* tmp = NULL;
  daisho_astnode_t* expr_ret_127 = NULL;
  daisho_astnode_t* expr_ret_126 = NULL;
  #define rule expr_ret_126

  daisho_astnode_t* expr_ret_128 = NULL;

  rec(slash_128);

  if (!expr_ret_128)
  {
    daisho_astnode_t* expr_ret_129 = NULL;
    rec(mod_129);
    {
      daisho_astnode_t* expr_ret_130 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        expr_ret_130 = leaf(FNTYPE);
        ctx->pos++;
      } else {
        expr_ret_130 = NULL;
      }

      expr_ret_129 = expr_ret_130;
      fn = expr_ret_130;
    }

    if (expr_ret_129)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        expr_ret_129 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_129 = NULL;
      }

    }

    if (expr_ret_129)
    {
      daisho_astnode_t* expr_ret_131 = NULL;
      #define ret expr_ret_131
      ret = SUCC;

      ret=list(ARGTYPES);

      #undef ret
      expr_ret_129 = expr_ret_131;
      argtypes = expr_ret_131;
    }

    if (expr_ret_129)
    {
      daisho_astnode_t* expr_ret_132 = NULL;
      daisho_astnode_t* expr_ret_133 = NULL;
      rec(mod_133);
      {
        daisho_astnode_t* expr_ret_134 = NULL;
        expr_ret_134 = daisho_parse_type(ctx);
        expr_ret_133 = expr_ret_134;
        t = expr_ret_134;
      }

      if (expr_ret_133)
      {
        #define ret expr_ret_133
        ret = SUCC;

        add(argtypes, t);

        #undef ret
      }

      if (!expr_ret_133) rew(mod_133);
      expr_ret_132 = expr_ret_133 ? SUCC : NULL;
      if (!expr_ret_132)
        expr_ret_132 = SUCC;
      expr_ret_129 = expr_ret_132;
    }

    if (expr_ret_129)
    {
      daisho_astnode_t* expr_ret_135 = NULL;
      expr_ret_135 = SUCC;
      while (expr_ret_135)
      {
        daisho_astnode_t* expr_ret_136 = NULL;
        rec(mod_136);
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            expr_ret_136 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_136 = NULL;
          }

        }

        if (expr_ret_136)
        {
          daisho_astnode_t* expr_ret_137 = NULL;
          expr_ret_137 = daisho_parse_type(ctx);
          expr_ret_136 = expr_ret_137;
          t = expr_ret_137;
        }

        if (expr_ret_136)
        {
          #define ret expr_ret_136
          ret = SUCC;

          add(argtypes, t);

          #undef ret
        }

        if (!expr_ret_136) rew(mod_136);
        expr_ret_135 = expr_ret_136 ? SUCC : NULL;
      }

      expr_ret_135 = SUCC;
      expr_ret_129 = expr_ret_135;
    }

    if (expr_ret_129)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        expr_ret_129 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_129 = NULL;
      }

    }

    if (expr_ret_129)
    {
      daisho_astnode_t* expr_ret_138 = NULL;
      expr_ret_138 = daisho_parse_type(ctx);
      expr_ret_129 = expr_ret_138;
      rettype = expr_ret_138;
    }

    if (expr_ret_129)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        expr_ret_129 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_129 = NULL;
      }

    }

    if (expr_ret_129)
    {
      #define ret expr_ret_129
      ret = SUCC;

      rule=node(FNTYPE, argtypes, rettype);

      #undef ret
    }

    if (!expr_ret_129) rew(mod_129);
    expr_ret_128 = expr_ret_129 ? SUCC : NULL;
  }

  if (!expr_ret_128)
  {
    daisho_astnode_t* expr_ret_139 = NULL;
    rec(mod_139);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
        expr_ret_139 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_139 = NULL;
      }

    }

    if (expr_ret_139)
    {
      daisho_astnode_t* expr_ret_140 = NULL;
      #define ret expr_ret_140
      ret = SUCC;

      rule=node(FNTYPE, (tmp=list(ARGTYPES), add(tmp, leaf(VOIDTYPE)), tmp), leaf(VOIDTYPE));

      #undef ret
      expr_ret_139 = expr_ret_140;
      tmp = expr_ret_140;
    }

    if (!expr_ret_139) rew(mod_139);
    expr_ret_128 = expr_ret_139 ? SUCC : NULL;
  }

  if (!expr_ret_128) rew(slash_128);
  expr_ret_127 = expr_ret_128;

  return expr_ret_127 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_142 = NULL;
  daisho_astnode_t* expr_ret_141 = NULL;
  #define rule expr_ret_141

  daisho_astnode_t* expr_ret_143 = NULL;
  rec(mod_143);
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TEMPLATE) {
    expr_ret_143 = leaf(TEMPLATE);
    ctx->pos++;
  } else {
    expr_ret_143 = NULL;
  }

  if (!expr_ret_143) rew(mod_143);
  expr_ret_142 = expr_ret_143;
  return expr_ret_142 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplspec(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_145 = NULL;
  daisho_astnode_t* expr_ret_144 = NULL;
  #define rule expr_ret_144

  daisho_astnode_t* expr_ret_146 = NULL;
  rec(mod_146);
  if (!expr_ret_146) rew(mod_146);
  expr_ret_145 = expr_ret_146 ? SUCC : NULL;
  return expr_ret_145 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_148 = NULL;
  daisho_astnode_t* expr_ret_147 = NULL;
  #define rule expr_ret_147

  daisho_astnode_t* expr_ret_149 = NULL;
  rec(mod_149);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      expr_ret_149 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_149 = NULL;
    }

  }

  if (expr_ret_149)
  {
    daisho_astnode_t* expr_ret_150 = NULL;
    expr_ret_150 = daisho_parse_tmplmember(ctx);
    if (!expr_ret_150)
      expr_ret_150 = SUCC;
    expr_ret_149 = expr_ret_150;
  }

  if (expr_ret_149)
  {
    daisho_astnode_t* expr_ret_151 = NULL;
    expr_ret_151 = SUCC;
    while (expr_ret_151)
    {
      daisho_astnode_t* expr_ret_152 = NULL;
      rec(mod_152);
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          expr_ret_152 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_152 = NULL;
        }

      }

      if (expr_ret_152)
      {
        expr_ret_152 = daisho_parse_tmplmember(ctx);
      }

      if (!expr_ret_152) rew(mod_152);
      expr_ret_151 = expr_ret_152 ? SUCC : NULL;
    }

    expr_ret_151 = SUCC;
    expr_ret_149 = expr_ret_151;
  }

  if (expr_ret_149)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      expr_ret_149 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_149 = NULL;
    }

  }

  if (!expr_ret_149) rew(mod_149);
  expr_ret_148 = expr_ret_149 ? SUCC : NULL;
  return expr_ret_148 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_154 = NULL;
  daisho_astnode_t* expr_ret_153 = NULL;
  #define rule expr_ret_153

  daisho_astnode_t* expr_ret_155 = NULL;
  rec(mod_155);
  expr_ret_155 = daisho_parse_type(ctx);
  if (!expr_ret_155) rew(mod_155);
  expr_ret_154 = expr_ret_155;
  return expr_ret_154 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_157 = NULL;
  daisho_astnode_t* expr_ret_156 = NULL;
  #define rule expr_ret_156

  daisho_astnode_t* expr_ret_158 = NULL;
  rec(mod_158);
  {
    expr_ret_158 = daisho_parse_type(ctx);
  }

  if (expr_ret_158)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      expr_ret_158 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_158 = NULL;
    }

  }

  if (expr_ret_158)
  {
    daisho_astnode_t* expr_ret_159 = NULL;
    expr_ret_159 = daisho_parse_fnarg(ctx);
    if (!expr_ret_159)
      expr_ret_159 = SUCC;
    expr_ret_158 = expr_ret_159;
  }

  if (expr_ret_158)
  {
    daisho_astnode_t* expr_ret_160 = NULL;
    expr_ret_160 = SUCC;
    while (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_161 = NULL;
      rec(mod_161);
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          expr_ret_161 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_161 = NULL;
        }

      }

      if (expr_ret_161)
      {
        expr_ret_161 = daisho_parse_fnarg(ctx);
      }

      if (!expr_ret_161) rew(mod_161);
      expr_ret_160 = expr_ret_161 ? SUCC : NULL;
    }

    expr_ret_160 = SUCC;
    expr_ret_158 = expr_ret_160;
  }

  if (expr_ret_158)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      expr_ret_158 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_158 = NULL;
    }

  }

  if (!expr_ret_158) rew(mod_158);
  expr_ret_157 = expr_ret_158 ? SUCC : NULL;
  return expr_ret_157 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_163 = NULL;
  daisho_astnode_t* expr_ret_162 = NULL;
  #define rule expr_ret_162

  daisho_astnode_t* expr_ret_164 = NULL;
  rec(mod_164);
  {
    expr_ret_164 = daisho_parse_type(ctx);
  }

  if (expr_ret_164)
  {
    daisho_astnode_t* expr_ret_165 = NULL;
    daisho_astnode_t* expr_ret_166 = NULL;
    rec(mod_166);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        expr_ret_166 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_166 = NULL;
      }

    }

    if (expr_ret_166)
    {
      daisho_astnode_t* expr_ret_167 = NULL;
      expr_ret_167 = daisho_parse_tmplexpand(ctx);
      if (!expr_ret_167)
        expr_ret_167 = SUCC;
      expr_ret_166 = expr_ret_167;
    }

    if (!expr_ret_166) rew(mod_166);
    expr_ret_165 = expr_ret_166 ? SUCC : NULL;
    if (!expr_ret_165)
      expr_ret_165 = SUCC;
    expr_ret_164 = expr_ret_165;
  }

  if (!expr_ret_164) rew(mod_164);
  expr_ret_163 = expr_ret_164 ? SUCC : NULL;
  return expr_ret_163 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_169 = NULL;
  daisho_astnode_t* expr_ret_168 = NULL;
  #define rule expr_ret_168

  daisho_astnode_t* expr_ret_170 = NULL;
  rec(mod_170);
  expr_ret_170 = daisho_parse_expr(ctx);
  if (!expr_ret_170) rew(mod_170);
  expr_ret_169 = expr_ret_170;
  return expr_ret_169 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_172 = NULL;
  daisho_astnode_t* expr_ret_171 = NULL;
  #define rule expr_ret_171

  daisho_astnode_t* expr_ret_173 = NULL;

  rec(slash_173);

  if (!expr_ret_173)
  {
    daisho_astnode_t* expr_ret_174 = NULL;
    rec(mod_174);
    expr_ret_174 = daisho_parse_cfexpr(ctx);
    if (!expr_ret_174) rew(mod_174);
    expr_ret_173 = expr_ret_174;
  }

  if (!expr_ret_173)
  {
    daisho_astnode_t* expr_ret_175 = NULL;
    rec(mod_175);
    expr_ret_175 = daisho_parse_binop(ctx);
    if (!expr_ret_175) rew(mod_175);
    expr_ret_173 = expr_ret_175;
  }

  if (!expr_ret_173) rew(slash_173);
  expr_ret_172 = expr_ret_173;

  return expr_ret_172 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_177 = NULL;
  daisho_astnode_t* expr_ret_176 = NULL;
  #define rule expr_ret_176

  daisho_astnode_t* expr_ret_178 = NULL;

  rec(slash_178);

  if (!expr_ret_178)
  {
    daisho_astnode_t* expr_ret_179 = NULL;
    rec(mod_179);
    expr_ret_179 = daisho_parse_forexpr(ctx);
    if (!expr_ret_179) rew(mod_179);
    expr_ret_178 = expr_ret_179;
  }

  if (!expr_ret_178)
  {
    daisho_astnode_t* expr_ret_180 = NULL;
    rec(mod_180);
    expr_ret_180 = daisho_parse_whileexpr(ctx);
    if (!expr_ret_180) rew(mod_180);
    expr_ret_178 = expr_ret_180;
  }

  if (!expr_ret_178)
  {
    daisho_astnode_t* expr_ret_181 = NULL;
    rec(mod_181);
    expr_ret_181 = daisho_parse_ternexpr(ctx);
    if (!expr_ret_181) rew(mod_181);
    expr_ret_178 = expr_ret_181;
  }

  if (!expr_ret_178) rew(slash_178);
  expr_ret_177 = expr_ret_178;

  return expr_ret_177 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_183 = NULL;
  daisho_astnode_t* expr_ret_182 = NULL;
  #define rule expr_ret_182

  daisho_astnode_t* expr_ret_184 = NULL;

  rec(slash_184);

  if (!expr_ret_184)
  {
    daisho_astnode_t* expr_ret_185 = NULL;
    rec(mod_185);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        expr_ret_185 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_185 = NULL;
      }

    }

    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_186 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        expr_ret_186 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_186 = NULL;
      }

      if (!expr_ret_186)
        expr_ret_186 = SUCC;
      expr_ret_185 = expr_ret_186;
    }

    if (expr_ret_185)
    {
      expr_ret_185 = daisho_parse_expr(ctx);
    }

    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_187 = NULL;

      rec(slash_187);

      if (!expr_ret_187)
      {
        daisho_astnode_t* expr_ret_188 = NULL;
        rec(mod_188);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          expr_ret_188 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_188 = NULL;
        }

        if (!expr_ret_188) rew(mod_188);
        expr_ret_187 = expr_ret_188;
      }

      if (!expr_ret_187)
      {
        daisho_astnode_t* expr_ret_189 = NULL;
        rec(mod_189);
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
          expr_ret_189 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_189 = NULL;
        }

        if (!expr_ret_189) rew(mod_189);
        expr_ret_187 = expr_ret_189;
      }

      if (!expr_ret_187) rew(slash_187);
      expr_ret_185 = expr_ret_187;

    }

    if (expr_ret_185)
    {
      expr_ret_185 = daisho_parse_expr(ctx);
    }

    if (expr_ret_185)
    {
      daisho_astnode_t* expr_ret_190 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        expr_ret_190 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_190 = NULL;
      }

      if (!expr_ret_190)
        expr_ret_190 = SUCC;
      expr_ret_185 = expr_ret_190;
    }

    if (expr_ret_185)
    {
      expr_ret_185 = daisho_parse_expr(ctx);
    }

    if (!expr_ret_185) rew(mod_185);
    expr_ret_184 = expr_ret_185 ? SUCC : NULL;
  }

  if (!expr_ret_184)
  {
    daisho_astnode_t* expr_ret_191 = NULL;
    rec(mod_191);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        expr_ret_191 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_191 = NULL;
      }

    }

    if (expr_ret_191)
    {
      daisho_astnode_t* expr_ret_192 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        expr_ret_192 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_192 = NULL;
      }

      if (!expr_ret_192)
        expr_ret_192 = SUCC;
      expr_ret_191 = expr_ret_192;
    }

    if (expr_ret_191)
    {
      expr_ret_191 = daisho_parse_expr(ctx);
    }

    if (expr_ret_191)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
        expr_ret_191 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_191 = NULL;
      }

    }

    if (expr_ret_191)
    {
      expr_ret_191 = daisho_parse_expr(ctx);
    }

    if (expr_ret_191)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
        expr_ret_191 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_191 = NULL;
      }

    }

    if (expr_ret_191)
    {
      expr_ret_191 = daisho_parse_expr(ctx);
    }

    if (expr_ret_191)
    {
      daisho_astnode_t* expr_ret_193 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        expr_ret_193 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_193 = NULL;
      }

      if (!expr_ret_193)
        expr_ret_193 = SUCC;
      expr_ret_191 = expr_ret_193;
    }

    if (expr_ret_191)
    {
      expr_ret_191 = daisho_parse_expr(ctx);
    }

    if (!expr_ret_191) rew(mod_191);
    expr_ret_184 = expr_ret_191 ? SUCC : NULL;
  }

  if (!expr_ret_184) rew(slash_184);
  expr_ret_183 = expr_ret_184;

  return expr_ret_183 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_195 = NULL;
  daisho_astnode_t* expr_ret_194 = NULL;
  #define rule expr_ret_194

  daisho_astnode_t* expr_ret_196 = NULL;
  rec(mod_196);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      expr_ret_196 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_196 = NULL;
    }

  }

  if (expr_ret_196)
  {
    daisho_astnode_t* expr_ret_197 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      expr_ret_197 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_197 = NULL;
    }

    if (!expr_ret_197)
      expr_ret_197 = SUCC;
    expr_ret_196 = expr_ret_197;
  }

  if (expr_ret_196)
  {
    expr_ret_196 = daisho_parse_expr(ctx);
  }

  if (expr_ret_196)
  {
    daisho_astnode_t* expr_ret_198 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      expr_ret_198 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_198 = NULL;
    }

    if (!expr_ret_198)
      expr_ret_198 = SUCC;
    expr_ret_196 = expr_ret_198;
  }

  if (expr_ret_196)
  {
    expr_ret_196 = daisho_parse_expr(ctx);
  }

  if (!expr_ret_196) rew(mod_196);
  expr_ret_195 = expr_ret_196 ? SUCC : NULL;
  return expr_ret_195 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* q = NULL;
  daisho_astnode_t* qe = NULL;
  daisho_astnode_t* c = NULL;
  daisho_astnode_t* ce = NULL;
  daisho_astnode_t* expr_ret_200 = NULL;
  daisho_astnode_t* expr_ret_199 = NULL;
  #define rule expr_ret_199

  daisho_astnode_t* expr_ret_201 = NULL;
  rec(mod_201);
  {
    daisho_astnode_t* expr_ret_202 = NULL;
    expr_ret_202 = daisho_parse_thenexpr(ctx);
    expr_ret_201 = expr_ret_202;
    n = expr_ret_202;
  }

  if (expr_ret_201)
  {
    daisho_astnode_t* expr_ret_203 = NULL;
    daisho_astnode_t* expr_ret_204 = NULL;
    rec(mod_204);
    {
      daisho_astnode_t* expr_ret_205 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
        expr_ret_205 = leaf(QUEST);
        ctx->pos++;
      } else {
        expr_ret_205 = NULL;
      }

      expr_ret_204 = expr_ret_205;
      q = expr_ret_205;
    }

    if (expr_ret_204)
    {
      daisho_astnode_t* expr_ret_206 = NULL;
      expr_ret_206 = daisho_parse_expr(ctx);
      expr_ret_204 = expr_ret_206;
      qe = expr_ret_206;
    }

    if (expr_ret_204)
    {
      daisho_astnode_t* expr_ret_207 = NULL;
      daisho_astnode_t* expr_ret_208 = NULL;
      rec(mod_208);
      {
        daisho_astnode_t* expr_ret_209 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          expr_ret_209 = leaf(COLON);
          ctx->pos++;
        } else {
          expr_ret_209 = NULL;
        }

        expr_ret_208 = expr_ret_209;
        c = expr_ret_209;
      }

      if (expr_ret_208)
      {
        daisho_astnode_t* expr_ret_210 = NULL;
        expr_ret_210 = daisho_parse_expr(ctx);
        expr_ret_208 = expr_ret_210;
        ce = expr_ret_210;
      }

      if (!expr_ret_208) rew(mod_208);
      expr_ret_207 = expr_ret_208 ? SUCC : NULL;
      if (!expr_ret_207)
        expr_ret_207 = SUCC;
      expr_ret_204 = expr_ret_207;
    }

    if (!expr_ret_204) rew(mod_204);
    expr_ret_203 = expr_ret_204 ? SUCC : NULL;
    if (!expr_ret_203)
      expr_ret_203 = SUCC;
    expr_ret_201 = expr_ret_203;
  }

  if (expr_ret_201)
  {
    #define ret expr_ret_201
    ret = SUCC;

    rule = (qe==SUCC) ? n
                    : (ce==SUCC) ? node(IFEXP, q, n, qe)
                    :              node(TERN, q, c, n, qe, ce);

    #undef ret
  }

  if (!expr_ret_201) rew(mod_201);
  expr_ret_200 = expr_ret_201 ? SUCC : NULL;
  return expr_ret_200 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_212 = NULL;
  daisho_astnode_t* expr_ret_211 = NULL;
  #define rule expr_ret_211

  daisho_astnode_t* expr_ret_213 = NULL;
  rec(mod_213);
  {
    daisho_astnode_t* expr_ret_214 = NULL;
    expr_ret_214 = daisho_parse_alsoexpr(ctx);
    expr_ret_213 = expr_ret_214;
    n = expr_ret_214;
  }

  if (expr_ret_213)
  {
    daisho_astnode_t* expr_ret_215 = NULL;
    daisho_astnode_t* expr_ret_216 = NULL;
    rec(mod_216);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        expr_ret_216 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_216 = NULL;
      }

    }

    if (expr_ret_216)
    {
      expr_ret_216 = daisho_parse_expr(ctx);
    }

    if (!expr_ret_216) rew(mod_216);
    expr_ret_215 = expr_ret_216 ? SUCC : NULL;
    if (!expr_ret_215)
      expr_ret_215 = SUCC;
    expr_ret_213 = expr_ret_215;
  }

  if (!expr_ret_213) rew(mod_213);
  expr_ret_212 = expr_ret_213 ? SUCC : NULL;
  return expr_ret_212 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_218 = NULL;
  daisho_astnode_t* expr_ret_217 = NULL;
  #define rule expr_ret_217

  daisho_astnode_t* expr_ret_219 = NULL;
  rec(mod_219);
  {
    daisho_astnode_t* expr_ret_220 = NULL;
    expr_ret_220 = daisho_parse_binop(ctx);
    expr_ret_219 = expr_ret_220;
    n = expr_ret_220;
  }

  if (expr_ret_219)
  {
    daisho_astnode_t* expr_ret_221 = NULL;
    daisho_astnode_t* expr_ret_222 = NULL;
    rec(mod_222);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        expr_ret_222 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_222 = NULL;
      }

    }

    if (expr_ret_222)
    {
      expr_ret_222 = daisho_parse_expr(ctx);
    }

    if (!expr_ret_222) rew(mod_222);
    expr_ret_221 = expr_ret_222 ? SUCC : NULL;
    if (!expr_ret_221)
      expr_ret_221 = SUCC;
    expr_ret_219 = expr_ret_221;
  }

  if (!expr_ret_219) rew(mod_219);
  expr_ret_218 = expr_ret_219 ? SUCC : NULL;
  return expr_ret_218 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_224 = NULL;
  daisho_astnode_t* expr_ret_223 = NULL;
  #define rule expr_ret_223

  daisho_astnode_t* expr_ret_225 = NULL;
  rec(mod_225);
  expr_ret_225 = daisho_parse_eqexpr(ctx);
  if (!expr_ret_225) rew(mod_225);
  expr_ret_224 = expr_ret_225;
  return expr_ret_224 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_227 = NULL;
  daisho_astnode_t* expr_ret_226 = NULL;
  #define rule expr_ret_226

  daisho_astnode_t* expr_ret_228 = NULL;
  rec(mod_228);
  {
    daisho_astnode_t* expr_ret_229 = NULL;
    expr_ret_229 = daisho_parse_logorexpr(ctx);
    expr_ret_228 = expr_ret_229;
    n = expr_ret_229;
  }

  if (expr_ret_228)
  {
    #define ret expr_ret_228
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_228)
  {
    daisho_astnode_t* expr_ret_230 = NULL;
    expr_ret_230 = SUCC;
    while (expr_ret_230)
    {
      daisho_astnode_t* expr_ret_231 = NULL;
      rec(mod_231);
      {
        daisho_astnode_t* expr_ret_232 = NULL;
        daisho_astnode_t* expr_ret_233 = NULL;

        rec(slash_233);

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_234 = NULL;
          rec(mod_234);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            expr_ret_234 = leaf(EQ);
            ctx->pos++;
          } else {
            expr_ret_234 = NULL;
          }

          if (!expr_ret_234) rew(mod_234);
          expr_ret_233 = expr_ret_234;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_235 = NULL;
          rec(mod_235);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            expr_ret_235 = leaf(PLEQ);
            ctx->pos++;
          } else {
            expr_ret_235 = NULL;
          }

          if (!expr_ret_235) rew(mod_235);
          expr_ret_233 = expr_ret_235;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_236 = NULL;
          rec(mod_236);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            expr_ret_236 = leaf(MINEQ);
            ctx->pos++;
          } else {
            expr_ret_236 = NULL;
          }

          if (!expr_ret_236) rew(mod_236);
          expr_ret_233 = expr_ret_236;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_237 = NULL;
          rec(mod_237);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            expr_ret_237 = leaf(MULEQ);
            ctx->pos++;
          } else {
            expr_ret_237 = NULL;
          }

          if (!expr_ret_237) rew(mod_237);
          expr_ret_233 = expr_ret_237;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_238 = NULL;
          rec(mod_238);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            expr_ret_238 = leaf(DIVEQ);
            ctx->pos++;
          } else {
            expr_ret_238 = NULL;
          }

          if (!expr_ret_238) rew(mod_238);
          expr_ret_233 = expr_ret_238;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_239 = NULL;
          rec(mod_239);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            expr_ret_239 = leaf(MODEQ);
            ctx->pos++;
          } else {
            expr_ret_239 = NULL;
          }

          if (!expr_ret_239) rew(mod_239);
          expr_ret_233 = expr_ret_239;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_240 = NULL;
          rec(mod_240);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            expr_ret_240 = leaf(ANDEQ);
            ctx->pos++;
          } else {
            expr_ret_240 = NULL;
          }

          if (!expr_ret_240) rew(mod_240);
          expr_ret_233 = expr_ret_240;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_241 = NULL;
          rec(mod_241);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            expr_ret_241 = leaf(OREQ);
            ctx->pos++;
          } else {
            expr_ret_241 = NULL;
          }

          if (!expr_ret_241) rew(mod_241);
          expr_ret_233 = expr_ret_241;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_242 = NULL;
          rec(mod_242);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            expr_ret_242 = leaf(XOREQ);
            ctx->pos++;
          } else {
            expr_ret_242 = NULL;
          }

          if (!expr_ret_242) rew(mod_242);
          expr_ret_233 = expr_ret_242;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_243 = NULL;
          rec(mod_243);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            expr_ret_243 = leaf(BNEQ);
            ctx->pos++;
          } else {
            expr_ret_243 = NULL;
          }

          if (!expr_ret_243) rew(mod_243);
          expr_ret_233 = expr_ret_243;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_244 = NULL;
          rec(mod_244);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            expr_ret_244 = leaf(BSREQ);
            ctx->pos++;
          } else {
            expr_ret_244 = NULL;
          }

          if (!expr_ret_244) rew(mod_244);
          expr_ret_233 = expr_ret_244;
        }

        if (!expr_ret_233)
        {
          daisho_astnode_t* expr_ret_245 = NULL;
          rec(mod_245);
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            expr_ret_245 = leaf(BSLEQ);
            ctx->pos++;
          } else {
            expr_ret_245 = NULL;
          }

          if (!expr_ret_245) rew(mod_245);
          expr_ret_233 = expr_ret_245;
        }

        if (!expr_ret_233) rew(slash_233);
        expr_ret_232 = expr_ret_233;

        expr_ret_231 = expr_ret_232;
        op = expr_ret_232;
      }

      if (expr_ret_231)
      {
        daisho_astnode_t* expr_ret_246 = NULL;
        expr_ret_246 = daisho_parse_logorexpr(ctx);
        expr_ret_231 = expr_ret_246;
        t = expr_ret_246;
      }

      if (expr_ret_231)
      {
        #define ret expr_ret_231
        ret = SUCC;

         
                if (op->kind == kind(EQ))         rule=node(EQ, op, rule, t);
                else if (op->kind == kind(PLEQ))  rule=node(EQ, op, rule, node(PLUS,  op, rule, t));
                else if (op->kind == kind(MINEQ)) rule=node(EQ, op, rule, node(MINUS, op, rule, t));
                else if (op->kind == kind(MULEQ)) rule=node(EQ, op, rule, node(MUL,   op, rule, t));
                else if (op->kind == kind(DIVEQ)) rule=node(EQ, op, rule, node(DIV,   op, rule, t));
                else if (op->kind == kind(MODEQ)) rule=node(EQ, op, rule, node(MOD,   op, rule, t));
                else if (op->kind == kind(ANDEQ)) rule=node(EQ, op, rule, node(AND,   op, rule, t));
                else if (op->kind == kind(OREQ))  rule=node(EQ, op, rule, node(OR,    op, rule, t));
                else if (op->kind == kind(XOREQ)) rule=node(EQ, op, rule, node(BNEQ,  op, rule, t));
                else if (op->kind == kind(BSREQ)) rule=node(EQ, op, rule, node(BSR,   op, rule, t));
                else if (op->kind == kind(BSLEQ)) rule=node(EQ, op, rule, node(BSL,   op, rule, t));
                else
                  #if defined(__DAI_UNREACHABLE)
                    __DAI_UNREACHABLE()
                  #else
                    assert(!"Unexpected node type.")
                  #endif
              ;

        #undef ret
      }

      if (!expr_ret_231) rew(mod_231);
      expr_ret_230 = expr_ret_231 ? SUCC : NULL;
    }

    expr_ret_230 = SUCC;
    expr_ret_228 = expr_ret_230;
  }

  if (!expr_ret_228) rew(mod_228);
  expr_ret_227 = expr_ret_228 ? SUCC : NULL;
  return expr_ret_227 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_248 = NULL;
  daisho_astnode_t* expr_ret_247 = NULL;
  #define rule expr_ret_247

  daisho_astnode_t* expr_ret_249 = NULL;
  rec(mod_249);
  {
    daisho_astnode_t* expr_ret_250 = NULL;
    expr_ret_250 = daisho_parse_logandexpr(ctx);
    expr_ret_249 = expr_ret_250;
    n = expr_ret_250;
  }

  if (expr_ret_249)
  {
    #define ret expr_ret_249
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_249)
  {
    daisho_astnode_t* expr_ret_251 = NULL;
    expr_ret_251 = SUCC;
    while (expr_ret_251)
    {
      daisho_astnode_t* expr_ret_252 = NULL;
      rec(mod_252);
      {
        daisho_astnode_t* expr_ret_253 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          expr_ret_253 = leaf(LOGOR);
          ctx->pos++;
        } else {
          expr_ret_253 = NULL;
        }

        expr_ret_252 = expr_ret_253;
        op = expr_ret_253;
      }

      if (expr_ret_252)
      {
        daisho_astnode_t* expr_ret_254 = NULL;
        expr_ret_254 = daisho_parse_logandexpr(ctx);
        expr_ret_252 = expr_ret_254;
        n = expr_ret_254;
      }

      if (expr_ret_252)
      {
        #define ret expr_ret_252
        ret = SUCC;

        rule=node(LOGOR,  op, rule, n);

        #undef ret
      }

      if (!expr_ret_252) rew(mod_252);
      expr_ret_251 = expr_ret_252 ? SUCC : NULL;
    }

    expr_ret_251 = SUCC;
    expr_ret_249 = expr_ret_251;
  }

  if (!expr_ret_249) rew(mod_249);
  expr_ret_248 = expr_ret_249 ? SUCC : NULL;
  return expr_ret_248 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_256 = NULL;
  daisho_astnode_t* expr_ret_255 = NULL;
  #define rule expr_ret_255

  daisho_astnode_t* expr_ret_257 = NULL;
  rec(mod_257);
  {
    daisho_astnode_t* expr_ret_258 = NULL;
    expr_ret_258 = daisho_parse_binorexpr(ctx);
    expr_ret_257 = expr_ret_258;
    n = expr_ret_258;
  }

  if (expr_ret_257)
  {
    #define ret expr_ret_257
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_257)
  {
    daisho_astnode_t* expr_ret_259 = NULL;
    expr_ret_259 = SUCC;
    while (expr_ret_259)
    {
      daisho_astnode_t* expr_ret_260 = NULL;
      rec(mod_260);
      {
        daisho_astnode_t* expr_ret_261 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          expr_ret_261 = leaf(LOGAND);
          ctx->pos++;
        } else {
          expr_ret_261 = NULL;
        }

        expr_ret_260 = expr_ret_261;
        op = expr_ret_261;
      }

      if (expr_ret_260)
      {
        daisho_astnode_t* expr_ret_262 = NULL;
        expr_ret_262 = daisho_parse_binorexpr(ctx);
        expr_ret_260 = expr_ret_262;
        n = expr_ret_262;
      }

      if (expr_ret_260)
      {
        #define ret expr_ret_260
        ret = SUCC;

        rule=node(LOGAND, op, rule, n);

        #undef ret
      }

      if (!expr_ret_260) rew(mod_260);
      expr_ret_259 = expr_ret_260 ? SUCC : NULL;
    }

    expr_ret_259 = SUCC;
    expr_ret_257 = expr_ret_259;
  }

  if (!expr_ret_257) rew(mod_257);
  expr_ret_256 = expr_ret_257 ? SUCC : NULL;
  return expr_ret_256 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_264 = NULL;
  daisho_astnode_t* expr_ret_263 = NULL;
  #define rule expr_ret_263

  daisho_astnode_t* expr_ret_265 = NULL;
  rec(mod_265);
  {
    daisho_astnode_t* expr_ret_266 = NULL;
    expr_ret_266 = daisho_parse_binxorexpr(ctx);
    expr_ret_265 = expr_ret_266;
    n = expr_ret_266;
  }

  if (expr_ret_265)
  {
    #define ret expr_ret_265
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_265)
  {
    daisho_astnode_t* expr_ret_267 = NULL;
    expr_ret_267 = SUCC;
    while (expr_ret_267)
    {
      daisho_astnode_t* expr_ret_268 = NULL;
      rec(mod_268);
      {
        daisho_astnode_t* expr_ret_269 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          expr_ret_269 = leaf(OR);
          ctx->pos++;
        } else {
          expr_ret_269 = NULL;
        }

        expr_ret_268 = expr_ret_269;
        op = expr_ret_269;
      }

      if (expr_ret_268)
      {
        daisho_astnode_t* expr_ret_270 = NULL;
        expr_ret_270 = daisho_parse_binxorexpr(ctx);
        expr_ret_268 = expr_ret_270;
        n = expr_ret_270;
      }

      if (expr_ret_268)
      {
        #define ret expr_ret_268
        ret = SUCC;

        rule=node(OR,     op, rule, n);

        #undef ret
      }

      if (!expr_ret_268) rew(mod_268);
      expr_ret_267 = expr_ret_268 ? SUCC : NULL;
    }

    expr_ret_267 = SUCC;
    expr_ret_265 = expr_ret_267;
  }

  if (!expr_ret_265) rew(mod_265);
  expr_ret_264 = expr_ret_265 ? SUCC : NULL;
  return expr_ret_264 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_272 = NULL;
  daisho_astnode_t* expr_ret_271 = NULL;
  #define rule expr_ret_271

  daisho_astnode_t* expr_ret_273 = NULL;
  rec(mod_273);
  {
    daisho_astnode_t* expr_ret_274 = NULL;
    expr_ret_274 = daisho_parse_binandexpr(ctx);
    expr_ret_273 = expr_ret_274;
    n = expr_ret_274;
  }

  if (expr_ret_273)
  {
    #define ret expr_ret_273
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_273)
  {
    daisho_astnode_t* expr_ret_275 = NULL;
    expr_ret_275 = SUCC;
    while (expr_ret_275)
    {
      daisho_astnode_t* expr_ret_276 = NULL;
      rec(mod_276);
      {
        daisho_astnode_t* expr_ret_277 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          expr_ret_277 = leaf(XOR);
          ctx->pos++;
        } else {
          expr_ret_277 = NULL;
        }

        expr_ret_276 = expr_ret_277;
        op = expr_ret_277;
      }

      if (expr_ret_276)
      {
        daisho_astnode_t* expr_ret_278 = NULL;
        expr_ret_278 = daisho_parse_binandexpr(ctx);
        expr_ret_276 = expr_ret_278;
        n = expr_ret_278;
      }

      if (expr_ret_276)
      {
        #define ret expr_ret_276
        ret = SUCC;

        rule=node(XOR,    op, rule, n);

        #undef ret
      }

      if (!expr_ret_276) rew(mod_276);
      expr_ret_275 = expr_ret_276 ? SUCC : NULL;
    }

    expr_ret_275 = SUCC;
    expr_ret_273 = expr_ret_275;
  }

  if (!expr_ret_273) rew(mod_273);
  expr_ret_272 = expr_ret_273 ? SUCC : NULL;
  return expr_ret_272 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_280 = NULL;
  daisho_astnode_t* expr_ret_279 = NULL;
  #define rule expr_ret_279

  daisho_astnode_t* expr_ret_281 = NULL;
  rec(mod_281);
  {
    daisho_astnode_t* expr_ret_282 = NULL;
    expr_ret_282 = daisho_parse_deneqexpr(ctx);
    expr_ret_281 = expr_ret_282;
    n = expr_ret_282;
  }

  if (expr_ret_281)
  {
    #define ret expr_ret_281
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_281)
  {
    daisho_astnode_t* expr_ret_283 = NULL;
    expr_ret_283 = SUCC;
    while (expr_ret_283)
    {
      daisho_astnode_t* expr_ret_284 = NULL;
      rec(mod_284);
      {
        daisho_astnode_t* expr_ret_285 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          expr_ret_285 = leaf(AND);
          ctx->pos++;
        } else {
          expr_ret_285 = NULL;
        }

        expr_ret_284 = expr_ret_285;
        op = expr_ret_285;
      }

      if (expr_ret_284)
      {
        daisho_astnode_t* expr_ret_286 = NULL;
        expr_ret_286 = daisho_parse_deneqexpr(ctx);
        expr_ret_284 = expr_ret_286;
        n = expr_ret_286;
      }

      if (expr_ret_284)
      {
        #define ret expr_ret_284
        ret = SUCC;

        rule=node(AND,    op, rule, n);

        #undef ret
      }

      if (!expr_ret_284) rew(mod_284);
      expr_ret_283 = expr_ret_284 ? SUCC : NULL;
    }

    expr_ret_283 = SUCC;
    expr_ret_281 = expr_ret_283;
  }

  if (!expr_ret_281) rew(mod_281);
  expr_ret_280 = expr_ret_281 ? SUCC : NULL;
  return expr_ret_280 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_288 = NULL;
  daisho_astnode_t* expr_ret_287 = NULL;
  #define rule expr_ret_287

  daisho_astnode_t* expr_ret_289 = NULL;
  rec(mod_289);
  {
    daisho_astnode_t* expr_ret_290 = NULL;
    expr_ret_290 = daisho_parse_cmpexpr(ctx);
    expr_ret_289 = expr_ret_290;
    n = expr_ret_290;
  }

  if (expr_ret_289)
  {
    #define ret expr_ret_289
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_289)
  {
    daisho_astnode_t* expr_ret_291 = NULL;
    expr_ret_291 = SUCC;
    while (expr_ret_291)
    {
      daisho_astnode_t* expr_ret_292 = NULL;

      rec(slash_292);

      if (!expr_ret_292)
      {
        daisho_astnode_t* expr_ret_293 = NULL;
        rec(mod_293);
        {
          daisho_astnode_t* expr_ret_294 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            expr_ret_294 = leaf(DEQ);
            ctx->pos++;
          } else {
            expr_ret_294 = NULL;
          }

          expr_ret_293 = expr_ret_294;
          op = expr_ret_294;
        }

        if (expr_ret_293)
        {
          daisho_astnode_t* expr_ret_295 = NULL;
          expr_ret_295 = daisho_parse_cmpexpr(ctx);
          expr_ret_293 = expr_ret_295;
          n = expr_ret_295;
        }

        if (expr_ret_293)
        {
          #define ret expr_ret_293
          ret = SUCC;

          rule=node(DEQ, op, rule, n);

          #undef ret
        }

        if (!expr_ret_293) rew(mod_293);
        expr_ret_292 = expr_ret_293 ? SUCC : NULL;
      }

      if (!expr_ret_292)
      {
        daisho_astnode_t* expr_ret_296 = NULL;
        rec(mod_296);
        {
          daisho_astnode_t* expr_ret_297 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            expr_ret_297 = leaf(NEQ);
            ctx->pos++;
          } else {
            expr_ret_297 = NULL;
          }

          expr_ret_296 = expr_ret_297;
          op = expr_ret_297;
        }

        if (expr_ret_296)
        {
          daisho_astnode_t* expr_ret_298 = NULL;
          expr_ret_298 = daisho_parse_cmpexpr(ctx);
          expr_ret_296 = expr_ret_298;
          n = expr_ret_298;
        }

        if (expr_ret_296)
        {
          #define ret expr_ret_296
          ret = SUCC;

          rule=node(NEQ, op, rule, n);

          #undef ret
        }

        if (!expr_ret_296) rew(mod_296);
        expr_ret_292 = expr_ret_296 ? SUCC : NULL;
      }

      if (!expr_ret_292) rew(slash_292);
      expr_ret_291 = expr_ret_292;

    }

    expr_ret_291 = SUCC;
    expr_ret_289 = expr_ret_291;
  }

  if (!expr_ret_289) rew(mod_289);
  expr_ret_288 = expr_ret_289 ? SUCC : NULL;
  return expr_ret_288 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_300 = NULL;
  daisho_astnode_t* expr_ret_299 = NULL;
  #define rule expr_ret_299

  daisho_astnode_t* expr_ret_301 = NULL;
  rec(mod_301);
  {
    daisho_astnode_t* expr_ret_302 = NULL;
    expr_ret_302 = daisho_parse_shfexpr(ctx);
    expr_ret_301 = expr_ret_302;
    n = expr_ret_302;
  }

  if (expr_ret_301)
  {
    #define ret expr_ret_301
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_301)
  {
    daisho_astnode_t* expr_ret_303 = NULL;
    expr_ret_303 = SUCC;
    while (expr_ret_303)
    {
      daisho_astnode_t* expr_ret_304 = NULL;

      rec(slash_304);

      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_305 = NULL;
        rec(mod_305);
        {
          daisho_astnode_t* expr_ret_306 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            expr_ret_306 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_306 = NULL;
          }

          expr_ret_305 = expr_ret_306;
          op = expr_ret_306;
        }

        if (expr_ret_305)
        {
          daisho_astnode_t* expr_ret_307 = NULL;
          expr_ret_307 = daisho_parse_shfexpr(ctx);
          expr_ret_305 = expr_ret_307;
          n = expr_ret_307;
        }

        if (expr_ret_305)
        {
          #define ret expr_ret_305
          ret = SUCC;

          rule=node(LT,  op, rule, n);

          #undef ret
        }

        if (!expr_ret_305) rew(mod_305);
        expr_ret_304 = expr_ret_305 ? SUCC : NULL;
      }

      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_308 = NULL;
        rec(mod_308);
        {
          daisho_astnode_t* expr_ret_309 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            expr_ret_309 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_309 = NULL;
          }

          expr_ret_308 = expr_ret_309;
          op = expr_ret_309;
        }

        if (expr_ret_308)
        {
          daisho_astnode_t* expr_ret_310 = NULL;
          expr_ret_310 = daisho_parse_shfexpr(ctx);
          expr_ret_308 = expr_ret_310;
          n = expr_ret_310;
        }

        if (expr_ret_308)
        {
          #define ret expr_ret_308
          ret = SUCC;

          rule=node(GT,  op, rule, n);

          #undef ret
        }

        if (!expr_ret_308) rew(mod_308);
        expr_ret_304 = expr_ret_308 ? SUCC : NULL;
      }

      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_311 = NULL;
        rec(mod_311);
        {
          daisho_astnode_t* expr_ret_312 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            expr_ret_312 = leaf(LEQ);
            ctx->pos++;
          } else {
            expr_ret_312 = NULL;
          }

          expr_ret_311 = expr_ret_312;
          op = expr_ret_312;
        }

        if (expr_ret_311)
        {
          daisho_astnode_t* expr_ret_313 = NULL;
          expr_ret_313 = daisho_parse_shfexpr(ctx);
          expr_ret_311 = expr_ret_313;
          n = expr_ret_313;
        }

        if (expr_ret_311)
        {
          #define ret expr_ret_311
          ret = SUCC;

          rule=node(LEQ, op, rule, n);

          #undef ret
        }

        if (!expr_ret_311) rew(mod_311);
        expr_ret_304 = expr_ret_311 ? SUCC : NULL;
      }

      if (!expr_ret_304)
      {
        daisho_astnode_t* expr_ret_314 = NULL;
        rec(mod_314);
        {
          daisho_astnode_t* expr_ret_315 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            expr_ret_315 = leaf(GEQ);
            ctx->pos++;
          } else {
            expr_ret_315 = NULL;
          }

          expr_ret_314 = expr_ret_315;
          op = expr_ret_315;
        }

        if (expr_ret_314)
        {
          daisho_astnode_t* expr_ret_316 = NULL;
          expr_ret_316 = daisho_parse_shfexpr(ctx);
          expr_ret_314 = expr_ret_316;
          n = expr_ret_316;
        }

        if (expr_ret_314)
        {
          #define ret expr_ret_314
          ret = SUCC;

          rule=node(GEQ, op, rule, n);

          #undef ret
        }

        if (!expr_ret_314) rew(mod_314);
        expr_ret_304 = expr_ret_314 ? SUCC : NULL;
      }

      if (!expr_ret_304) rew(slash_304);
      expr_ret_303 = expr_ret_304;

    }

    expr_ret_303 = SUCC;
    expr_ret_301 = expr_ret_303;
  }

  if (!expr_ret_301) rew(mod_301);
  expr_ret_300 = expr_ret_301 ? SUCC : NULL;
  return expr_ret_300 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  daisho_astnode_t* expr_ret_318 = NULL;
  daisho_astnode_t* expr_ret_317 = NULL;
  #define rule expr_ret_317

  daisho_astnode_t* expr_ret_319 = NULL;
  rec(mod_319);
  {
    daisho_astnode_t* expr_ret_320 = NULL;
    expr_ret_320 = daisho_parse_powexpr(ctx);
    expr_ret_319 = expr_ret_320;
    n = expr_ret_320;
  }

  if (expr_ret_319)
  {
    #define ret expr_ret_319
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_319)
  {
    daisho_astnode_t* expr_ret_321 = NULL;
    expr_ret_321 = SUCC;
    while (expr_ret_321)
    {
      daisho_astnode_t* expr_ret_322 = NULL;

      rec(slash_322);

      if (!expr_ret_322)
      {
        daisho_astnode_t* expr_ret_323 = NULL;
        rec(mod_323);
        {
          daisho_astnode_t* expr_ret_324 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            expr_ret_324 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_324 = NULL;
          }

          expr_ret_323 = expr_ret_324;
          l = expr_ret_324;
        }

        if (expr_ret_323)
        {
          daisho_astnode_t* expr_ret_325 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            expr_ret_325 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_325 = NULL;
          }

          expr_ret_323 = expr_ret_325;
          lt = expr_ret_325;
        }

        if (expr_ret_323)
        {
          daisho_astnode_t* expr_ret_326 = NULL;
          expr_ret_326 = daisho_parse_powexpr(ctx);
          expr_ret_323 = expr_ret_326;
          n = expr_ret_326;
        }

        if (expr_ret_323)
        {
          #define ret expr_ret_323
          ret = SUCC;

          rule=node(BSL, l, lt, rule, n);

          #undef ret
        }

        if (!expr_ret_323) rew(mod_323);
        expr_ret_322 = expr_ret_323 ? SUCC : NULL;
      }

      if (!expr_ret_322)
      {
        daisho_astnode_t* expr_ret_327 = NULL;
        rec(mod_327);
        {
          daisho_astnode_t* expr_ret_328 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            expr_ret_328 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_328 = NULL;
          }

          expr_ret_327 = expr_ret_328;
          g = expr_ret_328;
        }

        if (expr_ret_327)
        {
          daisho_astnode_t* expr_ret_329 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            expr_ret_329 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_329 = NULL;
          }

          expr_ret_327 = expr_ret_329;
          gt = expr_ret_329;
        }

        if (expr_ret_327)
        {
          daisho_astnode_t* expr_ret_330 = NULL;
          expr_ret_330 = daisho_parse_powexpr(ctx);
          expr_ret_327 = expr_ret_330;
          n = expr_ret_330;
        }

        if (expr_ret_327)
        {
          #define ret expr_ret_327
          ret = SUCC;

          rule=node(BSR, g, gt, rule, n);

          #undef ret
        }

        if (!expr_ret_327) rew(mod_327);
        expr_ret_322 = expr_ret_327 ? SUCC : NULL;
      }

      if (!expr_ret_322) rew(slash_322);
      expr_ret_321 = expr_ret_322;

    }

    expr_ret_321 = SUCC;
    expr_ret_319 = expr_ret_321;
  }

  if (!expr_ret_319) rew(mod_319);
  expr_ret_318 = expr_ret_319 ? SUCC : NULL;
  return expr_ret_318 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_powexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_332 = NULL;
  daisho_astnode_t* expr_ret_331 = NULL;
  #define rule expr_ret_331

  daisho_astnode_t* expr_ret_333 = NULL;
  rec(mod_333);
  {
    daisho_astnode_t* expr_ret_334 = NULL;
    expr_ret_334 = daisho_parse_multexpr(ctx);
    expr_ret_333 = expr_ret_334;
    n = expr_ret_334;
  }

  if (expr_ret_333)
  {
    #define ret expr_ret_333
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_333)
  {
    daisho_astnode_t* expr_ret_335 = NULL;
    expr_ret_335 = SUCC;
    while (expr_ret_335)
    {
      daisho_astnode_t* expr_ret_336 = NULL;
      rec(mod_336);
      {
        daisho_astnode_t* expr_ret_337 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_POW) {
          expr_ret_337 = leaf(POW);
          ctx->pos++;
        } else {
          expr_ret_337 = NULL;
        }

        expr_ret_336 = expr_ret_337;
        op = expr_ret_337;
      }

      if (expr_ret_336)
      {
        #define ret expr_ret_336
        ret = SUCC;

        rule=node(POW, op, rule, n);

        #undef ret
      }

      if (!expr_ret_336) rew(mod_336);
      expr_ret_335 = expr_ret_336 ? SUCC : NULL;
    }

    expr_ret_335 = SUCC;
    expr_ret_333 = expr_ret_335;
  }

  if (!expr_ret_333) rew(mod_333);
  expr_ret_332 = expr_ret_333 ? SUCC : NULL;
  return expr_ret_332 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_339 = NULL;
  daisho_astnode_t* expr_ret_338 = NULL;
  #define rule expr_ret_338

  daisho_astnode_t* expr_ret_340 = NULL;
  rec(mod_340);
  {
    daisho_astnode_t* expr_ret_341 = NULL;
    expr_ret_341 = daisho_parse_sumexpr(ctx);
    expr_ret_340 = expr_ret_341;
    n = expr_ret_341;
  }

  if (expr_ret_340)
  {
    #define ret expr_ret_340
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_340)
  {
    daisho_astnode_t* expr_ret_342 = NULL;
    expr_ret_342 = SUCC;
    while (expr_ret_342)
    {
      daisho_astnode_t* expr_ret_343 = NULL;

      rec(slash_343);

      if (!expr_ret_343)
      {
        daisho_astnode_t* expr_ret_344 = NULL;
        rec(mod_344);
        {
          daisho_astnode_t* expr_ret_345 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            expr_ret_345 = leaf(STAR);
            ctx->pos++;
          } else {
            expr_ret_345 = NULL;
          }

          expr_ret_344 = expr_ret_345;
          op = expr_ret_345;
        }

        if (expr_ret_344)
        {
          daisho_astnode_t* expr_ret_346 = NULL;
          expr_ret_346 = daisho_parse_sumexpr(ctx);
          expr_ret_344 = expr_ret_346;
          n = expr_ret_346;
        }

        if (expr_ret_344)
        {
          #define ret expr_ret_344
          ret = SUCC;

          rule=node(STAR, op, rule, n);

          #undef ret
        }

        if (!expr_ret_344) rew(mod_344);
        expr_ret_343 = expr_ret_344 ? SUCC : NULL;
      }

      if (!expr_ret_343)
      {
        daisho_astnode_t* expr_ret_347 = NULL;
        rec(mod_347);
        {
          daisho_astnode_t* expr_ret_348 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            expr_ret_348 = leaf(DIV);
            ctx->pos++;
          } else {
            expr_ret_348 = NULL;
          }

          expr_ret_347 = expr_ret_348;
          op = expr_ret_348;
        }

        if (expr_ret_347)
        {
          daisho_astnode_t* expr_ret_349 = NULL;
          expr_ret_349 = daisho_parse_sumexpr(ctx);
          expr_ret_347 = expr_ret_349;
          n = expr_ret_349;
        }

        if (expr_ret_347)
        {
          #define ret expr_ret_347
          ret = SUCC;

          rule=node(DIV,  op, rule, n);

          #undef ret
        }

        if (!expr_ret_347) rew(mod_347);
        expr_ret_343 = expr_ret_347 ? SUCC : NULL;
      }

      if (!expr_ret_343)
      {
        daisho_astnode_t* expr_ret_350 = NULL;
        rec(mod_350);
        {
          daisho_astnode_t* expr_ret_351 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            expr_ret_351 = leaf(MOD);
            ctx->pos++;
          } else {
            expr_ret_351 = NULL;
          }

          expr_ret_350 = expr_ret_351;
          op = expr_ret_351;
        }

        if (expr_ret_350)
        {
          daisho_astnode_t* expr_ret_352 = NULL;
          expr_ret_352 = daisho_parse_sumexpr(ctx);
          expr_ret_350 = expr_ret_352;
          n = expr_ret_352;
        }

        if (expr_ret_350)
        {
          #define ret expr_ret_350
          ret = SUCC;

          rule=node(MOD,  op, rule, n);

          #undef ret
        }

        if (!expr_ret_350) rew(mod_350);
        expr_ret_343 = expr_ret_350 ? SUCC : NULL;
      }

      if (!expr_ret_343) rew(slash_343);
      expr_ret_342 = expr_ret_343;

    }

    expr_ret_342 = SUCC;
    expr_ret_340 = expr_ret_342;
  }

  if (!expr_ret_340) rew(mod_340);
  expr_ret_339 = expr_ret_340 ? SUCC : NULL;
  return expr_ret_339 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_354 = NULL;
  daisho_astnode_t* expr_ret_353 = NULL;
  #define rule expr_ret_353

  daisho_astnode_t* expr_ret_355 = NULL;
  rec(mod_355);
  {
    daisho_astnode_t* expr_ret_356 = NULL;
    expr_ret_356 = daisho_parse_callexpr(ctx);
    expr_ret_355 = expr_ret_356;
    n = expr_ret_356;
  }

  if (expr_ret_355)
  {
    #define ret expr_ret_355
    ret = SUCC;

    rule=n;

    #undef ret
  }

  if (expr_ret_355)
  {
    daisho_astnode_t* expr_ret_357 = NULL;
    expr_ret_357 = SUCC;
    while (expr_ret_357)
    {
      daisho_astnode_t* expr_ret_358 = NULL;

      rec(slash_358);

      if (!expr_ret_358)
      {
        daisho_astnode_t* expr_ret_359 = NULL;
        rec(mod_359);
        {
          daisho_astnode_t* expr_ret_360 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            expr_ret_360 = leaf(PLUS);
            ctx->pos++;
          } else {
            expr_ret_360 = NULL;
          }

          expr_ret_359 = expr_ret_360;
          op = expr_ret_360;
        }

        if (expr_ret_359)
        {
          daisho_astnode_t* expr_ret_361 = NULL;
          expr_ret_361 = daisho_parse_callexpr(ctx);
          expr_ret_359 = expr_ret_361;
          n = expr_ret_361;
        }

        if (expr_ret_359)
        {
          #define ret expr_ret_359
          ret = SUCC;

          rule=node(PLUS, op, rule, n);

          #undef ret
        }

        if (!expr_ret_359) rew(mod_359);
        expr_ret_358 = expr_ret_359 ? SUCC : NULL;
      }

      if (!expr_ret_358)
      {
        daisho_astnode_t* expr_ret_362 = NULL;
        rec(mod_362);
        {
          daisho_astnode_t* expr_ret_363 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            expr_ret_363 = leaf(MINUS);
            ctx->pos++;
          } else {
            expr_ret_363 = NULL;
          }

          expr_ret_362 = expr_ret_363;
          op = expr_ret_363;
        }

        if (expr_ret_362)
        {
          daisho_astnode_t* expr_ret_364 = NULL;
          expr_ret_364 = daisho_parse_callexpr(ctx);
          expr_ret_362 = expr_ret_364;
          n = expr_ret_364;
        }

        if (expr_ret_362)
        {
          #define ret expr_ret_362
          ret = SUCC;

          rule=node(MINUS, op, rule, n);

          #undef ret
        }

        if (!expr_ret_362) rew(mod_362);
        expr_ret_358 = expr_ret_362 ? SUCC : NULL;
      }

      if (!expr_ret_358) rew(slash_358);
      expr_ret_357 = expr_ret_358;

    }

    expr_ret_357 = SUCC;
    expr_ret_355 = expr_ret_357;
  }

  if (!expr_ret_355) rew(mod_355);
  expr_ret_354 = expr_ret_355 ? SUCC : NULL;
  return expr_ret_354 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_366 = NULL;
  daisho_astnode_t* expr_ret_365 = NULL;
  #define rule expr_ret_365

  daisho_astnode_t* expr_ret_367 = NULL;

  rec(slash_367);

  if (!expr_ret_367)
  {
    daisho_astnode_t* expr_ret_368 = NULL;
    rec(mod_368);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        expr_ret_368 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_368 = NULL;
      }

    }

    if (expr_ret_368)
    {
      daisho_astnode_t* expr_ret_369 = NULL;
      expr_ret_369 = daisho_parse_tmplexpand(ctx);
      if (!expr_ret_369)
        expr_ret_369 = SUCC;
      expr_ret_368 = expr_ret_369;
      t = expr_ret_369;
    }

    if (expr_ret_368)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        expr_ret_368 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_368 = NULL;
      }

    }

    if (expr_ret_368)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        expr_ret_368 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_368 = NULL;
      }

    }

    if (!expr_ret_368) rew(mod_368);
    expr_ret_367 = expr_ret_368 ? SUCC : NULL;
  }

  if (!expr_ret_367)
  {
    daisho_astnode_t* expr_ret_370 = NULL;
    rec(mod_370);
    {
      daisho_astnode_t* expr_ret_371 = NULL;
      expr_ret_371 = daisho_parse_castexpr(ctx);
      expr_ret_370 = expr_ret_371;
      n = expr_ret_371;
    }

    if (expr_ret_370)
    {
      #define ret expr_ret_370
      ret = SUCC;

      rule=n;

      #undef ret
    }

    if (!expr_ret_370) rew(mod_370);
    expr_ret_367 = expr_ret_370 ? SUCC : NULL;
  }

  if (!expr_ret_367) rew(slash_367);
  expr_ret_366 = expr_ret_367;

  return expr_ret_366 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* re = NULL;
  daisho_astnode_t* expr_ret_373 = NULL;
  daisho_astnode_t* expr_ret_372 = NULL;
  #define rule expr_ret_372

  daisho_astnode_t* expr_ret_374 = NULL;

  rec(slash_374);

  if (!expr_ret_374)
  {
    daisho_astnode_t* expr_ret_375 = NULL;
    rec(mod_375);
    {
      daisho_astnode_t* expr_ret_376 = NULL;
      expr_ret_376 = daisho_parse_refexpr(ctx);
      expr_ret_375 = expr_ret_376;
      n = expr_ret_376;
    }

    if (expr_ret_375)
    {
      daisho_astnode_t* expr_ret_377 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        expr_ret_377 = leaf(OPEN);
        ctx->pos++;
      } else {
        expr_ret_377 = NULL;
      }

      expr_ret_375 = expr_ret_377;
      o = expr_ret_377;
    }

    if (expr_ret_375)
    {
      daisho_astnode_t* expr_ret_378 = NULL;
      expr_ret_378 = daisho_parse_type(ctx);
      expr_ret_375 = expr_ret_378;
      t = expr_ret_378;
    }

    if (expr_ret_375)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        expr_ret_375 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_375 = NULL;
      }

    }

    if (expr_ret_375)
    {
      #define ret expr_ret_375
      ret = SUCC;

      rule=node(CAST, o, t, n);

      #undef ret
    }

    if (!expr_ret_375) rew(mod_375);
    expr_ret_374 = expr_ret_375 ? SUCC : NULL;
  }

  if (!expr_ret_374)
  {
    daisho_astnode_t* expr_ret_379 = NULL;
    rec(mod_379);
    {
      daisho_astnode_t* expr_ret_380 = NULL;
      expr_ret_380 = daisho_parse_refexpr(ctx);
      expr_ret_379 = expr_ret_380;
      re = expr_ret_380;
    }

    if (expr_ret_379)
    {
      #define ret expr_ret_379
      ret = SUCC;

      rule = re;

      #undef ret
    }

    if (!expr_ret_379) rew(mod_379);
    expr_ret_374 = expr_ret_379 ? SUCC : NULL;
  }

  if (!expr_ret_374) rew(slash_374);
  expr_ret_373 = expr_ret_374;

  return expr_ret_373 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* expr_ret_382 = NULL;
  daisho_astnode_t* expr_ret_381 = NULL;
  #define rule expr_ret_381

  daisho_astnode_t* expr_ret_383 = NULL;
  rec(mod_383);
  {
    daisho_astnode_t* expr_ret_384 = NULL;
    expr_ret_384 = daisho_parse_derefexpr(ctx);
    expr_ret_383 = expr_ret_384;
    n = expr_ret_384;
  }

  if (expr_ret_383)
  {
    daisho_astnode_t* expr_ret_385 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      expr_ret_385 = leaf(REF);
      ctx->pos++;
    } else {
      expr_ret_385 = NULL;
    }

    if (!expr_ret_385)
      expr_ret_385 = SUCC;
    expr_ret_383 = expr_ret_385;
    r = expr_ret_385;
  }

  if (expr_ret_383)
  {
    #define ret expr_ret_383
    ret = SUCC;

    rule=(r != SUCC) ? node(REF, r, n) : n;

    #undef ret
  }

  if (!expr_ret_383) rew(mod_383);
  expr_ret_382 = expr_ret_383 ? SUCC : NULL;
  return expr_ret_382 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* d = NULL;
  daisho_astnode_t* expr_ret_387 = NULL;
  daisho_astnode_t* expr_ret_386 = NULL;
  #define rule expr_ret_386

  daisho_astnode_t* expr_ret_388 = NULL;
  rec(mod_388);
  {
    daisho_astnode_t* expr_ret_389 = NULL;
    expr_ret_389 = daisho_parse_postretexpr(ctx);
    expr_ret_388 = expr_ret_389;
    n = expr_ret_389;
  }

  if (expr_ret_388)
  {
    daisho_astnode_t* expr_ret_390 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEREF) {
      expr_ret_390 = leaf(DEREF);
      ctx->pos++;
    } else {
      expr_ret_390 = NULL;
    }

    if (!expr_ret_390)
      expr_ret_390 = SUCC;
    expr_ret_388 = expr_ret_390;
    d = expr_ret_390;
  }

  if (expr_ret_388)
  {
    #define ret expr_ret_388
    ret = SUCC;

    rule=(d != SUCC) ? node(REF, d, n) : n;

    #undef ret
  }

  if (!expr_ret_388) rew(mod_388);
  expr_ret_387 = expr_ret_388 ? SUCC : NULL;
  return expr_ret_387 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* expr_ret_392 = NULL;
  daisho_astnode_t* expr_ret_391 = NULL;
  #define rule expr_ret_391

  daisho_astnode_t* expr_ret_393 = NULL;
  rec(mod_393);
  {
    daisho_astnode_t* expr_ret_394 = NULL;
    expr_ret_394 = daisho_parse_atomexpr(ctx);
    expr_ret_393 = expr_ret_394;
    n = expr_ret_394;
  }

  if (expr_ret_393)
  {
    daisho_astnode_t* expr_ret_395 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      expr_ret_395 = leaf(GRAVE);
      ctx->pos++;
    } else {
      expr_ret_395 = NULL;
    }

    if (!expr_ret_395)
      expr_ret_395 = SUCC;
    expr_ret_393 = expr_ret_395;
    g = expr_ret_395;
  }

  if (expr_ret_393)
  {
    #define ret expr_ret_393
    ret = SUCC;

    rule=(g != SUCC) ? node(RET, g, n) : n;

    #undef ret
  }

  if (!expr_ret_393) rew(mod_393);
  expr_ret_392 = expr_ret_393 ? SUCC : NULL;
  return expr_ret_392 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_397 = NULL;
  daisho_astnode_t* expr_ret_396 = NULL;
  #define rule expr_ret_396

  daisho_astnode_t* expr_ret_398 = NULL;

  rec(slash_398);

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_399 = NULL;
    rec(mod_399);
    expr_ret_399 = daisho_parse_blockexpr(ctx);
    if (!expr_ret_399) rew(mod_399);
    expr_ret_398 = expr_ret_399;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_400 = NULL;
    rec(mod_400);
    expr_ret_400 = daisho_parse_lambdaexpr(ctx);
    if (!expr_ret_400) rew(mod_400);
    expr_ret_398 = expr_ret_400;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_401 = NULL;
    rec(mod_401);
    expr_ret_401 = daisho_parse_listcomp(ctx);
    if (!expr_ret_401) rew(mod_401);
    expr_ret_398 = expr_ret_401;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_402 = NULL;
    rec(mod_402);
    expr_ret_402 = daisho_parse_listlit(ctx);
    if (!expr_ret_402) rew(mod_402);
    expr_ret_398 = expr_ret_402;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_403 = NULL;
    rec(mod_403);
    expr_ret_403 = daisho_parse_parenexpr(ctx);
    if (!expr_ret_403) rew(mod_403);
    expr_ret_398 = expr_ret_403;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_404 = NULL;
    rec(mod_404);
    expr_ret_404 = daisho_parse_ctypeexpr(ctx);
    if (!expr_ret_404) rew(mod_404);
    expr_ret_398 = expr_ret_404;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_405 = NULL;
    rec(mod_405);
    expr_ret_405 = daisho_parse_cfuncexpr(ctx);
    if (!expr_ret_405) rew(mod_405);
    expr_ret_398 = expr_ret_405;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_406 = NULL;
    rec(mod_406);
    expr_ret_406 = daisho_parse_preretexpr(ctx);
    if (!expr_ret_406) rew(mod_406);
    expr_ret_398 = expr_ret_406;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_407 = NULL;
    rec(mod_407);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      expr_ret_407 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_407 = NULL;
    }

    if (!expr_ret_407) rew(mod_407);
    expr_ret_398 = expr_ret_407;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_408 = NULL;
    rec(mod_408);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      expr_ret_408 = leaf(NUMLIT);
      ctx->pos++;
    } else {
      expr_ret_408 = NULL;
    }

    if (!expr_ret_408) rew(mod_408);
    expr_ret_398 = expr_ret_408;
  }

  if (!expr_ret_398)
  {
    daisho_astnode_t* expr_ret_409 = NULL;
    rec(mod_409);
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      expr_ret_409 = leaf(STRLIT);
      ctx->pos++;
    } else {
      expr_ret_409 = NULL;
    }

    if (!expr_ret_409) rew(mod_409);
    expr_ret_398 = expr_ret_409;
  }

  if (!expr_ret_398) rew(slash_398);
  expr_ret_397 = expr_ret_398;

  return expr_ret_397 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_411 = NULL;
  daisho_astnode_t* expr_ret_410 = NULL;
  #define rule expr_ret_410

  daisho_astnode_t* expr_ret_412 = NULL;
  rec(mod_412);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      expr_ret_412 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_412 = NULL;
    }

  }

  if (expr_ret_412)
  {
    #define ret expr_ret_412
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  if (expr_ret_412)
  {
    daisho_astnode_t* expr_ret_413 = NULL;
    expr_ret_413 = SUCC;
    while (expr_ret_413)
    {
      daisho_astnode_t* expr_ret_414 = NULL;
      rec(mod_414);
      {
        daisho_astnode_t* expr_ret_415 = NULL;
        expr_ret_415 = daisho_parse_expr(ctx);
        expr_ret_414 = expr_ret_415;
        e = expr_ret_415;
      }

      if (expr_ret_414)
      {
        #define ret expr_ret_414
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      if (!expr_ret_414) rew(mod_414);
      expr_ret_413 = expr_ret_414 ? SUCC : NULL;
    }

    expr_ret_413 = SUCC;
    expr_ret_412 = expr_ret_413;
  }

  if (expr_ret_412)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      expr_ret_412 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_412 = NULL;
    }

  }

  if (!expr_ret_412) rew(mod_412);
  expr_ret_411 = expr_ret_412 ? SUCC : NULL;
  return expr_ret_411 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_417 = NULL;
  daisho_astnode_t* expr_ret_416 = NULL;
  #define rule expr_ret_416

  daisho_astnode_t* expr_ret_418 = NULL;
  rec(mod_418);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      expr_ret_418 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_418 = NULL;
    }

  }

  if (expr_ret_418)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      expr_ret_418 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_418 = NULL;
    }

  }

  if (!expr_ret_418) rew(mod_418);
  expr_ret_417 = expr_ret_418 ? SUCC : NULL;
  return expr_ret_417 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* expr_ret_420 = NULL;
  daisho_astnode_t* expr_ret_419 = NULL;
  #define rule expr_ret_419

  daisho_astnode_t* expr_ret_421 = NULL;
  rec(mod_421);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      expr_ret_421 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_421 = NULL;
    }

  }

  if (expr_ret_421)
  {
    daisho_astnode_t* expr_ret_422 = NULL;
    daisho_astnode_t* expr_ret_423 = NULL;
    rec(mod_423);
    {
      daisho_astnode_t* expr_ret_424 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        expr_ret_424 = leaf(VARIDENT);
        ctx->pos++;
      } else {
        expr_ret_424 = NULL;
      }

      expr_ret_423 = expr_ret_424;
      cnt = expr_ret_424;
    }

    if (expr_ret_423)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        expr_ret_423 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_423 = NULL;
      }

    }

    if (!expr_ret_423) rew(mod_423);
    expr_ret_422 = expr_ret_423 ? SUCC : NULL;
    if (!expr_ret_422)
      expr_ret_422 = SUCC;
    expr_ret_421 = expr_ret_422;
  }

  if (expr_ret_421)
  {
    expr_ret_421 = daisho_parse_expr(ctx);
  }

  if (expr_ret_421)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      expr_ret_421 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_421 = NULL;
    }

  }

  if (expr_ret_421)
  {
    daisho_astnode_t* expr_ret_425 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      expr_ret_425 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_425 = NULL;
    }

    expr_ret_421 = expr_ret_425;
    item = expr_ret_425;
  }

  if (expr_ret_421)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      expr_ret_421 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_421 = NULL;
    }

  }

  if (expr_ret_421)
  {
    expr_ret_421 = daisho_parse_expr(ctx);
  }

  if (expr_ret_421)
  {
    daisho_astnode_t* expr_ret_426 = NULL;
    daisho_astnode_t* expr_ret_427 = NULL;
    rec(mod_427);
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        expr_ret_427 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_427 = NULL;
      }

    }

    if (expr_ret_427)
    {
      expr_ret_427 = daisho_parse_expr(ctx);
    }

    if (!expr_ret_427) rew(mod_427);
    expr_ret_426 = expr_ret_427 ? SUCC : NULL;
    if (!expr_ret_426)
      expr_ret_426 = SUCC;
    expr_ret_421 = expr_ret_426;
  }

  if (expr_ret_421)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      expr_ret_421 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_421 = NULL;
    }

  }

  if (!expr_ret_421) rew(mod_421);
  expr_ret_420 = expr_ret_421 ? SUCC : NULL;
  return expr_ret_420 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_429 = NULL;
  daisho_astnode_t* expr_ret_428 = NULL;
  #define rule expr_ret_428

  daisho_astnode_t* expr_ret_430 = NULL;
  rec(mod_430);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      expr_ret_430 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_430 = NULL;
    }

  }

  if (expr_ret_430)
  {
    daisho_astnode_t* expr_ret_431 = NULL;
    expr_ret_431 = daisho_parse_expr(ctx);
    if (!expr_ret_431)
      expr_ret_431 = SUCC;
    expr_ret_430 = expr_ret_431;
  }

  if (expr_ret_430)
  {
    daisho_astnode_t* expr_ret_432 = NULL;
    expr_ret_432 = SUCC;
    while (expr_ret_432)
    {
      daisho_astnode_t* expr_ret_433 = NULL;
      rec(mod_433);
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          expr_ret_433 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_433 = NULL;
        }

      }

      if (expr_ret_433)
      {
        expr_ret_433 = daisho_parse_expr(ctx);
      }

      if (!expr_ret_433) rew(mod_433);
      expr_ret_432 = expr_ret_433 ? SUCC : NULL;
    }

    expr_ret_432 = SUCC;
    expr_ret_430 = expr_ret_432;
  }

  if (expr_ret_430)
  {
    daisho_astnode_t* expr_ret_434 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      expr_ret_434 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_434 = NULL;
    }

    if (!expr_ret_434)
      expr_ret_434 = SUCC;
    expr_ret_430 = expr_ret_434;
  }

  if (expr_ret_430)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      expr_ret_430 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_430 = NULL;
    }

  }

  if (!expr_ret_430) rew(mod_430);
  expr_ret_429 = expr_ret_430 ? SUCC : NULL;
  return expr_ret_429 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_436 = NULL;
  daisho_astnode_t* expr_ret_435 = NULL;
  #define rule expr_ret_435

  daisho_astnode_t* expr_ret_437 = NULL;
  rec(mod_437);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      expr_ret_437 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_437 = NULL;
    }

  }

  if (expr_ret_437)
  {
    daisho_astnode_t* expr_ret_438 = NULL;
    expr_ret_438 = daisho_parse_expr(ctx);
    expr_ret_437 = expr_ret_438;
    e = expr_ret_438;
  }

  if (expr_ret_437)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      expr_ret_437 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_437 = NULL;
    }

  }

  if (expr_ret_437)
  {
    #define ret expr_ret_437
    ret = SUCC;

    rule=e;

    #undef ret
  }

  if (!expr_ret_437) rew(mod_437);
  expr_ret_436 = expr_ret_437 ? SUCC : NULL;
  return expr_ret_436 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_440 = NULL;
  daisho_astnode_t* expr_ret_439 = NULL;
  #define rule expr_ret_439

  daisho_astnode_t* expr_ret_441 = NULL;
  rec(mod_441);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      expr_ret_441 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_441 = NULL;
    }

  }

  if (expr_ret_441)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      expr_ret_441 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_441 = NULL;
    }

  }

  if (expr_ret_441)
  {
    daisho_astnode_t* expr_ret_442 = NULL;
    expr_ret_442 = SUCC;
    while (expr_ret_442)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        expr_ret_442 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_442 = NULL;
      }

    }

    expr_ret_442 = SUCC;
    expr_ret_441 = expr_ret_442;
  }

  if (!expr_ret_441) rew(mod_441);
  expr_ret_440 = expr_ret_441 ? SUCC : NULL;
  return expr_ret_440 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_444 = NULL;
  daisho_astnode_t* expr_ret_443 = NULL;
  #define rule expr_ret_443

  daisho_astnode_t* expr_ret_445 = NULL;
  rec(mod_445);
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFUNC) {
      expr_ret_445 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_445 = NULL;
    }

  }

  if (expr_ret_445)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      expr_ret_445 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_445 = NULL;
    }

  }

  if (!expr_ret_445) rew(mod_445);
  expr_ret_444 = expr_ret_445 ? SUCC : NULL;
  return expr_ret_444 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_447 = NULL;
  daisho_astnode_t* expr_ret_446 = NULL;
  #define rule expr_ret_446

  daisho_astnode_t* expr_ret_448 = NULL;
  rec(mod_448);
  {
    daisho_astnode_t* expr_ret_449 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      expr_ret_449 = leaf(RET);
      ctx->pos++;
    } else {
      expr_ret_449 = NULL;
    }

    expr_ret_448 = expr_ret_449;
    r = expr_ret_449;
  }

  if (expr_ret_448)
  {
    daisho_astnode_t* expr_ret_450 = NULL;
    expr_ret_450 = daisho_parse_expr(ctx);
    expr_ret_448 = expr_ret_450;
    e = expr_ret_450;
  }

  if (expr_ret_448)
  {
    #define ret expr_ret_448
    ret = SUCC;

    rule=node(RET, r, e);

    #undef ret
  }

  if (!expr_ret_448) rew(mod_448);
  expr_ret_447 = expr_ret_448 ? SUCC : NULL;
  return expr_ret_447 ? rule : NULL;
  #undef rule
}



#undef rec
#undef rew
#undef node
#undef kind
#undef list
#undef leaf
#undef add
#undef defer
#undef SUCC

#endif /* PGEN_DAISHO_ASTNODE_INCLUDE */

