
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
// Tokens 1 through 84 are the ones you defined.
// This totals 86 kinds of tokens.
#define DAISHO_NUM_TOKENKINDS 86
static const char* daisho_tokenkind_name[DAISHO_NUM_TOKENKINDS] = {
  "DAISHO_TOK_STREAMBEGIN",
  "DAISHO_TOK_STREAMEND",
  "DAISHO_TOK_PLUS",
  "DAISHO_TOK_MINUS",
  "DAISHO_TOK_STAR",
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

    // Trie
    if (trie_state != -1) {
      all_dead = 0;
      if (trie_state == 0) {
        if (c == 33 /*'!'*/) trie_state = 9;
        else if (c == 34 /*'"'*/) trie_state = 111;
        else if (c == 35 /*'#'*/) trie_state = 106;
        else if (c == 36 /*'$'*/) trie_state = 108;
        else if (c == 37 /*'%'*/) trie_state = 5;
        else if (c == 38 /*'&'*/) trie_state = 6;
        else if (c == 39 /*'''*/) trie_state = 110;
        else if (c == 40 /*'('*/) trie_state = 100;
        else if (c == 41 /*')'*/) trie_state = 101;
        else if (c == 42 /*'*'*/) trie_state = 3;
        else if (c == 43 /*'+'*/) trie_state = 1;
        else if (c == 44 /*','*/) trie_state = 99;
        else if (c == 45 /*'-'*/) trie_state = 2;
        else if (c == 46 /*'.'*/) trie_state = 98;
        else if (c == 47 /*'/'*/) trie_state = 4;
        else if (c == 58 /*':'*/) trie_state = 36;
        else if (c == 59 /*';'*/) trie_state = 97;
        else if (c == 60 /*'<'*/) trie_state = 16;
        else if (c == 61 /*'='*/) trie_state = 13;
        else if (c == 62 /*'>'*/) trie_state = 18;
        else if (c == 63 /*'?'*/) trie_state = 35;
        else if (c == 64 /*'@'*/) trie_state = 107;
        else if (c == 70 /*'F'*/) trie_state = 69;
        else if (c == 83 /*'S'*/) trie_state = 76;
        else if (c == 86 /*'V'*/) trie_state = 84;
        else if (c == 91 /*'['*/) trie_state = 104;
        else if (c == 93 /*']'*/) trie_state = 105;
        else if (c == 94 /*'^'*/) trie_state = 8;
        else if (c == 96 /*'`'*/) trie_state = 109;
        else if (c == 97 /*'a'*/) trie_state = 52;
        else if (c == 99 /*'c'*/) trie_state = 71;
        else if (c == 102 /*'f'*/) trie_state = 38;
        else if (c == 105 /*'i'*/) trie_state = 41;
        else if (c == 110 /*'n'*/) trie_state = 88;
        else if (c == 115 /*'s'*/) trie_state = 80;
        else if (c == 116 /*'t'*/) trie_state = 48;
        else if (c == 117 /*'u'*/) trie_state = 59;
        else if (c == 119 /*'w'*/) trie_state = 43;
        else if (c == 123 /*'{'*/) trie_state = 102;
        else if (c == 124 /*'|'*/) trie_state = 7;
        else if (c == 125 /*'}'*/) trie_state = 103;
        else if (c == 126 /*'~'*/) trie_state = 10;
        else trie_state = -1;
      }
      else if (trie_state == 1) {
        if (c == 43 /*'+'*/) trie_state = 33;
        else if (c == 61 /*'='*/) trie_state = 20;
        else trie_state = -1;
      }
      else if (trie_state == 2) {
        if (c == 45 /*'-'*/) trie_state = 34;
        else if (c == 61 /*'='*/) trie_state = 21;
        else if (c == 62 /*'>'*/) trie_state = 112;
        else trie_state = -1;
      }
      else if (trie_state == 3) {
        if (c == 61 /*'='*/) trie_state = 22;
        else trie_state = -1;
      }
      else if (trie_state == 4) {
        if (c == 61 /*'='*/) trie_state = 23;
        else trie_state = -1;
      }
      else if (trie_state == 5) {
        if (c == 61 /*'='*/) trie_state = 24;
        else trie_state = -1;
      }
      else if (trie_state == 6) {
        if (c == 38 /*'&'*/) trie_state = 11;
        else if (c == 61 /*'='*/) trie_state = 25;
        else trie_state = -1;
      }
      else if (trie_state == 7) {
        if (c == 61 /*'='*/) trie_state = 26;
        else if (c == 124 /*'|'*/) trie_state = 12;
        else trie_state = -1;
      }
      else if (trie_state == 8) {
        if (c == 61 /*'='*/) trie_state = 27;
        else trie_state = -1;
      }
      else if (trie_state == 9) {
        if (c == 61 /*'='*/) trie_state = 15;
        else trie_state = -1;
      }
      else if (trie_state == 10) {
        if (c == 61 /*'='*/) trie_state = 28;
        else trie_state = -1;
      }
      else if (trie_state == 13) {
        if (c == 61 /*'='*/) trie_state = 14;
        else if (c == 62 /*'>'*/) trie_state = 113;
        else trie_state = -1;
      }
      else if (trie_state == 16) {
        if (c == 60 /*'<'*/) trie_state = 31;
        else if (c == 61 /*'='*/) trie_state = 17;
        else trie_state = -1;
      }
      else if (trie_state == 18) {
        if (c == 61 /*'='*/) trie_state = 19;
        else if (c == 62 /*'>'*/) trie_state = 29;
        else trie_state = -1;
      }
      else if (trie_state == 29) {
        if (c == 61 /*'='*/) trie_state = 30;
        else trie_state = -1;
      }
      else if (trie_state == 31) {
        if (c == 61 /*'='*/) trie_state = 32;
        else trie_state = -1;
      }
      else if (trie_state == 35) {
        if (c == 58 /*':'*/) trie_state = 37;
        else trie_state = -1;
      }
      else if (trie_state == 38) {
        if (c == 110 /*'n'*/) trie_state = 68;
        else if (c == 111 /*'o'*/) trie_state = 39;
        else trie_state = -1;
      }
      else if (trie_state == 39) {
        if (c == 114 /*'r'*/) trie_state = 40;
        else trie_state = -1;
      }
      else if (trie_state == 41) {
        if (c == 110 /*'n'*/) trie_state = 42;
        else trie_state = -1;
      }
      else if (trie_state == 43) {
        if (c == 104 /*'h'*/) trie_state = 44;
        else trie_state = -1;
      }
      else if (trie_state == 44) {
        if (c == 101 /*'e'*/) trie_state = 56;
        else if (c == 105 /*'i'*/) trie_state = 45;
        else trie_state = -1;
      }
      else if (trie_state == 45) {
        if (c == 108 /*'l'*/) trie_state = 46;
        else trie_state = -1;
      }
      else if (trie_state == 46) {
        if (c == 101 /*'e'*/) trie_state = 47;
        else trie_state = -1;
      }
      else if (trie_state == 48) {
        if (c == 104 /*'h'*/) trie_state = 49;
        else if (c == 114 /*'r'*/) trie_state = 64;
        else trie_state = -1;
      }
      else if (trie_state == 49) {
        if (c == 101 /*'e'*/) trie_state = 50;
        else trie_state = -1;
      }
      else if (trie_state == 50) {
        if (c == 110 /*'n'*/) trie_state = 51;
        else trie_state = -1;
      }
      else if (trie_state == 52) {
        if (c == 108 /*'l'*/) trie_state = 53;
        else trie_state = -1;
      }
      else if (trie_state == 53) {
        if (c == 115 /*'s'*/) trie_state = 54;
        else trie_state = -1;
      }
      else if (trie_state == 54) {
        if (c == 111 /*'o'*/) trie_state = 55;
        else trie_state = -1;
      }
      else if (trie_state == 56) {
        if (c == 114 /*'r'*/) trie_state = 57;
        else trie_state = -1;
      }
      else if (trie_state == 57) {
        if (c == 101 /*'e'*/) trie_state = 58;
        else trie_state = -1;
      }
      else if (trie_state == 59) {
        if (c == 110 /*'n'*/) trie_state = 60;
        else trie_state = -1;
      }
      else if (trie_state == 60) {
        if (c == 105 /*'i'*/) trie_state = 61;
        else trie_state = -1;
      }
      else if (trie_state == 61) {
        if (c == 111 /*'o'*/) trie_state = 62;
        else trie_state = -1;
      }
      else if (trie_state == 62) {
        if (c == 110 /*'n'*/) trie_state = 63;
        else trie_state = -1;
      }
      else if (trie_state == 64) {
        if (c == 97 /*'a'*/) trie_state = 65;
        else trie_state = -1;
      }
      else if (trie_state == 65) {
        if (c == 105 /*'i'*/) trie_state = 66;
        else trie_state = -1;
      }
      else if (trie_state == 66) {
        if (c == 116 /*'t'*/) trie_state = 67;
        else trie_state = -1;
      }
      else if (trie_state == 69) {
        if (c == 110 /*'n'*/) trie_state = 70;
        else trie_state = -1;
      }
      else if (trie_state == 71) {
        if (c == 116 /*'t'*/) trie_state = 72;
        else trie_state = -1;
      }
      else if (trie_state == 72) {
        if (c == 121 /*'y'*/) trie_state = 73;
        else trie_state = -1;
      }
      else if (trie_state == 73) {
        if (c == 112 /*'p'*/) trie_state = 74;
        else trie_state = -1;
      }
      else if (trie_state == 74) {
        if (c == 101 /*'e'*/) trie_state = 75;
        else trie_state = -1;
      }
      else if (trie_state == 76) {
        if (c == 101 /*'e'*/) trie_state = 77;
        else trie_state = -1;
      }
      else if (trie_state == 77) {
        if (c == 108 /*'l'*/) trie_state = 78;
        else trie_state = -1;
      }
      else if (trie_state == 78) {
        if (c == 102 /*'f'*/) trie_state = 79;
        else trie_state = -1;
      }
      else if (trie_state == 80) {
        if (c == 101 /*'e'*/) trie_state = 81;
        else trie_state = -1;
      }
      else if (trie_state == 81) {
        if (c == 108 /*'l'*/) trie_state = 82;
        else trie_state = -1;
      }
      else if (trie_state == 82) {
        if (c == 102 /*'f'*/) trie_state = 83;
        else trie_state = -1;
      }
      else if (trie_state == 84) {
        if (c == 111 /*'o'*/) trie_state = 85;
        else trie_state = -1;
      }
      else if (trie_state == 85) {
        if (c == 105 /*'i'*/) trie_state = 86;
        else trie_state = -1;
      }
      else if (trie_state == 86) {
        if (c == 100 /*'d'*/) trie_state = 87;
        else trie_state = -1;
      }
      else if (trie_state == 88) {
        if (c == 97 /*'a'*/) trie_state = 89;
        else trie_state = -1;
      }
      else if (trie_state == 89) {
        if (c == 109 /*'m'*/) trie_state = 90;
        else trie_state = -1;
      }
      else if (trie_state == 90) {
        if (c == 101 /*'e'*/) trie_state = 91;
        else trie_state = -1;
      }
      else if (trie_state == 91) {
        if (c == 115 /*'s'*/) trie_state = 92;
        else trie_state = -1;
      }
      else if (trie_state == 92) {
        if (c == 112 /*'p'*/) trie_state = 93;
        else trie_state = -1;
      }
      else if (trie_state == 93) {
        if (c == 97 /*'a'*/) trie_state = 94;
        else trie_state = -1;
      }
      else if (trie_state == 94) {
        if (c == 99 /*'c'*/) trie_state = 95;
        else trie_state = -1;
      }
      else if (trie_state == 95) {
        if (c == 101 /*'e'*/) trie_state = 96;
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
        trie_tokenkind =  DAISHO_TOK_MOD;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 6) {
        trie_tokenkind =  DAISHO_TOK_AND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 7) {
        trie_tokenkind =  DAISHO_TOK_OR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 8) {
        trie_tokenkind =  DAISHO_TOK_XOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 9) {
        trie_tokenkind =  DAISHO_TOK_NOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 10) {
        trie_tokenkind =  DAISHO_TOK_BITNOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 11) {
        trie_tokenkind =  DAISHO_TOK_LOGAND;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 12) {
        trie_tokenkind =  DAISHO_TOK_LOGOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 14) {
        trie_tokenkind =  DAISHO_TOK_DEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 15) {
        trie_tokenkind =  DAISHO_TOK_NEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 16) {
        trie_tokenkind =  DAISHO_TOK_LT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 17) {
        trie_tokenkind =  DAISHO_TOK_LEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 18) {
        trie_tokenkind =  DAISHO_TOK_GT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 19) {
        trie_tokenkind =  DAISHO_TOK_GEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 13) {
        trie_tokenkind =  DAISHO_TOK_EQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 20) {
        trie_tokenkind =  DAISHO_TOK_PLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 21) {
        trie_tokenkind =  DAISHO_TOK_MINEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 22) {
        trie_tokenkind =  DAISHO_TOK_MULEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 23) {
        trie_tokenkind =  DAISHO_TOK_DIVEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 24) {
        trie_tokenkind =  DAISHO_TOK_MODEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 25) {
        trie_tokenkind =  DAISHO_TOK_ANDEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 26) {
        trie_tokenkind =  DAISHO_TOK_OREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 27) {
        trie_tokenkind =  DAISHO_TOK_XOREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 28) {
        trie_tokenkind =  DAISHO_TOK_BNEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 30) {
        trie_tokenkind =  DAISHO_TOK_BSREQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 32) {
        trie_tokenkind =  DAISHO_TOK_BSLEQ;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 33) {
        trie_tokenkind =  DAISHO_TOK_INCR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 34) {
        trie_tokenkind =  DAISHO_TOK_DECR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 35) {
        trie_tokenkind =  DAISHO_TOK_QUEST;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 36) {
        trie_tokenkind =  DAISHO_TOK_COLON;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 37) {
        trie_tokenkind =  DAISHO_TOK_NCOLL;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 40) {
        trie_tokenkind =  DAISHO_TOK_FOR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 42) {
        trie_tokenkind =  DAISHO_TOK_IN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 47) {
        trie_tokenkind =  DAISHO_TOK_WHILE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 51) {
        trie_tokenkind =  DAISHO_TOK_THEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 55) {
        trie_tokenkind =  DAISHO_TOK_ALSO;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 58) {
        trie_tokenkind =  DAISHO_TOK_WHERE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 63) {
        trie_tokenkind =  DAISHO_TOK_UNION;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 67) {
        trie_tokenkind =  DAISHO_TOK_TRAIT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 68) {
        trie_tokenkind =  DAISHO_TOK_FN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 70) {
        trie_tokenkind =  DAISHO_TOK_FNTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 75) {
        trie_tokenkind =  DAISHO_TOK_CTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 79) {
        trie_tokenkind =  DAISHO_TOK_SELFTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 83) {
        trie_tokenkind =  DAISHO_TOK_SELFVAR;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 87) {
        trie_tokenkind =  DAISHO_TOK_VOIDTYPE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 96) {
        trie_tokenkind =  DAISHO_TOK_NAMESPACE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 97) {
        trie_tokenkind =  DAISHO_TOK_SEMI;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 98) {
        trie_tokenkind =  DAISHO_TOK_DOT;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 99) {
        trie_tokenkind =  DAISHO_TOK_COMMA;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 100) {
        trie_tokenkind =  DAISHO_TOK_OPEN;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 101) {
        trie_tokenkind =  DAISHO_TOK_CLOSE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 102) {
        trie_tokenkind =  DAISHO_TOK_LCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 103) {
        trie_tokenkind =  DAISHO_TOK_RCBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 104) {
        trie_tokenkind =  DAISHO_TOK_LSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 105) {
        trie_tokenkind =  DAISHO_TOK_RSBRACK;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 106) {
        trie_tokenkind =  DAISHO_TOK_HASH;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 107) {
        trie_tokenkind =  DAISHO_TOK_REF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 108) {
        trie_tokenkind =  DAISHO_TOK_DEREF;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 109) {
        trie_tokenkind =  DAISHO_TOK_GRAVE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 110) {
        trie_tokenkind =  DAISHO_TOK_SQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 111) {
        trie_tokenkind =  DAISHO_TOK_DQUOTE;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 112) {
        trie_tokenkind =  DAISHO_TOK_ARROW;
        trie_munch_size = iidx + 1;
      }
      else if (trie_state == 113) {
        trie_tokenkind =  DAISHO_TOK_DARROW;
        trie_munch_size = iidx + 1;
      }
    }

    // Transition TEMPLATE State Machine
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

      // Check accept
      if ((smaut_state_0 == 4) | (smaut_state_0 == 11)) {
        smaut_munch_size_0 = iidx + 1;
      }
    }

    // Transition STRUCT State Machine
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

      // Check accept
      if ((smaut_state_1 == 5) | (smaut_state_1 == 11) | (smaut_state_1 == 16)) {
        smaut_munch_size_1 = iidx + 1;
      }
    }

    // Transition IMPL State Machine
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

      // Check accept
      if ((smaut_state_2 == 4) | (smaut_state_2 == 10)) {
        smaut_munch_size_2 = iidx + 1;
      }
    }

    // Transition CFUNC State Machine
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

      // Check accept
      if ((smaut_state_3 == 4) | (smaut_state_3 == 5) | (smaut_state_3 == 6)) {
        smaut_munch_size_3 = iidx + 1;
      }
    }

    // Transition RET State Machine
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

      // Check accept
      if ((smaut_state_4 == 3) | (smaut_state_4 == 6)) {
        smaut_munch_size_4 = iidx + 1;
      }
    }

    // Transition OP State Machine
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

      // Check accept
      if ((smaut_state_5 == 2) | (smaut_state_5 == 8)) {
        smaut_munch_size_5 = iidx + 1;
      }
    }

    // Transition REDEF State Machine
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

      // Check accept
      if ((smaut_state_6 == 5) | (smaut_state_6 == 8)) {
        smaut_munch_size_6 = iidx + 1;
      }
    }

    // Transition STRUCTIDENT State Machine
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

      // Check accept
      if ((smaut_state_7 == 1) | (smaut_state_7 == 2)) {
        smaut_munch_size_7 = iidx + 1;
      }
    }

    // Transition TRAITIDENT State Machine
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

      // Check accept
      if (smaut_state_8 == 3) {
        smaut_munch_size_8 = iidx + 1;
      }
    }

    // Transition VARIDENT State Machine
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

      // Check accept
      if ((smaut_state_9 == 1) | (smaut_state_9 == 2)) {
        smaut_munch_size_9 = iidx + 1;
      }
    }

    // Transition CIDENT State Machine
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

      // Check accept
      if ((smaut_state_10 == 1) | (smaut_state_10 == 2)) {
        smaut_munch_size_10 = iidx + 1;
      }
    }

    // Transition NUMLIT State Machine
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

      // Check accept
      if ((smaut_state_11 == 2) | (smaut_state_11 == 3)) {
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
  DAISHO_NODE_ARGTYPES,
  DAISHO_NODE_PROG,
  DAISHO_NODE_SHEBANG,
  DAISHO_NODE_NAMESPACE,
  DAISHO_NODE_TEMPLATE,
  DAISHO_NODE_QUEST,
  DAISHO_NODE_COLON,
  DAISHO_NODE_FOR,
  DAISHO_NODE_WHILE,
  DAISHO_NODE_CAST,
  DAISHO_NODE_REF,
  DAISHO_NODE_DEREF,
  DAISHO_NODE_BLK,
  DAISHO_NODE_LAMBDA,
  DAISHO_NODE_ASSIGN,
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
  DAISHO_NODE_EQCHECK,
  DAISHO_NODE_DEQ,
  DAISHO_NODE_NEQ,
  DAISHO_NODE_CMP,
  DAISHO_NODE_LT,
  DAISHO_NODE_GT,
  DAISHO_NODE_LEQ,
  DAISHO_NODE_GEQ,
  DAISHO_NODE_SHIFT,
  DAISHO_NODE_BSL,
  DAISHO_NODE_BSR,
  DAISHO_NODE_FACTOR,
  DAISHO_NODE_STAR,
  DAISHO_NODE_DIV,
  DAISHO_NODE_MOD,
  DAISHO_NODE_SUM,
  DAISHO_NODE_PLUS,
  DAISHO_NODE_MINUS,
  DAISHO_NODE_RET,
  DAISHO_NODE_GRAVE,
  DAISHO_NODE_VOIDTYPE,
  DAISHO_NODE_FNTYPE,
  DAISHO_NODE_OPEN,
  DAISHO_NODE_CLOSE,
  DAISHO_NODE_VIDENT,
  DAISHO_NODE_NUMLIT,
  DAISHO_NODE_STRLIT,
  DAISHO_NODE_TYPEMEMBER,
  DAISHO_NODE_STRUCTIDENT,
  DAISHO_NODE_VARIDENT,
} daisho_astnode_kind;

#define DAISHO_NUM_NODEKINDS 64
static const char* daisho_nodekind_name[DAISHO_NUM_NODEKINDS] = {
  "DAISHO_NODE_EMPTY",
  "DAISHO_NODE_TYPE",
  "DAISHO_NODE_ARGTYPES",
  "DAISHO_NODE_PROG",
  "DAISHO_NODE_SHEBANG",
  "DAISHO_NODE_NAMESPACE",
  "DAISHO_NODE_TEMPLATE",
  "DAISHO_NODE_QUEST",
  "DAISHO_NODE_COLON",
  "DAISHO_NODE_FOR",
  "DAISHO_NODE_WHILE",
  "DAISHO_NODE_CAST",
  "DAISHO_NODE_REF",
  "DAISHO_NODE_DEREF",
  "DAISHO_NODE_BLK",
  "DAISHO_NODE_LAMBDA",
  "DAISHO_NODE_ASSIGN",
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
  "DAISHO_NODE_EQCHECK",
  "DAISHO_NODE_DEQ",
  "DAISHO_NODE_NEQ",
  "DAISHO_NODE_CMP",
  "DAISHO_NODE_LT",
  "DAISHO_NODE_GT",
  "DAISHO_NODE_LEQ",
  "DAISHO_NODE_GEQ",
  "DAISHO_NODE_SHIFT",
  "DAISHO_NODE_BSL",
  "DAISHO_NODE_BSR",
  "DAISHO_NODE_FACTOR",
  "DAISHO_NODE_STAR",
  "DAISHO_NODE_DIV",
  "DAISHO_NODE_MOD",
  "DAISHO_NODE_SUM",
  "DAISHO_NODE_PLUS",
  "DAISHO_NODE_MINUS",
  "DAISHO_NODE_RET",
  "DAISHO_NODE_GRAVE",
  "DAISHO_NODE_VOIDTYPE",
  "DAISHO_NODE_FNTYPE",
  "DAISHO_NODE_OPEN",
  "DAISHO_NODE_CLOSE",
  "DAISHO_NODE_VIDENT",
  "DAISHO_NODE_NUMLIT",
  "DAISHO_NODE_STRLIT",
  "DAISHO_NODE_TYPEMEMBER",
  "DAISHO_NODE_STRUCTIDENT",
  "DAISHO_NODE_VARIDENT",
};

struct daisho_astnode_t;
typedef struct daisho_astnode_t daisho_astnode_t;
struct daisho_astnode_t {
  // No %extra directives.

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
  if (!ret) PGEN_OOM();
  daisho_astnode_t *node = (daisho_astnode_t*)ret;

  daisho_astnode_t **children;
  if (initial_size) {
    children = (daisho_astnode_t**)malloc(sizeof(daisho_astnode_t*) * initial_size);
    if (!children)
      PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
  if (!ret) PGEN_OOM();
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
    if (!new_ptr)
      PGEN_OOM();
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
static inline daisho_astnode_t* daisho_parse_decl(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx);
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
static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx);
static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx);
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
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_3 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SHEBANG) {
      // Capturing SHEBANG.
      expr_ret_3 = leaf(SHEBANG);
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
  return expr_ret_1 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_topdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_7 = NULL;
  daisho_astnode_t* expr_ret_6 = NULL;
  #define rule expr_ret_6

  daisho_astnode_t* expr_ret_8 = NULL;

  rec(slash_8);

  // SlashExpr 0
  if (!expr_ret_8)
  {
    daisho_astnode_t* expr_ret_9 = NULL;
    rec(mod_9);
    // ModExprList Forwarding
    expr_ret_9 = daisho_parse_nsdecl(ctx);
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
    expr_ret_10 = daisho_parse_decl(ctx);
    // ModExprList end
    if (!expr_ret_10) rew(mod_10);
    expr_ret_8 = expr_ret_10;
  }

  // SlashExpr end
  if (!expr_ret_8) rew(slash_8);
  expr_ret_7 = expr_ret_8;

  return expr_ret_7 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_decl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_12 = NULL;
  daisho_astnode_t* expr_ret_11 = NULL;
  #define rule expr_ret_11

  daisho_astnode_t* expr_ret_13 = NULL;

  rec(slash_13);

  // SlashExpr 0
  if (!expr_ret_13)
  {
    daisho_astnode_t* expr_ret_14 = NULL;
    rec(mod_14);
    // ModExprList Forwarding
    expr_ret_14 = daisho_parse_structdecl(ctx);
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
    expr_ret_15 = daisho_parse_uniondecl(ctx);
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
    expr_ret_16 = daisho_parse_traitdecl(ctx);
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
    expr_ret_17 = daisho_parse_impldecl(ctx);
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
    expr_ret_18 = daisho_parse_nsdecl(ctx);
    // ModExprList end
    if (!expr_ret_18) rew(mod_18);
    expr_ret_13 = expr_ret_18;
  }

  // SlashExpr end
  if (!expr_ret_13) rew(slash_13);
  expr_ret_12 = expr_ret_13;

  return expr_ret_12 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* expr_ret_20 = NULL;
  daisho_astnode_t* expr_ret_19 = NULL;
  #define rule expr_ret_19

  daisho_astnode_t* expr_ret_21 = NULL;
  rec(mod_21);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCT) {
      // Not capturing STRUCT.
      expr_ret_21 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_22 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Capturing STRUCTIDENT.
      expr_ret_22 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_22 = NULL;
    }

    expr_ret_21 = expr_ret_22;
    id = expr_ret_22;
  }

  // ModExprList 2
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_23 = NULL;
    expr_ret_23 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_23)
      expr_ret_23 = SUCC;
    expr_ret_21 = expr_ret_23;
  }

  // ModExprList 3
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_24 = NULL;
    daisho_astnode_t* expr_ret_25 = NULL;
    rec(mod_25);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_25 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_25 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_25)
    {
      expr_ret_25 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_25)
    {
      daisho_astnode_t* expr_ret_26 = NULL;
      expr_ret_26 = SUCC;
      while (expr_ret_26)
      {
        daisho_astnode_t* expr_ret_27 = NULL;
        rec(mod_27);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_27 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_27 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_27)
        {
          expr_ret_27 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_27) rew(mod_27);
        expr_ret_26 = expr_ret_27 ? SUCC : NULL;
      }

      expr_ret_26 = SUCC;
      expr_ret_25 = expr_ret_26;
    }

    // ModExprList end
    if (!expr_ret_25) rew(mod_25);
    expr_ret_24 = expr_ret_25 ? SUCC : NULL;
    // optional
    if (!expr_ret_24)
      expr_ret_24 = SUCC;
    expr_ret_21 = expr_ret_24;
    impl = expr_ret_24;
  }

  // ModExprList 4
  if (expr_ret_21)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_21 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_21)
  {
    daisho_astnode_t* expr_ret_28 = NULL;
    expr_ret_28 = SUCC;
    while (expr_ret_28)
    {
      daisho_astnode_t* expr_ret_29 = NULL;
      rec(mod_29);
      // ModExprList Forwarding
      expr_ret_29 = daisho_parse_typemember(ctx);
      // ModExprList end
      if (!expr_ret_29) rew(mod_29);
      expr_ret_28 = expr_ret_29;
    }

    expr_ret_28 = SUCC;
    expr_ret_21 = expr_ret_28;
  }

  // ModExprList 6
  if (expr_ret_21)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_21 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_21 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_21) rew(mod_21);
  expr_ret_20 = expr_ret_21 ? SUCC : NULL;
  return expr_ret_20 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_uniondecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* expr_ret_31 = NULL;
  daisho_astnode_t* expr_ret_30 = NULL;
  #define rule expr_ret_30

  daisho_astnode_t* expr_ret_32 = NULL;
  rec(mod_32);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_UNION) {
      // Not capturing UNION.
      expr_ret_32 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_33 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Capturing STRUCTIDENT.
      expr_ret_33 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_33 = NULL;
    }

    expr_ret_32 = expr_ret_33;
    id = expr_ret_33;
  }

  // ModExprList 2
  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_34 = NULL;
    expr_ret_34 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_34)
      expr_ret_34 = SUCC;
    expr_ret_32 = expr_ret_34;
  }

  // ModExprList 3
  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_35 = NULL;
    daisho_astnode_t* expr_ret_36 = NULL;
    rec(mod_36);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_36 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_36 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_36)
    {
      expr_ret_36 = daisho_parse_type(ctx);
    }

    // ModExprList 2
    if (expr_ret_36)
    {
      daisho_astnode_t* expr_ret_37 = NULL;
      expr_ret_37 = SUCC;
      while (expr_ret_37)
      {
        daisho_astnode_t* expr_ret_38 = NULL;
        rec(mod_38);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_38 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_38 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_38)
        {
          expr_ret_38 = daisho_parse_type(ctx);
        }

        // ModExprList end
        if (!expr_ret_38) rew(mod_38);
        expr_ret_37 = expr_ret_38 ? SUCC : NULL;
      }

      expr_ret_37 = SUCC;
      expr_ret_36 = expr_ret_37;
    }

    // ModExprList end
    if (!expr_ret_36) rew(mod_36);
    expr_ret_35 = expr_ret_36 ? SUCC : NULL;
    // optional
    if (!expr_ret_35)
      expr_ret_35 = SUCC;
    expr_ret_32 = expr_ret_35;
    impl = expr_ret_35;
  }

  // ModExprList 4
  if (expr_ret_32)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_32 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_32)
  {
    daisho_astnode_t* expr_ret_39 = NULL;
    expr_ret_39 = SUCC;
    while (expr_ret_39)
    {
      daisho_astnode_t* expr_ret_40 = NULL;
      rec(mod_40);
      // ModExprList Forwarding
      expr_ret_40 = daisho_parse_typemember(ctx);
      // ModExprList end
      if (!expr_ret_40) rew(mod_40);
      expr_ret_39 = expr_ret_40;
    }

    expr_ret_39 = SUCC;
    expr_ret_32 = expr_ret_39;
  }

  // ModExprList 6
  if (expr_ret_32)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_32 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_32 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_32) rew(mod_32);
  expr_ret_31 = expr_ret_32 ? SUCC : NULL;
  return expr_ret_31 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traitdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* id = NULL;
  daisho_astnode_t* impl = NULL;
  daisho_astnode_t* expr_ret_42 = NULL;
  daisho_astnode_t* expr_ret_41 = NULL;
  #define rule expr_ret_41

  daisho_astnode_t* expr_ret_43 = NULL;
  rec(mod_43);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAIT) {
      // Not capturing TRAIT.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_44 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Capturing STRUCTIDENT.
      expr_ret_44 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_44 = NULL;
    }

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
  }

  // ModExprList 3
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_46 = NULL;
    daisho_astnode_t* expr_ret_47 = NULL;
    rec(mod_47);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
        // Not capturing IMPL.
        expr_ret_47 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_47 = NULL;
      }

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
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
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
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

  }

  // ModExprList 5
  if (expr_ret_43)
  {
    daisho_astnode_t* expr_ret_50 = NULL;
    expr_ret_50 = SUCC;
    while (expr_ret_50)
    {
      daisho_astnode_t* expr_ret_51 = NULL;
      rec(mod_51);
      // ModExprList Forwarding
      expr_ret_51 = daisho_parse_fnmember(ctx);
      // ModExprList end
      if (!expr_ret_51) rew(mod_51);
      expr_ret_50 = expr_ret_51;
    }

    expr_ret_50 = SUCC;
    expr_ret_43 = expr_ret_50;
  }

  // ModExprList 6
  if (expr_ret_43)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_43 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_43 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_43) rew(mod_43);
  expr_ret_42 = expr_ret_43 ? SUCC : NULL;
  return expr_ret_42 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fndecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_53 = NULL;
  daisho_astnode_t* expr_ret_52 = NULL;
  #define rule expr_ret_52

  daisho_astnode_t* expr_ret_54 = NULL;
  rec(mod_54);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
      // Not capturing FN.
      expr_ret_54 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_54 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_54)
  {
    expr_ret_54 = daisho_parse_fnproto(ctx);
  }

  // ModExprList 2
  if (expr_ret_54)
  {
    daisho_astnode_t* expr_ret_55 = NULL;
    expr_ret_55 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_55)
      expr_ret_55 = SUCC;
    expr_ret_54 = expr_ret_55;
  }

  // ModExprList 3
  if (expr_ret_54)
  {
    expr_ret_54 = daisho_parse_fnbody(ctx);
  }

  // ModExprList end
  if (!expr_ret_54) rew(mod_54);
  expr_ret_53 = expr_ret_54 ? SUCC : NULL;
  return expr_ret_53 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_impldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* tt = NULL;
  daisho_astnode_t* ft = NULL;
  daisho_astnode_t* expr_ret_57 = NULL;
  daisho_astnode_t* expr_ret_56 = NULL;
  #define rule expr_ret_56

  daisho_astnode_t* expr_ret_58 = NULL;
  rec(mod_58);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IMPL) {
      // Not capturing IMPL.
      expr_ret_58 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_58)
  {
    daisho_astnode_t* expr_ret_59 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Capturing STRUCTIDENT.
      expr_ret_59 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_59 = NULL;
    }

    expr_ret_58 = expr_ret_59;
    tt = expr_ret_59;
  }

  // ModExprList 2
  if (expr_ret_58)
  {
    daisho_astnode_t* expr_ret_60 = NULL;
    expr_ret_60 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_60)
      expr_ret_60 = SUCC;
    expr_ret_58 = expr_ret_60;
  }

  // ModExprList 3
  if (expr_ret_58)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_58 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_58)
  {
    daisho_astnode_t* expr_ret_61 = NULL;
    expr_ret_61 = daisho_parse_type(ctx);
    expr_ret_58 = expr_ret_61;
    ft = expr_ret_61;
  }

  // ModExprList 5
  if (expr_ret_58)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_58 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_58)
  {
    daisho_astnode_t* expr_ret_62 = NULL;
    expr_ret_62 = SUCC;
    while (expr_ret_62)
    {
      daisho_astnode_t* expr_ret_63 = NULL;
      rec(mod_63);
      // ModExprList Forwarding
      expr_ret_63 = daisho_parse_fnmember(ctx);
      // ModExprList end
      if (!expr_ret_63) rew(mod_63);
      expr_ret_62 = expr_ret_63;
    }

    expr_ret_62 = SUCC;
    expr_ret_58 = expr_ret_62;
  }

  // ModExprList 7
  if (expr_ret_58)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_58 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_58 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_58) rew(mod_58);
  expr_ret_57 = expr_ret_58 ? SUCC : NULL;
  return expr_ret_57 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_nsdecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_65 = NULL;
  daisho_astnode_t* expr_ret_64 = NULL;
  #define rule expr_ret_64

  daisho_astnode_t* expr_ret_66 = NULL;
  rec(mod_66);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NAMESPACE) {
      // Not capturing NAMESPACE.
      expr_ret_66 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_66 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_66)
  {
    daisho_astnode_t* expr_ret_67 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Capturing STRUCTIDENT.
      expr_ret_67 = leaf(STRUCTIDENT);
      ctx->pos++;
    } else {
      expr_ret_67 = NULL;
    }

    expr_ret_66 = expr_ret_67;
    t = expr_ret_67;
  }

  // ModExprList 2
  if (expr_ret_66)
  {
    // CodeExpr
    #define ret expr_ret_66
    ret = SUCC;

    rule=node(NAMESPACE, t);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_66) rew(mod_66);
  expr_ret_65 = expr_ret_66 ? SUCC : NULL;
  return expr_ret_65 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_typemember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* expr_ret_69 = NULL;
  daisho_astnode_t* expr_ret_68 = NULL;
  #define rule expr_ret_68

  daisho_astnode_t* expr_ret_70 = NULL;
  rec(mod_70);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_71 = NULL;
    expr_ret_71 = daisho_parse_type(ctx);
    expr_ret_70 = expr_ret_71;
    t = expr_ret_71;
  }

  // ModExprList 1
  if (expr_ret_70)
  {
    daisho_astnode_t* expr_ret_72 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_72 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_72 = NULL;
    }

    expr_ret_70 = expr_ret_72;
    v = expr_ret_72;
  }

  // ModExprList 2
  if (expr_ret_70)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_70 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_70 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_70)
  {
    // CodeExpr
    #define ret expr_ret_70
    ret = SUCC;

    rule=node(TYPEMEMBER, t, v);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_70) rew(mod_70);
  expr_ret_69 = expr_ret_70 ? SUCC : NULL;
  return expr_ret_69 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnmember(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* expr_ret_74 = NULL;
  daisho_astnode_t* expr_ret_73 = NULL;
  #define rule expr_ret_73

  daisho_astnode_t* expr_ret_75 = NULL;
  rec(mod_75);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_76 = NULL;
    daisho_astnode_t* expr_ret_77 = NULL;

    rec(slash_77);

    // SlashExpr 0
    if (!expr_ret_77)
    {
      daisho_astnode_t* expr_ret_78 = NULL;
      rec(mod_78);
      // ModExprList Forwarding
      expr_ret_78 = daisho_parse_fndecl(ctx);
      // ModExprList end
      if (!expr_ret_78) rew(mod_78);
      expr_ret_77 = expr_ret_78;
    }

    // SlashExpr 1
    if (!expr_ret_77)
    {
      daisho_astnode_t* expr_ret_79 = NULL;
      rec(mod_79);
      // ModExprList Forwarding
      expr_ret_79 = daisho_parse_fnproto(ctx);
      // ModExprList end
      if (!expr_ret_79) rew(mod_79);
      expr_ret_77 = expr_ret_79;
    }

    // SlashExpr end
    if (!expr_ret_77) rew(slash_77);
    expr_ret_76 = expr_ret_77;

    expr_ret_75 = expr_ret_76;
    r = expr_ret_76;
  }

  // ModExprList 1
  if (expr_ret_75)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
      // Not capturing SEMI.
      expr_ret_75 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_75 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_75)
  {
    // CodeExpr
    #define ret expr_ret_75
    ret = SUCC;

    rule=r;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_75) rew(mod_75);
  expr_ret_74 = expr_ret_75 ? SUCC : NULL;
  return expr_ret_74 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_type(daisho_parser_ctx* ctx) {
  daisho_astnode_t* v = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* s = NULL;
  daisho_astnode_t* f = NULL;
  daisho_astnode_t* expr_ret_81 = NULL;
  daisho_astnode_t* expr_ret_80 = NULL;
  #define rule expr_ret_80

  daisho_astnode_t* expr_ret_82 = NULL;

  rec(slash_82);

  // SlashExpr 0
  if (!expr_ret_82)
  {
    daisho_astnode_t* expr_ret_83 = NULL;
    rec(mod_83);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_84 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_84 = leaf(VOIDTYPE);
        ctx->pos++;
      } else {
        expr_ret_84 = NULL;
      }

      expr_ret_83 = expr_ret_84;
      v = expr_ret_84;
    }

    // ModExprList 1
    if (expr_ret_83)
    {
      daisho_astnode_t* expr_ret_85 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_85 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_85 = NULL;
      }

      // invert
      expr_ret_85 = expr_ret_85 ? NULL : SUCC;
      expr_ret_83 = expr_ret_85;
    }

    // ModExprList 2
    if (expr_ret_83)
    {
      // CodeExpr
      #define ret expr_ret_83
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_83) rew(mod_83);
    expr_ret_82 = expr_ret_83 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_82)
  {
    daisho_astnode_t* expr_ret_86 = NULL;
    rec(mod_86);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_87 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VOIDTYPE) {
        // Capturing VOIDTYPE.
        expr_ret_87 = leaf(VOIDTYPE);
        ctx->pos++;
      } else {
        expr_ret_87 = NULL;
      }

      expr_ret_86 = expr_ret_87;
      v = expr_ret_87;
    }

    // ModExprList 1
    if (expr_ret_86)
    {
      daisho_astnode_t* expr_ret_88 = NULL;
      expr_ret_88 = SUCC;
      while (expr_ret_88)
      {
        daisho_astnode_t* expr_ret_89 = NULL;
        rec(mod_89);
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_89 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_89 = NULL;
        }

        // ModExprList end
        if (!expr_ret_89) rew(mod_89);
        expr_ret_88 = expr_ret_89;
      }

      expr_ret_88 = SUCC;
      expr_ret_86 = expr_ret_88;
    }

    // ModExprList 2
    if (expr_ret_86)
    {
      // CodeExpr
      #define ret expr_ret_86
      ret = SUCC;

      rule=node(TYPE, v);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_86) rew(mod_86);
    expr_ret_82 = expr_ret_86 ? SUCC : NULL;
  }

  // SlashExpr 2
  if (!expr_ret_82)
  {
    daisho_astnode_t* expr_ret_90 = NULL;
    rec(mod_90);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_91 = NULL;
      expr_ret_91 = daisho_parse_traittype(ctx);
      expr_ret_90 = expr_ret_91;
      t = expr_ret_91;
    }

    // ModExprList 1
    if (expr_ret_90)
    {
      daisho_astnode_t* expr_ret_92 = NULL;
      expr_ret_92 = SUCC;
      while (expr_ret_92)
      {
        daisho_astnode_t* expr_ret_93 = NULL;
        rec(mod_93);
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_93 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_93 = NULL;
        }

        // ModExprList end
        if (!expr_ret_93) rew(mod_93);
        expr_ret_92 = expr_ret_93;
      }

      expr_ret_92 = SUCC;
      expr_ret_90 = expr_ret_92;
    }

    // ModExprList end
    if (!expr_ret_90) rew(mod_90);
    expr_ret_82 = expr_ret_90 ? SUCC : NULL;
  }

  // SlashExpr 3
  if (!expr_ret_82)
  {
    daisho_astnode_t* expr_ret_94 = NULL;
    rec(mod_94);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_95 = NULL;
      expr_ret_95 = daisho_parse_structtype(ctx);
      expr_ret_94 = expr_ret_95;
      s = expr_ret_95;
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
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_97 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_97 = NULL;
        }

        // ModExprList end
        if (!expr_ret_97) rew(mod_97);
        expr_ret_96 = expr_ret_97;
      }

      expr_ret_96 = SUCC;
      expr_ret_94 = expr_ret_96;
    }

    // ModExprList end
    if (!expr_ret_94) rew(mod_94);
    expr_ret_82 = expr_ret_94 ? SUCC : NULL;
  }

  // SlashExpr 4
  if (!expr_ret_82)
  {
    daisho_astnode_t* expr_ret_98 = NULL;
    rec(mod_98);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_99 = NULL;
      expr_ret_99 = daisho_parse_fntype(ctx);
      expr_ret_98 = expr_ret_99;
      f = expr_ret_99;
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
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
          // Not capturing STAR.
          expr_ret_101 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_101 = NULL;
        }

        // ModExprList end
        if (!expr_ret_101) rew(mod_101);
        expr_ret_100 = expr_ret_101;
      }

      expr_ret_100 = SUCC;
      expr_ret_98 = expr_ret_100;
    }

    // ModExprList end
    if (!expr_ret_98) rew(mod_98);
    expr_ret_82 = expr_ret_98 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_82) rew(slash_82);
  expr_ret_81 = expr_ret_82;

  return expr_ret_81 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_traittype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_103 = NULL;
  daisho_astnode_t* expr_ret_102 = NULL;
  #define rule expr_ret_102

  daisho_astnode_t* expr_ret_104 = NULL;
  rec(mod_104);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TRAITIDENT) {
      // Not capturing TRAITIDENT.
      expr_ret_104 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_104 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_104)
  {
    daisho_astnode_t* expr_ret_105 = NULL;
    expr_ret_105 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_105)
      expr_ret_105 = SUCC;
    expr_ret_104 = expr_ret_105;
  }

  // ModExprList end
  if (!expr_ret_104) rew(mod_104);
  expr_ret_103 = expr_ret_104 ? SUCC : NULL;
  return expr_ret_103 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_structtype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_107 = NULL;
  daisho_astnode_t* expr_ret_106 = NULL;
  #define rule expr_ret_106

  daisho_astnode_t* expr_ret_108 = NULL;
  rec(mod_108);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRUCTIDENT) {
      // Not capturing STRUCTIDENT.
      expr_ret_108 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_108 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_108)
  {
    daisho_astnode_t* expr_ret_109 = NULL;
    expr_ret_109 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_109)
      expr_ret_109 = SUCC;
    expr_ret_108 = expr_ret_109;
  }

  // ModExprList end
  if (!expr_ret_108) rew(mod_108);
  expr_ret_107 = expr_ret_108 ? SUCC : NULL;
  return expr_ret_107 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fntype(daisho_parser_ctx* ctx) {
  daisho_astnode_t* fn = NULL;
  daisho_astnode_t* argtypes = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* rettype = NULL;
  daisho_astnode_t* tmp = NULL;
  daisho_astnode_t* expr_ret_111 = NULL;
  daisho_astnode_t* expr_ret_110 = NULL;
  #define rule expr_ret_110

  daisho_astnode_t* expr_ret_112 = NULL;

  rec(slash_112);

  // SlashExpr 0
  if (!expr_ret_112)
  {
    daisho_astnode_t* expr_ret_113 = NULL;
    rec(mod_113);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_114 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FNTYPE) {
        // Capturing FNTYPE.
        expr_ret_114 = leaf(FNTYPE);
        ctx->pos++;
      } else {
        expr_ret_114 = NULL;
      }

      expr_ret_113 = expr_ret_114;
      fn = expr_ret_114;
    }

    // ModExprList 1
    if (expr_ret_113)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
        // Not capturing LT.
        expr_ret_113 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_113 = NULL;
      }

    }

    // ModExprList 2
    if (expr_ret_113)
    {
      daisho_astnode_t* expr_ret_115 = NULL;
      // CodeExpr
      #define ret expr_ret_115
      ret = SUCC;

      ret=list(ARGTYPES);

      #undef ret
      expr_ret_113 = expr_ret_115;
      argtypes = expr_ret_115;
    }

    // ModExprList 3
    if (expr_ret_113)
    {
      daisho_astnode_t* expr_ret_116 = NULL;
      daisho_astnode_t* expr_ret_117 = NULL;
      rec(mod_117);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_118 = NULL;
        expr_ret_118 = daisho_parse_type(ctx);
        expr_ret_117 = expr_ret_118;
        t = expr_ret_118;
      }

      // ModExprList 1
      if (expr_ret_117)
      {
        // CodeExpr
        #define ret expr_ret_117
        ret = SUCC;

        add(argtypes, t);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_117) rew(mod_117);
      expr_ret_116 = expr_ret_117 ? SUCC : NULL;
      // optional
      if (!expr_ret_116)
        expr_ret_116 = SUCC;
      expr_ret_113 = expr_ret_116;
    }

    // ModExprList 4
    if (expr_ret_113)
    {
      daisho_astnode_t* expr_ret_119 = NULL;
      expr_ret_119 = SUCC;
      while (expr_ret_119)
      {
        daisho_astnode_t* expr_ret_120 = NULL;
        rec(mod_120);
        // ModExprList 0
        {
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
            // Not capturing COMMA.
            expr_ret_120 = SUCC;
            ctx->pos++;
          } else {
            expr_ret_120 = NULL;
          }

        }

        // ModExprList 1
        if (expr_ret_120)
        {
          daisho_astnode_t* expr_ret_121 = NULL;
          expr_ret_121 = daisho_parse_type(ctx);
          expr_ret_120 = expr_ret_121;
          t = expr_ret_121;
        }

        // ModExprList 2
        if (expr_ret_120)
        {
          // CodeExpr
          #define ret expr_ret_120
          ret = SUCC;

          add(argtypes, t);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_120) rew(mod_120);
        expr_ret_119 = expr_ret_120 ? SUCC : NULL;
      }

      expr_ret_119 = SUCC;
      expr_ret_113 = expr_ret_119;
    }

    // ModExprList 5
    if (expr_ret_113)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ARROW) {
        // Not capturing ARROW.
        expr_ret_113 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_113 = NULL;
      }

    }

    // ModExprList 6
    if (expr_ret_113)
    {
      daisho_astnode_t* expr_ret_122 = NULL;
      expr_ret_122 = daisho_parse_type(ctx);
      expr_ret_113 = expr_ret_122;
      rettype = expr_ret_122;
    }

    // ModExprList 7
    if (expr_ret_113)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
        // Not capturing GT.
        expr_ret_113 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_113 = NULL;
      }

    }

    // ModExprList 8
    if (expr_ret_113)
    {
      // CodeExpr
      #define ret expr_ret_113
      ret = SUCC;

      rule=node(FNTYPE, argtypes, rettype);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_113) rew(mod_113);
    expr_ret_112 = expr_ret_113 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_112)
  {
    daisho_astnode_t* expr_ret_123 = NULL;
    rec(mod_123);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FN) {
        // Not capturing FN.
        expr_ret_123 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_123 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_123)
    {
      daisho_astnode_t* expr_ret_124 = NULL;
      // CodeExpr
      #define ret expr_ret_124
      ret = SUCC;

      rule=node(FNTYPE, (tmp=list(ARGTYPES), add(tmp), tmp), leaf(VOIDTYPE));

      #undef ret
      expr_ret_123 = expr_ret_124;
      tmp = expr_ret_124;
    }

    // ModExprList end
    if (!expr_ret_123) rew(mod_123);
    expr_ret_112 = expr_ret_123 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_112) rew(slash_112);
  expr_ret_111 = expr_ret_112;

  return expr_ret_111 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmpldecl(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_126 = NULL;
  daisho_astnode_t* expr_ret_125 = NULL;
  #define rule expr_ret_125

  daisho_astnode_t* expr_ret_127 = NULL;
  rec(mod_127);
  // ModExprList Forwarding
  if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_TEMPLATE) {
    // Capturing TEMPLATE.
    expr_ret_127 = leaf(TEMPLATE);
    ctx->pos++;
  } else {
    expr_ret_127 = NULL;
  }

  // ModExprList end
  if (!expr_ret_127) rew(mod_127);
  expr_ret_126 = expr_ret_127;
  return expr_ret_126 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_tmplexpand(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_129 = NULL;
  daisho_astnode_t* expr_ret_128 = NULL;
  #define rule expr_ret_128

  daisho_astnode_t* expr_ret_130 = NULL;
  rec(mod_130);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
      // Not capturing LT.
      expr_ret_130 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_130 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_130)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
      // Not capturing GT.
      expr_ret_130 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_130 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_130) rew(mod_130);
  expr_ret_129 = expr_ret_130 ? SUCC : NULL;
  return expr_ret_129 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnproto(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_132 = NULL;
  daisho_astnode_t* expr_ret_131 = NULL;
  #define rule expr_ret_131

  daisho_astnode_t* expr_ret_133 = NULL;
  rec(mod_133);
  // ModExprList 0
  {
    expr_ret_133 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_133)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_133 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_133 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_133)
  {
    daisho_astnode_t* expr_ret_134 = NULL;
    expr_ret_134 = daisho_parse_fnarg(ctx);
    // optional
    if (!expr_ret_134)
      expr_ret_134 = SUCC;
    expr_ret_133 = expr_ret_134;
  }

  // ModExprList 3
  if (expr_ret_133)
  {
    daisho_astnode_t* expr_ret_135 = NULL;
    expr_ret_135 = SUCC;
    while (expr_ret_135)
    {
      daisho_astnode_t* expr_ret_136 = NULL;
      rec(mod_136);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_136 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_136 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_136)
      {
        expr_ret_136 = daisho_parse_fnarg(ctx);
      }

      // ModExprList end
      if (!expr_ret_136) rew(mod_136);
      expr_ret_135 = expr_ret_136 ? SUCC : NULL;
    }

    expr_ret_135 = SUCC;
    expr_ret_133 = expr_ret_135;
  }

  // ModExprList 4
  if (expr_ret_133)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_133 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_133 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_133) rew(mod_133);
  expr_ret_132 = expr_ret_133 ? SUCC : NULL;
  return expr_ret_132 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnarg(daisho_parser_ctx* ctx) {
  a;

  daisho_astnode_t* expr_ret_138 = NULL;
  daisho_astnode_t* expr_ret_137 = NULL;
  #define rule expr_ret_137

  daisho_astnode_t* expr_ret_139 = NULL;
  rec(mod_139);
  // ModExprList 0
  {
    expr_ret_139 = daisho_parse_type(ctx);
  }

  // ModExprList 1
  if (expr_ret_139)
  {
    daisho_astnode_t* expr_ret_140 = NULL;
    daisho_astnode_t* expr_ret_141 = NULL;
    rec(mod_141);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Not capturing VARIDENT.
        expr_ret_141 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_141 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_141)
    {
      daisho_astnode_t* expr_ret_142 = NULL;
      expr_ret_142 = daisho_parse_tmplexpand(ctx);
      // optional
      if (!expr_ret_142)
        expr_ret_142 = SUCC;
      expr_ret_141 = expr_ret_142;
    }

    // ModExprList end
    if (!expr_ret_141) rew(mod_141);
    expr_ret_140 = expr_ret_141 ? SUCC : NULL;
    // optional
    if (!expr_ret_140)
      expr_ret_140 = SUCC;
    expr_ret_139 = expr_ret_140;
  }

  // ModExprList end
  if (!expr_ret_139) rew(mod_139);
  expr_ret_138 = expr_ret_139 ? SUCC : NULL;
  return expr_ret_138 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_fnbody(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_144 = NULL;
  daisho_astnode_t* expr_ret_143 = NULL;
  #define rule expr_ret_143

  daisho_astnode_t* expr_ret_145 = NULL;
  rec(mod_145);
  // ModExprList Forwarding
  expr_ret_145 = daisho_parse_expr(ctx);
  // ModExprList end
  if (!expr_ret_145) rew(mod_145);
  expr_ret_144 = expr_ret_145;
  return expr_ret_144 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_expr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_147 = NULL;
  daisho_astnode_t* expr_ret_146 = NULL;
  #define rule expr_ret_146

  daisho_astnode_t* expr_ret_148 = NULL;

  rec(slash_148);

  // SlashExpr 0
  if (!expr_ret_148)
  {
    daisho_astnode_t* expr_ret_149 = NULL;
    rec(mod_149);
    // ModExprList Forwarding
    expr_ret_149 = daisho_parse_cfexpr(ctx);
    // ModExprList end
    if (!expr_ret_149) rew(mod_149);
    expr_ret_148 = expr_ret_149;
  }

  // SlashExpr 1
  if (!expr_ret_148)
  {
    daisho_astnode_t* expr_ret_150 = NULL;
    rec(mod_150);
    // ModExprList Forwarding
    expr_ret_150 = daisho_parse_binop(ctx);
    // ModExprList end
    if (!expr_ret_150) rew(mod_150);
    expr_ret_148 = expr_ret_150;
  }

  // SlashExpr end
  if (!expr_ret_148) rew(slash_148);
  expr_ret_147 = expr_ret_148;

  return expr_ret_147 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_152 = NULL;
  daisho_astnode_t* expr_ret_151 = NULL;
  #define rule expr_ret_151

  daisho_astnode_t* expr_ret_153 = NULL;

  rec(slash_153);

  // SlashExpr 0
  if (!expr_ret_153)
  {
    daisho_astnode_t* expr_ret_154 = NULL;
    rec(mod_154);
    // ModExprList Forwarding
    expr_ret_154 = daisho_parse_forexpr(ctx);
    // ModExprList end
    if (!expr_ret_154) rew(mod_154);
    expr_ret_153 = expr_ret_154;
  }

  // SlashExpr 1
  if (!expr_ret_153)
  {
    daisho_astnode_t* expr_ret_155 = NULL;
    rec(mod_155);
    // ModExprList Forwarding
    expr_ret_155 = daisho_parse_whileexpr(ctx);
    // ModExprList end
    if (!expr_ret_155) rew(mod_155);
    expr_ret_153 = expr_ret_155;
  }

  // SlashExpr 2
  if (!expr_ret_153)
  {
    daisho_astnode_t* expr_ret_156 = NULL;
    rec(mod_156);
    // ModExprList Forwarding
    expr_ret_156 = daisho_parse_ternexpr(ctx);
    // ModExprList end
    if (!expr_ret_156) rew(mod_156);
    expr_ret_153 = expr_ret_156;
  }

  // SlashExpr end
  if (!expr_ret_153) rew(slash_153);
  expr_ret_152 = expr_ret_153;

  return expr_ret_152 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_forexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_158 = NULL;
  daisho_astnode_t* expr_ret_157 = NULL;
  #define rule expr_ret_157

  daisho_astnode_t* expr_ret_159 = NULL;

  rec(slash_159);

  // SlashExpr 0
  if (!expr_ret_159)
  {
    daisho_astnode_t* expr_ret_160 = NULL;
    rec(mod_160);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_160 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_160 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_161 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_161 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_161 = NULL;
      }

      // optional
      if (!expr_ret_161)
        expr_ret_161 = SUCC;
      expr_ret_160 = expr_ret_161;
    }

    // ModExprList 2
    if (expr_ret_160)
    {
      expr_ret_160 = daisho_parse_expr(ctx);
    }

    // ModExprList 3
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_162 = NULL;

      rec(slash_162);

      // SlashExpr 0
      if (!expr_ret_162)
      {
        daisho_astnode_t* expr_ret_163 = NULL;
        rec(mod_163);
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
          // Not capturing COLON.
          expr_ret_163 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_163 = NULL;
        }

        // ModExprList end
        if (!expr_ret_163) rew(mod_163);
        expr_ret_162 = expr_ret_163;
      }

      // SlashExpr 1
      if (!expr_ret_162)
      {
        daisho_astnode_t* expr_ret_164 = NULL;
        rec(mod_164);
        // ModExprList Forwarding
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
          // Not capturing IN.
          expr_ret_164 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_164 = NULL;
        }

        // ModExprList end
        if (!expr_ret_164) rew(mod_164);
        expr_ret_162 = expr_ret_164;
      }

      // SlashExpr end
      if (!expr_ret_162) rew(slash_162);
      expr_ret_160 = expr_ret_162;

    }

    // ModExprList 4
    if (expr_ret_160)
    {
      expr_ret_160 = daisho_parse_expr(ctx);
    }

    // ModExprList 5
    if (expr_ret_160)
    {
      daisho_astnode_t* expr_ret_165 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_165 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_165 = NULL;
      }

      // optional
      if (!expr_ret_165)
        expr_ret_165 = SUCC;
      expr_ret_160 = expr_ret_165;
    }

    // ModExprList 6
    if (expr_ret_160)
    {
      expr_ret_160 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_160) rew(mod_160);
    expr_ret_159 = expr_ret_160 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_159)
  {
    daisho_astnode_t* expr_ret_166 = NULL;
    rec(mod_166);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
        // Not capturing FOR.
        expr_ret_166 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_166 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_166)
    {
      daisho_astnode_t* expr_ret_167 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Not capturing OPEN.
        expr_ret_167 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_167 = NULL;
      }

      // optional
      if (!expr_ret_167)
        expr_ret_167 = SUCC;
      expr_ret_166 = expr_ret_167;
    }

    // ModExprList 2
    if (expr_ret_166)
    {
      expr_ret_166 = daisho_parse_expr(ctx);
    }

    // ModExprList 3
    if (expr_ret_166)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
        // Not capturing SEMI.
        expr_ret_166 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_166 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_166)
    {
      expr_ret_166 = daisho_parse_expr(ctx);
    }

    // ModExprList 5
    if (expr_ret_166)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_SEMI) {
        // Not capturing SEMI.
        expr_ret_166 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_166 = NULL;
      }

    }

    // ModExprList 6
    if (expr_ret_166)
    {
      expr_ret_166 = daisho_parse_expr(ctx);
    }

    // ModExprList 7
    if (expr_ret_166)
    {
      daisho_astnode_t* expr_ret_168 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_168 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_168 = NULL;
      }

      // optional
      if (!expr_ret_168)
        expr_ret_168 = SUCC;
      expr_ret_166 = expr_ret_168;
    }

    // ModExprList 8
    if (expr_ret_166)
    {
      expr_ret_166 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_166) rew(mod_166);
    expr_ret_159 = expr_ret_166 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_159) rew(slash_159);
  expr_ret_158 = expr_ret_159;

  return expr_ret_158 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_whileexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_170 = NULL;
  daisho_astnode_t* expr_ret_169 = NULL;
  #define rule expr_ret_169

  daisho_astnode_t* expr_ret_171 = NULL;
  rec(mod_171);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHILE) {
      // Not capturing WHILE.
      expr_ret_171 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_171 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_171)
  {
    daisho_astnode_t* expr_ret_172 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_172 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_172 = NULL;
    }

    // optional
    if (!expr_ret_172)
      expr_ret_172 = SUCC;
    expr_ret_171 = expr_ret_172;
  }

  // ModExprList 2
  if (expr_ret_171)
  {
    expr_ret_171 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_171)
  {
    daisho_astnode_t* expr_ret_173 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_173 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_173 = NULL;
    }

    // optional
    if (!expr_ret_173)
      expr_ret_173 = SUCC;
    expr_ret_171 = expr_ret_173;
  }

  // ModExprList 4
  if (expr_ret_171)
  {
    expr_ret_171 = daisho_parse_expr(ctx);
  }

  // ModExprList end
  if (!expr_ret_171) rew(mod_171);
  expr_ret_170 = expr_ret_171 ? SUCC : NULL;
  return expr_ret_170 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ternexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_175 = NULL;
  daisho_astnode_t* expr_ret_174 = NULL;
  #define rule expr_ret_174

  daisho_astnode_t* expr_ret_176 = NULL;
  rec(mod_176);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_177 = NULL;
    expr_ret_177 = daisho_parse_thenexpr(ctx);
    expr_ret_176 = expr_ret_177;
    n = expr_ret_177;
  }

  // ModExprList 1
  if (expr_ret_176)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_QUEST) {
      // Not capturing QUEST.
      expr_ret_176 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_176 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_176)
  {
    expr_ret_176 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_176)
  {
    daisho_astnode_t* expr_ret_178 = NULL;
    daisho_astnode_t* expr_ret_179 = NULL;
    rec(mod_179);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COLON) {
        // Not capturing COLON.
        expr_ret_179 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_179 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_179)
    {
      expr_ret_179 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_179) rew(mod_179);
    expr_ret_178 = expr_ret_179 ? SUCC : NULL;
    // optional
    if (!expr_ret_178)
      expr_ret_178 = SUCC;
    expr_ret_176 = expr_ret_178;
  }

  // ModExprList end
  if (!expr_ret_176) rew(mod_176);
  expr_ret_175 = expr_ret_176 ? SUCC : NULL;
  return expr_ret_175 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_thenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_181 = NULL;
  daisho_astnode_t* expr_ret_180 = NULL;
  #define rule expr_ret_180

  daisho_astnode_t* expr_ret_182 = NULL;
  rec(mod_182);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_183 = NULL;
    expr_ret_183 = daisho_parse_alsoexpr(ctx);
    expr_ret_182 = expr_ret_183;
    n = expr_ret_183;
  }

  // ModExprList 1
  if (expr_ret_182)
  {
    daisho_astnode_t* expr_ret_184 = NULL;
    daisho_astnode_t* expr_ret_185 = NULL;
    rec(mod_185);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_THEN) {
        // Not capturing THEN.
        expr_ret_185 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_185 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_185)
    {
      expr_ret_185 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_185) rew(mod_185);
    expr_ret_184 = expr_ret_185 ? SUCC : NULL;
    // optional
    if (!expr_ret_184)
      expr_ret_184 = SUCC;
    expr_ret_182 = expr_ret_184;
  }

  // ModExprList end
  if (!expr_ret_182) rew(mod_182);
  expr_ret_181 = expr_ret_182 ? SUCC : NULL;
  return expr_ret_181 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_alsoexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* expr_ret_187 = NULL;
  daisho_astnode_t* expr_ret_186 = NULL;
  #define rule expr_ret_186

  daisho_astnode_t* expr_ret_188 = NULL;
  rec(mod_188);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_189 = NULL;
    expr_ret_189 = daisho_parse_binop(ctx);
    expr_ret_188 = expr_ret_189;
    n = expr_ret_189;
  }

  // ModExprList 1
  if (expr_ret_188)
  {
    daisho_astnode_t* expr_ret_190 = NULL;
    daisho_astnode_t* expr_ret_191 = NULL;
    rec(mod_191);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ALSO) {
        // Not capturing ALSO.
        expr_ret_191 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_191 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_191)
    {
      expr_ret_191 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_191) rew(mod_191);
    expr_ret_190 = expr_ret_191 ? SUCC : NULL;
    // optional
    if (!expr_ret_190)
      expr_ret_190 = SUCC;
    expr_ret_188 = expr_ret_190;
  }

  // ModExprList end
  if (!expr_ret_188) rew(mod_188);
  expr_ret_187 = expr_ret_188 ? SUCC : NULL;
  return expr_ret_187 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binop(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_193 = NULL;
  daisho_astnode_t* expr_ret_192 = NULL;
  #define rule expr_ret_192

  daisho_astnode_t* expr_ret_194 = NULL;
  rec(mod_194);
  // ModExprList Forwarding
  expr_ret_194 = daisho_parse_eqexpr(ctx);
  // ModExprList end
  if (!expr_ret_194) rew(mod_194);
  expr_ret_193 = expr_ret_194;
  return expr_ret_193 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_eqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_196 = NULL;
  daisho_astnode_t* expr_ret_195 = NULL;
  #define rule expr_ret_195

  daisho_astnode_t* expr_ret_197 = NULL;
  rec(mod_197);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_198 = NULL;
    expr_ret_198 = daisho_parse_logorexpr(ctx);
    expr_ret_197 = expr_ret_198;
    n = expr_ret_198;
  }

  // ModExprList 1
  if (expr_ret_197)
  {
    // CodeExpr
    #define ret expr_ret_197
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_197)
  {
    daisho_astnode_t* expr_ret_199 = NULL;
    expr_ret_199 = SUCC;
    while (expr_ret_199)
    {
      daisho_astnode_t* expr_ret_200 = NULL;
      rec(mod_200);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_201 = NULL;
        daisho_astnode_t* expr_ret_202 = NULL;

        rec(slash_202);

        // SlashExpr 0
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_203 = NULL;
          rec(mod_203);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_EQ) {
            // Capturing EQ.
            expr_ret_203 = leaf(EQ);
            ctx->pos++;
          } else {
            expr_ret_203 = NULL;
          }

          // ModExprList end
          if (!expr_ret_203) rew(mod_203);
          expr_ret_202 = expr_ret_203;
        }

        // SlashExpr 1
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_204 = NULL;
          rec(mod_204);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLEQ) {
            // Capturing PLEQ.
            expr_ret_204 = leaf(PLEQ);
            ctx->pos++;
          } else {
            expr_ret_204 = NULL;
          }

          // ModExprList end
          if (!expr_ret_204) rew(mod_204);
          expr_ret_202 = expr_ret_204;
        }

        // SlashExpr 2
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_205 = NULL;
          rec(mod_205);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINEQ) {
            // Capturing MINEQ.
            expr_ret_205 = leaf(MINEQ);
            ctx->pos++;
          } else {
            expr_ret_205 = NULL;
          }

          // ModExprList end
          if (!expr_ret_205) rew(mod_205);
          expr_ret_202 = expr_ret_205;
        }

        // SlashExpr 3
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_206 = NULL;
          rec(mod_206);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MULEQ) {
            // Capturing MULEQ.
            expr_ret_206 = leaf(MULEQ);
            ctx->pos++;
          } else {
            expr_ret_206 = NULL;
          }

          // ModExprList end
          if (!expr_ret_206) rew(mod_206);
          expr_ret_202 = expr_ret_206;
        }

        // SlashExpr 4
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_207 = NULL;
          rec(mod_207);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIVEQ) {
            // Capturing DIVEQ.
            expr_ret_207 = leaf(DIVEQ);
            ctx->pos++;
          } else {
            expr_ret_207 = NULL;
          }

          // ModExprList end
          if (!expr_ret_207) rew(mod_207);
          expr_ret_202 = expr_ret_207;
        }

        // SlashExpr 5
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_208 = NULL;
          rec(mod_208);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MODEQ) {
            // Capturing MODEQ.
            expr_ret_208 = leaf(MODEQ);
            ctx->pos++;
          } else {
            expr_ret_208 = NULL;
          }

          // ModExprList end
          if (!expr_ret_208) rew(mod_208);
          expr_ret_202 = expr_ret_208;
        }

        // SlashExpr 6
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_209 = NULL;
          rec(mod_209);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_ANDEQ) {
            // Capturing ANDEQ.
            expr_ret_209 = leaf(ANDEQ);
            ctx->pos++;
          } else {
            expr_ret_209 = NULL;
          }

          // ModExprList end
          if (!expr_ret_209) rew(mod_209);
          expr_ret_202 = expr_ret_209;
        }

        // SlashExpr 7
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_210 = NULL;
          rec(mod_210);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OREQ) {
            // Capturing OREQ.
            expr_ret_210 = leaf(OREQ);
            ctx->pos++;
          } else {
            expr_ret_210 = NULL;
          }

          // ModExprList end
          if (!expr_ret_210) rew(mod_210);
          expr_ret_202 = expr_ret_210;
        }

        // SlashExpr 8
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_211 = NULL;
          rec(mod_211);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOREQ) {
            // Capturing XOREQ.
            expr_ret_211 = leaf(XOREQ);
            ctx->pos++;
          } else {
            expr_ret_211 = NULL;
          }

          // ModExprList end
          if (!expr_ret_211) rew(mod_211);
          expr_ret_202 = expr_ret_211;
        }

        // SlashExpr 9
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_212 = NULL;
          rec(mod_212);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BNEQ) {
            // Capturing BNEQ.
            expr_ret_212 = leaf(BNEQ);
            ctx->pos++;
          } else {
            expr_ret_212 = NULL;
          }

          // ModExprList end
          if (!expr_ret_212) rew(mod_212);
          expr_ret_202 = expr_ret_212;
        }

        // SlashExpr 10
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_213 = NULL;
          rec(mod_213);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSREQ) {
            // Capturing BSREQ.
            expr_ret_213 = leaf(BSREQ);
            ctx->pos++;
          } else {
            expr_ret_213 = NULL;
          }

          // ModExprList end
          if (!expr_ret_213) rew(mod_213);
          expr_ret_202 = expr_ret_213;
        }

        // SlashExpr 11
        if (!expr_ret_202)
        {
          daisho_astnode_t* expr_ret_214 = NULL;
          rec(mod_214);
          // ModExprList Forwarding
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_BSLEQ) {
            // Capturing BSLEQ.
            expr_ret_214 = leaf(BSLEQ);
            ctx->pos++;
          } else {
            expr_ret_214 = NULL;
          }

          // ModExprList end
          if (!expr_ret_214) rew(mod_214);
          expr_ret_202 = expr_ret_214;
        }

        // SlashExpr end
        if (!expr_ret_202) rew(slash_202);
        expr_ret_201 = expr_ret_202;

        expr_ret_200 = expr_ret_201;
        op = expr_ret_201;
      }

      // ModExprList 1
      if (expr_ret_200)
      {
        daisho_astnode_t* expr_ret_215 = NULL;
        expr_ret_215 = daisho_parse_logorexpr(ctx);
        expr_ret_200 = expr_ret_215;
        t = expr_ret_215;
      }

      // ModExprList 2
      if (expr_ret_200)
      {
        // CodeExpr
        #define ret expr_ret_200
        ret = SUCC;

        
                if (op->kind == kind(EQ))
                  rule=node(EQ, op, rule, t);
                else if (op->kind == kind(PLEQ))
                  rule=node(EQ, op, rule, node(PLUS,  op, rule, t));
                else if (op->kind == kind(MINEQ))
                  rule=node(EQ, op, rule, node(MINUS, op, rule, t));
                else if (op->kind == kind(MULEQ))
                  rule=node(EQ, op, rule, node(MUL,   op, rule, t));
                else if (op->kind == kind(DIVEQ))
                  rule=node(EQ, op, rule, node(DIV,   op, rule, t));
                else if (op->kind == kind(MODEQ))
                  rule=node(EQ, op, rule, node(MOD,   op, rule, t));
                else if (op->kind == kind(ANDEQ))
                  rule=node(EQ, op, rule, node(AND,   op, rule, t));
                else if (op->kind == kind(OREQ))
                  rule=node(EQ, op, rule, node(OR,    op, rule, t));
                else if (op->kind == kind(XOREQ))
                  rule=node(EQ, op, rule, node(BNEQ,  op, rule, t));
                else if (op->kind == kind(BSREQ))
                  rule=node(EQ, op, rule, node(BSR,   op, rule, t));
                else if (op->kind == kind(BSLEQ))
                  rule=node(EQ, op, rule, node(BSL,   op, rule, t));
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
      if (!expr_ret_200) rew(mod_200);
      expr_ret_199 = expr_ret_200 ? SUCC : NULL;
    }

    expr_ret_199 = SUCC;
    expr_ret_197 = expr_ret_199;
  }

  // ModExprList end
  if (!expr_ret_197) rew(mod_197);
  expr_ret_196 = expr_ret_197 ? SUCC : NULL;
  return expr_ret_196 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_217 = NULL;
  daisho_astnode_t* expr_ret_216 = NULL;
  #define rule expr_ret_216

  daisho_astnode_t* expr_ret_218 = NULL;
  rec(mod_218);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_219 = NULL;
    expr_ret_219 = daisho_parse_logandexpr(ctx);
    expr_ret_218 = expr_ret_219;
    n = expr_ret_219;
  }

  // ModExprList 1
  if (expr_ret_218)
  {
    // CodeExpr
    #define ret expr_ret_218
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_218)
  {
    daisho_astnode_t* expr_ret_220 = NULL;
    expr_ret_220 = SUCC;
    while (expr_ret_220)
    {
      daisho_astnode_t* expr_ret_221 = NULL;
      rec(mod_221);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_222 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGOR) {
          // Capturing LOGOR.
          expr_ret_222 = leaf(LOGOR);
          ctx->pos++;
        } else {
          expr_ret_222 = NULL;
        }

        expr_ret_221 = expr_ret_222;
        op = expr_ret_222;
      }

      // ModExprList 1
      if (expr_ret_221)
      {
        daisho_astnode_t* expr_ret_223 = NULL;
        expr_ret_223 = daisho_parse_logandexpr(ctx);
        expr_ret_221 = expr_ret_223;
        n = expr_ret_223;
      }

      // ModExprList 2
      if (expr_ret_221)
      {
        // CodeExpr
        #define ret expr_ret_221
        ret = SUCC;

        rule=node(LOGOR,  op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_221) rew(mod_221);
      expr_ret_220 = expr_ret_221 ? SUCC : NULL;
    }

    expr_ret_220 = SUCC;
    expr_ret_218 = expr_ret_220;
  }

  // ModExprList end
  if (!expr_ret_218) rew(mod_218);
  expr_ret_217 = expr_ret_218 ? SUCC : NULL;
  return expr_ret_217 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_logandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_225 = NULL;
  daisho_astnode_t* expr_ret_224 = NULL;
  #define rule expr_ret_224

  daisho_astnode_t* expr_ret_226 = NULL;
  rec(mod_226);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_227 = NULL;
    expr_ret_227 = daisho_parse_binorexpr(ctx);
    expr_ret_226 = expr_ret_227;
    n = expr_ret_227;
  }

  // ModExprList 1
  if (expr_ret_226)
  {
    // CodeExpr
    #define ret expr_ret_226
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_226)
  {
    daisho_astnode_t* expr_ret_228 = NULL;
    expr_ret_228 = SUCC;
    while (expr_ret_228)
    {
      daisho_astnode_t* expr_ret_229 = NULL;
      rec(mod_229);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_230 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LOGAND) {
          // Capturing LOGAND.
          expr_ret_230 = leaf(LOGAND);
          ctx->pos++;
        } else {
          expr_ret_230 = NULL;
        }

        expr_ret_229 = expr_ret_230;
        op = expr_ret_230;
      }

      // ModExprList 1
      if (expr_ret_229)
      {
        daisho_astnode_t* expr_ret_231 = NULL;
        expr_ret_231 = daisho_parse_binorexpr(ctx);
        expr_ret_229 = expr_ret_231;
        n = expr_ret_231;
      }

      // ModExprList 2
      if (expr_ret_229)
      {
        // CodeExpr
        #define ret expr_ret_229
        ret = SUCC;

        rule=node(LOGAND, op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_229) rew(mod_229);
      expr_ret_228 = expr_ret_229 ? SUCC : NULL;
    }

    expr_ret_228 = SUCC;
    expr_ret_226 = expr_ret_228;
  }

  // ModExprList end
  if (!expr_ret_226) rew(mod_226);
  expr_ret_225 = expr_ret_226 ? SUCC : NULL;
  return expr_ret_225 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_233 = NULL;
  daisho_astnode_t* expr_ret_232 = NULL;
  #define rule expr_ret_232

  daisho_astnode_t* expr_ret_234 = NULL;
  rec(mod_234);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_235 = NULL;
    expr_ret_235 = daisho_parse_binxorexpr(ctx);
    expr_ret_234 = expr_ret_235;
    n = expr_ret_235;
  }

  // ModExprList 1
  if (expr_ret_234)
  {
    // CodeExpr
    #define ret expr_ret_234
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_234)
  {
    daisho_astnode_t* expr_ret_236 = NULL;
    expr_ret_236 = SUCC;
    while (expr_ret_236)
    {
      daisho_astnode_t* expr_ret_237 = NULL;
      rec(mod_237);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_238 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OR) {
          // Capturing OR.
          expr_ret_238 = leaf(OR);
          ctx->pos++;
        } else {
          expr_ret_238 = NULL;
        }

        expr_ret_237 = expr_ret_238;
        op = expr_ret_238;
      }

      // ModExprList 1
      if (expr_ret_237)
      {
        daisho_astnode_t* expr_ret_239 = NULL;
        expr_ret_239 = daisho_parse_binxorexpr(ctx);
        expr_ret_237 = expr_ret_239;
        n = expr_ret_239;
      }

      // ModExprList 2
      if (expr_ret_237)
      {
        // CodeExpr
        #define ret expr_ret_237
        ret = SUCC;

        rule=node(OR,     op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_237) rew(mod_237);
      expr_ret_236 = expr_ret_237 ? SUCC : NULL;
    }

    expr_ret_236 = SUCC;
    expr_ret_234 = expr_ret_236;
  }

  // ModExprList end
  if (!expr_ret_234) rew(mod_234);
  expr_ret_233 = expr_ret_234 ? SUCC : NULL;
  return expr_ret_233 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binxorexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_241 = NULL;
  daisho_astnode_t* expr_ret_240 = NULL;
  #define rule expr_ret_240

  daisho_astnode_t* expr_ret_242 = NULL;
  rec(mod_242);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_243 = NULL;
    expr_ret_243 = daisho_parse_binandexpr(ctx);
    expr_ret_242 = expr_ret_243;
    n = expr_ret_243;
  }

  // ModExprList 1
  if (expr_ret_242)
  {
    // CodeExpr
    #define ret expr_ret_242
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_242)
  {
    daisho_astnode_t* expr_ret_244 = NULL;
    expr_ret_244 = SUCC;
    while (expr_ret_244)
    {
      daisho_astnode_t* expr_ret_245 = NULL;
      rec(mod_245);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_246 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_XOR) {
          // Capturing XOR.
          expr_ret_246 = leaf(XOR);
          ctx->pos++;
        } else {
          expr_ret_246 = NULL;
        }

        expr_ret_245 = expr_ret_246;
        op = expr_ret_246;
      }

      // ModExprList 1
      if (expr_ret_245)
      {
        daisho_astnode_t* expr_ret_247 = NULL;
        expr_ret_247 = daisho_parse_binandexpr(ctx);
        expr_ret_245 = expr_ret_247;
        n = expr_ret_247;
      }

      // ModExprList 2
      if (expr_ret_245)
      {
        // CodeExpr
        #define ret expr_ret_245
        ret = SUCC;

        rule=node(XOR,    op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_245) rew(mod_245);
      expr_ret_244 = expr_ret_245 ? SUCC : NULL;
    }

    expr_ret_244 = SUCC;
    expr_ret_242 = expr_ret_244;
  }

  // ModExprList end
  if (!expr_ret_242) rew(mod_242);
  expr_ret_241 = expr_ret_242 ? SUCC : NULL;
  return expr_ret_241 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_binandexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_249 = NULL;
  daisho_astnode_t* expr_ret_248 = NULL;
  #define rule expr_ret_248

  daisho_astnode_t* expr_ret_250 = NULL;
  rec(mod_250);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_251 = NULL;
    expr_ret_251 = daisho_parse_deneqexpr(ctx);
    expr_ret_250 = expr_ret_251;
    n = expr_ret_251;
  }

  // ModExprList 1
  if (expr_ret_250)
  {
    // CodeExpr
    #define ret expr_ret_250
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_250)
  {
    daisho_astnode_t* expr_ret_252 = NULL;
    expr_ret_252 = SUCC;
    while (expr_ret_252)
    {
      daisho_astnode_t* expr_ret_253 = NULL;
      rec(mod_253);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_254 = NULL;
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_AND) {
          // Capturing AND.
          expr_ret_254 = leaf(AND);
          ctx->pos++;
        } else {
          expr_ret_254 = NULL;
        }

        expr_ret_253 = expr_ret_254;
        op = expr_ret_254;
      }

      // ModExprList 1
      if (expr_ret_253)
      {
        daisho_astnode_t* expr_ret_255 = NULL;
        expr_ret_255 = daisho_parse_deneqexpr(ctx);
        expr_ret_253 = expr_ret_255;
        n = expr_ret_255;
      }

      // ModExprList 2
      if (expr_ret_253)
      {
        // CodeExpr
        #define ret expr_ret_253
        ret = SUCC;

        rule=node(AND,    op, rule, n);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_253) rew(mod_253);
      expr_ret_252 = expr_ret_253 ? SUCC : NULL;
    }

    expr_ret_252 = SUCC;
    expr_ret_250 = expr_ret_252;
  }

  // ModExprList end
  if (!expr_ret_250) rew(mod_250);
  expr_ret_249 = expr_ret_250 ? SUCC : NULL;
  return expr_ret_249 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_deneqexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_257 = NULL;
  daisho_astnode_t* expr_ret_256 = NULL;
  #define rule expr_ret_256

  daisho_astnode_t* expr_ret_258 = NULL;
  rec(mod_258);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_259 = NULL;
    expr_ret_259 = daisho_parse_cmpexpr(ctx);
    expr_ret_258 = expr_ret_259;
    n = expr_ret_259;
  }

  // ModExprList 1
  if (expr_ret_258)
  {
    // CodeExpr
    #define ret expr_ret_258
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_258)
  {
    daisho_astnode_t* expr_ret_260 = NULL;
    expr_ret_260 = SUCC;
    while (expr_ret_260)
    {
      daisho_astnode_t* expr_ret_261 = NULL;

      rec(slash_261);

      // SlashExpr 0
      if (!expr_ret_261)
      {
        daisho_astnode_t* expr_ret_262 = NULL;
        rec(mod_262);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_263 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DEQ) {
            // Capturing DEQ.
            expr_ret_263 = leaf(DEQ);
            ctx->pos++;
          } else {
            expr_ret_263 = NULL;
          }

          expr_ret_262 = expr_ret_263;
          op = expr_ret_263;
        }

        // ModExprList 1
        if (expr_ret_262)
        {
          daisho_astnode_t* expr_ret_264 = NULL;
          expr_ret_264 = daisho_parse_cmpexpr(ctx);
          expr_ret_262 = expr_ret_264;
          n = expr_ret_264;
        }

        // ModExprList 2
        if (expr_ret_262)
        {
          // CodeExpr
          #define ret expr_ret_262
          ret = SUCC;

          rule=node(DEQ, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_262) rew(mod_262);
        expr_ret_261 = expr_ret_262 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_261)
      {
        daisho_astnode_t* expr_ret_265 = NULL;
        rec(mod_265);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_266 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NEQ) {
            // Capturing NEQ.
            expr_ret_266 = leaf(NEQ);
            ctx->pos++;
          } else {
            expr_ret_266 = NULL;
          }

          expr_ret_265 = expr_ret_266;
          op = expr_ret_266;
        }

        // ModExprList 1
        if (expr_ret_265)
        {
          daisho_astnode_t* expr_ret_267 = NULL;
          expr_ret_267 = daisho_parse_cmpexpr(ctx);
          expr_ret_265 = expr_ret_267;
          n = expr_ret_267;
        }

        // ModExprList 2
        if (expr_ret_265)
        {
          // CodeExpr
          #define ret expr_ret_265
          ret = SUCC;

          rule=node(NEQ, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_265) rew(mod_265);
        expr_ret_261 = expr_ret_265 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_261) rew(slash_261);
      expr_ret_260 = expr_ret_261;

    }

    expr_ret_260 = SUCC;
    expr_ret_258 = expr_ret_260;
  }

  // ModExprList end
  if (!expr_ret_258) rew(mod_258);
  expr_ret_257 = expr_ret_258 ? SUCC : NULL;
  return expr_ret_257 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cmpexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_269 = NULL;
  daisho_astnode_t* expr_ret_268 = NULL;
  #define rule expr_ret_268

  daisho_astnode_t* expr_ret_270 = NULL;
  rec(mod_270);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_271 = NULL;
    expr_ret_271 = daisho_parse_shfexpr(ctx);
    expr_ret_270 = expr_ret_271;
    n = expr_ret_271;
  }

  // ModExprList 1
  if (expr_ret_270)
  {
    // CodeExpr
    #define ret expr_ret_270
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_270)
  {
    daisho_astnode_t* expr_ret_272 = NULL;
    expr_ret_272 = SUCC;
    while (expr_ret_272)
    {
      daisho_astnode_t* expr_ret_273 = NULL;

      rec(slash_273);

      // SlashExpr 0
      if (!expr_ret_273)
      {
        daisho_astnode_t* expr_ret_274 = NULL;
        rec(mod_274);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_275 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_275 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_275 = NULL;
          }

          expr_ret_274 = expr_ret_275;
          op = expr_ret_275;
        }

        // ModExprList 1
        if (expr_ret_274)
        {
          daisho_astnode_t* expr_ret_276 = NULL;
          expr_ret_276 = daisho_parse_shfexpr(ctx);
          expr_ret_274 = expr_ret_276;
          n = expr_ret_276;
        }

        // ModExprList 2
        if (expr_ret_274)
        {
          // CodeExpr
          #define ret expr_ret_274
          ret = SUCC;

          rule=node(LT,  op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_274) rew(mod_274);
        expr_ret_273 = expr_ret_274 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_273)
      {
        daisho_astnode_t* expr_ret_277 = NULL;
        rec(mod_277);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_278 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_278 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_278 = NULL;
          }

          expr_ret_277 = expr_ret_278;
          op = expr_ret_278;
        }

        // ModExprList 1
        if (expr_ret_277)
        {
          daisho_astnode_t* expr_ret_279 = NULL;
          expr_ret_279 = daisho_parse_shfexpr(ctx);
          expr_ret_277 = expr_ret_279;
          n = expr_ret_279;
        }

        // ModExprList 2
        if (expr_ret_277)
        {
          // CodeExpr
          #define ret expr_ret_277
          ret = SUCC;

          rule=node(GT,  op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_277) rew(mod_277);
        expr_ret_273 = expr_ret_277 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_273)
      {
        daisho_astnode_t* expr_ret_280 = NULL;
        rec(mod_280);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_281 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LEQ) {
            // Capturing LEQ.
            expr_ret_281 = leaf(LEQ);
            ctx->pos++;
          } else {
            expr_ret_281 = NULL;
          }

          expr_ret_280 = expr_ret_281;
          op = expr_ret_281;
        }

        // ModExprList 1
        if (expr_ret_280)
        {
          daisho_astnode_t* expr_ret_282 = NULL;
          expr_ret_282 = daisho_parse_shfexpr(ctx);
          expr_ret_280 = expr_ret_282;
          n = expr_ret_282;
        }

        // ModExprList 2
        if (expr_ret_280)
        {
          // CodeExpr
          #define ret expr_ret_280
          ret = SUCC;

          rule=node(LEQ, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_280) rew(mod_280);
        expr_ret_273 = expr_ret_280 ? SUCC : NULL;
      }

      // SlashExpr 3
      if (!expr_ret_273)
      {
        daisho_astnode_t* expr_ret_283 = NULL;
        rec(mod_283);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_284 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GEQ) {
            // Capturing GEQ.
            expr_ret_284 = leaf(GEQ);
            ctx->pos++;
          } else {
            expr_ret_284 = NULL;
          }

          expr_ret_283 = expr_ret_284;
          op = expr_ret_284;
        }

        // ModExprList 1
        if (expr_ret_283)
        {
          daisho_astnode_t* expr_ret_285 = NULL;
          expr_ret_285 = daisho_parse_shfexpr(ctx);
          expr_ret_283 = expr_ret_285;
          n = expr_ret_285;
        }

        // ModExprList 2
        if (expr_ret_283)
        {
          // CodeExpr
          #define ret expr_ret_283
          ret = SUCC;

          rule=node(GEQ, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_283) rew(mod_283);
        expr_ret_273 = expr_ret_283 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_273) rew(slash_273);
      expr_ret_272 = expr_ret_273;

    }

    expr_ret_272 = SUCC;
    expr_ret_270 = expr_ret_272;
  }

  // ModExprList end
  if (!expr_ret_270) rew(mod_270);
  expr_ret_269 = expr_ret_270 ? SUCC : NULL;
  return expr_ret_269 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_shfexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* l = NULL;
  daisho_astnode_t* lt = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* gt = NULL;
  daisho_astnode_t* expr_ret_287 = NULL;
  daisho_astnode_t* expr_ret_286 = NULL;
  #define rule expr_ret_286

  daisho_astnode_t* expr_ret_288 = NULL;
  rec(mod_288);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_289 = NULL;
    expr_ret_289 = daisho_parse_multexpr(ctx);
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

      rec(slash_291);

      // SlashExpr 0
      if (!expr_ret_291)
      {
        daisho_astnode_t* expr_ret_292 = NULL;
        rec(mod_292);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_293 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_293 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_293 = NULL;
          }

          expr_ret_292 = expr_ret_293;
          l = expr_ret_293;
        }

        // ModExprList 1
        if (expr_ret_292)
        {
          daisho_astnode_t* expr_ret_294 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LT) {
            // Capturing LT.
            expr_ret_294 = leaf(LT);
            ctx->pos++;
          } else {
            expr_ret_294 = NULL;
          }

          expr_ret_292 = expr_ret_294;
          lt = expr_ret_294;
        }

        // ModExprList 2
        if (expr_ret_292)
        {
          daisho_astnode_t* expr_ret_295 = NULL;
          expr_ret_295 = daisho_parse_multexpr(ctx);
          expr_ret_292 = expr_ret_295;
          n = expr_ret_295;
        }

        // ModExprList 3
        if (expr_ret_292)
        {
          // CodeExpr
          #define ret expr_ret_292
          ret = SUCC;

          rule=node(BSL, l, lt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_292) rew(mod_292);
        expr_ret_291 = expr_ret_292 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_291)
      {
        daisho_astnode_t* expr_ret_296 = NULL;
        rec(mod_296);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_297 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_297 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_297 = NULL;
          }

          expr_ret_296 = expr_ret_297;
          g = expr_ret_297;
        }

        // ModExprList 1
        if (expr_ret_296)
        {
          daisho_astnode_t* expr_ret_298 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GT) {
            // Capturing GT.
            expr_ret_298 = leaf(GT);
            ctx->pos++;
          } else {
            expr_ret_298 = NULL;
          }

          expr_ret_296 = expr_ret_298;
          gt = expr_ret_298;
        }

        // ModExprList 2
        if (expr_ret_296)
        {
          daisho_astnode_t* expr_ret_299 = NULL;
          expr_ret_299 = daisho_parse_multexpr(ctx);
          expr_ret_296 = expr_ret_299;
          n = expr_ret_299;
        }

        // ModExprList 3
        if (expr_ret_296)
        {
          // CodeExpr
          #define ret expr_ret_296
          ret = SUCC;

          rule=node(BSR, g, gt, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_296) rew(mod_296);
        expr_ret_291 = expr_ret_296 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_291) rew(slash_291);
      expr_ret_290 = expr_ret_291;

    }

    expr_ret_290 = SUCC;
    expr_ret_288 = expr_ret_290;
  }

  // ModExprList end
  if (!expr_ret_288) rew(mod_288);
  expr_ret_287 = expr_ret_288 ? SUCC : NULL;
  return expr_ret_287 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_multexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_301 = NULL;
  daisho_astnode_t* expr_ret_300 = NULL;
  #define rule expr_ret_300

  daisho_astnode_t* expr_ret_302 = NULL;
  rec(mod_302);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_303 = NULL;
    expr_ret_303 = daisho_parse_sumexpr(ctx);
    expr_ret_302 = expr_ret_303;
    n = expr_ret_303;
  }

  // ModExprList 1
  if (expr_ret_302)
  {
    // CodeExpr
    #define ret expr_ret_302
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_302)
  {
    daisho_astnode_t* expr_ret_304 = NULL;
    expr_ret_304 = SUCC;
    while (expr_ret_304)
    {
      daisho_astnode_t* expr_ret_305 = NULL;

      rec(slash_305);

      // SlashExpr 0
      if (!expr_ret_305)
      {
        daisho_astnode_t* expr_ret_306 = NULL;
        rec(mod_306);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_307 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
            // Capturing STAR.
            expr_ret_307 = leaf(STAR);
            ctx->pos++;
          } else {
            expr_ret_307 = NULL;
          }

          expr_ret_306 = expr_ret_307;
          op = expr_ret_307;
        }

        // ModExprList 1
        if (expr_ret_306)
        {
          daisho_astnode_t* expr_ret_308 = NULL;
          expr_ret_308 = daisho_parse_sumexpr(ctx);
          expr_ret_306 = expr_ret_308;
          n = expr_ret_308;
        }

        // ModExprList 2
        if (expr_ret_306)
        {
          // CodeExpr
          #define ret expr_ret_306
          ret = SUCC;

          rule=node(STAR, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_306) rew(mod_306);
        expr_ret_305 = expr_ret_306 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_305)
      {
        daisho_astnode_t* expr_ret_309 = NULL;
        rec(mod_309);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_310 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_DIV) {
            // Capturing DIV.
            expr_ret_310 = leaf(DIV);
            ctx->pos++;
          } else {
            expr_ret_310 = NULL;
          }

          expr_ret_309 = expr_ret_310;
          op = expr_ret_310;
        }

        // ModExprList 1
        if (expr_ret_309)
        {
          daisho_astnode_t* expr_ret_311 = NULL;
          expr_ret_311 = daisho_parse_sumexpr(ctx);
          expr_ret_309 = expr_ret_311;
          n = expr_ret_311;
        }

        // ModExprList 2
        if (expr_ret_309)
        {
          // CodeExpr
          #define ret expr_ret_309
          ret = SUCC;

          rule=node(DIV,  op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_309) rew(mod_309);
        expr_ret_305 = expr_ret_309 ? SUCC : NULL;
      }

      // SlashExpr 2
      if (!expr_ret_305)
      {
        daisho_astnode_t* expr_ret_312 = NULL;
        rec(mod_312);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_313 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MOD) {
            // Capturing MOD.
            expr_ret_313 = leaf(MOD);
            ctx->pos++;
          } else {
            expr_ret_313 = NULL;
          }

          expr_ret_312 = expr_ret_313;
          op = expr_ret_313;
        }

        // ModExprList 1
        if (expr_ret_312)
        {
          daisho_astnode_t* expr_ret_314 = NULL;
          expr_ret_314 = daisho_parse_sumexpr(ctx);
          expr_ret_312 = expr_ret_314;
          n = expr_ret_314;
        }

        // ModExprList 2
        if (expr_ret_312)
        {
          // CodeExpr
          #define ret expr_ret_312
          ret = SUCC;

          rule=node(MOD,  op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_312) rew(mod_312);
        expr_ret_305 = expr_ret_312 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_305) rew(slash_305);
      expr_ret_304 = expr_ret_305;

    }

    expr_ret_304 = SUCC;
    expr_ret_302 = expr_ret_304;
  }

  // ModExprList end
  if (!expr_ret_302) rew(mod_302);
  expr_ret_301 = expr_ret_302 ? SUCC : NULL;
  return expr_ret_301 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_sumexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* op = NULL;
  daisho_astnode_t* expr_ret_316 = NULL;
  daisho_astnode_t* expr_ret_315 = NULL;
  #define rule expr_ret_315

  daisho_astnode_t* expr_ret_317 = NULL;
  rec(mod_317);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_318 = NULL;
    expr_ret_318 = daisho_parse_castexpr(ctx);
    expr_ret_317 = expr_ret_318;
    n = expr_ret_318;
  }

  // ModExprList 1
  if (expr_ret_317)
  {
    // CodeExpr
    #define ret expr_ret_317
    ret = SUCC;

    rule=n;

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_317)
  {
    daisho_astnode_t* expr_ret_319 = NULL;
    expr_ret_319 = SUCC;
    while (expr_ret_319)
    {
      daisho_astnode_t* expr_ret_320 = NULL;

      rec(slash_320);

      // SlashExpr 0
      if (!expr_ret_320)
      {
        daisho_astnode_t* expr_ret_321 = NULL;
        rec(mod_321);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_322 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_PLUS) {
            // Capturing PLUS.
            expr_ret_322 = leaf(PLUS);
            ctx->pos++;
          } else {
            expr_ret_322 = NULL;
          }

          expr_ret_321 = expr_ret_322;
          op = expr_ret_322;
        }

        // ModExprList 1
        if (expr_ret_321)
        {
          daisho_astnode_t* expr_ret_323 = NULL;
          expr_ret_323 = daisho_parse_castexpr(ctx);
          expr_ret_321 = expr_ret_323;
          n = expr_ret_323;
        }

        // ModExprList 2
        if (expr_ret_321)
        {
          // CodeExpr
          #define ret expr_ret_321
          ret = SUCC;

          rule=node(PLUS, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_321) rew(mod_321);
        expr_ret_320 = expr_ret_321 ? SUCC : NULL;
      }

      // SlashExpr 1
      if (!expr_ret_320)
      {
        daisho_astnode_t* expr_ret_324 = NULL;
        rec(mod_324);
        // ModExprList 0
        {
          daisho_astnode_t* expr_ret_325 = NULL;
          if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_MINUS) {
            // Capturing MINUS.
            expr_ret_325 = leaf(MINUS);
            ctx->pos++;
          } else {
            expr_ret_325 = NULL;
          }

          expr_ret_324 = expr_ret_325;
          op = expr_ret_325;
        }

        // ModExprList 1
        if (expr_ret_324)
        {
          daisho_astnode_t* expr_ret_326 = NULL;
          expr_ret_326 = daisho_parse_castexpr(ctx);
          expr_ret_324 = expr_ret_326;
          n = expr_ret_326;
        }

        // ModExprList 2
        if (expr_ret_324)
        {
          // CodeExpr
          #define ret expr_ret_324
          ret = SUCC;

          rule=node(MINUS, op, rule, n);

          #undef ret
        }

        // ModExprList end
        if (!expr_ret_324) rew(mod_324);
        expr_ret_320 = expr_ret_324 ? SUCC : NULL;
      }

      // SlashExpr end
      if (!expr_ret_320) rew(slash_320);
      expr_ret_319 = expr_ret_320;

    }

    expr_ret_319 = SUCC;
    expr_ret_317 = expr_ret_319;
  }

  // ModExprList end
  if (!expr_ret_317) rew(mod_317);
  expr_ret_316 = expr_ret_317 ? SUCC : NULL;
  return expr_ret_316 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_castexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* o = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* re = NULL;
  daisho_astnode_t* expr_ret_328 = NULL;
  daisho_astnode_t* expr_ret_327 = NULL;
  #define rule expr_ret_327

  daisho_astnode_t* expr_ret_329 = NULL;

  rec(slash_329);

  // SlashExpr 0
  if (!expr_ret_329)
  {
    daisho_astnode_t* expr_ret_330 = NULL;
    rec(mod_330);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_331 = NULL;
      expr_ret_331 = daisho_parse_callexpr(ctx);
      expr_ret_330 = expr_ret_331;
      n = expr_ret_331;
    }

    // ModExprList 1
    if (expr_ret_330)
    {
      daisho_astnode_t* expr_ret_332 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
        // Capturing OPEN.
        expr_ret_332 = leaf(OPEN);
        ctx->pos++;
      } else {
        expr_ret_332 = NULL;
      }

      expr_ret_330 = expr_ret_332;
      o = expr_ret_332;
    }

    // ModExprList 2
    if (expr_ret_330)
    {
      daisho_astnode_t* expr_ret_333 = NULL;
      expr_ret_333 = daisho_parse_type(ctx);
      expr_ret_330 = expr_ret_333;
      t = expr_ret_333;
    }

    // ModExprList 3
    if (expr_ret_330)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
        // Not capturing CLOSE.
        expr_ret_330 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_330 = NULL;
      }

    }

    // ModExprList 4
    if (expr_ret_330)
    {
      // CodeExpr
      #define ret expr_ret_330
      ret = SUCC;

      rule=node(CAST, o, t, n);

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_330) rew(mod_330);
    expr_ret_329 = expr_ret_330 ? SUCC : NULL;
  }

  // SlashExpr 1
  if (!expr_ret_329)
  {
    daisho_astnode_t* expr_ret_334 = NULL;
    rec(mod_334);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_335 = NULL;
      expr_ret_335 = daisho_parse_refexpr(ctx);
      expr_ret_334 = expr_ret_335;
      re = expr_ret_335;
    }

    // ModExprList 1
    if (expr_ret_334)
    {
      // CodeExpr
      #define ret expr_ret_334
      ret = SUCC;

       rule = re; ;

      #undef ret
    }

    // ModExprList end
    if (!expr_ret_334) rew(mod_334);
    expr_ret_329 = expr_ret_334 ? SUCC : NULL;
  }

  // SlashExpr end
  if (!expr_ret_329) rew(slash_329);
  expr_ret_328 = expr_ret_329;

  return expr_ret_328 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_callexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* t = NULL;
  daisho_astnode_t* expr_ret_337 = NULL;
  daisho_astnode_t* expr_ret_336 = NULL;
  #define rule expr_ret_336

  daisho_astnode_t* expr_ret_338 = NULL;
  rec(mod_338);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_339 = NULL;
    expr_ret_339 = daisho_parse_refexpr(ctx);
    expr_ret_338 = expr_ret_339;
    n = expr_ret_339;
  }

  // ModExprList 1
  if (expr_ret_338)
  {
    daisho_astnode_t* expr_ret_340 = NULL;
    expr_ret_340 = daisho_parse_tmplexpand(ctx);
    // optional
    if (!expr_ret_340)
      expr_ret_340 = SUCC;
    expr_ret_338 = expr_ret_340;
    t = expr_ret_340;
  }

  // ModExprList 2
  if (expr_ret_338)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_338 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_338 = NULL;
    }

  }

  // ModExprList 3
  if (expr_ret_338)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_338 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_338 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_338) rew(mod_338);
  expr_ret_337 = expr_ret_338 ? SUCC : NULL;
  return expr_ret_337 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_refexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* a = NULL;
  daisho_astnode_t* expr_ret_342 = NULL;
  daisho_astnode_t* expr_ret_341 = NULL;
  #define rule expr_ret_341

  daisho_astnode_t* expr_ret_343 = NULL;
  rec(mod_343);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_344 = NULL;
    expr_ret_344 = daisho_parse_derefexpr(ctx);
    expr_ret_343 = expr_ret_344;
    n = expr_ret_344;
  }

  // ModExprList 1
  if (expr_ret_343)
  {
    daisho_astnode_t* expr_ret_345 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_REF) {
      // Capturing REF.
      expr_ret_345 = leaf(REF);
      ctx->pos++;
    } else {
      expr_ret_345 = NULL;
    }

    // optional
    if (!expr_ret_345)
      expr_ret_345 = SUCC;
    expr_ret_343 = expr_ret_345;
    a = expr_ret_345;
  }

  // ModExprList 2
  if (expr_ret_343)
  {
    // CodeExpr
    #define ret expr_ret_343
    ret = SUCC;

    rule=(a != SUCC) ? node(REF, a, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_343) rew(mod_343);
  expr_ret_342 = expr_ret_343 ? SUCC : NULL;
  return expr_ret_342 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_derefexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_347 = NULL;
  daisho_astnode_t* expr_ret_346 = NULL;
  #define rule expr_ret_346

  daisho_astnode_t* expr_ret_348 = NULL;
  rec(mod_348);
  // ModExprList end
  if (!expr_ret_348) rew(mod_348);
  expr_ret_347 = expr_ret_348 ? SUCC : NULL;
  return expr_ret_347 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_postretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* n = NULL;
  daisho_astnode_t* g = NULL;
  daisho_astnode_t* expr_ret_350 = NULL;
  daisho_astnode_t* expr_ret_349 = NULL;
  #define rule expr_ret_349

  daisho_astnode_t* expr_ret_351 = NULL;
  rec(mod_351);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_352 = NULL;
    expr_ret_352 = daisho_parse_atomexpr(ctx);
    expr_ret_351 = expr_ret_352;
    n = expr_ret_352;
  }

  // ModExprList 1
  if (expr_ret_351)
  {
    daisho_astnode_t* expr_ret_353 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_GRAVE) {
      // Capturing GRAVE.
      expr_ret_353 = leaf(GRAVE);
      ctx->pos++;
    } else {
      expr_ret_353 = NULL;
    }

    // optional
    if (!expr_ret_353)
      expr_ret_353 = SUCC;
    expr_ret_351 = expr_ret_353;
    g = expr_ret_353;
  }

  // ModExprList 2
  if (expr_ret_351)
  {
    // CodeExpr
    #define ret expr_ret_351
    ret = SUCC;

    rule=(g != SUCC)?node(RET, g, n) : n;

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_351) rew(mod_351);
  expr_ret_350 = expr_ret_351 ? SUCC : NULL;
  return expr_ret_350 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_atomexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_355 = NULL;
  daisho_astnode_t* expr_ret_354 = NULL;
  #define rule expr_ret_354

  daisho_astnode_t* expr_ret_356 = NULL;

  rec(slash_356);

  // SlashExpr 0
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_357 = NULL;
    rec(mod_357);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_357 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_357 = NULL;
    }

    // ModExprList end
    if (!expr_ret_357) rew(mod_357);
    expr_ret_356 = expr_ret_357;
  }

  // SlashExpr 1
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_358 = NULL;
    rec(mod_358);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_NUMLIT) {
      // Capturing NUMLIT.
      expr_ret_358 = leaf(NUMLIT);
      ctx->pos++;
    } else {
      expr_ret_358 = NULL;
    }

    // ModExprList end
    if (!expr_ret_358) rew(mod_358);
    expr_ret_356 = expr_ret_358;
  }

  // SlashExpr 2
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_359 = NULL;
    rec(mod_359);
    // ModExprList Forwarding
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STRLIT) {
      // Capturing STRLIT.
      expr_ret_359 = leaf(STRLIT);
      ctx->pos++;
    } else {
      expr_ret_359 = NULL;
    }

    // ModExprList end
    if (!expr_ret_359) rew(mod_359);
    expr_ret_356 = expr_ret_359;
  }

  // SlashExpr 3
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_360 = NULL;
    rec(mod_360);
    // ModExprList Forwarding
    expr_ret_360 = daisho_parse_blockexpr(ctx);
    // ModExprList end
    if (!expr_ret_360) rew(mod_360);
    expr_ret_356 = expr_ret_360;
  }

  // SlashExpr 4
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_361 = NULL;
    rec(mod_361);
    // ModExprList Forwarding
    expr_ret_361 = daisho_parse_lambdaexpr(ctx);
    // ModExprList end
    if (!expr_ret_361) rew(mod_361);
    expr_ret_356 = expr_ret_361;
  }

  // SlashExpr 5
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_362 = NULL;
    rec(mod_362);
    // ModExprList Forwarding
    expr_ret_362 = daisho_parse_listcomp(ctx);
    // ModExprList end
    if (!expr_ret_362) rew(mod_362);
    expr_ret_356 = expr_ret_362;
  }

  // SlashExpr 6
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_363 = NULL;
    rec(mod_363);
    // ModExprList Forwarding
    expr_ret_363 = daisho_parse_listlit(ctx);
    // ModExprList end
    if (!expr_ret_363) rew(mod_363);
    expr_ret_356 = expr_ret_363;
  }

  // SlashExpr 7
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_364 = NULL;
    rec(mod_364);
    // ModExprList Forwarding
    expr_ret_364 = daisho_parse_parenexpr(ctx);
    // ModExprList end
    if (!expr_ret_364) rew(mod_364);
    expr_ret_356 = expr_ret_364;
  }

  // SlashExpr 8
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_365 = NULL;
    rec(mod_365);
    // ModExprList Forwarding
    expr_ret_365 = daisho_parse_ctypeexpr(ctx);
    // ModExprList end
    if (!expr_ret_365) rew(mod_365);
    expr_ret_356 = expr_ret_365;
  }

  // SlashExpr 9
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_366 = NULL;
    rec(mod_366);
    // ModExprList Forwarding
    expr_ret_366 = daisho_parse_cfuncexpr(ctx);
    // ModExprList end
    if (!expr_ret_366) rew(mod_366);
    expr_ret_356 = expr_ret_366;
  }

  // SlashExpr 10
  if (!expr_ret_356)
  {
    daisho_astnode_t* expr_ret_367 = NULL;
    rec(mod_367);
    // ModExprList Forwarding
    expr_ret_367 = daisho_parse_preretexpr(ctx);
    // ModExprList end
    if (!expr_ret_367) rew(mod_367);
    expr_ret_356 = expr_ret_367;
  }

  // SlashExpr end
  if (!expr_ret_356) rew(slash_356);
  expr_ret_355 = expr_ret_356;

  return expr_ret_355 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_blockexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_369 = NULL;
  daisho_astnode_t* expr_ret_368 = NULL;
  #define rule expr_ret_368

  daisho_astnode_t* expr_ret_370 = NULL;
  rec(mod_370);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LCBRACK) {
      // Not capturing LCBRACK.
      expr_ret_370 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_370 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_370)
  {
    // CodeExpr
    #define ret expr_ret_370
    ret = SUCC;

    rule=list(BLK);

    #undef ret
  }

  // ModExprList 2
  if (expr_ret_370)
  {
    daisho_astnode_t* expr_ret_371 = NULL;
    expr_ret_371 = SUCC;
    while (expr_ret_371)
    {
      daisho_astnode_t* expr_ret_372 = NULL;
      rec(mod_372);
      // ModExprList 0
      {
        daisho_astnode_t* expr_ret_373 = NULL;
        expr_ret_373 = daisho_parse_expr(ctx);
        expr_ret_372 = expr_ret_373;
        e = expr_ret_373;
      }

      // ModExprList 1
      if (expr_ret_372)
      {
        // CodeExpr
        #define ret expr_ret_372
        ret = SUCC;

        add(rule, e);

        #undef ret
      }

      // ModExprList end
      if (!expr_ret_372) rew(mod_372);
      expr_ret_371 = expr_ret_372 ? SUCC : NULL;
    }

    expr_ret_371 = SUCC;
    expr_ret_370 = expr_ret_371;
  }

  // ModExprList 3
  if (expr_ret_370)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RCBRACK) {
      // Not capturing RCBRACK.
      expr_ret_370 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_370 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_370) rew(mod_370);
  expr_ret_369 = expr_ret_370 ? SUCC : NULL;
  return expr_ret_369 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_lambdaexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_375 = NULL;
  daisho_astnode_t* expr_ret_374 = NULL;
  #define rule expr_ret_374

  daisho_astnode_t* expr_ret_376 = NULL;
  rec(mod_376);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_376 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_376 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_376)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_376 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_376 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_376) rew(mod_376);
  expr_ret_375 = expr_ret_376 ? SUCC : NULL;
  return expr_ret_375 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listcomp(daisho_parser_ctx* ctx) {
  daisho_astnode_t* cnt = NULL;
  daisho_astnode_t* item = NULL;
  daisho_astnode_t* expr_ret_378 = NULL;
  daisho_astnode_t* expr_ret_377 = NULL;
  #define rule expr_ret_377

  daisho_astnode_t* expr_ret_379 = NULL;
  rec(mod_379);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
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
    daisho_astnode_t* expr_ret_381 = NULL;
    rec(mod_381);
    // ModExprList 0
    {
      daisho_astnode_t* expr_ret_382 = NULL;
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
        // Capturing VARIDENT.
        expr_ret_382 = leaf(VARIDENT);
        ctx->pos++;
      } else {
        expr_ret_382 = NULL;
      }

      expr_ret_381 = expr_ret_382;
      cnt = expr_ret_382;
    }

    // ModExprList 1
    if (expr_ret_381)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
        // Not capturing COMMA.
        expr_ret_381 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_381 = NULL;
      }

    }

    // ModExprList end
    if (!expr_ret_381) rew(mod_381);
    expr_ret_380 = expr_ret_381 ? SUCC : NULL;
    // optional
    if (!expr_ret_380)
      expr_ret_380 = SUCC;
    expr_ret_379 = expr_ret_380;
  }

  // ModExprList 2
  if (expr_ret_379)
  {
    expr_ret_379 = daisho_parse_expr(ctx);
  }

  // ModExprList 3
  if (expr_ret_379)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_FOR) {
      // Not capturing FOR.
      expr_ret_379 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_379 = NULL;
    }

  }

  // ModExprList 4
  if (expr_ret_379)
  {
    daisho_astnode_t* expr_ret_383 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_VARIDENT) {
      // Capturing VARIDENT.
      expr_ret_383 = leaf(VARIDENT);
      ctx->pos++;
    } else {
      expr_ret_383 = NULL;
    }

    expr_ret_379 = expr_ret_383;
    item = expr_ret_383;
  }

  // ModExprList 5
  if (expr_ret_379)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_IN) {
      // Not capturing IN.
      expr_ret_379 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_379 = NULL;
    }

  }

  // ModExprList 6
  if (expr_ret_379)
  {
    expr_ret_379 = daisho_parse_expr(ctx);
  }

  // ModExprList 7
  if (expr_ret_379)
  {
    daisho_astnode_t* expr_ret_384 = NULL;
    daisho_astnode_t* expr_ret_385 = NULL;
    rec(mod_385);
    // ModExprList 0
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_WHERE) {
        // Not capturing WHERE.
        expr_ret_385 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_385 = NULL;
      }

    }

    // ModExprList 1
    if (expr_ret_385)
    {
      expr_ret_385 = daisho_parse_expr(ctx);
    }

    // ModExprList end
    if (!expr_ret_385) rew(mod_385);
    expr_ret_384 = expr_ret_385 ? SUCC : NULL;
    // optional
    if (!expr_ret_384)
      expr_ret_384 = SUCC;
    expr_ret_379 = expr_ret_384;
  }

  // ModExprList 8
  if (expr_ret_379)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_379 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_379 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_379) rew(mod_379);
  expr_ret_378 = expr_ret_379 ? SUCC : NULL;
  return expr_ret_378 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_listlit(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_387 = NULL;
  daisho_astnode_t* expr_ret_386 = NULL;
  #define rule expr_ret_386

  daisho_astnode_t* expr_ret_388 = NULL;
  rec(mod_388);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_LSBRACK) {
      // Not capturing LSBRACK.
      expr_ret_388 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_388 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_388)
  {
    daisho_astnode_t* expr_ret_389 = NULL;
    expr_ret_389 = daisho_parse_expr(ctx);
    // optional
    if (!expr_ret_389)
      expr_ret_389 = SUCC;
    expr_ret_388 = expr_ret_389;
  }

  // ModExprList 2
  if (expr_ret_388)
  {
    daisho_astnode_t* expr_ret_390 = NULL;
    expr_ret_390 = SUCC;
    while (expr_ret_390)
    {
      daisho_astnode_t* expr_ret_391 = NULL;
      rec(mod_391);
      // ModExprList 0
      {
        if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
          // Not capturing COMMA.
          expr_ret_391 = SUCC;
          ctx->pos++;
        } else {
          expr_ret_391 = NULL;
        }

      }

      // ModExprList 1
      if (expr_ret_391)
      {
        expr_ret_391 = daisho_parse_expr(ctx);
      }

      // ModExprList end
      if (!expr_ret_391) rew(mod_391);
      expr_ret_390 = expr_ret_391 ? SUCC : NULL;
    }

    expr_ret_390 = SUCC;
    expr_ret_388 = expr_ret_390;
  }

  // ModExprList 3
  if (expr_ret_388)
  {
    daisho_astnode_t* expr_ret_392 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_COMMA) {
      // Not capturing COMMA.
      expr_ret_392 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_392 = NULL;
    }

    // optional
    if (!expr_ret_392)
      expr_ret_392 = SUCC;
    expr_ret_388 = expr_ret_392;
  }

  // ModExprList 4
  if (expr_ret_388)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RSBRACK) {
      // Not capturing RSBRACK.
      expr_ret_388 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_388 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_388) rew(mod_388);
  expr_ret_387 = expr_ret_388 ? SUCC : NULL;
  return expr_ret_387 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_parenexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_394 = NULL;
  daisho_astnode_t* expr_ret_393 = NULL;
  #define rule expr_ret_393

  daisho_astnode_t* expr_ret_395 = NULL;
  rec(mod_395);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_OPEN) {
      // Not capturing OPEN.
      expr_ret_395 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_395 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_395)
  {
    expr_ret_395 = daisho_parse_expr(ctx);
  }

  // ModExprList 2
  if (expr_ret_395)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CLOSE) {
      // Not capturing CLOSE.
      expr_ret_395 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_395 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_395) rew(mod_395);
  expr_ret_394 = expr_ret_395 ? SUCC : NULL;
  return expr_ret_394 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_ctypeexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_397 = NULL;
  daisho_astnode_t* expr_ret_396 = NULL;
  #define rule expr_ret_396

  daisho_astnode_t* expr_ret_398 = NULL;
  rec(mod_398);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CTYPE) {
      // Not capturing CTYPE.
      expr_ret_398 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_398 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_398)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_398 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_398 = NULL;
    }

  }

  // ModExprList 2
  if (expr_ret_398)
  {
    daisho_astnode_t* expr_ret_399 = NULL;
    expr_ret_399 = SUCC;
    while (expr_ret_399)
    {
      if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_STAR) {
        // Not capturing STAR.
        expr_ret_399 = SUCC;
        ctx->pos++;
      } else {
        expr_ret_399 = NULL;
      }

    }

    expr_ret_399 = SUCC;
    expr_ret_398 = expr_ret_399;
  }

  // ModExprList end
  if (!expr_ret_398) rew(mod_398);
  expr_ret_397 = expr_ret_398 ? SUCC : NULL;
  return expr_ret_397 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_cfuncexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* expr_ret_401 = NULL;
  daisho_astnode_t* expr_ret_400 = NULL;
  #define rule expr_ret_400

  daisho_astnode_t* expr_ret_402 = NULL;
  rec(mod_402);
  // ModExprList 0
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CFUNC) {
      // Not capturing CFUNC.
      expr_ret_402 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_402 = NULL;
    }

  }

  // ModExprList 1
  if (expr_ret_402)
  {
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_CIDENT) {
      // Not capturing CIDENT.
      expr_ret_402 = SUCC;
      ctx->pos++;
    } else {
      expr_ret_402 = NULL;
    }

  }

  // ModExprList end
  if (!expr_ret_402) rew(mod_402);
  expr_ret_401 = expr_ret_402 ? SUCC : NULL;
  return expr_ret_401 ? rule : NULL;
  #undef rule
}

static inline daisho_astnode_t* daisho_parse_preretexpr(daisho_parser_ctx* ctx) {
  daisho_astnode_t* r = NULL;
  daisho_astnode_t* e = NULL;
  daisho_astnode_t* expr_ret_404 = NULL;
  daisho_astnode_t* expr_ret_403 = NULL;
  #define rule expr_ret_403

  daisho_astnode_t* expr_ret_405 = NULL;
  rec(mod_405);
  // ModExprList 0
  {
    daisho_astnode_t* expr_ret_406 = NULL;
    if (ctx->tokens[ctx->pos].kind == DAISHO_TOK_RET) {
      // Capturing RET.
      expr_ret_406 = leaf(RET);
      ctx->pos++;
    } else {
      expr_ret_406 = NULL;
    }

    expr_ret_405 = expr_ret_406;
    r = expr_ret_406;
  }

  // ModExprList 1
  if (expr_ret_405)
  {
    daisho_astnode_t* expr_ret_407 = NULL;
    expr_ret_407 = daisho_parse_expr(ctx);
    expr_ret_405 = expr_ret_407;
    e = expr_ret_407;
  }

  // ModExprList 2
  if (expr_ret_405)
  {
    // CodeExpr
    #define ret expr_ret_405
    ret = SUCC;

    rule=node(RET, r, e);

    #undef ret
  }

  // ModExprList end
  if (!expr_ret_405) rew(mod_405);
  expr_ret_404 = expr_ret_405 ? SUCC : NULL;
  return expr_ret_404 ? rule : NULL;
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

