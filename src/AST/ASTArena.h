#ifndef ASTARENA_INCLUDE
#define ASTARENA_INCLUDE

#include <stdio.h>
#include <stdlib.h>

#ifndef ASTARENA_BT
#define ASTARENA_BT 0
#endif

// Find out how large a page is with the "getconf PAGESIZE" command.
// Mine happens to be 4096.
#define PAGE_SIZE 4096
#define NUM_PAGES 64
#define ARENA_SIZE (PAGE_SIZE * NUM_PAGES)

struct ASTArena;
typedef struct ASTArena ASTArena;
struct ASTArena {
  ASTArena *next;

  void *buffer;
  size_t buf_size;
  size_t buf_cap;
};

/* Helpers */
static inline size_t _roundToAlignment(size_t n, size_t alignment) {
  return (n + alignment - 1) / alignment * alignment;
}
#define _ARENA_STR_EVAL(tok) #tok
#define _ARENA_STR(tok) _ARENA_STR_EVAL(tok)

#if ASTARENA_BT
/************************************/
/*            Backtrace             */
/************************************/
#define _ARENA_STR_EVAL(tok) #tok
#define _ARENA_STR(tok) _ARENA_STR_EVAL(tok)

#define _ASTARENA_ASSERT(_NodeType)                                            \
  /* For speed, I assume that everything is aligned to _Alignof(void*). */     \
  _Static_assert(_Alignof(_NodeType) <= _Alignof(void *),                      \
                 "Invalid void* alignment assumption for type: " _ARENA_STR(   \
                     _NodeType) ".");
#define _ASTARENA_NAME(_NodeType)                                              \
  /* String literal with the name of the rule */                               \
  static char __ASTARENA_NAME_##_NodeType[] = _ARENA_STR(_NodeType);
#define _ASTARENA_SIZE(_NodeType)                                              \
  static const size_t __ASTARENA_##_NodeType##_FRAME_SIZE =                    \
      sizeof(_NodeType) + sizeof(char *) + sizeof(size_t);
#define _ASTARENA_TRACK_ALLOC(_NodeType)                                       \
  do {                                                                         \
    *((char **)(stack_frame + sizeof(_NodeType))) =                            \
        __ASTARENA_NAME_##_NodeType;                                           \
    *((size_t *)(stack_frame + sizeof(_NodeType) + sizeof(char *))) =          \
        __ASTARENA_##_NodeType##_FRAME_SIZE;                                   \
  } while (0);
#else
/************************************/
/*           No Backtrace           */
/************************************/
#define _ASTARENA_ASSERT(_NodeType) ;
#define _ASTARENA_NAME(_NodeType) ;
#define _ASTARENA_SIZE(_NodeType)                                              \
  static const size_t __ASTARENA_##_NodeType##_FRAME_SIZE = sizeof(_NodeType);
#define _ASTARENA_TRACK_ALLOC(_NodeType) ;
#endif

/************************************/
/*              Methods             */
/************************************/

static inline ASTArena *ASTArena_init(void *buffer, size_t buf_cap) {
  if (!buffer | (buf_cap < sizeof(ASTArena))) {
    fprintf(stderr, "Out of memory allocating an arena.\n");
    exit(1);
  }

  ASTArena *arena = (ASTArena *)buffer;
  arena->buffer = (((char *)buffer) + sizeof(ASTArena));
  arena->buf_size = 0;
  arena->buf_cap = buf_cap - sizeof(ASTArena);
  arena->next = NULL;
  return arena;
}

static inline ASTArena *ASTArena_new() {
  return ASTArena_init(malloc(ARENA_SIZE), ARENA_SIZE);
}

static inline ASTArena *_ASTArena_new_on(ASTArena *arena) {
  // Allocate a new Arena.
  ASTArena *new_arena = ASTArena_new();
  if (!new_arena) {
    fprintf(stderr, "Out of memory allocating arena.\n");
    exit(1);
  }

  // Throw it into the LL.
  while (arena->next)
    arena = arena->next;
  arena->next = new_arena;

  return new_arena;
}

static inline void ASTArena_destroy(ASTArena *arena) {
  ASTArena *f = arena->next;
  free(arena);
  if (f)
    ASTArena_destroy(f);
}

#define _ASTARENA_ALLOC(_NodeType)                                             \
  /* A function, specifically to allocate this type. */                        \
  static inline _NodeType *ASTArena_alloc_##_NodeType(ASTArena *arena) {       \
    /* Find the first arena with space in it, or make a new one. */            \
    size_t newsize;                                                            \
    do {                                                                       \
      newsize = arena->buf_size + __ASTARENA_##_NodeType##_FRAME_SIZE;         \
      if (!(newsize <= ARENA_SIZE)) {                                          \
        if (!arena->next)                                                      \
          arena = arena->next = _ASTArena_new_on(arena);                       \
        else                                                                   \
          arena = arena->next;                                                 \
      } else                                                                   \
        break;                                                                 \
    } while (1);                                                               \
                                                                               \
    /* Allocate */                                                             \
    char *stack_frame = ((char *)arena->buffer) + arena->buf_size;             \
    arena->buf_size = newsize;                                                 \
                                                                               \
    /* Keep track of the size of the allocation for backtrace */               \
    _ASTARENA_TRACK_ALLOC(_NodeType)                                           \
                                                                               \
    return (_NodeType *)stack_frame;                                           \
  }

#define _ASTARENA_FREE(_NodeType)                                              \
  /* Pops the width of an allocation of this type. */                          \
  static inline void ASTArena_free_##_NodeType(ASTArena *arena) {              \
    arena->buf_size -= __ASTARENA_##_NodeType##_FRAME_SIZE;                    \
  }

#define ASTARENA_REGISTER(_NodeType)                                           \
  _ASTARENA_ASSERT(_NodeType)                                                  \
  _ASTARENA_NAME(_NodeType)                                                    \
  _ASTARENA_SIZE(_NodeType)                                                    \
  _ASTARENA_ALLOC(_NodeType)                                                   \
  _ASTARENA_FREE(_NodeType)

static inline void _ASTArena_bt_helper(ASTArena *arena) {
  if (arena->next)
    _ASTArena_bt_helper(arena->next);
  size_t stack_size = arena->buf_size;
  while (stack_size) {
    char *frame_size_loc =
        (char *)arena->buffer + (stack_size - sizeof(size_t));
    size_t frame_size;

    stack_size -= *(size_t *)frame_size_loc;

    fflush(stdout);
    char *rule_name = *(char **)(frame_size_loc - sizeof(char *));

    puts(rule_name);
  }
}

#if ASTARENA_BT
static inline void ASTArena_backtrace(ASTArena *arena) {
  printf("Parser rule backtrace:\n");
  _ASTArena_bt_helper(arena);
  putchar('\n');
}
#else
static inline void ASTArena_backtrace(ASTArena *arena) { (void)arena; }
#endif

#endif // ASTARENA_INCLUDE

/************************************/
/*          Example Usage           */
/************************************/

/*

#include <stdbool.h>
#include <stddef.h>

#define REGISTER_EXAMPLE(name, type)                                           \
  struct name {                                                                \
    type a;                                                                    \
  };                                                                           \
  typedef struct name name;                                                    \
  ASTARENA_REGISTER(name);

REGISTER_EXAMPLE(REEEE, char);
REGISTER_EXAMPLE(EEEEE, short)
REGISTER_EXAMPLE(OWO, FILE);
REGISTER_EXAMPLE(UWU, int);
REGISTER_EXAMPLE(OMO, size_t);
REGISTER_EXAMPLE(UGU, void *);
REGISTER_EXAMPLE(O_O, ptrdiff_t);
REGISTER_EXAMPLE(U_U, bool);

int main() {
  ASTArena *arena = ASTArena_new();

  ASTArena_alloc_OWO(arena);
  ASTArena_alloc_UWU(arena);
  ASTArena_alloc_OMO(arena);
  ASTArena_alloc_UGU(arena);
  ASTArena_alloc_O_O(arena);
  ASTArena_alloc_U_U(arena);

  ASTArena_alloc_REEEE(arena);
  for (size_t i = 0; i < 10000000; i++)
    ASTArena_alloc_EEEEE(arena);

  ASTArena_backtrace(arena);

  ASTArena_destroy(arena);
}
*/