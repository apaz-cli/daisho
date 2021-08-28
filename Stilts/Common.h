#ifndef COMMON_INCLUDES
#define COMMON_INCLUDES

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Macros

#define PANIC(err_msg)                                                         \
  do {                                                                         \
    printf("%s\n", err_msg);                                                   \
    fflush(stdout);                                                            \
    exit(2);                                                                   \
  } while (0);

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

// Inline functions

inline void *pmalloc(size_t size, char *err_msg) {
  void *ptr = malloc(size);
  if (!ptr)
    PANIC(err_msg);
  return ptr;
}

inline void *prealloc(void *ptr, size_t new_size, char *err_msg) {
  ptr = realloc(ptr, new_size);
  if (!ptr)
    PANIC(err_msg)
  return ptr;
}

inline void pfree(void *ptr) { free(ptr); }

#endif // COMMON_INCLUDES