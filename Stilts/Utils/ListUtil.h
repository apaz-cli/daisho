#ifndef INCLUDE_LISTUTIL
#define INCLUDE_LISTUTIL
#include "MemConfig.h" // Includes a memory debugger that wraps malloc()

#define LIST_DEFINE(type)                                                      \
  typedef type *List_##type;                                                   \
  static inline List_##type List_##type##_new(size_t capacity) {               \
    void *vptr = malloc(sizeof(size_t) * 2 + sizeof(type) * capacity);         \
    size_t *stptr = (size_t *)vptr;                                            \
    *stptr = 0;                                                                \
    stptr += 1;                                                                \
    *stptr = capacity;                                                         \
    stptr += 1;                                                                \
    return (List_##type)stptr;                                                 \
  }                                                                            \
  static inline List_##type List_##type##_resize(List_##type to_resize,        \
                                                 size_t new_capacity) {        \
    size_t *vptr = ((size_t *)to_resize) - 2;                                  \
    const size_t new_s = sizeof(size_t) * 2 + sizeof(type) * new_capacity;     \
    size_t *stptr = (size_t *)realloc(vptr, new_s);                            \
    stptr += 1;                                                                \
    *stptr = new_capacity;                                                     \
    stptr += 1;                                                                \
    return (List_##type)stptr;                                                 \
  }                                                                            \
  static inline void List_##type##_destroy(List_##type to_destroy) {           \
    free(((size_t *)to_destroy) - 2);                                          \
  }                                                                            \
  static inline size_t List_##type##_len(List_##type list) {                   \
    return *(((size_t *)list) - 2);                                            \
  }                                                                            \
  static inline void __List_##type##_setlen(List_##type list,                  \
                                            size_t new_len) {                  \
    *(((size_t *)list) - 2) = new_len;                                         \
  }                                                                            \
  static inline size_t List_##type##_cap(List_##type list) {                   \
    return *(((size_t *)list) - 1);                                            \
  }                                                                            \
  static inline void __List_##type##_setcap(List_##type list,                  \
                                            size_t new_cap) {                  \
    *(((size_t *)list) - 1) = new_cap;                                         \
  }                                                                            \
  static inline void List_##type##_add(List_##type list, type to_append) {     \
    size_t current_len = List_##type##_len(list);                              \
    size_t current_cap = List_##type##_cap(list);                              \
    if (current_len == current_cap) {                                          \
      list = List_##type##_resize(list, (size_t)(current_cap * 1.5) + 16);     \
    }                                                                          \
    list[current_len] = to_append;                                             \
    __List_##type##_setlen(list, current_len + 1);                             \
  }                                                                            \
  static inline void List_##type##_pop(List_##type list) {                     \
    __List_##type##_setlen(list, List_##type##_len(list) - 1);                 \
  }                                                                            \
  static inline type *List_##type##_peek(List_##type list) {                   \
    return list + (List_##type##_len(list) - 1);                               \
  }

#endif // INCLUDE_LISTUTIL