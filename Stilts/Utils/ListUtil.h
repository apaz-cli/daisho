#ifndef INCLUDE_LISTUTIL
#define INCLUDE_LISTUTIL
#include <stdbool.h>
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
  static inline List_##type List_##type##_new_of(                              \
      type *items, size_t num_items, size_t capacity) {                        \
    List_##type nl = List_##type##_new(capacity);                              \
    for (size_t i = 0; i < num_items; i++)                                     \
      nl[i] = items[i];                                                        \
    return nl;                                                                 \
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
  static inline void List_##type##_trim(List_##type list) {                    \
    List_##type##_resize(list, List_##type##_len(list));                       \
  }                                                                            \
  static inline List_##type List_##type##_clone(List_##type to_clone) {        \
    List_##type nl = List_##type##_new(List_##type##_len(to_clone));           \
    for (size_t i = 0; i < List_##type##_len(to_clone); i++)                   \
      nl[i] = to_clone[i];                                                     \
    return nl;                                                                 \
  }                                                                            \
  static inline void List_##type##_add(List_##type list, type to_append) {     \
    size_t current_len = List_##type##_len(list);                              \
    size_t current_cap = List_##type##_cap(list);                              \
    if (current_len == current_cap)                                            \
      list = List_##type##_resize(list, (size_t)(current_cap * 1.5) + 16);     \
    list[current_len] = to_append;                                             \
    __List_##type##_setlen(list, current_len + 1);                             \
  }                                                                            \
  static inline void List_##type##_pop(List_##type list) {                     \
    __List_##type##_setlen(list, List_##type##_len(list) - 1);                 \
  }                                                                            \
  static inline type *List_##type##_peek(List_##type list) {                   \
    return list + (List_##type##_len(list) - 1);                               \
  }

#define LIST_DEFINE_MONAD(type, map_type)                                      \
  static inline List_##map_type List_##type##_map_to_##map_type(               \
      List_##type list, map_type (*mapper)(type, void *), void *extra_data) {  \
    /* TODO Add case for sizeof(type)==sizeof(map_type) */                     \
    List_##map_type nl = List_##map_type##_new(List_##type##_len(list));       \
    for (size_t i = 0; i < List_##type##_len(list); i++)                       \
      nl[i] = mapper(list[i], extra_data);                                     \
    List_##type##_destroy(list);                                               \
    return nl;                                                                 \
  }                                                                            \
  static inline List_##type List_##type##filter(                               \
      List_##type list, bool (*filter_fn)(type, void *), void *extra_data) {   \
    /* Since the list would be destroyed anyway, it can be reused. */          \
    for (size_t i = 0, retained = 0; i < List_##type##_len(list); i++)         \
      if (filter_fn(list[i], extra_data))                                      \
        list[retained++] = list[i];                                            \
    return list;                                                               \
  }                                                                            \
  static inline List_##map_type List_##type##_flatmap_to_##map_type(           \
      List_##type list, List_##map_type (*mapper)(type, void *),               \
      void *extra_data) {                                                      \
    size_t nll_len = List_##type##_len(list), size_sum = 0;                    \
    List_List_##map_type nll = List_List_##map_type##_new(nll_len);            \
    for (size_t i = 0; i < nll_len; i++) {                                     \
      List_##map_type ml = mapper(list[i], extra_data);                        \
      nll_len += List_##map_type##_len(ml);                                    \
      nll[i] = ml;                                                             \
    }                                                                          \
    /* TODO Optimize with buffer re-use if possible.*/                         \
    /* TODO Debate using a VLA in place of nll. */                             \
    List_##map_type retlist = List_##map_type##_new(size_sum);                 \
    for (size_t i = 0; i < nll_len; i++)                                       \
      for (size_t j = 0; j < List_##map_type##_len(nll[i]); j++)               \
        retlist[j] = nll[i][j];                                                \
    List_##type##_destroy(list);                                               \
    return retlist;                                                            \
  }                                                                            \
  static inline void List_##type##_foreach(                                    \
      List_##type list, void (*action_fn)(type, void *), void *extra_data) {   \
    for (size_t i = 0; i < List_##type##_len(list); i++)                       \
      action_fn(list[i], extra_data);                                          \
    List_##type##_destroy(list);                                               \
  }

#endif // INCLUDE_LISTUTIL