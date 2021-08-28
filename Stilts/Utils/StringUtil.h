#ifndef STRUTIL_INCLUDE
#define STRUTIL_INCLUDE
#include <stdlib.h>
#include "MemConfig.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

typedef char *String;

static inline String String_new(size_t len) {
  void *ptr = malloc(sizeof(size_t) + len + 1);
  *((size_t *)ptr) = len;
  String data = ((String)ptr) + sizeof(size_t);
  data[len] = '\0';
  return data;
}

static inline String String_resize(String str, size_t new_size) {
  void *ptr = str - sizeof(size_t);
  ptr = realloc(ptr, sizeof(size_t) + new_size + 1);
  *((size_t *)ptr) = new_size;
  String data = ((String)ptr) + sizeof(size_t);
  data[new_size] = '\0';
  return data;
}

static inline void String_destroy(String str) { free(str - sizeof(size_t)); }

static inline size_t String_len(String str) {
  return *((size_t *)(str - sizeof(size_t)));
}

static inline String String_add(String str1, String str2) {
  size_t sl1 = String_len(str1), sl2 = String_len(str2);
  size_t sl3 = sl1 + sl2;
  String ns = String_new(sl3);
  size_t i = 0, j = 0;
  for (; i < sl1; i++)
    ns[i] = str1[i];
  for (; j < sl2; i++, j++)
    ns[i] = str2[j];
  ns[sl3] = '\0';
  return ns;
}

static inline String String_add_equals(String base, String to_append) {
  size_t blen = String_len(base), alen = String_len(to_append);
  size_t nlen = blen + alen;
  base = String_resize(base, nlen);
  for (size_t i = 0; i < nlen; i++)
    base[blen + i] = to_append[i];
  return base;
}

static inline String String_copy(String source, String dest) {
  size_t slen = String_len(source);
  size_t dlen = String_len(dest);
  size_t minlen = MIN(slen, dlen);
  for (size_t i = 0; i < minlen; i++)
    dest[i] = source[i];
  return source;
}

static inline String String_clone(String to_clone) {
  String ns = String_new(String_len(to_clone));
  String_copy(to_clone, ns);
  return ns;
}

static inline String String_substring_copy(String str, size_t start,
                                           size_t end) {
  String ns = String_new(end - start);
  String_copy(str, ns);
  return ns;
}

#endif // STRUTIL_INCLUDE