#define MEMDEBUG 1
#include <apaz-libc.h>

int popt() {
  Arena a = Arena_new("popt");
  for (size_t i = 0; i < 50; i++)
    Arena_malloc(&a, i);
  for (size_t i = 50; i --> 0; ) {
    Arena_pop(&a, i)
  }
  size_t ret = arena->buf_size;
  Arena_destroy(&a, false, true);

  return (int)ret | (int)get_num_allocs();
}

int sar() {
  Arena* a = (Arena*)malloc(sizeof(Arena));

  for (size_t i = 0; i < 100000; i++) Arena_malloc(a, i);
  Arena_destroy(a, true, false);
  return (int)get_num_allocs();
}

int har() {
  Arena a = Arena_new("har");

  for (size_t i = 0; i < 100000; i++) Arena_malloc(&a, i);
  Arena_destroy(&a, false, true);
  return (int)get_num_allocs();
}

int nar() {
  size_t asize = 10000;
  Arena a;
  char buffer[asize];
  Arena_init(&a, "nar", buffer, asize);

  for (size_t i = 0; i < 100000; i++) Arena_malloc(&a, i);
  Arena_destroy(&a, false, false);
  return (int)get_num_allocs();
}

int bar() {
  size_t asize = 1000;
  Arena* a = (Arena*)malloc(sizeof(Arena));
  void* buf = malloc(asize);
  Arena_init(a, "bar", asize);

  for (size_t i = 0; i < 100000; i++) Arena_malloc(a, i);
  Arena_destroy(a, true, true);
  return (int)get_num_allocs();
}

int main() {
  if (sar()) return 1;
  if (har()) return 2;
  if (bar()) return 3;
  if (nar()) return 4;
  if (popt()) return 5;
  return 0;
}
