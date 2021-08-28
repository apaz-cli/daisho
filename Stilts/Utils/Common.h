#ifndef COMMON_INCLUDES
#define COMMON_INCLUDES

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ListUtil.h"
#include "StringUtil.h"


// Test string types and multiple applications.

// Because a * cannot be inside a function name macro expansion.
typedef void *void_ptr;
LIST_DEFINE(void_ptr);
LIST_DEFINE(String);
LIST_DEFINE(List_String);
LIST_DEFINE(List_void_ptr);
LIST_DEFINE_MONAD(String, void_ptr);

// Test Integral types
LIST_DEFINE(char);
LIST_DEFINE(int);


// Test Structs
struct s { };
typedef struct s s;
LIST_DEFINE(s);
LIST_DEFINE(List_s);

void *testhelp(String s) { return (void *)s; }
void test() {
  String s = String_new_of_strlen("aa");
  List_String ls = List_String_new_of(&s, 1, 1);
}

#endif // COMMON_INCLUDES