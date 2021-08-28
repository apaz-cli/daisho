#ifndef COMMON_INCLUDES
#define COMMON_INCLUDES

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ListUtil.h"
#include "StringUtil.h"

// Because a * cannot be inside a function name macro expansion.
typedef void *void_ptr;

// So I can type one less underscore
typedef size_t sizet;

LIST_DEFINE(sizet);
LIST_DEFINE(void_ptr);
LIST_DEFINE(String);

#endif // COMMON_INCLUDES