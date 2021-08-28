#ifndef COMMON_INCLUDES
#define COMMON_INCLUDES

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ListUtil.h"
#include "StringUtil.h"

LIST_DEFINE(size_t);
typedef void *void_ptr;
LIST_DEFINE(void_ptr);
LIST_DEFINE(String);

#endif // COMMON_INCLUDES