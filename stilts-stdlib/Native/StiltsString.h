#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *buffer;
  size_t size;
  size_t _cap;
} LargeStiltsStr;

#define STILTS_SMALL_STR_CHARBUF_SIZE (sizeof(LargeStiltsStr) - 1)

typedef struct {
  char ssopt[STILTS_SMALL_STR_CHARBUF_SIZE];
  char remaining;
} SmallStiltsStr;

typedef union {
  SmallStiltsStr small;
  LargeStiltsStr large;
} StiltsString;

#endif /* STILTS_STDLIB_STRING */