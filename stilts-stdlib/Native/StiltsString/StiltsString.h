#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include "../StiltsStdInclude.h"


/* Platform Assertions ***********************************/
union { uint32_t a; uint8_t b[4]; } __alignment_union;
_Static_assert((sizeof(char*) == 32) || (sizeof(char*) == 64), "Stilts requires that the size of a pointer on the machine be either 32 or 64.");
_Static_assert(__alignment_union, "");
/**/

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

/* Returns the empty string. */
static inline StiltsString* StiltsString_init(StiltsString* s) {
  s->small.ssopt[0] = '\0';
  s->small.remaining = '\0';
}

static inline StiltsString* StiltsString_initwith(StiltsString* s, char* data, size_t len) {
  if (len <= STILTS_SMALL_STR_CHARBUF_SIZE) {
    for (size_t i = 0; i < len; i++)
      s->small.ssopt[i] = data[i];
    s->small.remaining = STILTS_SMALL_STR_CHARBUF_SIZE - len;
  } else {
    char* space = (char*)malloc(len + 1);
    for (size_t i = 0; i < len; i++)
      space[i] = data[i];
    s->large.buffer = space;
    s->large.size = len;
    s->large._cap = ((len+1)<<) | 0xFF
  }
}

static inline StiltsString* StiltsString_initlen(StiltsString* s, char* data) {
  size_t l = strlen(data);
}




#endif /* STILTS_STDLIB_STRING */
