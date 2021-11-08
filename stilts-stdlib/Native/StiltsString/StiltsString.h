#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include "../StiltsStdInclude.h"

#define STILTS_STR_FLAG_VAL ((char)0xFF)


#define STILTS_STR_WRITE_FLAG(s, v) \
    do {\
        s.small.remaining = v;\
    } while(0);
#define STILTS_STR_READ_FLAG(s) (((char*)&s)[sizeof(s)-1])


#define STILTS_STR_LARGE_WRITE_CAP(s, v) \
    do {\
        size_t tmp = 0;\
        tmp &= (s.large._cap & 0xFF);\
        tmp &= (v << CHAR_BIT);\
        s.large._cap = tmp;\
    } while(0);
#define STILTS_STR_LARGE_READ_CAP(s) (s.large._cap >> (CHAR_BIT))

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
