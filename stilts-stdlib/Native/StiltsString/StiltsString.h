#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include "../StiltsStdInclude.h"

typedef struct {
  char*     buffer;
  uint64_t  size;
  uint64_t _cap;
} LargeStiltsStr;

#define STILTS_SMALL_STR_CHARBUF_SIZE ((sizeof(LargeStiltsStr) / sizeof(uint8_t)) - 1)

typedef struct {
  uint8_t ssopt[STILTS_SMALL_STR_CHARBUF_SIZE];
  uint8_t remaining;
} SmallStiltsStr;

typedef union {
  SmallStiltsStr small;
  LargeStiltsStr large;
} StiltsString;

static inline bool
StiltsString_isLarge(StiltsString* s) {
  return s->small.remaining == 0xFF;
}

static inline size_t
StiltsString_len(StiltsString* s) {
  return StiltsString_isLarge(s) ?
         (size_t)(s->large.size) :
         (size_t)(STILTS_SMALL_STR_CHARBUF_SIZE - (s->small.remaining));
}

/*
 * Setting/getting the cap are only applicable when the StiltsString is large.
 * This method also sets the StiltsString large.
 */
static inline void
__StiltsString_setCap(StiltsString* s, uint64_t cap) {
    int endi = get_endianness();
    if (endi == ENDIANNESS_LITTLE) {
      s->large._cap = (cap << 8) | 0x00000000000000FF;
    } else if (endi == ENDIANNESS_BIG) {
      s->large._cap = (cap)        | 0x00000000000000FF;
    } else {
      assert(false);
    }
}
static inline uint64_t
__StilltsString_getCap(StiltsString* s) {
  uint64_t cap;
  int endi = get_endianness();
  if (endi == ENDIANNESS_LITTLE) {
    cap = (s->large._cap & 0xFFFFFFFFFFFFFF00) >> 8;
  } else if (endi == ENDIANNESS_BIG) {
    cap = (s->large._cap & 0xFFFFFFFFFFFFFF00);
  } else {
    assert(false);
  }
  return cap;
}


/* Platform Assertions ***********************************/
// _Static_assert((sizeof(char*) == 4) || (sizeof(char*) == 8), "Stilts requires that the size of a pointer on the machine (in bytes) be either 4 or 8, usually corresponding to 32 or 64 bits.");
// _Static_assert(sizeof(uintptr_t) == sizeof(char*),           "The size of uintptr_t is not the same size as a char*.")
/**/

/* Returns the empty string. */
static inline StiltsString*
StiltsString_initempty(StiltsString* s) {
  s->small.ssopt[0] = '\0';
  s->small.remaining = STILTS_SMALL_STR_CHARBUF_SIZE;
}

static inline StiltsString*
StiltsString_initwith(StiltsString* s, char* data, uint64_t len) {
  /* Small */
  if (len <= STILTS_SMALL_STR_CHARBUF_SIZE) {
    /* Use small string optimization */
    for (size_t i = 0; i < len; i++)
      s->small.ssopt[i] = data[i];
    s->small.remaining = STILTS_SMALL_STR_CHARBUF_SIZE - len;
  }

  /* Large */
  else {
    /* Allocate and copy */
    char* space = (char*)malloc(len + 1);
    for (size_t i = 0; i < len; i++)
      space[i] = data[i];
    s->large.buffer = space;
    s->large.size = len;

    /* Set cap and large flag. */
    __StiltsString_setCap(s, len+1);
  }

  return s;
}

static inline StiltsString*
StiltsString__copy(StiltsString* s, StiltsString* toCopy) {
}

static inline StiltsString*
StiltsString_initlen(StiltsString* s, char* data) {
  return StiltsString_initwith(s, data, (uint64_t)strlen(data));
}




#endif /* STILTS_STDLIB_STRING */
