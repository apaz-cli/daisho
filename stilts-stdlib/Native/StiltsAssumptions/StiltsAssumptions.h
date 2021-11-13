#ifndef STILTS_STDLIB_ASSUMPTIONS
#define STILTS_STDLIB_ASSUMPTIONS

#include <stdint.h>


#define ENDIANNESS_OTHER  0
#define ENDIANNESS_LITTLE 1
#define ENDIANNESS_BIG    2

static inline int get_endianness() {
  union {
    uint32_t a;
    uint8_t  b[4];
  } endi;
  endi.a = 0x01020304;

  switch (endi.b[0]) {
    case 0x01: return ENDIANNESS_BIG;
    case 0x04: return ENDIANNESS_LITTLE;
    default:   return ENDIANNESS_OTHER;
  }
}

#endif
