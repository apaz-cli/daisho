
#include "StiltsStdInclude.h"


/*****************/
/* Sanity checks */
/*****************/

/* Endianness */
typedef enum {
  BIG,
  LITTLE,
  OTHER,
} Endianness;

typedef union {
  uint32_t a;
  uint8_t  b[4];
} Endi;

static const Endi endi = 0x01020304;

Endianness get_endianness() {
  switch (endi[0]) {
    case 0x01: return BIG;
    case 0x02: return OTHER;
    case 0x03: return OTHER;
    case 0x04: return LITTLE;
    default:   return OTHER;
  };
}

/**************************************/
/* Main (Called during bootstrapping) */
/**************************************/

/*
 * The Stilts runtime and standard library makes (hopefully reasonable)
 * assumptions about the platform. This program validates those assuptions.
 */
int main() {
  
}
