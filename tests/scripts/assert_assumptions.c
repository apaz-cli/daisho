#include "../../stilts-stdlib/Native/Stilts.h"

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


int main() {
    int endi = get_endianness();
    if (endi != ENDIANNESS_LITTLE) {
        fprintf(stderr,
                "The Stilts standard library is not supported on "
                "big-endian or unknown endianness platforms.\n");
        return 1;
    }

    if (sizeof(uint8_t) != 1) {
        fprintf(stderr,
                "The Stilts standard library assumes that the size of uint8_t "
                "on the machine is one.\n");
        return 2;
    }

    if (!(SIZE_MAX <= UINT64_MAX)) {
        fprintf(stderr,
                "The Stilts standard library assumes that size_t's max value "
                "is less than or equal to uint64_t's max value.\n");
        return 3;
    }

    if (!setlocale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "Could not set locale to utf8.\n");
        return 4;
    }

    puts("SUCCESS");
}
