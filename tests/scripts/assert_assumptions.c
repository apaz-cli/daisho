#include "../../stilts-stdlib/Native/Stilts.h"

int
main() {
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
