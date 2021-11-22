#include "../../stilts-stdlib/Native/Stilts.h"

int
main() {
    int endi = get_endianness();
    printf("Endianness: ");
    if (endi == ENDIANNESS_BIG)
        puts("BIG");
    else if (endi == ENDIANNESS_LITTLE)
        puts("LITTLE");
    else {
        puts("ERROR");
        fprintf(stderr,
                "STILTS IS NOT SUPPORTED ON UNKNOWN ENDIANNES PLATFORMS.\n");
        return 1;
    }

    if (SIZE_MAX <= UINT64_MAX) {
        puts("size_t is correctly sized.");
    } else {
        fprintf(stderr, "size_t is not correctly sized. It must be smaller than or the same as uint64_t.");
        return 2;
    }

    printf("Using small string optimization size of: %zu.\n", sizeof(__Stilts_String) - sizeof(uint8_t));
}
