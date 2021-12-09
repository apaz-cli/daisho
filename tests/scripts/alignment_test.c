#include <apaz-libc.h>

const size_t NITS = 10000;
const size_t alignments[] = {1, 2, 4, 8, 16};

int
main(void) {
    for (size_t j = 0; j < 5; j++)
        for (size_t i = 0; i < NITS; i++)
            if (_roundToAlignment(i, alignments[j]) % alignments[j]) return 1;
    // printf("%zu: %zu\n", i, _roundToAlignment(i, alignments[j]));

    puts("SUCCESS");
    return 0;
}
