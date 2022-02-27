#define __GNU_SOURCE
#define __DAI_NO_LIBRARIES
#include "../../stdlib/Daisho.h"

int main(void) {
    srand(time(0));
    uint64_t seed = (uint64_t)rand();
    seed |= (uint64_t)rand() << 32;

    __Dai_Random rand;
    __Dai_Random_init(&rand, seed);

    for (size_t i = 0; i < 10; i++) {
        printf("%f\n", __Dai_rand_normal(&rand));
    }

}
