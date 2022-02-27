#ifndef __DAI_STDLIB_RANDOM
#define __DAI_STDLIB_RANDOM
#include "../PreStart/PreStart.h"

// Not threadsafe.
// Not suitable for cryptography.

typedef struct {
    uint64_t state;
} __Dai_Random;

__DAI_FN uint64_t
__Dai_osrand(void) {
    // TODO configure for machines without a /dev/random.
    const char errmsg1[] = "Could not open /dev/random.";
    const char errmsg2[] = "Could not read /dev/random.";
    const char devrand[] = "/dev/random";

    uint64_t ret;
    int rand_fid = open(devrand, O_RDONLY);
    __DAI_SANE_ASSERT(rand_fid != -1, errmsg1);

    int succ = read(rand_fid, &ret, sizeof(ret));
    __DAI_SANE_ASSERT(succ != -1, errmsg2);

    return ret;
}

__DAI_FN void
__Dai_Random_init(__Dai_Random* self, uint64_t seed) {
    self->state = seed;
}

__DAI_FN void
__Dai_Random_init_default(__Dai_Random* self) {
    self->state = 0xabcdef0123456789;
}

__DAI_FN void
__Dai_Random_init_rand(__Dai_Random* self, uint64_t seed) {
    self->state = __Dai_osrand();
}

__DAI_FN uint32_t
__Dai_rand_32(__Dai_Random* self) {
    uint32_t x = (uint32_t)self->state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    self->state = self->state ^ x;
    return x;
}

__DAI_FN uint64_t
__Dai_rand_64(__Dai_Random* self) {
    uint64_t x = self->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    self->state = x;
    return x;
}

__DAI_FN bool
__Dai_rand_bernoulli(__Dai_Random* self, float p) {
    return (__Dai_rand_32(self) * (1. / UINT32_MAX)) <= p;
}

__DAI_FN double
__Dai_rand_gaussian(__Dai_Random* self, double mean, double stddev) {
    /* Polar Box–Muller transform.
       https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform */
    double s1, s2, s;
    do {
        /* Generate two random numbers in (-1, 1) inside a unit circle. */
        s1 = 2 * ((float)(int)__Dai_rand_32(self) / (1.0 * INT32_MAX)) - 1;
        s2 = 2 * ((float)(int)__Dai_rand_32(self) / (1.0 * INT32_MAX)) - 1;
        s = s1 * s1 + s2 * s2;
    } while ((s >= 1) | !s);

    /* Transform onto gaussian normal */
    double normal = s1 * sqrt(-2.0 * log(s) / s);

    /* Skew */
    return (mean + stddev * normal);
}

__DAI_FN double
__Dai_rand_normal(__Dai_Random* self) {
    return __Dai_rand_gaussian(self, 0, 1);
}

#endif /* __DAI_STDLIB_RANDOM */