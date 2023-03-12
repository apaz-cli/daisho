#ifndef _DAI_STDLIB_RANDOM
#define _DAI_STDLIB_RANDOM
#include "../PreStart/PreStart.h"

// Not threadsafe.
// Not suitable for cryptography.

typedef struct {
    uint64_t state;
} _Dai_Random;

_DAI_FN uint64_t
_Dai_osrand(void) {
    // TODO configure for machines without a /dev/random.
    const char errmsg1[] = "Could not open /dev/random.";
    const char errmsg2[] = "Could not read /dev/random.";
    const char devrand[] = "/dev/random";

    uint64_t ret;
    int rand_fid = open(devrand, O_RDONLY);
    _DAI_SANE_ASSERT(rand_fid != -1, errmsg1);

    int succ = read(rand_fid, &ret, sizeof(ret));
    _DAI_SANE_ASSERT(succ != -1, errmsg2);

    return ret;
}

_DAI_FN void
_Dai_Random_init(_Dai_Random* self, uint64_t seed) {
    self->state = seed;
}

_DAI_FN void
_Dai_Random_init_default(_Dai_Random* self) {
    self->state = 0xabcdef0123456789;
}

_DAI_FN void
_Dai_Random_init_rand(_Dai_Random* self) {
    self->state = _Dai_osrand();
}

_DAI_FN uint32_t
_Dai_rand_32(_Dai_Random* self) {
    uint32_t x = (uint32_t)self->state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    self->state = self->state ^ x;
    return x;
}

_DAI_FN uint64_t
_Dai_rand_64(_Dai_Random* self) {
    uint64_t x = self->state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    self->state = x;
    return x;
}

_DAI_FN bool
_Dai_rand_bernoulli(_Dai_Random* self, float p) {
    return (_Dai_rand_32(self) * (1. / UINT32_MAX)) <= p;
}

/*
_DAI_FN double
_Dai_rand_gaussian(_Dai_Random* self, double mean, double stddev) {
    // Polar Box–Muller transform. https://en.wikipedia.org/wiki/Box%E2%80%93Muller_transform
    double s1, s2, s;
    do {
        // Generate two random numbers in (-1, 1) inside a unit circle.
        s1 = 2 * ((float)(int)_Dai_rand_32(self) / (1.0 * INT32_MAX)) - 1;
        s2 = 2 * ((float)(int)_Dai_rand_32(self) / (1.0 * INT32_MAX)) - 1;
        s = s1 * s1 + s2 * s2;
    } while ((s >= 1) | !s);

    // Transform onto gaussian normal
    double normal = s1 * sqrt(-2.0 * log(s) / s);

    // Skew
    return (mean + stddev * normal);
}
*/

/*
_DAI_FN double
_Dai_rand_normal(_Dai_Random* self) {
    return _Dai_rand_gaussian(self, 0, 1);
}
*/

#endif /* _DAI_STDLIB_RANDOM */
