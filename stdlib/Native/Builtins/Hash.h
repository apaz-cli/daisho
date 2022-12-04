#ifndef _DAI_STDLIB_HASH
#define _DAI_STDLIB_HASH
#include "../PreStart/PreStart.h"

_DAI_FN uint32_t
_Dai_murm_fmi32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

_DAI_FN uint64_t
_Dai_murm_fmi64(uint64_t h) {
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53L;
    h ^= h >> 33;
    return h;
}

_DAI_FN uint32_t
_Dai_strhash32(char* str) {
    char c; // djb2
    uint32_t h = 5381;
    while ((c = *str++))
        h = ((h << 5) + h) + c;
    return h;
}

_DAI_FN uint64_t
_Dai_strhash64(char* str) {
    char c; // djb2
    uint64_t h = 5381;
    while ((c = *str++))
        h = ((h << 5) + h) + c;
    return h;
}


#endif /* _DAI_STDLIB_HASH */
