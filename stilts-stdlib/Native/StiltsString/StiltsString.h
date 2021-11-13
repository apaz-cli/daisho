#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include "../StiltsStdInclude.h"

typedef struct {
    char *buffer;
    uint64_t size;
    uint64_t _cap;
} LargeStiltsStr;

#define STILTS_SMALL_STR_CHARBUF_SIZE (sizeof(LargeStiltsStr) - sizeof(uint8_t))

typedef struct {
    char ssopt[STILTS_SMALL_STR_CHARBUF_SIZE];
    uint8_t remaining;
} SmallStiltsStr;

typedef union {
    SmallStiltsStr _small;
    LargeStiltsStr _large;
} StiltsString;

/*********************/
/* Utility functions */
/*********************/

static inline bool
StiltsString_isLarge(StiltsString *s) {
    return s->_small.remaining == 0xFF;
}

static inline size_t
StiltsString_len(StiltsString *s) {
    return StiltsString_isLarge(s) ? (size_t)(s->_large.size)
                                   : (size_t)(STILTS_SMALL_STR_CHARBUF_SIZE -
                                              (s->_small.remaining));
}

/*
 * Setting/getting the cap are only applicable when the StiltsString is large.
 * This method also sets the StiltsString large.
 */
static inline void
__StiltsString_setCap(StiltsString *s, uint64_t cap) {
    int endi = get_endianness();
    if (endi == ENDIANNESS_LITTLE) {
        s->_large._cap = (cap << 8) | 0x00000000000000FF;
    } else if (endi == ENDIANNESS_BIG) {
        s->_large._cap = (cap) | 0x00000000000000FF;
    } else {
        assert(false);
    }
}
static inline uint64_t
__StilltsString_getCap(StiltsString *s) {
    uint64_t cap;
    int endi = get_endianness();
    if (endi == ENDIANNESS_LITTLE) {
        cap = (s->_large._cap & 0xFFFFFFFFFFFFFF00) >> 8;
    } else if (endi == ENDIANNESS_BIG) {
        cap = (s->_large._cap & 0xFFFFFFFFFFFFFF00);
    } else {
        assert(false);
    }
    return cap;
}

/******************************/
/* Constructors / Destructors */
/******************************/

/* Returns the empty string. */
static inline StiltsString *
StiltsString_initempty(StiltsString *s) {
    s->_small.ssopt[0] = '\0';
    s->_small.remaining = STILTS_SMALL_STR_CHARBUF_SIZE;
    return s;
}

static inline StiltsString *
StiltsString_initwith(StiltsString *s, char *data, uint64_t len) {
    /* Small */
    if (len <= STILTS_SMALL_STR_CHARBUF_SIZE) {
        /* Use small string optimization */
        for (size_t i = 0; i < len; i++) s->_small.ssopt[i] = data[i];
        s->_small.remaining = STILTS_SMALL_STR_CHARBUF_SIZE - len;
    }

    /* Large */
    else {
        /* Allocate and copy */
        char *space = (char *)malloc(len + 1);
        for (size_t i = 0; i < len; i++) space[i] = data[i];
        s->_large.buffer = space;
        s->_large.size = len;

        /* Set cap and large flag. */
        __StiltsString_setCap(s, len + 1);
    }

    return s;
}

static inline StiltsString *
StiltsString_initWithMallocedData(StiltsString *s, char *data, uint64_t cap,
                                  uint64_t len) {
    s->_large.buffer = data;
    s->_large.size = len;
    __StiltsString_setCap(s, cap);
    return s;
}

static inline StiltsString *
StiltsString_initlen(StiltsString *s, char *data) {
    return StiltsString_initwith(s, data, (uint64_t)strlen(data));
}

static inline StiltsString *
StiltsString_copy(StiltsString *s, StiltsString *toCopy) {
    return StiltsString_isLarge(toCopy)
               ? StiltsString_initwith(s, s->_large.buffer,
                                       StiltsString_len(toCopy))
               : StiltsString_initwith(s, s->_small.ssopt,
                                       StiltsString_len(toCopy));
}

static inline void
StiltsString_destroy(StiltsString *s) {
    if (StiltsString_isLarge(s)) free(s);
}

#endif /* STILTS_STDLIB_STRING */
