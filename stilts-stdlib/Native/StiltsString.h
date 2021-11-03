#ifndef STILTS_STDLIB_STRING
#define STILTS_STDLIB_STRING
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef STD_STR_CHARBUF_LEN
#ifndef STD_STR_CHARBUF_LEN 23
#endif

struct StiltsString {
    char  ssopt[STD_STR_CHARBUF_LEN];
    uchar remaining;
};
typedef struct StiltsString StiltsString;





#endif /* STILTS_STDLIB_STRING */




