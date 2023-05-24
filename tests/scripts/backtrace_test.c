#define _DAI_TESTING_BACKTRACES 1
#include "../../stdlib/Daisho.h"

void
f1(void) {
    _Dai_raise_backtrace();
}

void
f2(void) {
    f1();
}

int
main(void) {
    _Dai_initialize();
    f2();
    puts("SUCCESS");
}
