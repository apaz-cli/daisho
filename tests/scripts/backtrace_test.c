#define _DAI_NO_LIBRARIES 1
#define _DAI_TESTING_BACKTRACES 1
#include "../../stdlib/Daisho.h"

void
f1(void) {
    _Dai_unsafe_print_backtrace();
}

void
f2(void) {
    f1();
}

int
main(int argc, char** argv) {
    _Dai_initialize(argc, argv);
    f2();
    puts("SUCCESS");
}
