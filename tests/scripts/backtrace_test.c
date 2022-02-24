#include "../../stdlib/Daisho.h"

void
f1(void) {
    __Dai_print_backtrace();
}

void
f2(void) {
    f1();
}

int
main(int argc, char** argv) {
    __Dai_initialize(argc, argv);
    f2();
    puts("SUCCESS");
}
