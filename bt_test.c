#define _GNU_SOURCE 1
#define _DAI_TESTING_BACKTRACES
#include "stdlib/Daisho.h"

void func2(void) {
  _Dai_raise_backtrace();
}

void func1(void) { func2(); }

int main(void) {
    _Dai_init_backtrace();
    func1();
}


