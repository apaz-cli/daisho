#define _GNU_SOURCE 1
#define _DAI_TESTING_BACKTRACES
#include "stdlib/Daisho.h"

// TODO create a backtrace error enum
// TODO switch _Dai_print_backtrace() to writing to a buffer instead of a fd.
// TODO rewrite the backtrace signal handler to call _Dai_print_backtrace().

int main(void) {
    _Dai_init_backtraces();
    _Dai_print_backtrace(_Dai_backtrace_fd, STDERR_FILENO, 0, 0, 1);
}
