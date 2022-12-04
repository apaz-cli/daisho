#include <execinfo.h>

#define _DAI_SANITY_CHECK 2
#define _DAI_TESTING_BACKTRACES
#define _DAI_NO_LIBRARIES
#include "../stdlib/Daisho.h"

void
sighandler(int sig, siginfo_t* info, void* ucontext) {
    ucontext_t ctx = *(ucontext_t*)ucontext;
    fprintf(stderr, "In signal handler.");
}

int
main() {
    // Test backtrace functions
    void* arr[50];
    char** strings;
    if (!backtrace(arr, 50)) return 1;
    if (!(strings = backtrace_symbols(arr, 50))) return 1;
    free(strings);

    // Test builtin
    _Dai_init_backtraces();
    _Dai_raise_test_backtrace_signal();

    return 1;
}
