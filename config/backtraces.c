#include <execinfo.h>

#define __DAI_SANITY_CHECK 2
#define __DAI_TESTING_BACKTRACES
#define __DAI_NO_LIBRARIES
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
    __Dai_init_backtraces();
    __Dai_raise_test_backtrace_signal();

    return 1;
}
