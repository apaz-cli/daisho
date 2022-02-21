#include <execinfo.h>

#define __DAI_SANITY_CHECK 2
#define __DAI_TESTING_BACKTRACES
#define __DAI_NO_LIBRARIES
#include "../stdlib/Daisho.h"

void
sighandler(int sig, siginfo_t* info, void* ucontext) {
    ucontext_t ctx = *(ucontext_t*)ucontext;
    puts("In signal handler.");
}

int
main() {
    // Test backtrace functions
    void* arr[50];
    if (!backtrace(arr, 50)) return 1;
    if (!backtrace_symbols(arr, 50)) return 1;

    // Install signal handlers
    __Dai_install_backtrace_signals();

    // Throw signal
    raise(SIGSEGV);


    puts("Got here.");
}
