#include <execinfo.h>

int main() {
    void* arr[50];
    if (!backtrace(arr, 50)) return 1;
    return backtrace_symbols(arr, 50) ? 0 : 1;
}
