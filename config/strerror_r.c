#include <stdio.h>
#include <string.h>

#define STRERR_R                                     \
    _Generic(strerror_r, int (*)(int, char*, size_t) \
             : "XSI", char* (*)(int, char*, size_t)  \
             : "GNU", default                        \
             : "UNK")
// Return nonzero exit code if not XSI compliant.
int
main(void) {
    return !!strcmp(STRERR_R, "XSI");
}
