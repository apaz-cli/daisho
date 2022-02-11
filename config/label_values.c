#include <apaz-libc.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    void* lblval = &&lbl;
    goto *lblval;

    lbl:;
    return 0;
}
