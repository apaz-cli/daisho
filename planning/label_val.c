#include <stdint.h>
#include <stdio.h>
int main(void) {
    lbl:;
    void* lblval = (&&lbl);
    return puts("SUCCESS");
}
