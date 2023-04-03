#include "../../stdlib/Daisho.h"

int
main(void) {
    _Dai_initialize();

    _Dai_String s;
    _Dai_String_initEmpty(&s);

    puts("SUCCESS");
    return 0;
}
