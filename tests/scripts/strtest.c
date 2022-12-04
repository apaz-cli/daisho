#include "../../stdlib/Daisho.h"

int
main(int argc, char** argv) {
    _Dai_initialize(argc, argv);

    _Dai_String s;
    _Dai_String_initEmpty(&s);

    puts("SUCCESS");
    return 0;
}
