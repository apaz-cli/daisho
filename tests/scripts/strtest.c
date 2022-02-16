#include "../../stdlib/Daisho.h"

int
main(int argc, char** argv) {
    __Dai_pre_main(argc, argv);

    __Dai_String s;
    __Dai_String_initEmpty(&s);

    puts("SUCCESS");
    return 0;
}
