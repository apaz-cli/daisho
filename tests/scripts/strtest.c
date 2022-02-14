#include "../../stdlib/Native/Daisho.h"

#define ALT 0xAAAAAAAAAAAAAAAA
#define CAP 2003

int
main(int argc, char** argv) {
    __Dai_pre_main(argc, argv);
    __Dai_String s;
    __Dai_String_initEmpty(&s);

    puts("SUCCESS");
    return 0;
}
