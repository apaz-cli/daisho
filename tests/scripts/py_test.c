#include "../../stilts-stdlib/Native/Stilts.h"

int
main(int argc, char** argv) {
    __Stilts_pre_main(argc, argv);

#if __STILTS_EMBED_PYTHON
    __Stilts_py_eval("print('SUCCESS')");
#else
    puts("SUCCESS");
#endif

    __Stilts_exit(0);
}
