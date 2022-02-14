#define __DAI_EMBED_PYTHON 1
#include "../../stdlib/Daisho.h"

int
main(int argc, char** argv) {
    __Dai_pre_main(argc, argv);

#if __DAI_EMBED_PYTHON
    __Dai_py_eval((char*)"print('SUCCESS')");
#else
    puts("SUCCESS");
#endif

    __Dai_exit(0);
}
