#define _DAI_EMBED_PYTHON 1
#include "../../stdlib/Daisho.h"

int
main(int argc, char** argv) {
    _Dai_initialize(argc, argv);

#if _DAI_EMBED_PYTHON
    _Dai_py_eval((char*)"print('SUCCESS')");
#else
    puts("SUCCESS");
#endif

    _Dai_exit(0);
}
