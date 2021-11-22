#include "../../stilts-stdlib/Native/Stilts.h"

int main(int argc, char** argv) {
  __Stilts_pre_main(argc, argv);

  __Stilts_py_test();

  __Stilts_exit(0);
}
