#include "../../stilts-stdlib/Native/Stilts.h"

#define ALT 0xAAAAAAAAAAAAAAAA
#define CAP 2003

int main(int argc, char** argv) {
  __Stilts_pre_main(argc, argv);
  __Stilts_String s;
  __Stilts_String_initEmpty(&s);

  puts("SUCCESS");
  return 0;
}
