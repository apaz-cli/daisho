#include "../../stilts-stdlib/Native/Stilts.h"

#define ALT 0xAAAAAAAAAAAAAAAA
#define CAP 2003

int main() {
  __Stilts_pre_main();
  __Stilts_String s;
  StiltsString_initempty(&s);
  
  puts("SUCCESS");
  return 0;
}
