#include "../../stilts-stdlib/Native/Stilts.h"
#include <assert.h>

#define ALT 0xAAAAAAAAAAAAAAAA
#define CAP 2003

int main() {

  // printf("%zu\n", sizeof(StiltsString));

  StiltsString s1 = {0};
  STILTS_STR_WRITE_FLAG(s1, STILTS_STR_FLAG_VAL);
  if (STILTS_STR_READ_FLAG(s1) != STILTS_STR_FLAG_VAL) return 1;

  StiltsString s2;
  STILTS_STR_WRITE_FLAG(s2, STILTS_STR_FLAG_VAL);
  s2.large.buffer = (char*)ALT;
  s2.large.size = (size_t)ALT;
  if (STILTS_STR_READ_FLAG(s2) != STILTS_STR_FLAG_VAL) return 1;

  StiltsString s3;
  STILTS_STR_WRITE_FLAG(s3, STILTS_STR_FLAG_VAL);
  s3.large.buffer = (char*)ALT;
  s3.large.size = ALT;
  if (STILTS_STR_READ_FLAG(s3) != STILTS_STR_FLAG_VAL) return 1;
  puts("here 1");
  STILTS_STR_LARGE_WRITE_CAP(s3, CAP);
  if (STILTS_STR_LARGE_READ_CAP(s3) != CAP) return 1;
  puts("here 2");
  if (STILTS_STR_READ_FLAG(s3) != STILTS_STR_FLAG_VAL) return 1;

  puts("SUCCESS");
  return 0;
}
