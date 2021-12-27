#include "../../stdlib/Native/Stilts.h"
void f1(void) { __Stilts_backtrace(); }
void f2(void) { f1(); }
int main(void) { f2(); puts("SUCCESS"); }
