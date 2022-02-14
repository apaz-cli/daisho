#include "../../stdlib/Native/Daisho.h"
void f1(void) { __Dai_backtrace(); }
void f2(void) { f1(); }
int main(void) { f2(); puts("SUCCESS"); }
