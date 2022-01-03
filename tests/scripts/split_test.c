#include "../../stdlib/Native/Stilts.h"

int main() {
    __Stilts_String_split_impl("This has many words.", " ");
    __Stilts_String_split_impl("Thisisarunonsentence.", " ");
}
