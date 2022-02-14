#include "../../stdlib/Native/Daisho.h"

int main() {
    __Dai_String_split_impl("This has many words.", " ");
    __Dai_String_split_impl("Thisisarunonsentence.", " ");
}
