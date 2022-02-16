#include "../../stdlib/Daisho.h"

int
toFromTest(char* path) {
    __Dai_String_View raw = __Dai_readFile(path);
    __Dai_UTF8_String_View utf = __Dai_UTF8_readFile(path);
    __Dai_Unicode_Codepoint_String_View cps = __Dai_Unicode_readFile(path);
    // __Dai_Unicode_Codepoint_String_View raw_cps = __Dai_;

    // These had better match up.
    // printf("[%zu, %zu]", back.len, original.len);
    if (back.len != original.len) return 1;

    // printf("%s\n", back.content);
    // printf("%s\n", original.content);
    if (!apaz_str_equals(back.content, original.content)) return 1;
    return 0;
}

int
main(void) {
    if (toFromTest("samples/greek.txt")) return 1;
    if (toFromTest("samples/utf8rand.txt")) return 1;

    puts("SUCCESS");
    return 0;
}
