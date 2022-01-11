#include <apaz-libc.h>

int
toFromTest(const char* path) {
    UTF8FileContent to = utf8_readFile((char*)path);
    FileContent back = utf8_encode_content(to);
    FileContent original = apaz_str_readFile((char*)path);

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
