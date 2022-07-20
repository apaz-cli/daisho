#include "LSPTypes.h"

int
main(int argc, char** argv) {
    cJSON* empty = cJSON_Parse(
        "{"
        "  \"Thingy\": 500, "
        "  \"other\": \"owo.\""
        "}");

    char* str = cJSON_Print(empty);
    puts(str);
    free(str);

    cJSON_Delete(empty);
}