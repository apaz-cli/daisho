#include <locale.h>
#include <stdio.h>

int main(void) {
    if (!setlocale(LC_ALL, "C.UTF-8")) {
        fprintf(stderr, "Could not set locale to utf8.\n");
        return 1;
    }
}
