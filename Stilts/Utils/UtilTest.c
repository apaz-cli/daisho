#include "Common.h"
#include "StringUtil.h"

int main() {
    String a = String_new_of_strlen("Hello ");
    String b = String_new_of_strlen("World!");
    String_print(a);
    String_println(b);

    String c = String_add(a, b);
    String_println(c);
    
    STRING_DESTROY(a, b, c);
}
