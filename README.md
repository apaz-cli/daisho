# Stilts

## A high level programming language which compiles to C.

The following:
```
int main(String[] args) {
    println("Hello World!");
    return 0;
}
```

Generates:
```c
#include <stilts_headers.h>

// ...

char static_str_0[] = "Hello World!";

// ...

int main() {
    // (From <stilts_headers>, which dispatches using _Generic())
    PRINTLN("%s\n", static_str_0);
    return 0;
}
```

Which gets macro-expanded and optimized by any modern C compiler to:
```c
#include <stdio.h>

int main() {
    printf("%s\n", "Hello World!");
    return 0;
}
```
