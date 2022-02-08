
#include <apaz-libc.h>


accept()

int main(int argc, char** argv) {
    (void)argc;
    char* input = argv[1];
    if (!input) {
        fprintf(stdout, "Please provide input.\n");
    }

    char stack_space[50000];

    void* current_node;

    while(true) {
        program:;
        block:;
        statement:;
        ident:;
        condition:;
        expression:;
        term:;
        factor:;
    }

}
