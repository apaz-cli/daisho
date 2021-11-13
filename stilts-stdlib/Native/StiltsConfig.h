#define HANDLE_OOM()                                              \
    do {                                                          \
        printf("OUT OF MEMORY AT: %s:%zu\n", __FILE__, __LINE__); \
        fflush(stdout);                                           \
    } while (0)