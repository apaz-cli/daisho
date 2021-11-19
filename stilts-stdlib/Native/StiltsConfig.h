
#define __STILTS_PAGESIZE 4096

#define __STILTS_SANITY_CHECK 1

#define __STILTS_HANDLE_OOM()                                     \
    do {                                                          \
        printf("OUT OF MEMORY AT: %s:%zu inside %s().\n",         \
                           __FILE__, __LINE__, __func__);         \
        fflush(stdout);                                           \
        exit(23);                                                 \
    } while (0)

#define __STILTS_TEMP_ARENA_PAGES
