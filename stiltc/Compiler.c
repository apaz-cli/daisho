#include <apaz-libc.h>
#include <daisho/Daisho.h>

#include "Argparse.h"
#include "Declarations/Declarations.h"

static inline void
readTargets() {
    size_t n = List_Target_len(cmdFlags.targets);
    for (size_t i = 0; i < n; i++) {
        cmdFlags.targets[i].fileInfo = utf8_readFile(cmdFlags.targets[i].file_name);
        if (!cmdFlags.targets[i].fileInfo.content) {
            printf("Could not open file: %s\n", cmdFlags.targets[i].file_name);
            // TODO make catching memory leaks less shit
            exit(1);
        }
    }
}

struct TokenizeTaskArgs {};
typedef struct TokenizeTaskArgs TokenizeTaskArgs;
static inline void
tokenize_task(void* targs) {
    TokenizeTaskArgs* args = (TokenizeTaskArgs*)targs;
}
static inline void
tokenizeTargets() {
    initTokenizerDFAs();

    Threadpool pool;
    Threadpool_create(&pool, cmdFlags.num_threads);
    // Threadpool_exectask(&pool, tokenize_task, );
}

int
main(int argc, char** argv) {
    // Parse command line flags
    parseFlags(argc, argv);
    // printFlags();

    // Read Files
    readTargets();

    // Tokenize
    tokenizeTargets();

    // Parse (Construct AST)

    // Semantic analysis

    destroyFlags();
    print_heap();
}
