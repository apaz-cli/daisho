#include "Declarations/Declarations.h"
#include "Declarations/Generated/Automata.h"
#include "Declarations/GlobalState.h"
#include "Declarations/MethodDeclarations.h"
#include "Declarations/StructDeclarations.h"
#include <apaz-libc.h>

const char *usageMesasge =
    "Stilts v0.1\n"
    "Usage:\n"
    "  -h --help : Display this message and exit.\n"
    "\n"
    "Pipeline Flags:\n"
    "  --tokenize : Only tokenize the target file.\n"
    "  --parse    : Only tokenize and create an AST of the target file.\n"
    "  --check    : Only validate the types/syntax of the target file.\n"
    "  --codegen  : Only tokenize/parse/check the source file, and output C.\n"
    "  --compile  : Execute the whole pipeline and produce a binary (defaut).\n"
    "\n"
    "C Compiler Flags:\n"
    "  --CC       : Specify which C compiler to use (System cc by default).\n"
    "  --cflags   : Specify which flags to give to the C compiler.\n"
    "\n"
    "Runtime Extension Flags:\n"
    " --python    : Embed python support by linking against system Python3.\n"
    " --no-python : Don't add python support.\n"
    "\n"
    "Debugging Flags:\n"
    " --pedantic : Add pedantic sanity checks. Slow, but good for debugging.\n"
    " --sane     : Basic sanity checks are performed. (Null checks, OOM, etc.)\n"
    " --insane   : No sanity checks. Difficult to debug, but very fast.\n"
    "\n"
    "Memdebug Flags:\n"
    " --no-memdebug    : Don't wrap malloc(), calloc(), realloc(), free().\n"
    " --memdebug       : Wrap memory functions for tracking leaks and bugs.\n"
    " --memdebug-print : Also print every allocation and free to stderr.\n"
    "\n"
    "Malloc Flags:\n"
    " --normal-malloc  : Stilts gets memory from malloc().\n"
    " --replace-malloc : Stilts gets memory from its own allocator.\n"
    "\n"
    "Stiltc Flags:\n"
    "  --jobs -j  : Specify how many threads stiltc should process your code "
    "with.\n"
    "\n";

// Lambdas
static inline void str_destroy(String s, void *none) { String_destroy(s); }
static inline bool filterEmpty(String str, void *extra) {
  (void)extra;
  bool empty = str[0] == '\0';
  if (empty) String_destroy(str);
  return !empty;
}

// Helpers
static inline void arg_err(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}
static inline void usage() {
  // Consumes.
  int ex = puts(usageMesasge);
  destroyFlags();
  print_heap();
  exit(ex);
}

static inline void parseFlags(int argc, char **argv) {
  cmdFlags.temp_folder = "/tmp/stilts/";
  cmdFlags.CC = "cc";
  cmdFlags.cflags = List_String_new_cap(0);
  cmdFlags.targets = List_Target_new_cap(1);
  cmdFlags.parse = true;
  cmdFlags.check = true;
  cmdFlags.codegen = true;
  cmdFlags.compileC = true;

  bool grabNext = false;
  if (argc <= 1) {
    usage();
  } else {
    for (size_t i = 1; i < argc; i++) {
      // Skip the argument if it has already been captured, and do what the
      // previous arg says.
      if (grabNext) {
        grabNext = false;

        if (apaz_str_equals(argv[i - 1], "--CC")) {
          cmdFlags.CC = String_new_of_strlen(argv[i]);
          continue;
        } else if (apaz_str_equals(argv[i - 1], "--cflags")) {
          String sarg = String_new_of_strlen(argv[i]);
          List_String_destroy(cmdFlags.cflags);
          cmdFlags.cflags =
              List_String_filter(String_split(sarg, " "), filterEmpty, NULL);
          String_destroy(sarg);
          continue;
        } else if (apaz_str_equals(argv[i - 1], "-j")) {
          int i = atoi(argv[i]);
          if (!(i > 0))
            arg_err("The number of jobs must be a number greater than zero.");
          cmdFlags.num_threads = (size_t)i;
        }
      }

      // Help flag
      else if (apaz_str_equals(argv[i], "-h") |
               apaz_str_equals(argv[i], "--help")) {
        usage();
      }

      // Pipeline Flags
      else if (apaz_str_equals(argv[i], "--tokenize"))
        cmdFlags.parse = false;
      else if (apaz_str_equals(argv[i], "--parse"))
        cmdFlags.check = false;
      else if (apaz_str_equals(argv[i], "--check"))
        cmdFlags.codegen = false;
      else if (apaz_str_equals(argv[i], "--codegen"))
        cmdFlags.compileC = false;

      // Compiler Flags
      else if (apaz_str_equals(argv[i], "--CC")) {
        if (i == argc)
          arg_err("--CC requires an argument (The C compiler to use).");
        grabNext = true;
      } else if (apaz_str_equals(argv[i], "--cflags")) {
        if (i == argc)
          arg_err("--cflags requires an argument (The flags to pass to the C "
                  "compiler, all in one arg).");
        grabNext = true;
      } else if (apaz_str_equals(argv[i], "-j") ||
                 apaz_str_equals(argv[i], "--jobs")) {
        if (i == argc)
          arg_err("--jobs/-j requires an argument (The number of threads to "
                  "create).");
        grabNext = true;
      }

      // Targets
      else {
        Target t = {.file_name = argv[i]};
        cmdFlags.targets = List_Target_addeq(cmdFlags.targets, t);
      }
    }
  }

  cmdFlags.cflags = List_String_trim(cmdFlags.cflags);
  cmdFlags.targets = List_Target_trim(cmdFlags.targets);
}

static inline void destroyFlags() {
  List_String_foreach(cmdFlags.cflags, str_destroy, NULL);
  List_Target_destroy(cmdFlags.targets);
}

static inline const char *strb(bool b) { return b ? "yes" : "no"; }
static inline void printFlags() {
  printf(
      "Command Line Flags:\n\n    /* Pipeline Options */\n    parse:   %s\n   "
      " check:   %s\n    codegen: %s\n    compile: %s\n\n",
      strb(cmdFlags.parse), strb(cmdFlags.check), strb(cmdFlags.codegen),
      strb(cmdFlags.compileC));

  puts("    /* Codegen Options */");
  printf("    CC:      %s\n", cmdFlags.CC);
  printf("    cflags:  [");
  if (List_String_len(cmdFlags.cflags))
    printf("%s", cmdFlags.cflags[0]);
  for (size_t i = 1; i < List_String_len(cmdFlags.cflags); i++)
    printf(", %s", cmdFlags.cflags[i]);
  printf("]\n");

  printf("    targets: [");
  if (List_Target_len(cmdFlags.targets))
    printf("%s", cmdFlags.targets[0].file_name);
  for (size_t i = 1; i < List_Target_len(cmdFlags.targets); i++)
    printf(", %s", cmdFlags.targets[i].file_name);
  printf("]\n\n");
  fflush(stdout);
}

static inline void readTargets() {
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
static inline void tokenize_task(void *targs) {
  TokenizeTaskArgs *args = targs;
}
static inline void tokenizeTargets() {
  initTokenizerDFAs();

  Threadpool pool;
  Threadpool_create(&pool, cmdFlags.num_threads);
  // Threadpool_exectask(&pool, tokenize_task, );
}

int main(int argc, char **argv) {
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
