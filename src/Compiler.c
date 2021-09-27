#include "Declarations/Declarations.h"
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
    "  --codegen  : Only tokenize/parse/check the source file, and output a .c "
    "file.\n"
    "  --compile  : Execute the whole pipeline and produce a binary (defaut).\n"
    "\n"
    "C Compiler Flags:\n"
    "  --CC       : Specify which C compiler to use (System CC by default).\n"
    "  --cflags   : Specify which flags to give to the C compiler.\n\n";

// Lambdas
static inline void str_destroy(String s, void *none) { String_destroy(s); }
static inline void name_destroy(Target t, void *none) {
  String_destroy(t.file_name);
}
static inline bool filterEmpty(String str, void *extra) {
  (void)extra;
  bool empty = str[0] == '\0';
  if (empty)
    String_destroy(str);
  return !empty;
}

// Helpers
static inline void arg_err(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}
static inline void usage() {
  // Consumes.
  List_String_foreach(cmdFlags.cflags, str_destroy, NULL);
  List_Target_foreach(cmdFlags.targets, name_destroy, NULL);
  print_heap();
  exit(puts(usageMesasge));
}

static inline void parseFlags(int argc, char **argv) {
  cmdFlags.temp_folder = "/tmp/stilts/";
  cmdFlags.CC = "cc";
  cmdFlags.cflags = List_charptr_new_cap(0);
  cmdFlags.targets = List_Target_new_cap(1);
  cmdFlags.parse = true;
  cmdFlags.check = true;
  cmdFlags.codegen = true;
  cmdFlags.compileC = true;

  bool snext = false;
  if (argc <= 1) {
    usage();
  } else {
    for (int i = 1; i < argc; i++) {
      // Skip the argument if it has already been captured, and do what the
      // previous arg says.
      if (snext) {
        snext = false;

        if (apaz_str_equals(argv[i - 1], "--CC")) {
          cmdFlags.CC = String_new_of_strlen(argv[i]);
          continue;
        } else if (apaz_str_equals(argv[i - 1], "--cflags")) {
          cmdFlags.cflags =
              List_String_filter(String_split(argv[i], " "), filterEmpty, NULL);
          continue;
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
      else if (apaz_str_equals(argv[i], "--CC") ||
               apaz_str_equals(argv[i - 1], "--cflags")) {
        if (i == argc)
          arg_err("--CC requires an argument (The C compiler to use).");
        snext = true;
      }

      // Targets
      else {
        Target t = {.file_name = argv[i]};
        cmdFlags.targets = List_Target_addeq(cmdFlags.targets, t);
      }
    }
  }

  List_Target_trim(cmdFlags.targets);
  List_String_trim(cmdFlags.cflags);
}

static inline const char *strb(bool b) { return b ? "yes" : "no"; }
static inline void printFlags() {
  printf("Command Line Flags:\n\n    /* Pipeline Options */\n    parse:   %s\n   "
         " check:   %s\n    codegen: %s\n    compile: %s\n\n",
         strb(cmdFlags.parse), strb(cmdFlags.check), strb(cmdFlags.codegen),
         strb(cmdFlags.compileC));

  puts("    /* Codegen Options */");
  printf("    CC:      %s\n", cmdFlags.CC);
  printf("    cflags:  [");
  if (List_String_len(cmdFlags.cflags))
    puts(cmdFlags.cflags[0]);
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

int main(int argc, char **argv) {
  parseFlags(argc, argv);
  printFlags();
}