#include "stilts-common.h"
#include <apaz-libc.h>
#include <apaz-string.h/apaz-string.h>
#include <stdio.h>

struct CMDLINEFLAGS {

  bool parse;
  bool check;
  bool codegen;
  bool compileC;

  String CC;
  List_String cflags;
  String temp_folder;

  List_String targets;
} cmdFlags;
typedef struct CMDLINEFLAGS CMDLINEFLAGS;

const char *usage =
    "Stilts v0.1\n\n"
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

void ERR(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

static inline bool filterEmpty(String str, void *extra) {
  (void)extra;
  bool empty = apaz_str_equals(str, "");
  if (empty)
    String_destroy(str);
  return !empty;
}

static inline void parseFlags(int argc, char **argv) {
  cmdFlags.temp_folder = String_new_of_strlen("/tmp/stilts/");
  cmdFlags.cflags = List_String_new_cap(0);
  cmdFlags.targets = List_String_new_cap(1);
  cmdFlags.parse = true;
  cmdFlags.check = true;
  cmdFlags.codegen = true;
  cmdFlags.compileC = true;

  bool snext = false;
  if (argc <= 1) {
    exit(puts(usage));
  } else {
    for (int i = 1; i < argc; i++) {
      // Skip the argument if it has already been captured, and do what the
      // previous arg says.
      if (snext) {
        snext = false;

        if (apaz_str_equals(argv[i - 1], "--CC")) {
          cmdFlags.CC = String_new_of_strlen(argv[i]);
        } else if (apaz_str_equals(argv[i - 1], "--cflags")) {
          cmdFlags.cflags =
              List_String_filter(String_split(argv[i], " "), filterEmpty, NULL);
        }
      }

      // Help flag
      else if (apaz_str_equals(argv[i], "-h") |
               apaz_str_equals(argv[i], "--help")) {
        exit(puts(usage));
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
          ERR("--CC requires an argument (The C compiler to use).");
      }

      // Targets
      else {
        cmdFlags.targets = List_String_addeq(cmdFlags.targets, argv[i]);
      }
    }
  }
}

int main(int argc, char **argv) {
  parseFlags(argc, argv);
  printf("Flags:\nparse: %i\ncheck: %i\ncodegen: %i\ncompile: %i\n",
         cmdFlags.parse, cmdFlags.check, cmdFlags.codegen, cmdFlags.compileC);
  printf("targets: ");
  List_String_print(cmdFlags.targets);
}