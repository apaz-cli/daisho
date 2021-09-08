#include "stilts-common.hpp"

struct CMDLINEFLAGS {

  bool tokenize = true;
  bool parse = true;
  bool check = true;
  bool codegen = true;
  bool compileC = true;

  string CC = "";
  vector<string> cflags = vector<string>();
  string temp_folder = "/tmp/stilts/";

  vector<string> targets;
} cmdFlags;
typedef struct CMDLINEFLAGS CMDLINEFLAGS;

string usage =
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
    "  --cflags   : Specify which flags to give to the C compiler.\n";

static inline void parseFlags(int argc, char **argv) {

  bool snext = false;
  auto ERR = [](string msg) {
    cerr << msg;
    exit(1);
  };
  auto strcmp = [](char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
      s1++ || s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
  };

  if (argc <= 1) {
    cout << usage << endl;
    exit(0);
  } else {
    for (int i = 0; i < argc; i++) {
      // Skip the argument if it has already been captured, and do what the
      // previous arg says.
      if (snext) {
        snext = false;

        if (strcmp(argv[i - 1], "--CC")) {
          cmdFlags.CC = string(argv[i]);
        } else if (strcmp(argv[i - 1], "--cflags")) {
          vector<string> v;

          // Split on space
          string s;
          istringstream f(argv[i]);
          while (getline(f, s, ' '))
            v.push_back(s);
          cmdFlags.cflags = v;
        }
      }

      // Help flag
      else if (strcmp(argv[i], "-h") | strcmp(argv[i], "--help")) {
        cout << usage;
        exit(0);
      }

      // Pipeline Flags
      else if (strcmp(argv[i], "--tokenize"))
        cmdFlags.parse = false;
      else if (strcmp(argv[i], "--parse"))
        cmdFlags.check = false;
      else if (strcmp(argv[i], "--check"))
        cmdFlags.codegen = false;
      else if (strcmp(argv[i], "--codegen"))
        cmdFlags.compileC = false;
      else if (strcmp(argv[i], "--compileC"))
        ; // nop

      // Compiler Flags
      else if (strcmp(argv[i], "--CC")) {
        if (i == argc)
          ERR("--CC requires an argument (The C compiler to use).");
      }

      // Targets
      else {
        cmdFlags.targets.push_back(argv[i]);
      }
    }
  }
}

int main(int argc, char **argv) {
  parseFlags(argc, argv); 
  
  
  
}