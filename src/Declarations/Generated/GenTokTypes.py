#!/bin/python

# [TokType, literal]


def pcase(s): return [s.upper(), s.lower()]

exact_tokens = [
    # Pragma
    pcase("native"),
    pcase("ctype"),

    # Types
    ["BOOL", "Bool"],
    ["CHAR", "Char"],
    ["UCHAR", "UChar"],
    ["SHORT", "Short"],
    ["USHORT", "UShort"],
    ["INT", "Int"],
    ["UINT", "UInt"],
    ["LONG", "Long"],
    ["FLOAT", "Float"],
    ["DOUBLE", "Double"],
    ["VOID", "Void"],

    # Control
    pcase('if'),
    pcase('else'),

    # Loops
    pcase('for'),
    pcase('while'),
    pcase('continue'),
    pcase('break'),
    pcase('in'),

    # Exceptions
    # makeLower('try'),
    # makeLower('catch'),
    # makeLower('finally'),

    # Classes
    pcase('class'),
    pcase('this'),
    pcase('operator'),
    # pcase('extends'),

    # Interfaces
    pcase('trait'),
    pcase('impl'),

    # Other containers
    pcase('enum'),

    # Access Modifiers
    pcase('private'),
    pcase('protected'),
    pcase('public'),

    # Builtin functions
    pcase('super'),
    pcase('instanceof'),
    pcase('sizeof'),
    pcase('assert'),

    # Boolean literals
    pcase('true'),
    pcase('false'),

    # Separators
    ["LPAREN", "("],
    ["RPAREN", ")"],
    ["LBRACE", "{"],
    ["RBRACE", "}"],
    ["LBRACK", "["],
    ["RBRACK", "]"],
    ["LARROW", "<"],
    ["RARROW", ">"],
    ["SEMI", ";"],
    ["COMMA", ","],
    ["DOT", "."],
    ["STAR", "*"],
    ["EQUALS", "="],
    ["LAMBDA_ARROW", "=>"],

    # Operators
    ["BANG", "!"],
    ["TILDE", "~"],
    ["QUESTION", "?"],
    ["COLON", ":"],
    ["EQUAL", "=="],
    ["LE", "<="],
    ["GE", ">="],
    ["NOTEQUAL", "!="],
    ["AND", "&&"],
    ["OR", "||"],
    ["INC", "++"],
    ["DEC", "--"],
    ["ADD", "+"],
    ["SUB", "-"],
    ["DIV", "/"],
    ["AMP", "&"],
    ["BITOR", "|"],
    ["CARET", "^"],
    ["MOD", "%"],
    ["DEREF_ARROW", "->"],

    ["ADD_ASSIGN", "+="],
    ["SUB_ASSIGN", "-="],
    ["MUL_ASSIGN", "*="],
    ["DIV_ASSIGN", "/="],
    ["AND_ASSIGN", "&="],
    ["OR_ASSIGN", "|="],
    ["XOR_ASSIGN", "^="],
    ["MOD_ASSIGN", "%="],
]

custom = ['INVALID', 'END_OF_FILE', 'WS', 'IMPORT', 'SL_COMMENT', 'ML_COMMENT', 'IDENT', ]

names = custom + [k[0] for k in exact_tokens]

custom_functions = """
/**********/
/* Custom */
/**********/


static inline TokType validImport(char *str) {
  return String_equals(str, "include") || String_equals(str, "import")
             ? IMPORT
             : INVALID;
}

static inline bool potentialImport(char *str) {
  return apaz_str_startsWith("import", str) ||
         apaz_str_startsWith("include", str);
}

static inline TokType validIdent(char *str) {
  size_t slen = String_len(str);
  for (size_t i = 0; i < slen; i++) {
    if ((str[i] != ' ') &
        (str[i] != '\\t') &
        (str[i] != '\\r') &
        (str[i] != '\\n'))
      return INVALID;
  }
  return IDENT;
}

static inline bool potentialIdent(char *str) { }

static inline TokType validComment(char *str) {
  size_t slen = apaz_strlen(str);
  if (slen < 3)
    return INVALID;
  else if (String_startsWith(str, "/*") && String_endsWith(str, "*/")) {
    size_t search_end = slen - 4; // Prefix/suffix
    str = str + 2;
    for (size_t i = 0; i < search_end; i++)
      if (str[i] == '*' & str[i + 1] == '/')
        return INVALID;
    return COMMENT;
  } else if (String_startsWith(str, "//") && String_endsWith(str, "\\n")) {
    size_t search_end = slen - 3; // -3 for prefix/suffix
    str = str + 2;
    for (size_t i = 0; i < search_end; i++)
      if (str[i] == '\\n')
        return INVALID;
    return COMMENT;
  }
  return INVALID;
}

static inline bool potentialComment(char *str) {
  bool sl = apaz_str_startsWith(str, "//");
  bool ml = apaz_str_startsWith(str, "/*");
  if (!(sl | ml))
    return false;

  size_t slen = apaz_strlen(str);
  if (sl) {
    for (size_t i = 2; i < slen - 1; i++)
      if (str[i] == '\\n')
        return false;
    return true;
  } else {
    for (size_t i = 2; i < slen - 2; i++)
      if (str[i] == '*' & str[i + 1] == '/')
        return false;
    return true;
  }
}

"""

automata_description = """

"""

custom_rules = """
/* IDENT */
/* First char of ident, [_a-zA-Zalpha-omegaALPHA-OMEGA] */
const DFARule IDENT_rule_1 = { .start_range = 'a', .end_range = 'z', .start_state = 1, .end_state = 2 };
const DFARule IDENT_rule_2 = { .start_range = 'A', .end_range = 'Z', .start_state = 1, .end_state = 2 };
const DFARule IDENT_rule_3 = { .start_range = '_', .end_range = '_', .start_state = 1, .end_state = 2 };
const DFARule IDENT_rule_4 = { .start_range = 0xceb1, .end_range = 0xcf89, .start_state = 1, .end_state = 2 };
const DFARule IDENT_rule_5 = { .start_range = 0xcea9, .end_range = 0xce91, .start_state = 1, .end_state = 2 };
/* Remaining chars of ident [_a-zA-Zalpha-omegaALPHA-OMEGA0-9] */
const DFARule IDENT_rule_6 = { .start_range = 'a', .end_range = 'z', .start_state = 2, .end_state = 2 };
const DFARule IDENT_rule_7 = { .start_range = 'A', .end_range = 'Z', .start_state = 2, .end_state = 2 };
const DFARule IDENT_rule_8 = { .start_range = '_', .end_range = '_', .start_state = 2, .end_state = 2 };
const DFARule IDENT_rule_9 = { .start_range = 0xceb1, .end_range = 0xcf89, .start_state = 2, .end_state = 2 };
const DFARule IDENT_rule_10 = { .start_range = 0xcea9, .end_range = 0xce91, .start_state = 2, .end_state = 2 };
const DFARule IDENT_rule_11 = { .start_range = '0', .end_range = '9', .start_state = 2, .end_state = 2 };
const DFARule IDENT_rules[] = { IDENT_rule_1, IDENT_rule_2, IDENT_rule_3, IDENT_rule_4, IDENT_rule_5, 
      IDENT_rule_6, IDENT_rule_7, IDENT_rule_8, IDENT_rule_9, IDENT_rule_10, IDENT_rule_11 };
const DFA IDENT_DFA = { .rules = (const DFARule* const)IDENT_rules, .num_rules = ARR_SIZE(IDENT_rules), .current_state = 1, .accepting_state = 2 };

/* Whitespace (Any amount) */
/* Start rule */
const DFARule WS_rule_1 = { .start_range = ' ', .end_range = ' ', .start_state = 1, .end_state = 1 };
const DFARule WS_rule_2 = { .start_range = '\\t', .end_range = '\\t', .start_state = 1, .end_state = 1 };
const DFARule WS_rule_3 = { .start_range = '\\r', .end_range = '\\r', .start_state = 1, .end_state = 1 };
const DFARule WS_rule_4 = { .start_range = '\\n', .end_range = '\\n', .start_state = 1, .end_state = 1 };
const DFARule WS_rules[] = { WS_rule_1, WS_rule_2, WS_rule_3, WS_rule_4 };
const DFA WS_DFA = { .rules = (const DFARule* const)WS_rules, .num_rules = ARR_SIZE(WS_rules), .current_state = 1, .accepting_state = 2 };

/* Multi-Line Comment */
const DFARule ML_COMMENT_rule_1 = { .start_range = '/', .end_range = '/', .start_state = 1, .end_state = 2 };
const DFARule ML_COMMENT_rule_2 = { .start_range = '*', .end_range = '*', .start_state = 2, .end_state = 3 };
const DFARule ML_COMMENT_rule_3 = { .start_range = '*', .end_range = '*', .start_state = 3, .end_state = 4 };
const DFARule ML_COMMENT_rule_4 = { .start_range = '/', .end_range = '/', .start_state = 4, .end_state = 5 };
// Capture all but */ while inside comment
const DFARule ML_COMMENT_rule_5 = { .start_range = 0, .end_range = NFASTATE_MAX, .start_state = 3, .end_state = 3 };
const DFARule ML_COMMENT_rules[] = { ML_COMMENT_rule_1, ML_COMMENT_rule_2, ML_COMMENT_rule_3, ML_COMMENT_rule_4, ML_COMMENT_rule_5 };
const DFA ML_COMMENT_DFA = { .rules = (const DFARule* const)ML_COMMENT_rules, .num_rules = ARR_SIZE(ML_COMMENT_rules), .current_state = 1, .accepting_state = 5 };

/* Single-Line Comment */
const DFARule SL_COMMENT_rule_1 = { .start_range = '/', .end_range = '/', .start_state = 1, .end_state = 2 };
const DFARule SL_COMMENT_rule_2 = { .start_range = '/', .end_range = '/', .start_state = 2, .end_state = 3 };
const DFARule SL_COMMENT_rule_3 = { .start_range = '\\n', .end_range = '\\n', .start_state = 3, .end_state = 4 };
// Capture all but \\n while inside comment
const DFARule SL_COMMENT_rule_4 = { .start_range = 0, .end_range = NFASTATE_MAX, .start_state = 3, .end_state = 3 };
const DFARule SL_COMMENT_rules[] = { SL_COMMENT_rule_1, SL_COMMENT_rule_2, SL_COMMENT_rule_3, SL_COMMENT_rule_4 };
const DFA SL_COMMENT_DFA = { .rules = (const DFARule* const)SL_COMMENT_rules, .num_rules = ARR_SIZE(SL_COMMENT_rules), .current_state=1, .accepting_state = 4 };

/* Import / Include */
const DFARule IMPORT_rule_1 = { .start_range = 'i', .end_range = 'i', .start_state = 1, .end_state = 2 };
const DFARule IMPORT_rule_2 = { .start_range = 'm', .end_range = 'i', .start_state = 2, .end_state = 3 };
const DFARule IMPORT_rule_3 = { .start_range = 'p', .end_range = 'i', .start_state = 3, .end_state = 4 };
const DFARule IMPORT_rule_4 = { .start_range = 'o', .end_range = 'i', .start_state = 4, .end_state = 5 };
const DFARule IMPORT_rule_5 = { .start_range = 'r', .end_range = 'i', .start_state = 5, .end_state = 6 };
const DFARule IMPORT_rule_6 = { .start_range = 't', .end_range = 'i', .start_state = 6, .end_state = 8 };
const DFARule IMPORT_rule_7 = { .start_range = 'n', .end_range = 'i', .start_state = 2, .end_state = 3 };
const DFARule IMPORT_rule_8 = { .start_range = 'c', .end_range = 'i', .start_state = 3, .end_state = 4 };
const DFARule IMPORT_rule_9 = { .start_range = 'l', .end_range = 'i', .start_state = 4, .end_state = 5 };
const DFARule IMPORT_rule_10 = { .start_range = 'u', .end_range = 'i', .start_state = 5, .end_state = 6 };
const DFARule IMPORT_rule_11 = { .start_range = 'd', .end_range = 'i', .start_state = 6, .end_state = 7 };
const DFARule IMPORT_rule_12 = { .start_range = 'e', .end_range = 'i', .start_state = 7, .end_state = 8 };
const DFARule IMPORT_rules[] = { IMPORT_rule_1, IMPORT_rule_2, IMPORT_rule_3, IMPORT_rule_4, IMPORT_rule_5, 
                                 IMPORT_rule_6, IMPORT_rule_7, IMPORT_rule_8, IMPORT_rule_9, IMPORT_rule_10, 
                                 IMPORT_rule_11, IMPORT_rule_12 };
const DFA IMPORT_DFA = { .rules = (const DFARule* const)IMPORT_rules, .num_rules = ARR_SIZE(IMPORT_rules), .current_state=1, .accepting_state = 8 };


"""

def flowerbox(str):
    tb = "/" + ("*"*(len(str)+4)) + "/\n"
    f.write(tb)
    f.write("/* " + str + " */\n")
    f.write(tb)


def writeValid(name, literal):
    f.write(
        f"static inline TokType valid_{name}(char* str) {{ static const char* tok = \"{literal}\"; const char *s = tok; while (*s) ++s; size_t toklen = (size_t)(s - str); for (size_t i = 0; i < toklen; i++) if (str[i] != tok[i]) return INVALID; return {name}; }}\n")


def writePotential(name, literal):
    f.write(
        f"static inline bool potential_{name}(char* str) {{ static const char* tok = \"{literal}\"; while (*str) if (*str++ != *tok++) return false; return true; }}\n")


def writeExactDFARules(name, literal):

    for n, c in enumerate(literal):
        f.write(
            f'const DFARule {name}_rule_{n+1} = {{ .start_range = \'{c}\', .end_range = \'{c}\', .start_state = {n+1}, .end_state = {n+2} }};\n')
    f.write(
        f'const DFARule {name}_rules[] = {{ {", ".join([name + "_rule_" + str(n+1) for n in range(len(literal)) ])} }};\n')
    f.write(
        f'const DFA {name}_DFA = {{ .rules = (const DFARule* const){name}_rules, .num_rules = ARR_SIZE({name}_rules), .current_state=1, .accepting_state = {len(literal)+1} }};\n\n')


with open("TokType.h", 'w') as f:
    # Header
    f.write('// THIS FILE GENERATED BY GenTokType.py. DO NOT EDIT.\n')
    f.write('#ifndef INCLUDE_TOKENS\n')
    f.write('#define INCLUDE_TOKENS\n')
    f.write('#include <apaz-libc.h>\n\n')

    # Declare token types
    f.write(f'#define NUM_TOKTYPES {len(names)}\n')
    f.write(f'#define MAX_TOKTYPE_NAME_LEN {max([len(n) for n in names])}\n')
    f.write('enum TokType {\n')
    [f.write(f"  {c},\n") for c in custom]
    [f.write(f"  {e[0]},\n") for e in exact_tokens]
    f.write('};\ntypedef enum TokType TokType;\n')

    # Declare reverse map from TokType to TOKNAME as a static array of string.
    dq = '"'
    nl = '\n'
    f.write(
        f'static const char* TokNameMap[] = {{{nl}{f", {nl}".join([f"  {dq}{name}{dq}" for name in names])}\n}};{nl}{nl}')

    # Write methods for tokenizaton that can be generated

    # Write the ones that can't be automatically generated.
    # f.write(custom_functions)

    # Footer
    f.write("\n#endif // INCLUDE_TOKENS")

with open('Automata.h', 'w') as f:
    f.write('// THIS FILE GENERATED BY GenTokType.py. DO NOT EDIT.\n')
    f.write('#ifndef INCLUDE_AUTOMATA\n')
    f.write('#define INCLUDE_AUTOMATA\n')
    f.write('#include <apaz-libc.h>\n')
    f.write('#include "../../UTF-8.h"\n\n')
    
    f.write("typedef uint8_t NFAState;\n#define NFASTATE_MAX UINT8_MAX\n\nTYPE_DECLARE(DFARule);\nstruct DFARule {\n  // Start and end are inclusive\n  utf8_t start_range; utf8_t end_range;\n  NFAState start_state;\n  NFAState end_state;\n};\n\nTYPE_DECLARE(DFA);\nstruct DFA {\n  const DFARule* const rules;\n  size_t num_rules;\n  NFAState current_state;\n  NFAState accepting_state;\n};\n\n")

    flowerbox("Exact Rules")
    for e in exact_tokens:
        writeExactDFARules(e[0], e[1])
    f.write('\n')
    flowerbox("Custom Rules")
    f.write(custom_rules + "\n\n")

    f.write('#endif // INCLUDE_AUTOMATA\n')