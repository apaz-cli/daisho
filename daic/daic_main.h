#ifndef DAIC_MAIN_INCLUDE
#define DAIC_MAIN_INCLUDE

#include <daisho/Daisho.h>

#include "allocator.h"
#include "argparse.h"
#include "daisho_peg.h"
#include "extraparsing.h"
#include "list.h"
#include "typecheck.h"
#include "types.h"

int
daic_main(int argc, char** argv) {
    Daic_Args args = daic_argparse(argc, argv);

    // Tokenize
    _Daic_List_daisho_token tokens = _Daic_List_daisho_token_new();
    _Daic_List_InputFile input_files = _Daic_List_InputFile_new();
    char* err_str = NULL;
    daic_read_utf8decode_tokenize_file(args.target, &input_files, &tokens, 1, &err_str);
    if (err_str) {
        printf("Failed to tokenize file.\nReason: %s\n", err_str);
    }

    // Parse AST
    daisho_parser_ctx parser;
    pgen_allocator allocator = pgen_allocator_new();
    daisho_parser_ctx_init(&parser, &allocator, tokens.buf, tokens.len);

    daisho_astnode_t* ast = daisho_parse_program(&parser);

    // Check for errors
    if (parser.num_errors) {
        int ex = 0;
        char* sevstr[] = {"INFO", "WARNING", "ERROR", "PANIC"};
        for (int sev = 4; sev-- > 0;) {
            for (size_t i = 0; i < parser.num_errors; i++) {
                if (parser.errlist[i].severity == sev) {
                    if ((sev == 2) | (sev == 3)) ex = 1;
                    fprintf(stderr, "%s on line %zu: %s\n", sevstr[sev], parser.errlist[i].line,
                            parser.errlist[i].msg);
                }
            }
        }
        if (ex) exit(1);
    }

    // Print AST
    if (ast)
        daisho_astnode_print_json(tokens.buf, ast);
    else
        puts("null");

    if (parser.pos != parser.len) {
        fprintf(stderr, "Didn't consume the entire input.\n");
        exit(1);
    }

    if (ast) exprTypeVisit(ast, NULL);

    pgen_allocator_destroy(&allocator);
    for (size_t i = 0; i < input_files.len; i++) {
        InputFile_free(input_files.buf[i]);
    }
    _Daic_List_InputFile_clear(&input_files);
    _Daic_List_daisho_token_clear(&tokens);

    return 0;
}

#endif /* DAIC_MAIN_INCLUDE */
