#ifndef DAIC_MAIN_INCLUDE
#define DAIC_MAIN_INCLUDE

#include "allocator.h"
#include "argparse.h"
#include "cleanup.h"
#include "daisho_peg.h"
#include "extraparsing.h"
#include "list.h"
#include "typecheck.h"
#include "types.h"

int
daic_main_args(Daic_Args args) {
    if (args.h)
        return 0;
    else if (args.parse_failed)
        return 1;

    DaicCleanupContext cctx = daic_cleanup_init();

    // Tokenize
    char* err_str = NULL;
    _Daic_List_daisho_token tokens = _Daic_List_daisho_token_new();
    _Daic_List_InputFile input_files = _Daic_List_InputFile_new();
    daic_cleanup_add(&cctx, daic_tokenlist_cleanup, &tokens);
    daic_cleanup_add(&cctx, InputFile_cleanup, &input_files);

    daic_read_utf8decode_tokenize_file(args.target, &input_files, &tokens, 1, &err_str);
    if (err_str) {
        printf("Failed to tokenize %s\nReason: %s\n", args.target, err_str);
        daic_cleanup(&cctx);
        return 1;
    }

    pgen_allocator allocator = pgen_allocator_new();
    daic_cleanup_add(&cctx, daic_allocator_cleanup, &allocator);

    // Parse AST
    daisho_parser_ctx parser;
    daisho_parser_ctx_init(&parser, &allocator, tokens.buf, tokens.len);
    daisho_astnode_t* ast = daisho_parse_program(&parser);

    // Check for parse errors
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
        return 1;
    }

    if (ast) {
        _Daic_List_NamespaceDecl nsdecls = extractNamespacesAndTLDs(ast);
        exprTypeVisit(ast, NULL);
    }

    pgen_allocator_destroy(&allocator);
    for (size_t i = 0; i < input_files.len; i++) {
        InputFile_free(input_files.buf[i]);
    }
    _Daic_List_InputFile_clear(&input_files);
    _Daic_List_daisho_token_clear(&tokens);

    return 0;
}

int
daic_main(int argc, char** argv) {
    return daic_main_args(daic_argparse(argc, argv));
}

#endif /* DAIC_MAIN_INCLUDE */
