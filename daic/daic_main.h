#ifndef DAIC_MAIN_INCLUDE
#define DAIC_MAIN_INCLUDE

#include "allocator.h"
#include "argparse.h"
#include "cleanup.h"
#include "daisho.peg.h"
#include "extraparsing.h"
#include "list.h"
#include "typecheck.h"
#include "types.h"

static inline int
daic_main_args(Daic_Args args) {
    if (args.h)
        return puts(helpmsg), 0;
    else if (args.v)
        return puts(versionmsg), 0;
    else if (args.errfail)
        return 1;
    else if (args.errstr)
        return fputs(args.errstr, stderr), free(args.errstr), 1;

    DaicCleanupContext cctx = daic_cleanup_init();

    char* err_str = NULL;
    _Daic_List_daisho_token tokens = _Daic_List_daisho_token_new();
    _Daic_List_InputFile input_files = _Daic_List_InputFile_new();
    daic_cleanup_add(&cctx, _Daic_List_daisho_token_cleanup, &tokens);
    daic_cleanup_add(&cctx, InputFile_cleanup, &input_files);

    // Read file, Tokenize. Combined, because imports read other files.
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
        for (int sev = 4; sev-- > 0;) {
            for (size_t i = 0; i < parser.num_errors; i++) {
                if (parser.errlist[i].severity == sev) {
                    if ((sev == 2) | (sev == 3)) ex = 1;
                    fprintf(stderr, "%s on line %zu: %s\n", daic_sevstr_lower[sev],
                            parser.errlist[i].line, parser.errlist[i].msg);
                }
            }
        }
        if (ex) {
            daic_cleanup(&cctx);
            return 1;
        }
    }

    // Print AST
    daisho_astnode_print_json(tokens.buf, ast);

    if (parser.pos != parser.len) {
        fprintf(stderr, "Didn't consume the entire input.\n");
        return 1;
    }

    if (ast) {
        _Daic_List_NamespaceDecl nsdecls = extractNamespacesAndTLDs(ast);
        daic_cleanup_add(&cctx, _Daic_List_NamespaceDecl_cleanup, &nsdecls);
        exprTypeVisit(ast, NULL);
    }

    daic_cleanup(&cctx);
    return 0;
}

static inline int
daic_main(int argc, char** argv) {
    return daic_main_args(daic_argparse(argc, argv));
}

#endif /* DAIC_MAIN_INCLUDE */
