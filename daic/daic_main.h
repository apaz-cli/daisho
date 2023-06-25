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
daic_main_args(Daic_Args args, FILE* daic_stdout, FILE* daic_stderr) {
    DaicContext ctx = {0};

    if (!daic_stdout || !daic_stderr)
        return fputs("daic_stdout and daic_stderr should not be null.", stderr),
               daic_argdestroy(&args), 1;
    ctx.daic_stdout = daic_stdout;
    ctx.daic_stderr = daic_stderr;

    if (args.h)
        return fputs(helpmsg, daic_stderr), daic_argdestroy(&args), 0;
    else if (args.v)
        return fputs(versionmsg, daic_stdout), daic_argdestroy(&args), 0;
    else if (args.errfail)
        return daic_argdestroy(&args), 1;
    else if (args.errstr)
        return fputs(args.errstr, daic_stderr), daic_argdestroy(&args), 1;
    ctx.args = args;

    if (setjmp(ctx.panic_handler)) {
        daic_print_panic(&ctx, ctx.panic_err_message);
        return 1;
    }

    // Equivalent to "ctx.cleanup = _Daic_List_DaicCleanupEntry_new()".
    // We do this because making lists takes the ctx, containing
    // and depending on this list. Therefore, we have to create
    // this list special.
    // Sets ctx.panic_err_message on failure.
    daic_cleanup_init(&ctx);
    if (ctx.panic_err_message) {
        daic_print_panic(&ctx, ctx.panic_err_message);
        return 1;
    }

    // Also initialize pretty errors.
    _Daic_List_DaicErrorPtr errors = _Daic_List_DaicErrorPtr_new(&ctx);

    // Error handling will be handling like so.
    // Errors are put into three categories.
    // 1. Compiler errors (DaicError and daic_error_print())
    // 2. Internal errors ()
    // 3. Panics errors

    // From now on, we have a working way to do cleanup.
    // That means we can rely on the panic handler, and
    // ditch direct calls to daic_print_panic().

    char* err_str = NULL;
    _Daic_List_daisho_token tokens = _Daic_List_daisho_token_new(&ctx);
    _Daic_List_InputFile input_files = _Daic_List_InputFile_new(&ctx);

    // Read file, Tokenize. Combined, because imports read other files.
    DaicError* err =
        daic_read_utf8decode_tokenize_file(&ctx, args.target, &tokens, &input_files, 1);
    if (err) {
        daic_error_print(daic_stderr, err, 1);
        daic_cleanup(&ctx);
        return 1;
    }

    pgen_allocator allocator = pgen_allocator_new();
    daic_cleanup_add(&ctx, daic_allocator_cleanup, (void*)&allocator);

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
                    fprintf(daic_stderr, "%s on line %zu: %s\n", daic_sevstr_lower[sev],
                            parser.errlist[i].line, parser.errlist[i].msg);
                    DaicError* err =
                        daic_error_new(&ctx, DAIC_ERROR_STAGE_PARSER, (char*)parser.errlist[i].msg,
                                       parser.errlist[i].from_file->fname, parser.errlist[i].line,
                                       parser.errlist[i].col, parser.errlist[i].severity, 0);
                    _Daic_List_DaicErrorPtr_add(&errors, err);
                }
            }
        }
        if (ex) {
            daic_print_errlist(daic_stderr, &errors, 1);
            daic_cleanup(&ctx);
            return 1;
        }
    }

    // Print AST
    daisho_astnode_print_json(tokens.buf, ast);

    if (parser.pos != parser.len) {
        fprintf(daic_stderr, "Didn't consume the entire input.\n");
        return 1;
    }

    if (ast) {
        extractNamespacesAndTLDs(&ctx, ast);
        exprTypeVisit(&ctx, ast, NULL);
    }

    daic_cleanup(&ctx);
    return 0;
}

static inline int
daic_main(int argc, char** argv) {
    return daic_main_args(daic_argparse(argc, argv), stdout, stderr);
}

#endif /* DAIC_MAIN_INCLUDE */
