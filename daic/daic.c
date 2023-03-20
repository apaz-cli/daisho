#include <daisho/Daisho.h>

#include "argparse.h"
#include "allocator.h"
#include "daisho_peg.h"
#include "extraparsing.h"
#include "typecheck.h"
#include "types.h"

_DAI_LIST_DECLARE(daisho_token)
_DAI_LIST_DEFINE(daisho_token)

static inline void
daic_tokenize(codepoint_t* cps, size_t cpslen, _Dai_List_daisho_token* append_tokens,
                   int first_file) {
    daisho_tokenizer tokenizer;
    daisho_tokenizer_init(&tokenizer, cps, cpslen);

    int firsttoken = 1;
    daisho_token tok;
    do {
        tok = daisho_nextToken(&tokenizer);

        // Skip the shebang.
        if (!first_file && firsttoken) {
            if (tok.kind == DAISHO_TOK_SHEBANG) continue;
        }

        // Discard whitespace and end of stream, add other tokens to the list.
        if ((tok.kind == DAISHO_TOK_SLCOM) | (tok.kind == DAISHO_TOK_MLCOM) |
            (tok.kind == DAISHO_TOK_WS) | (tok.kind == DAISHO_TOK_STREAMEND))
            continue;

        if (tok.kind == DAISHO_TOK_NATIVE) {
            _Dai_List_daisho_token_add(append_tokens, tok);
            tok = parse_Nativebody(&tokenizer);
            if (tok.kind == DAISHO_TOK_STREAMEND) {
                fprintf(stderr, "Error on line %zu: Could not parse native body.\n",
                        tokenizer.pos_line);
                exit(1);
            }
        }

        if (tok.kind == DAISHO_TOK_INCLUDE) {
            char* inclpath = parse_includePath(&tokenizer);
            codepoint_t* incl_cps;
            size_t incl_cpslen;
            char* incl_errstr;
            daic_read_utf8decode_file(inclpath, &incl_cps, &incl_cpslen, &incl_errstr);
            daic_tokenize(incl_cps, incl_cpslen, append_tokens, 0);
        }

        _Dai_List_daisho_token_add(append_tokens, tok);
    } while (tok.kind != DAISHO_TOK_STREAMEND);
}

int
daic_main(int argc, char** argv) {

    Daic_Args args = daic_argparse(argc, argv);

    codepoint_t* cps;
    size_t cpslen;
    char* err_msg = NULL;
    daic_read_utf8decode_file(args.target, &cps, &cpslen, &err_msg);

    // Tokenize
    _Dai_List_daisho_token tokens = _Dai_List_daisho_token_new();
    daic_tokenize(cps, cpslen, &tokens, 1);

    // Parse AST
    pgen_allocator allocator = pgen_allocator_new();
    daisho_parser_ctx parser;
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

    if (parser.pos != parser.len) {
        fprintf(stderr, "Didn't consume the entire input.\n");
        exit(1);
    }

    // Print AST
    if (ast)
        daisho_astnode_print_json(tokens.buf, ast);
    else
        puts("null");

    if (ast) exprTypeVisit(ast, NULL);

    free(cps);
    _Dai_List_daisho_token_clear(&tokens);
    pgen_allocator_destroy(&allocator);

    return 0;
}

int
main(int argc, char** argv) {
    return daic_main(argc, argv);
}
