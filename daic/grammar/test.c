#include <daisho/Daisho.h>

#include "../typecheck.h"
#include "../types.h"
#include "daisho_tokenizer_parser.h"

_DAI_LIST_DECLARE(daisho_token)
_DAI_LIST_DEFINE(daisho_token)

static inline void
pgen_readfile(char* filePath, char** str, size_t* len, char** error) {
    long inputFileLen, numRead;
    FILE* inputFile;
    char* filestr;

    if (!(inputFile = fopen(filePath, "r"))) {
        *str = NULL;
        *len = 0;
        *error = "Could not open the file.";
        return;
    }
    if (fseek(inputFile, 0, SEEK_END) == -1) {
        *str = NULL;
        *len = 0;
        *error = "Could not seek to end of file.";
        return;
    }
    if ((inputFileLen = ftell(inputFile)) == -1) {
        *str = NULL;
        *len = 0;
        *error = "Could not check file length.";
        return;
    }
    if (fseek(inputFile, 0, SEEK_SET) == -1) {
        *str = NULL;
        *len = 0;
        *error = "Could not rewind the file.";
        return;
    }
    if (!(filestr = (char*)malloc(inputFileLen + 1))) {
        *str = NULL;
        *len = 0;
        *error = "Could not allocate memory.";
        return;
    }
    if ((numRead = fread(filestr, 1, inputFileLen, inputFile)), numRead != inputFileLen) {
        *str = NULL;
        *len = 0;
        *error = "Could not read from the file.";
        return;
    }
    filestr[inputFileLen] = '\0';
    fclose(inputFile);

    *str = filestr;
    *len = inputFileLen;
    *error = NULL;
}

static inline void
printtok(daisho_token tok) {
    printf("Token: (");
    for (size_t i = 0; i < tok.len; i++) {
        codepoint_t c = tok.content[i];
        if (c == '\n')
            printf("\\n");
        else if (c == '\t')
            printf("\\t");
        else if (c == '\r')
            printf("\\r");
        else
            putchar(c);
    }

    printf(") {.kind=%s, .len=%zu, .line=%zu, .col=%zu}\n", daisho_tokenkind_name[tok.kind],
           tok.len, tok.line, tok.col);
}

static inline size_t
parse_current(daisho_tokenizer* ctx, char* s) {
    size_t len = strlen(s);
    if (!((ctx->len - ctx->pos) >= len)) return 0;

    size_t idx = ctx->pos;
    for (size_t i = 0; i < len; i++)
        if ((codepoint_t)s[i] != ctx->start[idx++]) return 0;

    return len;
}

static inline void
parse_ws(daisho_tokenizer* ctx) {
    int skipped = 0;
    while (true) {
        int cs = 0;
        codepoint_t c = ctx->start[ctx->pos];
        if ((c == ' ') | (c == '\r') | (c == '\t')) {
            cs = 1;
            ctx->pos++;
            ctx->pos_col++;
        } else if (c == '\n') {
            cs = 1;
            ctx->pos++;
            ctx->pos_line++;
            ctx->pos_col = 0;
        } else if (parse_current(ctx, "//")) {
            cs = 1;
            ctx->pos += 2;
            ctx->pos_col += 2;
            while ((ctx->pos != ctx->len) && ctx->start[ctx->pos] != '\n') {
                ctx->pos++;
                ctx->pos_col++;
            }
        } else if (parse_current(ctx, "/*")) {
            cs = 1;
            ctx->pos += 2;
            ctx->pos_col += 2;
            while (!parse_current(ctx, "*/")) {
                if (ctx->start[ctx->pos] == '\n') {
                    ctx->pos_line++;
                    ctx->pos_col = 0;
                } else {
                    ctx->pos_col++;
                }
                ctx->pos++;
            }
            size_t n = parse_current(ctx, "*/");
            ctx->pos_col += n;
            ctx->pos += n;
        }

        if (!cs)
            break;
        else
            skipped = 1;
    }
}

static inline daisho_token
parse_Nativebody(daisho_tokenizer* ctx) {
    parse_ws(ctx);
    size_t line = ctx->pos_line;
    size_t col = ctx->pos_col;
    size_t original_pos = ctx->pos;

    daisho_token failure;
    failure.kind = DAISHO_TOK_STREAMEND;
    failure.content = NULL;
    failure.len = 0;
    failure.line = line;
    failure.col = col;

    size_t depth = 1;
    size_t first = parse_current(ctx, "{");
    ctx->pos++;
    ctx->pos_col++;
    if (!first) return failure;

    while (depth && (ctx->pos <= ctx->len)) {
        codepoint_t c = ctx->start[ctx->pos];
        ctx->pos++;
        if (c == '{')
            depth++;
        else if (c == '}')
            depth--;

        if (c == '\n') {
            ctx->pos_col = 0;
            ctx->pos_line++;
        } else {
            ctx->pos_col++;
        }
    }

    if (depth) return failure;

    daisho_token capture;
    capture.kind = DAISHO_TOK_NATIVE;
    capture.len = (ctx->pos - original_pos);      // Strip last }
    capture.content = ctx->start + original_pos;  // Strip first {
    capture.line = line;
    capture.col = col;
    return capture;
}

int main(void) {
    // Read file
    char* input_file = "sample.txt";
    char *input_str, *ferr;
    size_t input_len;
    pgen_readfile(input_file, &input_str, &input_len, &ferr);
    if (ferr) fprintf(stderr, "Error reading %s: %s\n", input_file, ferr), exit(1);
    if (!input_len) fprintf(stderr, "The input file is empty."), exit(1);

    // Decode to UTF32
    codepoint_t* cps = NULL;
    size_t cpslen = 0;
    if (!UTF8_decode(input_str, input_len, &cps, &cpslen))
        fprintf(stderr, "Could not decode to UTF32.\n"), exit(1);
    free(input_str);

    // Tokenize
    _Dai_List_daisho_token tokens = _Dai_List_daisho_token_new();
    daisho_tokenizer tokenizer;
    daisho_tokenizer_init(&tokenizer, cps, input_len);

    daisho_token tok;
    do {
        tok = daisho_nextToken(&tokenizer);

        // Discard whitespace and end of stream, add other tokens to the list.
        if ((tok.kind == DAISHO_TOK_SLCOM) | (tok.kind == DAISHO_TOK_MLCOM) |
            (tok.kind == DAISHO_TOK_WS) | (tok.kind == DAISHO_TOK_STREAMEND))
            continue;

        if (tok.kind == DAISHO_TOK_NATIVE) {
            _Dai_List_daisho_token_add(&tokens, tok);
            tok = parse_Nativebody(&tokenizer);
            if (tok.kind == DAISHO_TOK_STREAMEND) {
                fprintf(stderr, "Error on line %zu: Could not parse native body.\n",
                        tokenizer.pos_line);
                exit(1);
            }
        }

        _Dai_List_daisho_token_add(&tokens, tok);
    } while (tok.kind != DAISHO_TOK_STREAMEND);

    // Print tokens
    for (size_t i = 0; i < tokens.len; i++) {
        printtok(tokens.buf[i]);
    }

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
}
