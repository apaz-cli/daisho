#include "apaz-libc.h"
#include "daisho/Daisho.h"
#include "daisho_tokenizer_parser.h"

LIST_DECLARE(daisho_token)
LIST_DEFINE(daisho_token)

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

int
main(void) {
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
    List_daisho_token tokens = List_daisho_token_new_cap(1000);
    daisho_tokenizer tokenizer;
    daisho_tokenizer_init(&tokenizer, cps, input_len);

    daisho_token tok;
    do {
        tok = daisho_nextToken(&tokenizer);

        // Discard whitespace and end of stream, add other tokens to the list.
        if (!((tok.kind == DAISHO_TOK_SLCOM) | (tok.kind == DAISHO_TOK_MLCOM) |
              (tok.kind == DAISHO_TOK_WS) | (tok.kind == DAISHO_TOK_STREAMEND)))
            List_daisho_token_add(&tokens, tok);

    } while (tok.kind != DAISHO_TOK_STREAMEND);

    // Print tokens
    for (size_t i = 0; i < List_daisho_token_len(tokens); i++) {
        printtok(tokens[i]);
    }

    // Parse AST
    pgen_allocator allocator = pgen_allocator_new();
    daisho_parser_ctx parser;
    daisho_parser_ctx_init(&parser, &allocator, tokens, List_daisho_token_len(tokens));

    daisho_astnode_t* ast = daisho_parse_expr(&parser);

    // Check for errors
    if (parser.num_errors) {
        for (size_t i = 0; i < parser.num_errors; i++) {
            fprintf(stderr, "Error on line %zu: %s\n", parser.errlist[i].line,
                    parser.errlist[i].msg);
        }
        exit(1);
    }

    // Print AST
    if (ast)
        daisho_astnode_print_json(tokens, ast);
    else
        puts("null");

    free(cps);
    List_daisho_token_destroy(tokens);
    pgen_allocator_destroy(&allocator);
}
