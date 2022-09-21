#include "apaz-libc.h"
#include "daisho/Daisho.h"
#define DAISHO_SOURCEINFO 1
#include "daisho_tokenizer_parser.h"

LIST_DECLARE(daisho_token)
LIST_DEFINE(daisho_token)

static inline void
readFile(char* filePath, char** str, size_t* len) {
    long inputFileLen;
    FILE* inputFile;
    char* filestr;

    if (!(inputFile = fopen(filePath, "r")))
        fprintf(stderr, "Error: Could not open %s.\n", filePath), exit(1);
    if (fseek(inputFile, 0, SEEK_END) == -1)
        fprintf(stderr, "Error: Could not seek to end of file.\n"), exit(1);
    if ((inputFileLen = ftell(inputFile)) == -1)
        fprintf(stderr, "Error: Could not check file length.\n"), exit(1);
    if (fseek(inputFile, 0, SEEK_SET) == -1)
        fprintf(stderr, "Error: Could not rewind the file.\n"), exit(1);
    if (!(filestr = (char*)malloc(inputFileLen + 1)))
        fprintf(stderr, "Error: Could not allocate memory.\n"), exit(1);
    if (!fread(filestr, 1, inputFileLen, inputFile))
        fprintf(stderr, "Error: Could not read any bytes from the file.\n"), exit(1);
    filestr[inputFileLen] = '\0';
    fclose(inputFile);

    *str = filestr;
    *len = inputFileLen;
}

static inline void
printtok(daisho_token tok, void* _tokenizer) {
    daisho_tokenizer tokenizer = *(daisho_tokenizer*)_tokenizer;
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

#if DAISHO_SOURCEINFO
    printf(") {.kind=%s, .len=%zu, .line=%zu, .col=%zu}\n", daisho_tokenkind_name[tok.kind],
           tok.len, tok.line, tok.col);
#else
    printf(") {.kind=%s, .len=%zu}\n", daisho_tokenkind_name[tok.kind], tok.len);
#endif
}

int
main(void) {
    // Read file
    char* input_str = NULL;
    size_t input_len = 0;
    readFile("sample.txt", &input_str, &input_len);

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
        printtok(tokens[i], &tokenizer);
    }

    // Parse AST
    pgen_allocator allocator = pgen_allocator_new();
    daisho_parser_ctx parser;
    daisho_parser_ctx_init(&parser, &allocator, tokens, List_daisho_token_len(tokens));

    daisho_astnode_t* ast = daisho_parse_expr(&parser);

    // Print AST
    if (ast)
        daisho_astnode_print_json(tokens, ast);
    else
        puts("null");

    free(cps);
    List_daisho_token_destroy(tokens);
    pgen_allocator_destroy(&allocator);
}
