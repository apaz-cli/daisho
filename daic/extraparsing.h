#ifndef DAIC_NATIVEPARSE_INCLUDE
#define DAIC_NATIVEPARSE_INCLUDE
#include "daisho_peg.h"

// typedef char* cstr;
// _DAI_LIST_DECLARE(cstr)
// _DAI_LIST_DEFINE(cstr)
_DAI_LIST_DECLARE(codepoint_t)
_DAI_LIST_DEFINE(codepoint_t)

static inline void
daic_readfile(char* filePath, char** str, size_t* len, char** error) {
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
        fclose(inputFile);
        return;
    }
    if ((inputFileLen = ftell(inputFile)) == -1) {
        *str = NULL;
        *len = 0;
        *error = "Could not check file length.";
        fclose(inputFile);
        return;
    }
    if (fseek(inputFile, 0, SEEK_SET) == -1) {
        *str = NULL;
        *len = 0;
        *error = "Could not rewind the file.";
        fclose(inputFile);
        return;
    }
    if (!(filestr = (char*)malloc(inputFileLen + 1))) {
        *str = NULL;
        *len = 0;
        *error = "Could not allocate memory.";
        fclose(inputFile);
        return;
    }
    if ((numRead = fread(filestr, 1, inputFileLen, inputFile)), numRead != inputFileLen) {
        *str = NULL;
        *len = 0;
        *error = numRead == -1 ? "Could not read from the file."
                               : "Couldn't read enough bytes from the file.";
        fclose(inputFile);
        free(filestr);
        return;
    }
    filestr[inputFileLen] = '\0';
    fclose(inputFile);

    *str = filestr;
    *len = inputFileLen;
    *error = NULL;
}

static inline void
daic_read_utf8decode_file(char* path, codepoint_t** cps, size_t* cpslen, char** err_msg) {
    char* input_str;
    size_t input_len;
    daic_readfile(path, &input_str, &input_len, err_msg);
    if (err_msg) return;

    if (!UTF8_decode(input_str, input_len, cps, cpslen)) {
        *err_msg = "Could not decode to UTF32.";
    }

    free(input_str);
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

        if (!cs) break;
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
    capture.kind = DAISHO_TOK_NATIVEBODY;
    capture.len = (ctx->pos - original_pos);      // Strip last }
    capture.content = ctx->start + original_pos;  // Strip first {
    capture.line = line;
    capture.col = col;
    return capture;
}

// To be called after an INCLUDE is tokenized.
// The returned string must be freed with UTF8_FREE.
// Returns null on error.
static inline char*
parse_includePath(daisho_tokenizer* ctx) {
    parse_ws(ctx);

    _Dai_List_codepoint_t pathcps = _Dai_List_codepoint_t_new();

    daisho_token tok = daisho_nextToken(ctx);
    int isstr = tok.kind == DAISHO_TOK_STRLIT;
    int ispath = tok.kind == DAISHO_TOK_INCLUDEPATH;
    if (isstr | ispath) return NULL;

    // We know that the token parsed, so we can
    // make structural assumptions.
    if (tok.len <= 2) return NULL;
    for (size_t i = 1; i < tok.len - 1; i++) {
        codepoint_t c = tok.content[i];
        if (c == '\\') {
            i++;
#define ADDESCAPE(un, esc) \
    if (c == un) _Dai_List_codepoint_t_add(&pathcps, esc);
            ADDESCAPE('n', '\n');
            ADDESCAPE('f', '\f');
            ADDESCAPE('b', '\b');
            ADDESCAPE('r', '\r');
            ADDESCAPE('t', '\t');
            ADDESCAPE('e', 27);
            ADDESCAPE('\\', '\\');
            ADDESCAPE('\'', '\'');
            ADDESCAPE('\"', '\"');
            ADDESCAPE('{', '{');
            ADDESCAPE('}', '}');
#undef ADDESCAPE
            i++;
        } else {
            _Dai_List_codepoint_t_add(&pathcps, c);
        }
    }

    char* retstr;
    size_t retlen;
    UTF8_encode(pathcps.buf, pathcps.len, &retstr, &retlen);
    _Dai_List_codepoint_t_clear(&pathcps);

    return retstr;
}

#endif /* DAIC_NATIVEPARSE_INCLUDE */
